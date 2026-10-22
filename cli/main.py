"""CLI interface for VLESS Toolkit — zero external dependencies.

Usage:
    vtk vless://...                    # auto-detect & convert (default from settings)
    vtk vless://... -f mihomo         # specific format
    vtk vless://... -o config.json     # save to file
    vtk interactive                    # interactive mode — asks for format
    vtk settings                       # show/set settings (like bot inline menu)
"""

import argparse
import asyncio
import sys

from core.converters import Format, convert, to_txt
from core.logic import (
    ParseError,
    parse_link,
    parse_subscription_text,
    parse_text_input,
    process_input,
)
from core.reverse import from_config as from_config_reverse
from core.settings import load_settings, save_settings

FORMATS = ["singbox", "mihomo", "flclash", "txt", "xray"]


# ---------------------------------------------------------------------------
# Core logic (same as before, no typer dependency)
# ---------------------------------------------------------------------------

def _detect_input(text: str) -> str:
    text = text.strip()
    if text.startswith(("http://", "https://")):
        return "sub"
    if text.startswith("{") or "proxies:" in text or text.startswith("- name:"):
        return "config"
    return "link"


def do_convert(input_str: str, fmt_str: str = "", output: str = "", protocol: str = ""):
    chosen_fmt = Format(fmt_str) if fmt_str else None

    res = asyncio.run(process_input(input_str, fmt=chosen_fmt, protocol=protocol or None))

    if not res.get("ok"):
        print(f"❌ {res.get('error', 'Processing failed')}", file=sys.stderr)
        sys.exit(1)

    result = res["result"]
    nodes = res["nodes"]
    print(f"✅ {nodes} nodes")

    if output:
        with open(output, "w") as f:
            f.write(result)
        print(f"Written to {output}")
    else:
        print(result)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_check(args):
    try:
        node = parse_link(args.link)
        print(f"✅ Valid {node.protocol}")
        print(node.display_name)
    except ParseError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)


def cmd_parse(args):
    try:
        node = parse_link(args.link)
        print(f"Protocol : {node.protocol}")
        print(f"Name     : {node.display_name}")
        print(f"Address  : {node.address}:{node.port}")
        if node.uuid:
            print(f"UUID     : {node.uuid}")
        if node.net and node.net != "tcp":
            print(f"Network  : {node.net}")
        if node.tls:
            print(f"TLS      : yes (sni={node.sni or 'default'})")
        if node.reality_pbk:
            print(f"Reality  : pbk={node.reality_pbk[:20]}... sid={node.reality_sid}")
        if node.flow:
            print(f"Flow     : {node.flow}")
    except ParseError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)


def cmd_convert(args):
    do_convert(args.input, args.format, args.output, getattr(args, "protocol", "") or "")


def cmd_interactive(args):
    s = load_settings()
    print("🔧 VLESS Toolkit — Interactive mode\n")
    print("Supported: proxy link, subscription URL, config (JSON/YAML)")
    print("Paste your input (empty line to finish):\n")

    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if not line and lines:
            break
        lines.append(line)

    text = "\n".join(lines).strip()
    if not text:
        print("❌ Empty input", file=sys.stderr)
        sys.exit(1)

    # Protocol selection (only when multiple protocols present)
    res0 = asyncio.run(process_input(text, fmt=Format.SINGBOX))
    if not res0.get("ok"):
        print(f"❌ {res0.get('error', 'Processing failed')}", file=sys.stderr)
        sys.exit(1)
    protos = res0["protocols"]
    chosen_proto = ""
    if len(protos) > 1:
        print("\nSelect protocol:")
        proto_items = [("all", f"all ({res0['total_nodes']})"), *protos.items()]
        for i, (p, cnt) in enumerate(proto_items, 1):
            print(f"  {i}. {p} ({cnt})")
        try:
            pchoice = input("\nChoice [1]: ").strip()
        except EOFError:
            pchoice = ""
        idx = int(pchoice) - 1 if pchoice.isdigit() else 0
        if 0 <= idx < len(proto_items):
            chosen_proto = proto_items[idx][0]
        chosen_proto = chosen_proto if chosen_proto not in ("", "all") else ""


    input_type = _detect_input(text)
    type_labels = {"sub": "subscription", "config": "config", "link": "link(s)"}
    print(f"\n📎 Detected: {type_labels.get(input_type, input_type)}")

    fmt_map = {
        "sub": ("sub_format", [Format.SINGBOX, Format.MIHOMO, Format.FLCLASH, Format.TXT]),
        "link": ("link_format", [Format.SINGBOX, Format.MIHOMO, Format.FLCLASH, Format.TXT]),
        "config": ("config_format", [Format.TXT, Format.SINGBOX, Format.MIHOMO]),
    }
    setting_key, formats = fmt_map.get(input_type, fmt_map["link"])
    current = getattr(s, setting_key)

    print(f"\nCurrent default: {current.value}")
    print("Select output format:")
    for i, f in enumerate(formats, 1):
        mark = "✅" if f == current else "  "
        print(f"  {mark} {i}. {f.value}")

    try:
        choice = input("\nChoice [1]: ").strip()
    except EOFError:
        choice = ""

    if not choice:
        choice = "1"

    try:
        idx = int(choice) - 1
        chosen_fmt = formats[idx]
    except (ValueError, IndexError):
        chosen_fmt = current
    res = asyncio.run(process_input(text, fmt=chosen_fmt, protocol=chosen_proto or None))
    if not res.get("ok"):
        print(f"❌ {res.get('error', 'Processing failed')}", file=sys.stderr)
        sys.exit(1)
    result = res["result"]
    print(f"\n✅ {res['nodes']} nodes:\n")
    print(result)



def _fmt_ext(fmt: Format) -> str:
    return {"singbox": "json", "mihomo": "yaml", "flclash": "yaml", "txt": "txt", "xray": "json"}.get(fmt.value, "txt")


def _safe_filename(name: str, ext: str) -> str:
    safe = "".join(c for c in name if c.isalnum() or c in "._- ")[:50].strip()
    return f"{safe}.{ext}" if safe else f"config.{ext}"


def cmd_sub(args):
    from core.logic import extract_subscription_name

    async def _fetch():
        from core.logic import fetch_subscription
        return await fetch_subscription(args.url)

    try:
        content = asyncio.run(_fetch())
        sub_name = extract_subscription_name(args.url, content)
        nodes = parse_subscription_text(content)
        if not nodes:
            nodes = from_config_reverse(content)
        if not nodes:
            print("❌ No nodes found in subscription", file=sys.stderr)
            sys.exit(1)
        fmt = Format(args.format)
        result = convert(nodes, fmt)
    except ParseError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        out_path = args.output
    else:
        ext = _fmt_ext(fmt)
        out_path = _safe_filename(sub_name, ext)

    with open(out_path, "w") as f:
        f.write(result)
    print(f"✅ {len(nodes)} nodes «{sub_name or 'config'}» → {out_path}")


def cmd_batch(args):
    with open(args.input_file) as f:
        text = f.read()
    nodes = parse_text_input(text)
    nodes = [n for n in nodes if n.protocol != "error"]
    proto = getattr(args, "protocol", "") or ""
    if proto:
        nodes = [n for n in nodes if n.protocol == proto]
    if not nodes:
        msg = f"No {proto} nodes found" if proto else "No valid nodes found"
        print(f"❌ {msg}", file=sys.stderr)
        sys.exit(1)
    try:
        result = convert(nodes, Format(args.format))
    except ParseError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        with open(args.output, "w") as f:
            f.write(result)
        print(f"Converted {len(nodes)} nodes → {args.output}")
    else:
        print(result)


def cmd_extract(args):
    with open(args.input_file) as f:
        text = f.read()
    try:
        nodes = from_config_reverse(text)
    except ParseError as e:
        print(f"❌ {e}", file=sys.stderr)
        sys.exit(1)
    if not nodes:
        print("❌ No convertible nodes found", file=sys.stderr)
        sys.exit(1)

    result = to_txt(nodes)
    if args.output:
        with open(args.output, "w") as f:
            f.write(result)
        print(f"Extracted {len(nodes)} links → {args.output}")
    else:
        print(result)


def cmd_settings_show(args):
    s = load_settings()
    print(f"Sub format    : {s.sub_format.value}")
    print(f"Link format   : {s.link_format.value}")
    print(f"Config format : {s.config_format.value}")
    print(f"TXT format    : {s.txt_format.value}")
    print(f"Group by country: {s.group_by_country}")
    print(f"Tag prefix    : {s.tag_prefix or '(none)'}")
    print(f"Timeout       : {s.timeout}s")
    print(f"Sub passthrough: {s.sub_passthrough}")
    print(f"Insecure TLS  : {s.insecure_tls}")


def cmd_settings_interactive(args):
    s = load_settings()
    print("⚙️ Settings — Select output format per input type\n")
    print(f"  1. 📋 Subs → {s.sub_format.value}")
    print(f"  2. 🔗 Links → {s.link_format.value}")
    print(f"  3. ⚙️ Configs → {s.config_format.value}")
    print(f"  4. 📝 TXT → {s.txt_format.value}")
    print(f"  5. 🔄 Group by country: {'✅' if s.group_by_country else '❌'}")
    print(f"  6. 🔗 Sub passthrough: {'✅' if s.sub_passthrough else '❌'}")
    print()

    try:
        choice = input("Choose section [1-6]: ").strip()
    except EOFError:
        return

    format_options = [Format.SINGBOX, Format.MIHOMO, Format.FLCLASH, Format.TXT, Format.XRAY]

    if choice == "1":
        setting_key, label = "sub_format", "Subscription"
    elif choice == "2":
        setting_key, label = "link_format", "Links"
    elif choice == "3":
        setting_key, label = "config_format", "Configs"
    elif choice == "4":
        setting_key, label = "txt_format", "TXT"
    elif choice == "5":
        s.group_by_country = not s.group_by_country
        save_settings(s)
        print(f"✅ group_by_country = {s.group_by_country}")
        return
    elif choice == "6":
        s.sub_passthrough = not s.sub_passthrough
        save_settings(s)
        print(f"✅ sub_passthrough = {s.sub_passthrough}")
        return
    else:
        print("Invalid choice", file=sys.stderr)
        return

    current = getattr(s, setting_key)
    print(f"\n{label} format (current: {current.value}):")
    for i, f in enumerate(format_options, 1):
        mark = "✅" if f == current else "  "
        print(f"  {mark} {i}. {f.value}")

    try:
        fmt_choice = input(f"\nChoice [1-{len(format_options)}]: ").strip()
    except EOFError:
        return

    try:
        idx = int(fmt_choice) - 1
        new_fmt = format_options[idx]
        setattr(s, setting_key, new_fmt)
        save_settings(s)
        print(f"✅ {setting_key} = {new_fmt.value}")
    except (ValueError, IndexError):
        print("Invalid choice", file=sys.stderr)


def cmd_settings_set(args):
    s = load_settings()
    if not hasattr(s, args.key):
        print(f"❌ Unknown setting: {args.key}", file=sys.stderr)
        sys.exit(1)
    current = getattr(s, args.key)
    if isinstance(current, int):
        setattr(s, args.key, int(args.value))
    elif isinstance(current, bool):
        setattr(s, args.key, args.value.lower() in ("true", "1", "yes"))
    else:
        setattr(s, args.key, args.value)
    save_settings(s)
    print(f"✅ {args.key} = {getattr(s, args.key)}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="vtk",
        description="VLESS Toolkit — parse, validate, convert proxy links & subscriptions",
    )
    parser.add_argument("--version", action="version", version="vtk 0.1.0")

    sub = parser.add_subparsers(dest="command")

    # convert (default when no subcommand given)
    p_convert = sub.add_parser("convert", help="Convert a link/URL/config")
    p_convert.add_argument("input", help="Proxy link, subscription URL, or config text")
    p_convert.add_argument("-f", "--format", default="", choices=FORMATS, help="Output format")
    p_convert.add_argument("-p", "--protocol", default="", help="Filter by protocol (vless, hysteria2, …)")
    p_convert.add_argument("-o", "--output", default="", help="Output file")

    # interactive
    sub.add_parser("interactive", help="Interactive mode — paste input, choose format")

    # check
    p_check = sub.add_parser("check", help="Validate a proxy link")
    p_check.add_argument("link", help="Proxy link to validate")

    # parse
    p_parse = sub.add_parser("parse", help="Parse a proxy link and print fields")
    p_parse.add_argument("link", help="Proxy link to parse")

    # sub (subscription)
    p_sub = sub.add_parser("sub", help="Fetch and convert a subscription")
    p_sub.add_argument("url", help="Subscription URL or file path")
    p_sub.add_argument("-f", "--format", default="mihomo", choices=FORMATS, help="Output format")
    p_sub.add_argument("-o", "--output", default="", help="Output file")

    # batch
    p_batch = sub.add_parser("batch", help="Convert a file with multiple links")
    p_batch.add_argument("input_file", help="File with links (one per line)")
    p_batch.add_argument("-f", "--format", default="singbox", choices=FORMATS, help="Output format")
    p_batch.add_argument("-p", "--protocol", default="", help="Filter by protocol (vless, hysteria2, …)")
    p_batch.add_argument("-o", "--output", default="", help="Output file")

    # extract
    p_extract = sub.add_parser("extract", help="Extract share links from config")
    p_extract.add_argument("input_file", help="sing-box JSON or mihomo YAML config file")
    p_extract.add_argument("-o", "--output", default="", help="Output file")

    # settings
    p_settings = sub.add_parser("settings", help="Manage default settings")
    settings_sub = p_settings.add_subparsers(dest="settings_command")

    settings_sub.add_parser("show", help="Show current settings")
    settings_sub.add_parser("interactive", help="Interactive settings menu (like bot /settings)")

    p_set = settings_sub.add_parser("set", help="Set a value: vtk settings set link_format mihomo")
    p_set.add_argument("key", help="Setting key")
    p_set.add_argument("value", help="Value")

    # If first arg is not a known subcommand and not a flag, treat as link
    known_commands = {"convert", "interactive", "check", "parse", "sub", "batch", "extract",
                      "settings", "-h", "--help", "--version"}
    if len(sys.argv) > 1 and sys.argv[1] not in known_commands and not sys.argv[1].startswith("-"):
        do_convert(sys.argv[1])
        return

    args = parser.parse_args()

    # Dispatch
    dispatch = {
        "convert": cmd_convert,
        "interactive": cmd_interactive,
        "check": cmd_check,
        "parse": cmd_parse,
        "sub": cmd_sub,
        "batch": cmd_batch,
        "extract": cmd_extract,
    }

    if args.command == "settings":
        if args.settings_command == "show" or args.settings_command is None:
            cmd_settings_show(args)
        elif args.settings_command == "interactive":
            cmd_settings_interactive(args)
        elif args.settings_command == "set":
            cmd_settings_set(args)
    elif args.command in dispatch:
        dispatch[args.command](args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
