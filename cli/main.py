"""CLI interface for VLESS Toolkit — Typer.

Usage:
    vtk vless://...                    # auto-detect & convert (default: singbox)
    vtk vless://... -f mihomo         # specific format
    vtk vless://... -o config.json     # save to file
    vtk interactive                    # interactive mode — asks for format
    vtk settings                       # show/set settings (like bot inline menu)
"""

import asyncio
import sys

import typer

from core.converters import Format, convert, to_txt
from core.logic import (
    ParseError,
    fix_link,
    parse_link,
    parse_subscription_text,
    parse_text_input,
)
from core.reverse import from_config as from_config_reverse
from core.settings import load_settings, save_settings

app = typer.Typer(
    name="vtk",
    help="VLESS Toolkit — parse, validate, convert proxy links & subscriptions",
    no_args_is_help=True,
)

FORMATS = "singbox, mihomo, flclash, txt, xray"


def _detect_input(text: str) -> str:
    """Detect input type: 'sub', 'config', 'link'."""
    text = text.strip()
    if text.startswith(("http://", "https://")):
        return "sub"
    if text.startswith("{") or "proxies:" in text or text.startswith("- name:"):
        return "config"
    return "link"


def _convert_link(link: str, fmt: Format | None = None) -> str:
    """Parse a single link (with fix_link), convert to requested format.

    If fmt is None, uses the user's default link_format setting.
    """
    link = fix_link(link.strip())
    node = parse_link(link)
    if fmt is None:
        s = load_settings()
        fmt = s.link_format
    return convert([node], fmt)


def _convert_links(text: str, fmt: Format | None = None) -> tuple[str, int]:
    """Parse multiple links from text, convert to requested format.

    Returns (result, node_count).
    """
    nodes = parse_text_input(text)
    nodes = [n for n in nodes if n.protocol != "error"]
    if not nodes:
        raise ParseError("No valid proxy links found")
    if fmt is None:
        s = load_settings()
        # If multiple links, use txt_format; otherwise link_format
        lines = [l.strip() for l in text.strip().splitlines() if l.strip() and not l.startswith("#")]
        share_prefixes = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")
        link_lines = [l for l in lines if any(l.startswith(p) for p in share_prefixes)]
        fmt = s.txt_format if len(link_lines) > 1 else s.link_format
    return convert(nodes, fmt), len(nodes)


def _convert_config(text: str, fmt: Format | None = None) -> tuple[str, int]:
    """Parse JSON/YAML config, reverse to share links."""
    nodes = from_config_reverse(text)
    if not nodes:
        raise ParseError("No convertible nodes found")
    if fmt is None:
        s = load_settings()
        fmt = s.config_format
    return convert(nodes, fmt), len(nodes)


# ---------------------------------------------------------------------------
# Default command — convert a link/text input (like sending to bot)
# ---------------------------------------------------------------------------

def _do_convert(input_str: str, fmt: str = "", output: str = ""):
    """Core convert logic — used by both default command and convert subcommand."""
    input_type = _detect_input(input_str)
    chosen_fmt = Format(fmt) if fmt else None

    try:
        if input_type == "sub":
            async def _fetch():
                from core.logic import fetch_subscription
                return await fetch_subscription(input_str.strip())
            content = asyncio.run(_fetch())
            nodes = parse_subscription_text(content)
            if not nodes:
                nodes = from_config_reverse(content)
            if not nodes:
                typer.secho("❌ No nodes found in subscription", fg=typer.colors.RED)
                raise typer.Exit(1)
            if chosen_fmt is None:
                chosen_fmt = load_settings().sub_format
            result = convert(nodes, chosen_fmt)
            typer.echo(f"✅ {len(nodes)} nodes from subscription")

        elif input_type == "config":
            nodes = from_config_reverse(input_str)
            if not nodes:
                typer.secho("❌ No convertible nodes found", fg=typer.colors.RED)
                raise typer.Exit(1)
            if chosen_fmt is None:
                chosen_fmt = load_settings().config_format
            result = convert(nodes, chosen_fmt)
            typer.echo(f"✅ {len(nodes)} nodes from config")

        else:
            link_prefixes = ("vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "socks://")
            stripped = input_str.strip()
            is_single = any(stripped.startswith(p) for p in link_prefixes) and "\n" not in stripped

            if is_single:
                result = _convert_link(stripped, chosen_fmt)
                typer.echo("✅ 1 node")
            else:
                result, count = _convert_links(stripped, chosen_fmt)
                typer.echo(f"✅ {count} nodes")

    except ParseError as e:
        typer.secho(f"❌ {e}", fg=typer.colors.RED)
        raise typer.Exit(1)

    if output:
        with open(output, "w") as f:
            f.write(result)
        typer.echo(f"Written to {output}")
    else:
        typer.echo(result)


@app.command()
def convert_cmd(
    input_str: str = typer.Argument(..., help="Proxy link, subscription URL, or config text"),
    fmt: str = typer.Option("", "--format", "-f", help=f"Output format: {FORMATS}"),
    output: str = typer.Option("", "--output", "-o", help="Output file (stdout if empty)"),
):
    """Convert a proxy link, subscription URL, or config to the specified format.

    If no format is given, uses your default settings (singbox for links,
    mihomo for subscriptions, txt for configs).
    """
    _do_convert(input_str, fmt, output)


# ---------------------------------------------------------------------------
# Interactive mode
# ---------------------------------------------------------------------------

@app.command()
def interactive():
    """Interactive mode — paste input, choose format, get result."""
    s = load_settings()

    typer.echo("🔧 VLESS Toolkit — Interactive mode\n")
    typer.echo("Supported: proxy link, subscription URL, config (JSON/YAML)")
    typer.echo("Paste your input (empty line to finish):\n")

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
        typer.secho("❌ Empty input", fg=typer.colors.RED)
        raise typer.Exit(1)

    input_type = _detect_input(text)
    type_labels = {"sub": "subscription", "config": "config", "link": "link(s)"}
    typer.echo(f"\n📎 Detected: {type_labels.get(input_type, input_type)}")

    # Choose format
    fmt_map = {
        "sub": ("sub_format", [Format.SINGBOX, Format.MIHOMO, Format.FLCLASH, Format.TXT]),
        "link": ("link_format", [Format.SINGBOX, Format.MIHOMO, Format.FLCLASH, Format.TXT]),
        "config": ("config_format", [Format.TXT, Format.SINGBOX, Format.MIHOMO]),
    }

    setting_key, formats = fmt_map.get(input_type, fmt_map["link"])
    current = getattr(s, setting_key)

    typer.echo(f"\nCurrent default: {current.value}")
    typer.echo("Select output format:")
    for i, f in enumerate(formats, 1):
        mark = "✅" if f == current else "  "
        typer.echo(f"  {mark} {i}. {f.value}")
    typer.echo(f"     5. (custom)")

    try:
        choice = input("\nChoice [1]: ").strip()
    except EOFError:
        choice = ""

    if not choice:
        choice = "1"

    if choice == "5":
        custom = input(f"Format ({FORMATS}): ").strip()
        try:
            chosen_fmt = Format(custom)
        except ValueError:
            typer.secho(f"❌ Unknown format: {custom}", fg=typer.colors.RED)
            raise typer.Exit(1)
    else:
        try:
            idx = int(choice) - 1
            chosen_fmt = formats[idx]
        except (ValueError, IndexError):
            chosen_fmt = current

    # Convert
    try:
        if input_type == "sub":
            async def _fetch():
                from core.logic import fetch_subscription
                return await fetch_subscription(text.strip())
            content = asyncio.run(_fetch())
            nodes = parse_subscription_text(content)
            if not nodes:
                nodes = from_config_reverse(content)
            if not nodes:
                typer.secho("❌ No nodes found", fg=typer.colors.RED)
                raise typer.Exit(1)
            result = convert(nodes, chosen_fmt)
            typer.echo(f"\n✅ {len(nodes)} nodes:\n")

        elif input_type == "config":
            nodes = from_config_reverse(text)
            if not nodes:
                typer.secho("❌ No convertible nodes", fg=typer.colors.RED)
                raise typer.Exit(1)
            result = convert(nodes, chosen_fmt)
            typer.echo(f"\n✅ {len(nodes)} nodes:\n")

        else:
            link_prefixes = ("vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "socks://")
            stripped = text.strip()
            is_single = any(stripped.startswith(p) for p in link_prefixes) and "\n" not in stripped

            if is_single:
                result = _convert_link(stripped, chosen_fmt)
                typer.echo(f"\n✅ 1 node:\n")
            else:
                result, count = _convert_links(text, chosen_fmt)
                typer.echo(f"\n✅ {count} nodes:\n")

    except ParseError as e:
        typer.secho(f"❌ {e}", fg=typer.colors.RED)
        raise typer.Exit(1)

    typer.echo(result)


# ---------------------------------------------------------------------------
# Quick commands
# ---------------------------------------------------------------------------

@app.command()
def check(link: str):
    """Validate a proxy link."""
    try:
        node = parse_link(link)
        typer.secho(f"✅ Valid {node.protocol}", fg=typer.colors.GREEN)
        typer.echo(node.display_name)
    except ParseError as e:
        typer.secho(f"❌ {e}", fg=typer.colors.RED)
        raise typer.Exit(1)


@app.command()
def parse(link: str):
    """Parse a proxy link and print fields."""
    try:
        node = parse_link(link)
        typer.echo(f"Protocol : {node.protocol}")
        typer.echo(f"Name     : {node.display_name}")
        typer.echo(f"Address  : {node.address}:{node.port}")
        if node.uuid:
            typer.echo(f"UUID     : {node.uuid}")
        if node.net and node.net != "tcp":
            typer.echo(f"Network  : {node.net}")
        if node.tls:
            typer.echo(f"TLS      : yes (sni={node.sni or 'default'})")
        if node.reality_pbk:
            typer.echo(f"Reality  : pbk={node.reality_pbk[:20]}... sid={node.reality_sid}")
        if node.flow:
            typer.echo(f"Flow     : {node.flow}")
    except ParseError as e:
        typer.secho(f"❌ {e}", fg=typer.colors.RED)
        raise typer.Exit(1)


# ---------------------------------------------------------------------------
# Settings (like bot inline menu)
# ---------------------------------------------------------------------------

settings_app = typer.Typer(help="Manage default settings (like bot /settings)")
app.add_typer(settings_app, name="settings")


@settings_app.command("show")
def settings_show():
    """Show current settings."""
    s = load_settings()
    typer.echo(f"Sub format    : {s.sub_format.value}")
    typer.echo(f"Link format   : {s.link_format.value}")
    typer.echo(f"Config format : {s.config_format.value}")
    typer.echo(f"TXT format    : {s.txt_format.value}")
    typer.echo(f"Group by country: {s.group_by_country}")
    typer.echo(f"Tag prefix    : {s.tag_prefix or '(none)'}")
    typer.echo(f"Timeout       : {s.timeout}s")
    typer.echo(f"Sub passthrough: {s.sub_passthrough}")


@settings_app.command("interactive")
def settings_interactive():
    """Interactive settings menu (like bot inline keyboard)."""
    s = load_settings()

    typer.echo("⚙️ Settings — Select output format per input type\n")
    typer.echo(f"  1. 📋 Subs → {s.sub_format.value}")
    typer.echo(f"  2. 🔗 Links → {s.link_format.value}")
    typer.echo(f"  3. ⚙️ Configs → {s.config_format.value}")
    typer.echo(f"  4. 📝 TXT → {s.txt_format.value}")
    typer.echo(f"  5. 🔄 Group by country: {'✅' if s.group_by_country else '❌'}")
    typer.echo(f"  6. 🔗 Sub passthrough: {'✅' if s.sub_passthrough else '❌'}")
    typer.echo()

    try:
        choice = input("Choose section [1-6]: ").strip()
    except EOFError:
        return

    format_options = [Format.SINGBOX, Format.MIHOMO, Format.FLCLASH, Format.TXT, Format.XRAY]

    if choice == "1":
        setting_key = "sub_format"
        label = "Subscription"
    elif choice == "2":
        setting_key = "link_format"
        label = "Links"
    elif choice == "3":
        setting_key = "config_format"
        label = "Configs"
    elif choice == "4":
        setting_key = "txt_format"
        label = "TXT"
    elif choice == "5":
        s.group_by_country = not s.group_by_country
        save_settings(s)
        typer.echo(f"✅ group_by_country = {s.group_by_country}")
        return
    elif choice == "6":
        s.sub_passthrough = not s.sub_passthrough
        save_settings(s)
        typer.echo(f"✅ sub_passthrough = {s.sub_passthrough}")
        return
    else:
        typer.secho("Invalid choice", fg=typer.colors.RED)
        return

    current = getattr(s, setting_key)
    typer.echo(f"\n{label} format (current: {current.value}):")
    for i, f in enumerate(format_options, 1):
        mark = "✅" if f == current else "  "
        typer.echo(f"  {mark} {i}. {f.value}")

    try:
        fmt_choice = input(f"\nChoice [1-{len(format_options)}]: ").strip()
    except EOFError:
        return

    try:
        idx = int(fmt_choice) - 1
        new_fmt = format_options[idx]
        setattr(s, setting_key, new_fmt)
        save_settings(s)
        typer.echo(f"✅ {setting_key} = {new_fmt.value}")
    except (ValueError, IndexError):
        typer.secho("Invalid choice", fg=typer.colors.RED)


@settings_app.command("set")
def settings_set(
    key: str = typer.Argument(..., help="Setting key"),
    value: str = typer.Argument(..., help="Value"),
):
    """Set a setting value directly. Example: vtk settings set link_format mihomo"""
    s = load_settings()
    if not hasattr(s, key):
        typer.secho(f"❌ Unknown setting: {key}", fg=typer.colors.RED)
        raise typer.Exit(1)
    current = getattr(s, key)
    if isinstance(current, int):
        setattr(s, key, int(value))
    elif isinstance(current, bool):
        setattr(s, key, value.lower() in ("true", "1", "yes"))
    else:
        setattr(s, key, value)
    save_settings(s)
    typer.echo(f"✅ {key} = {getattr(s, key)}")


# ---------------------------------------------------------------------------
# Subscription & batch (keep existing)
# ---------------------------------------------------------------------------

@app.command()
def sub(
    url: str = typer.Argument(..., help="Subscription URL or file path"),
    fmt: str = typer.Option("mihomo", "--format", "-f", help=f"Output format: {FORMATS}"),
    output: str = typer.Option("", "--output", "-o", help="Output file"),
):
    """Fetch and convert a subscription."""
    async def _run():
        from core.logic import fetch_subscription
        content = await fetch_subscription(url)
        nodes = parse_subscription_text(content)
        if not nodes:
            nodes = from_config_reverse(content)
        if not nodes:
            typer.secho("❌ No nodes found in subscription", fg=typer.colors.RED)
            raise typer.Exit(1)
        return nodes

    try:
        nodes = asyncio.run(_run())
        result = convert(nodes, Format(fmt))
    except ParseError as e:
        typer.secho(f"❌ {e}", fg=typer.colors.RED)
        raise typer.Exit(1)

    if output:
        with open(output, "w") as f:
            f.write(result)
        typer.echo(f"Converted {len(nodes)} nodes → {output}")
    else:
        typer.echo(result)


@app.command()
def batch(
    input_file: str = typer.Argument(..., help="File with links (one per line)"),
    fmt: str = typer.Option("singbox", "--format", "-f", help=f"Output format: {FORMATS}"),
    output: str = typer.Option("", "--output", "-o", help="Output file"),
):
    """Convert a file with multiple links."""
    with open(input_file) as f:
        text = f.read()
    nodes = parse_text_input(text)
    nodes = [n for n in nodes if n.protocol != "error"]
    if not nodes:
        typer.secho("❌ No valid nodes found", fg=typer.colors.RED)
        raise typer.Exit(1)

    try:
        result = convert(nodes, Format(fmt))
    except ParseError as e:
        typer.secho(f"❌ {e}", fg=typer.colors.RED)
        raise typer.Exit(1)

    if output:
        with open(output, "w") as f:
            f.write(result)
        typer.echo(f"Converted {len(nodes)} nodes → {output}")
    else:
        typer.echo(result)


@app.command()
def extract(
    input_file: str = typer.Argument(..., help="sing-box JSON or mihomo YAML config file"),
    output: str = typer.Option("", "--output", "-o", help="Output file (stdout if empty)"),
):
    """Extract share links from a sing-box JSON or mihomo YAML config."""
    with open(input_file) as f:
        text = f.read()
    try:
        nodes = from_config_reverse(text)
    except ParseError as e:
        typer.secho(f"❌ {e}", fg=typer.colors.RED)
        raise typer.Exit(1)

    if not nodes:
        typer.secho("❌ No convertible nodes found", fg=typer.colors.RED)
        raise typer.Exit(1)

    result = to_txt(nodes)
    if output:
        with open(output, "w") as f:
            f.write(result)
        typer.echo(f"Extracted {len(nodes)} links → {output}")
    else:
        typer.echo(result)


def main():
    """Entry point for the vtk CLI."""
    # If first positional arg is not a known subcommand and not a flag,
    # treat it as a link to convert (like bot: just paste a link).
    _SUBCOMMANDS = {"convert-cmd", "convert", "interactive", "settings", "check",
                     "parse", "sub", "batch", "extract"}
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-") and sys.argv[1] not in _SUBCOMMANDS:
        sys.argv.insert(1, "convert-cmd")
    app()


if __name__ == "__main__":
    main()
