"""CLI interface for VLESS toolkit — Typer."""

import asyncio
import typer
from core.logic import parse_link, parse_text_input, parse_subscription_text, ParseError
from core.converters import convert, Format, to_txt
from core.reverse import from_config
from core.settings import load_settings, save_settings, Settings

app = typer.Typer(
    name="vtk",
    help="VLESS Toolkit — parse, validate, convert proxy links & subscriptions",
)

FORMATS = "singbox, mihomo, flclash, txt"


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
def parse_cmd(link: str):
    """Parse a proxy link and print config."""
    try:
        node = parse_link(link)
        typer.echo(f"Protocol : {node.protocol}")
        typer.echo(f"Name     : {node.display_name}")
        typer.echo(f"Address  : {node.address}:{node.port}")
        if node.net and node.net != "tcp":
            typer.echo(f"Network  : {node.net}")
        if node.tls:
            typer.echo(f"TLS      : yes (sni={node.sni or 'default'})")
    except ParseError as e:
        typer.secho(f"❌ {e}", fg=typer.colors.RED)
        raise typer.Exit(1)


@app.command()
def convert_cmd(
    link: str = typer.Option(..., "--link", "-l", help="Single proxy link"),
    fmt: str = typer.Option("singbox", "--format", "-f", help=f"Output format: {FORMATS}"),
    output: str = typer.Option("", "--output", "-o", help="Output file (stdout if empty)"),
):
    """Convert a single link to specified format."""
    try:
        node = parse_link(link)
        result = convert([node], Format(fmt))
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
def sub(
    url: str = typer.Argument(..., help="Subscription URL or file path"),
    fmt: str = typer.Option("mihomo", "--format", "-f", help=f"Output format: {FORMATS}"),
    output: str = typer.Option("", "--output", "-o", help="Output file"),
    tag_prefix: str = typer.Option("", "--tag-prefix", "-t", help="Tag prefix for node names"),
):
    """Fetch and convert a subscription."""
    async def _run():
        from core.logic import fetch_subscription
        content = await fetch_subscription(url)
        nodes = parse_subscription_text(content)
        if not nodes:
            typer.secho("❌ No nodes found in subscription", fg=typer.colors.RED)
            raise typer.Exit(1)
        return nodes

    try:
        nodes = asyncio.run(_run())
        result = convert(nodes, Format(fmt), tag_prefix=tag_prefix)
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
        nodes = from_config(text)
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


settings_app = typer.Typer(help="Manage default settings")
app.add_typer(settings_app, name="settings")


@settings_app.command("show")
def settings_show():
    """Show current settings."""
    s = load_settings()
    typer.echo(f"Sub format    : {s.sub_format.value}")
    typer.echo(f"Link format   : {s.link_format.value}")
    typer.echo(f"Config format : {s.config_format.value}")
    typer.echo(f"TXT format    : {s.txt_format.value}")
    typer.echo(f"Tag prefix    : {s.tag_prefix or '(none)'}")
    typer.echo(f"Timeout       : {s.timeout}s")


@settings_app.command("set")
def settings_set(
    key: str = typer.Argument(..., help="Setting key"),
    value: str = typer.Argument(..., help="Value"),
):
    """Set a setting value."""
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


if __name__ == "__main__":
    app()
