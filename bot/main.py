"""Telegram bot — inline keyboard settings, file upload support."""

import asyncio
import logging
import os
import tempfile
import time
from collections import defaultdict

from aiogram import Bot, Dispatcher, Router, F
from aiogram.types import (
    Message, BufferedInputFile,
    InlineKeyboardMarkup, InlineKeyboardButton,
    CallbackQuery,
)
from aiogram.filters import Command
from aiogram.enums import ParseMode

from core.logic import parse_link, parse_text_input, parse_subscription_text, ParseError
from core.converters import convert, Format, to_txt
from core.reverse import from_config
from core.settings import load_settings, save_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

TOKEN = os.environ.get("VTK_BOT_TOKEN", "")
router = Router()

# Rate-limit: 3 msg/sec per user
_RATE_LIMIT = 3
_RATE_WINDOW = 1.0  # seconds
_user_timestamps: dict[int, list[float]] = defaultdict(list)


def _check_rate_limit(user_id: int) -> bool:
    """Return True if user is within rate limit."""
    now = time.monotonic()
    timestamps = _user_timestamps[user_id]
    # Remove old entries
    while timestamps and now - timestamps[0] > _RATE_WINDOW:
        timestamps.pop(0)
    if len(timestamps) >= _RATE_LIMIT:
        return False
    timestamps.append(now)
    return True

# Callback prefixes
CB_SUB_FMT = "sub"
CB_LINK_FMT = "link"
CB_CONFIG_FMT = "cfg"
CB_TXT_FMT = "txt"


def _format_kb(prefix: str, current: Format) -> InlineKeyboardMarkup:
    """Build format selection keyboard for a given section prefix."""
    rows = []
    for fmt in Format:
        mark = "✅" if fmt == current else "  "
        rows.append([
            InlineKeyboardButton(
                text=f"{mark} {fmt.value}",
                callback_data=f"{prefix}:{fmt.value}",
            )
        ])
    rows.append([InlineKeyboardButton(text="🔙 Back", callback_data="back")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def _main_kb(s) -> InlineKeyboardMarkup:
    """Build main settings keyboard — format sections + subscription modes."""
    rows = [
        [
            InlineKeyboardButton(
                text=f"📋 Subs → {s.sub_format.value}",
                callback_data=CB_SUB_FMT,
            )
        ],
        [
            InlineKeyboardButton(
                text=f"🔗 Links → {s.link_format.value}",
                callback_data=CB_LINK_FMT,
            )
        ],
        [
            InlineKeyboardButton(
                text=f"⚙️ Configs → {s.config_format.value}",
                callback_data=CB_CONFIG_FMT,
            )
        ],
        [
            InlineKeyboardButton(
                text=f"📝 TXT → {s.txt_format.value}",
                callback_data=CB_TXT_FMT,
            )
        ],
        [
            InlineKeyboardButton(
                text=f"{'✅' if s.sub_passthrough else '❌'} Passthrough (proxy link)",
                callback_data="sub_passthrough",
            )
        ],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


async def _reply_as_file(message, content: str, filename: str):
    f = BufferedInputFile(content.encode(), filename=filename)
    await message.reply_document(f)


def _detect_input(text: str) -> str:
    """Detect input type: 'sub', 'config', 'link'."""
    text = text.strip()
    if text.startswith(("http://", "https://")):
        return "sub"
    if text.startswith("{") or "proxies:" in text or text.startswith("- name:"):
        return "config"
    return "link"


def _resolve_format(s, input_type: str) -> Format:
    """Get output format for detected input type."""
    fmt_map = {
        "sub": s.sub_format,
        "link": s.link_format,
        "config": s.config_format,
    }
    return fmt_map.get(input_type, s.link_format)


def _fmt_ext(fmt: Format) -> str:
    return {"singbox": "json", "mihomo": "yaml", "flclash": "yaml", "txt": "txt", "xray": "json"}.get(fmt.value, "txt")


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

@router.message(Command("start"))
async def cmd_start(message: Message):
    await message.reply(
        "🔧 <b>VLESS Toolkit</b>\n\n"
        "Send:\n"
        "• Proxy link (vless/vmess/ss/trojan/ssr)\n"
        "• Subscription URL\n"
        "• Config file (sing-box JSON / mihomo YAML)\n"
        "• TXT file with links\n"
        "• happ://crypt* links (auto-decrypted)\n\n"
        "/settings — configure output formats\n"
        "/happkey — set Happy Decoder API key",
        parse_mode=ParseMode.HTML,
    )


@router.message(Command("help"))
async def cmd_help(message: Message):
    await message.reply(
        "<b>Usage:</b>\n"
        "Just send a link, URL, or file — bot auto-detects type and converts.\n\n"
        "<b>Settings:</b>\n"
        "/settings — set output format per input type:\n"
        "  📋 Subs — subscription URLs\n"
        "  🔗 Links — single/multi proxy links\n"
        "  ⚙️ Configs — JSON/YAML configs → share links\n"
        "  📝 TXT — TXT files with links",
        parse_mode=ParseMode.HTML,
    )


@router.message(Command("happkey"))
async def cmd_happkey(message: Message):
    """Set Happy Decoder API key. Usage: /happkey <key>"""
    parts = message.text.split(maxsplit=1)
    if len(parts) < 2:
        s = load_settings()
        current = s.happ_key or "demo (5 req/min)"
        await message.reply(f"🔑 Current Happ key: <code>{current}</code>\n\nUsage: /happkey <your_key>", parse_mode=ParseMode.HTML)
        return
    key = parts[1].strip()
    s = load_settings()
    s.happ_key = key
    save_settings(s)
    await message.reply(f"✅ Happ key saved")


@router.message(Command("settings"))
async def cmd_settings(message: Message):
    s = load_settings()
    text = (
        "⚙️ <b>Settings</b>\n\n"
        "Select output format for each input type:"
    )
    await message.reply(text, reply_markup=_main_kb(s), parse_mode=ParseMode.HTML)


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------

@router.callback_query(F.data.in_({CB_SUB_FMT, CB_LINK_FMT, CB_CONFIG_FMT, CB_TXT_FMT}))
async def cb_section(callback: CallbackQuery):
    s = load_settings()
    section = callback.data

    fmt_map = {
        CB_SUB_FMT: ("📋 Subscriptions", s.sub_format, CB_SUB_FMT),
        CB_LINK_FMT: ("🔗 Links", s.link_format, CB_LINK_FMT),
        CB_CONFIG_FMT: ("⚙️ Configs", s.config_format, CB_CONFIG_FMT),
        CB_TXT_FMT: ("📝 TXT files", s.txt_format, CB_TXT_FMT),
    }

    title, current, prefix = fmt_map[section]
    text = f"{title}\nCurrent: <code>{current.value}</code>\n\nSelect output format:"
    await callback.message.edit_text(
        text, reply_markup=_format_kb(prefix, current), parse_mode=ParseMode.HTML,
    )
    await callback.answer()


@router.callback_query(F.data.startswith((CB_SUB_FMT + ":", CB_LINK_FMT + ":", CB_CONFIG_FMT + ":", CB_TXT_FMT + ":")))
async def cb_set_format(callback: CallbackQuery):
    parts = callback.data.split(":")
    if len(parts) != 2:
        await callback.answer()
        return

    prefix, fmt_str = parts
    fmt = Format(fmt_str)
    s = load_settings()

    if prefix == CB_SUB_FMT:
        s.sub_format = fmt
    elif prefix == CB_LINK_FMT:
        s.link_format = fmt
    elif prefix == CB_CONFIG_FMT:
        s.config_format = fmt
    elif prefix == CB_TXT_FMT:
        s.txt_format = fmt

    save_settings(s)
    await callback.answer(f"✅ → {fmt.value}")

    # Return to main menu
    text = "⚙️ <b>Settings</b>\n\nSelect output format for each input type:"
    await callback.message.edit_text(text, reply_markup=_main_kb(s), parse_mode=ParseMode.HTML)


@router.callback_query(F.data == "sub_passthrough")
async def cb_toggle_passthrough(callback: CallbackQuery):
    s = load_settings()
    s.sub_passthrough = not s.sub_passthrough
    save_settings(s)
    await callback.answer()
    text = "⚙️ <b>Settings</b>\n\nSelect output format for each input type:"
    await callback.message.edit_text(text, reply_markup=_main_kb(s), parse_mode=ParseMode.HTML)


@router.callback_query(F.data == "back")
async def cb_back(callback: CallbackQuery):
    s = load_settings()
    text = "⚙️ <b>Settings</b>\n\nSelect output format for each input type:"
    await callback.message.edit_text(text, reply_markup=_main_kb(s), parse_mode=ParseMode.HTML)
    await callback.answer()


# ---------------------------------------------------------------------------
# Message handler (text + documents)
# ---------------------------------------------------------------------------

async def _process_input(message, text: str):
    """Process text input and reply with converted output."""
    t_start = time.perf_counter()
    s = load_settings()
    input_type = _detect_input(text)
    sub_name = ""  # extracted subscription name for filename

    # Decrypt happ:// links before processing
    from core.happ import is_happ, decrypt_text, _get_key
    if is_happ(text):
        try:
            text = decrypt_text(text)
        except Exception as e:
            await message.reply(f"❌ Happ decrypt failed: {e}")
            return

    # Fetch subscription URL
    if input_type == "sub":
        status_msg = await message.reply("⏳ Fetching subscription...")
        try:
            import asyncio
            from core.logic import fetch_subscription, extract_subscription_name
            sub_url = text.strip()
            content = await fetch_subscription(sub_url, timeout=s.timeout)
            sub_name = extract_subscription_name(sub_url, content)

            # Always parse nodes for conversion
            nodes = parse_subscription_text(content)
            if not nodes:
                try:
                    nodes = from_config(content)
                except Exception:
                    pass

            # Passthrough: send proxy URL + raw JSON file
            if s.sub_passthrough:
                proxy_url = f"https://happy-decoder.cc/p/{sub_url}"
                await message.reply(
                    f"🔗 <b>Proxy link:</b>\n<code>{proxy_url}</code>\n\n"
                    f"📋 Parsed {len(nodes)} nodes «{sub_name}»",
                    parse_mode=ParseMode.HTML,
                )
                # Send raw proxy JSON as file
                safe_name = "".join(c for c in sub_name if c.isalnum() or c in "._- ")[:50].strip() or "config"
                raw_file = BufferedInputFile(content.encode(), filename=f"{safe_name}_raw.json")
                await message.reply_document(raw_file, caption="📦 Raw proxy JSON (full config)")

            if not nodes:
                if not s.sub_passthrough:
                    await status_msg.edit_text("❌ No nodes found (tried share links and config parsing)")
                else:
                    await status_msg.delete()
                return

            fmt = s.sub_format
            await status_msg.edit_text(f"✅ {len(nodes)} nodes «{sub_name}», converting to {fmt.value}...")
            result = convert(nodes, fmt, group_by_country=s.group_by_country)
        except Exception as e:
            await status_msg.edit_text(f"❌ Error: {e}")
            return

    # Config (JSON / YAML) → reverse to share links
    elif input_type == "config":
        try:
            nodes = from_config(text)
        except ParseError as e:
            await message.reply(f"❌ {e}")
            return
        if not nodes:
            await message.reply("❌ No convertible nodes found")
            return
        fmt = s.config_format
        input_msg = f"✅ Config: {len(nodes)} nodes"

    # Links or TXT
    else:
        nodes = parse_text_input(text)
        nodes = [n for n in nodes if n.protocol != "error"]
        if not nodes:
            logger.warning(f"No valid nodes parsed. Input: {text[:100]}")
            # Show what we got
            all_nodes = parse_text_input(text)
            errors = [n for n in all_nodes if n.protocol == "error"]
            if errors:
                logger.warning(f"Parse errors ({len(errors)}): {errors[0].name}")
            await message.reply(f"❌ No valid proxy links found in: <pre>{text[:200]}</pre>",
                                parse_mode=ParseMode.HTML)
            return
        # Check if it looks like a txt file (multiple share links)
        lines = [l.strip() for l in text.strip().splitlines() if l.strip() and not l.startswith("#")]
        share_prefixes = ("vless://", "vmess://", "trojan://", "ss://", "ssr://")
        link_lines = [l for l in lines if any(l.startswith(p) for p in share_prefixes)]
        if len(link_lines) > 1:
            fmt = s.txt_format
        else:
            fmt = s.link_format
        input_msg = f"✅ {len(nodes)} nodes"
        logger.info(f"Parsed {len(nodes)} nodes, format={fmt.value}")

    result = None

    # Convert (skip for passthrough — result already set)
    if fmt is not None and result is None:
        try:
            result = convert(nodes, fmt, group_by_country=s.group_by_country)
        except ParseError as e:
            await message.reply(f"❌ {e}")
            return

    t_done = time.perf_counter()
    logger.info(f"Total processing: {(t_done - t_start)*1000:.0f}ms")

    ext = _fmt_ext(fmt) if fmt else "json"
    logger.info(f"Result: {len(result)} chars, ext={ext}")
    # Build filename: use subscription name if available
    if sub_name:
        safe_name = "".join(c for c in sub_name if c.isalnum() or c in "._- ")[:50].strip()
        filename = f"{safe_name}.{ext}"
    else:
        filename = f"config.{ext}"
    if len(result) > 3000:
        await _reply_as_file(message, result, filename)
    elif result.strip():
        await message.reply(f"<pre>{result}</pre>", parse_mode=ParseMode.HTML)
    else:
        await message.reply(f"❌ Empty result — {len(nodes)} nodes parsed but nothing to output")


@router.message(F.document)
async def handle_document(message: Message):
    """Handle uploaded files."""
    doc = message.document
    try:
        file = await message.bot.get_file(doc.file_id)
        content = await message.bot.download_file(file.file_path)
        text = content.read().decode("utf-8", errors="replace")
    except Exception as e:
        await message.reply(f"❌ Error reading file: {e}")
        return

    await _process_input(message, text)


@router.message(F.text)
async def handle_text(message: Message):
    if not _check_rate_limit(message.from_user.id):
        await message.reply("⏳ Too many messages. Wait a second.")
        return
    await _process_input(message, message.text)


async def _set_commands(bot: Bot):
    """Register bot commands visible in Telegram menu."""
    from aiogram.types import BotCommand
    await bot.set_my_commands([
        BotCommand(command="start", description="Welcome & usage"),
        BotCommand(command="help", description="How to use"),
        BotCommand(command="settings", description="Configure output formats"),
        BotCommand(command="happkey", description="Set Happy Decoder API key"),
    ])


async def main():
    if not TOKEN:
        logger.error("Set VTK_BOT_TOKEN env var")
        return
    bot = Bot(token=TOKEN)
    dp = Dispatcher()
    dp.include_router(router)
    await _set_commands(bot)
    await dp.start_polling(bot, poll_interval=0)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
