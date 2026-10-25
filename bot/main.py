"""Telegram bot — inline keyboard settings, file upload support."""

import asyncio
import logging
import os
import time
from collections import defaultdict

from aiogram import Bot, Dispatcher, F, Router
from aiogram.enums import ParseMode
from aiogram.filters import Command
from aiogram.types import (
    BufferedInputFile,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
)

from bot.state import PendingConversion, PendingStore
from core.converters import Format
from core.decryptors import decrypt_input
from core.fingerprint import (
    generate_device_fingerprint,
    get_proxy_base,
    parse_app_proxy_url,
    parse_device_params,
    random_device,
    to_params_string,
)
from core.formats import FORMATS, SECTIONS, extension
from core.input import InputKind, classify
from core.logic import process_input, render_nodes
from core.settings import Settings, load_settings, save_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load .env from repo root (no python-dotenv dep: TOKEN is the only required var)
if not os.environ.get("VTK_BOT_TOKEN"):
    _env_file = os.path.join(os.path.dirname(__file__), "..", ".env")
    try:
        with open(_env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    os.environ.setdefault(k.strip(), v.strip().strip("'\""))
    except OSError:
        pass

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

# Section callback prefixes, keyed by the Settings field they edit.
CB_SUB_FMT = "sub"
CB_LINK_FMT = "link"
CB_CONFIG_FMT = "cfg"
CB_TXT_FMT = "txt"
CB_PROXY = "proxy"

_SECTION_PREFIXES = {
    "sub_format": CB_SUB_FMT,
    "link_format": CB_LINK_FMT,
    "config_format": CB_CONFIG_FMT,
    "txt_format": CB_TXT_FMT,
}
_PREFIX_TO_KEY = {prefix: key for key, prefix in _SECTION_PREFIXES.items()}
_SECTION_UI = {
    "sub_format": "📋 Subscriptions",
    "link_format": "🔗 Links",
    "config_format": "⚙️ Configs",
    "txt_format": "📝 TXT files",
}

# Parsed batches waiting for a protocol pick, keyed by (chat_id, message_id).
PENDING = PendingStore()


def _format_kb(prefix: str, current: Format) -> InlineKeyboardMarkup:
    """Build format selection keyboard for a given section prefix."""
    rows = []
    for fmt_spec in FORMATS:
        mark = "✅" if fmt_spec.fmt == current else "  "
        rows.append([
            InlineKeyboardButton(
                text=f"{mark} {fmt_spec.fmt.value}",
                callback_data=f"{prefix}:{fmt_spec.fmt.value}",
            )
        ])
    rows.append([InlineKeyboardButton(text="🔙 Back", callback_data="back")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def _main_kb(s) -> InlineKeyboardMarkup:
    """Build main settings keyboard — format sections + subscription modes."""
    rows = [
        [
            InlineKeyboardButton(
                text=f"{_SECTION_UI[section.key]} → {getattr(s, section.key).value}",
                callback_data=_SECTION_PREFIXES[section.key],
            )
        ]
        for section in SECTIONS
    ]
    rows += [
        [
            InlineKeyboardButton(
                text="📱 Proxy device",
                callback_data=CB_PROXY,
            )
        ],
        [
            InlineKeyboardButton(
                text=f"{'✅' if s.group_by_country else '❌'} Group by country",
                callback_data="group_by_country",
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


def _short(v: str, n: int = 14) -> str:
    return (v[:n] + "…") if v and len(v) > n else (v or "—")


def _proxy_kb(s: Settings) -> InlineKeyboardMarkup:
    """Proxy device fingerprint settings keyboard."""
    hs = "✅" if s.proxy_headers_on else "❌"
    hwid = "✅" if s.proxy_hwid_on else "❌"
    os_name = (s.proxy_os or "android").lower()
    rows = [
        [
            InlineKeyboardButton(text=f"{hs} Send device headers", callback_data="proxy_headers_on"),
        ],
        [
            InlineKeyboardButton(
                text=f"📱 OS: {os_name}",
                callback_data="proxy_os",
            ),
        ],
        [
            InlineKeyboardButton(
                text=f"{hwid} HWID: {_short(s.proxy_hwid)}",
                callback_data="proxy_hwid_on",
            ),
        ],
        [
            InlineKeyboardButton(text=f"🆔 UA: {_short(s.proxy_ua)}", callback_data="proxy_ignore"),
        ],
        [
            InlineKeyboardButton(text=f"🏷 Ver: {_short(s.proxy_ver)}", callback_data="proxy_ignore"),
            InlineKeyboardButton(text=f"📱 Model: {_short(s.proxy_model)}", callback_data="proxy_ignore"),
        ],
        [
            InlineKeyboardButton(text=f"🌐 Locale: {_short(s.proxy_locale)}", callback_data="proxy_ignore"),
        ],
        [
            InlineKeyboardButton(text="🎲 Randomize", callback_data="proxy_random"),
        ],
        [
            InlineKeyboardButton(text="🧹 Clear", callback_data="proxy_clear"),
        ],
        [
            InlineKeyboardButton(text="🔙 Back", callback_data="back"),
        ],
    ]
    return InlineKeyboardMarkup(inline_keyboard=rows)


async def _reply_as_file(message, content: str, filename: str):
    f = BufferedInputFile(content.encode(), filename=filename)
    await message.reply_document(f)


async def _deliver_result(message, result: str, name: str, fmt: Format,
                          empty_hint: str = "nothing to output") -> None:
    """Send converted output: YAML and long results as a file, else inline."""
    ext = extension(fmt)
    safe_name = "".join(
        c for c in name if c.isalnum() or c in "._- "
    )[:50].strip() or "config"
    if ext == "yaml" or len(result) > 3000:
        await _reply_as_file(message, result, f"{safe_name}.{ext}")
    elif result.strip():
        await message.reply(f"<pre>{result}</pre>", parse_mode=ParseMode.HTML)
    else:
        await message.reply(f"❌ Empty result — {empty_hint}")


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
        "• happ://crypt* links (auto-decrypted)\n"
        "• incy://crypt* links (auto-decrypted)\n\n"
        "/settings — configure output formats\n",
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
        "  📝 TXT — TXT files with links\n"
        "  📱 Proxy — device headers for subscriptions (import from app-link)",
        parse_mode=ParseMode.HTML,
    )


@router.message(Command("settings"))
async def cmd_settings(message: Message):
    s = load_settings()
    text = (
        "⚙️ <b>Settings</b>\n\n"
        "Select output format for each input type:"
    )
    await message.reply(text, reply_markup=_main_kb(s), parse_mode=ParseMode.HTML)


@router.message(Command("proxy"))
async def cmd_proxy(message: Message):
    """Proxy device settings. Usage: /proxy [set <android,ver=..,ua=..,hwid=..>]"""
    parts = message.text.split(maxsplit=1)
    s = load_settings()
    if len(parts) >= 2 and parts[1].strip().lower().startswith("set"):
        rest = parts[1][3:].strip()
        params = parse_device_params(rest)
        if "os" in params:
            s.proxy_os = params["os"]
        if "ua" in params:
            s.proxy_ua = params["ua"]
        if "ver" in params:
            s.proxy_ver = params["ver"]
        if "model" in params:
            s.proxy_model = params["model"]
        if "locale" in params:
            s.proxy_locale = params["locale"]
        if "hwid" in params:
            s.proxy_hwid = params["hwid"]
        save_settings(s)
        await message.reply("✅ Proxy device params saved.")
        return
    text = (
        "📱 <b>Proxy device</b>\n\n"
        "Configure device headers sent to subscriptions.\n"
        "Send a web app-link (…/<code>/p/android,ua=…/https://…</code>) to import.\n"
        "/proxy set android,ver=3.8.13,ua=Happ/3.26.0,hwid=abc — set manually"
    )
    await message.reply(text, reply_markup=_proxy_kb(s), parse_mode=ParseMode.HTML)


# ---------------------------------------------------------------------------
# Callbacks
# ---------------------------------------------------------------------------

@router.callback_query(F.data.in_(set(_PREFIX_TO_KEY)))
async def cb_section(callback: CallbackQuery):
    s = load_settings()
    key = _PREFIX_TO_KEY[callback.data]
    current = getattr(s, key)
    text = (f"{_SECTION_UI[key]}\nCurrent: <code>{current.value}</code>\n\n"
            "Select output format:")
    await callback.message.edit_text(
        text, reply_markup=_format_kb(callback.data, current),
        parse_mode=ParseMode.HTML,
    )
    await callback.answer()

@router.callback_query(F.data.regexp(r"^proto:(.+)$"))
async def cb_protocol(callback: CallbackQuery):
    """Render the batch already parsed for this keyboard as the picked protocol."""
    proto = callback.data.split(":", 1)[1]
    key = (callback.message.chat.id, callback.message.message_id)
    pending = PENDING.take(key)
    if pending is None:
        await callback.answer("⏳ Expired — send the subscription again", show_alert=True)
        return
    await callback.answer()
    status = await callback.message.edit_text(
        f"⏳ Converting {proto} → {pending.fmt.value}...", reply_markup=None
    )
    res = render_nodes(
        pending.nodes, pending.fmt,
        protocol=None if proto == "all" else proto,
        group_by_country=pending.group_by_country,
        tag_prefix=pending.tag_prefix,
        sub_name=pending.sub_name,
    )
    if not res.get("ok"):
        await status.edit_text(f"❌ {res.get('error', 'Unknown error')}")
        return
    suffix = f"_{proto}" if proto != "all" else ""
    await _deliver_result(
        callback.message, res["result"], f"{pending.sub_name or 'config'}{suffix}",
        pending.fmt,
    )


@router.callback_query(F.data.startswith(
    tuple(f"{prefix}:" for prefix in _PREFIX_TO_KEY)
))
async def cb_set_format(callback: CallbackQuery):
    prefix, sep, fmt_str = callback.data.partition(":")
    if not sep or prefix not in _PREFIX_TO_KEY:
        await callback.answer()
        return
    fmt = Format(fmt_str)
    s = load_settings()
    setattr(s, _PREFIX_TO_KEY[prefix], fmt)

    save_settings(s)
    await callback.answer(f"✅ → {fmt.value}")

    text = "⚙️ <b>Settings</b>\n\nSelect output format for each input type:"
    await callback.message.edit_text(text, reply_markup=_main_kb(s),
                                     parse_mode=ParseMode.HTML)


@router.callback_query(F.data == "sub_passthrough")
async def cb_toggle_passthrough(callback: CallbackQuery):
    s = load_settings()
    s.sub_passthrough = not s.sub_passthrough
    save_settings(s)
    text = "⚙️ <b>Settings</b>\n\nSelect output format for each input type:"
    await callback.message.edit_text(text, reply_markup=_main_kb(s), parse_mode=ParseMode.HTML)


@router.callback_query(F.data == "group_by_country")
async def cb_toggle_group_country(callback: CallbackQuery):
    s = load_settings()
    s.group_by_country = not s.group_by_country
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
# Proxy device callbacks
# ---------------------------------------------------------------------------

@router.callback_query(F.data == CB_PROXY)
async def cb_proxy_menu(callback: CallbackQuery):
    s = load_settings()
    text = (
        "📱 <b>Proxy device</b>\n\n"
        "Device headers sent to subscriptions when «Send device headers» is on.\n"
        "Send a web app-link to import its device params."
    )
    await callback.message.edit_text(text, reply_markup=_proxy_kb(s), parse_mode=ParseMode.HTML)
    await callback.answer()


@router.callback_query(F.data == "proxy_headers_on")
async def cb_proxy_headers(callback: CallbackQuery):
    s = load_settings()
    s.proxy_headers_on = not s.proxy_headers_on
    save_settings(s)
    await callback.answer()
    await cb_proxy_menu(callback)


@router.callback_query(F.data == "proxy_os")
async def cb_proxy_os(callback: CallbackQuery):
    s = load_settings()
    s.proxy_os = "ios" if (s.proxy_os or "android").lower() == "android" else "android"
    save_settings(s)
    await callback.answer()
    await cb_proxy_menu(callback)


@router.callback_query(F.data == "proxy_hwid_on")
async def cb_proxy_hwid(callback: CallbackQuery):
    s = load_settings()
    s.proxy_hwid_on = not s.proxy_hwid_on
    save_settings(s)
    await callback.answer()
    await cb_proxy_menu(callback)


@router.callback_query(F.data == "proxy_random")
async def cb_proxy_random(callback: CallbackQuery):
    s = load_settings()
    d = random_device()
    s.proxy_os = d["os"]
    s.proxy_ua = d["ua"]
    s.proxy_ver = d["ver"]
    s.proxy_model = d["model"]
    s.proxy_locale = d["locale"]
    s.proxy_hwid = d["hwid"]
    save_settings(s)
    await callback.answer("🎲 Randomized")
    await cb_proxy_menu(callback)


@router.callback_query(F.data == "proxy_clear")
async def cb_proxy_clear(callback: CallbackQuery):
    s = load_settings()
    s.proxy_ua = ""
    s.proxy_ver = ""
    s.proxy_model = ""
    s.proxy_locale = ""
    s.proxy_hwid = ""
    save_settings(s)
    await callback.answer("🧹 Cleared")
    await cb_proxy_menu(callback)


@router.callback_query(F.data == "proxy_ignore")
async def cb_proxy_ignore(callback: CallbackQuery):
    await callback.answer()


# ---------------------------------------------------------------------------
# Message handler (text + documents)
# ---------------------------------------------------------------------------

async def _process_input(message, text: str):
    """Process text input and reply with converted output."""
    t_start = time.perf_counter()
    s = load_settings()

    # Import device params from a pasted web app-link (…/p/<params>/<url>)
    app_link = parse_app_proxy_url(text)
    if app_link:
        p = app_link["params"]
        s.proxy_headers_on = True
        if p.get("os"):
            s.proxy_os = p["os"]
        if p.get("ua"):
            s.proxy_ua = p["ua"]
        if p.get("ver"):
            s.proxy_ver = p["ver"]
        if p.get("model"):
            s.proxy_model = p["model"]
        if p.get("locale"):
            s.proxy_locale = p["locale"]
        if p.get("hwid"):
            s.proxy_hwid = p["hwid"]
        save_settings(s)
        text = app_link["target_url"]
        await message.reply(
            "📥 Imported device params from app-link. Headers ON.",
            parse_mode=ParseMode.HTML,
        )

    # Decryption is now centralized inside core.logic.process_input
    # (via decrypt_input), so we no longer call happ/incy decrypt here.
    # Input-type detection for an app-link was already forced to "sub"
    # above; otherwise process_input detects on the decrypted text.

    # Device headers (only when explicitly enabled)
    device_headers = None
    if s.proxy_headers_on:
        fp = generate_device_fingerprint(
            ua=s.proxy_ua, hwid=s.proxy_hwid if s.proxy_hwid_on else "",
            os_name=s.proxy_os, ver=s.proxy_ver, model=s.proxy_model,
            locale=s.proxy_locale,
        )
        device_headers = fp

    # Single unified core path: decrypt -> classify -> fetch/parse -> convert.
    # Classification runs on the *decrypted* text inside process_input, so
    # incy://-wrapped subscriptions are correctly treated as a sub.
    status_msg = None
    if classify(decrypt_input(text)) is InputKind.SUB:
        status_msg = await message.reply("⏳ Fetching subscription...")

    res = await process_input(text, device_headers=device_headers)

    if not res.get("ok"):
        err = res.get("error", "Unknown error")
        if status_msg:
            await status_msg.edit_text(f"❌ {err}")
        else:
            await message.reply(f"❌ {err}")
        return

    nodes = res["nodes"]
    result = res["result"]
    sub_name = res["sub_name"]
    content = res["content"]
    fmt = Format(res["format"])

    # Protocol selection — inline keyboard when the batch mixes protocols.
    protocols = res.get("protocols") or {}
    if len(protocols) > 1:
        rows = [[InlineKeyboardButton(
            text=f"{p} ({cnt})" if p != "all" else f"all ({res.get('total_nodes', nodes)})",
            callback_data=f"proto:{p}",
        )] for p, cnt in [("all", res.get("total_nodes", nodes)), *protocols.items()]]
        kb = InlineKeyboardMarkup(inline_keyboard=rows)
        msg_txt = f"📋 {nodes} nodes «{sub_name}» — select protocol:"
        if status_msg:
            prompt = await status_msg.edit_text(msg_txt, reply_markup=kb)
        else:
            prompt = await message.reply(msg_txt, reply_markup=kb)
        # Keyed by the message carrying the keyboard: no hashing, no refetch.
        PENDING.store(
            (prompt.chat.id, prompt.message_id),
            PendingConversion(
                nodes=res["parsed"],
                protocols=protocols,
                fmt=fmt,
                sub_name=sub_name,
            ),
        )
        return

    # Passthrough: send proxy URL + raw JSON file
    if res["input_type"] == "sub" and s.sub_passthrough:
        params_str = to_params_string({
            "os": s.proxy_os, "ver": s.proxy_ver, "model": s.proxy_model,
            "ua": s.proxy_ua, "locale": s.proxy_locale,
            "hwid": s.proxy_hwid if s.proxy_hwid_on else "",
        })
        sub_url = res.get("sub_url") or text.strip()
        proxy_url = f"{get_proxy_base()}/p/{params_str}/{sub_url}"
        await message.reply(
            f"🔗 <b>Proxy link:</b>\n<code>{proxy_url}</code>\n\n"
            f"📋 Parsed {nodes} nodes «{sub_name}»",
            parse_mode=ParseMode.HTML,
        )
        # Send raw proxy JSON as file
        safe_name = "".join(c for c in sub_name if c.isalnum() or c in "._- ")[:50].strip() or "config"
        raw_file = BufferedInputFile(content.encode(), filename=f"{safe_name}_raw.json")
        await message.reply_document(raw_file, caption="📦 Raw proxy JSON (full config)")

    if status_msg:
        await status_msg.edit_text(f"✅ {nodes} nodes «{sub_name}», converting to {fmt.value}...")

    t_done = time.perf_counter()
    logger.info(f"Total processing: {(t_done - t_start)*1000:.0f}ms")
    logger.info(f"Parsed {nodes} nodes, format={fmt.value}")

    await _deliver_result(message, result, sub_name or "config", fmt,
                          empty_hint=f"{nodes} nodes parsed but nothing to output")


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
        BotCommand(command="proxy", description="Configure proxy device headers"),
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
