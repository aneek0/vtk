# Централизация дешифровки и конвертации в ядре (`process_input`)

## Цель
Убрать дублирование вызова дешифровки `happ://`/`incy://` на каждой платформе, чтобы бот,
веб и CLI шли через один путь ядра:
  сырой ввод -> decrypt -> detect (link/sub/config) -> fetch/parse -> convert -> результат.
Платформа не должна «вспоминать» вызвать `decrypt_text` сама — именно это дало расхождение
на вкладке конвертации (incy:// проходил мимо парсера протоколов -> "No valid proxy links").

## Решения (утверждены пользователем)
1. Да — реализуем рефактор.
2. Да — `process_input` возвращает богатый `servers`-dict (`_node_to_dict`), бот переиспользует его.
3. Да — детект типа ввода идёт ПО расшифрованному тексту (не до дешифровки).
4. Да — защитный `decrypt_input` внутри `parse_text_input`/`parse_subscription_text` в scope
   (идемпотентно, предотвращает регрессию для будущих прямых вызовов).

## Область / затрагиваемые места
- `core/logic.py` — добавить `decrypt_input(raw)`, `process_input(...)`; вызвать `decrypt_input`
  внутри `parse_text_input` и `parse_subscription_text`.
- `core/happ.py` / `core/incy.py` — оставить `decrypt_link`/`decrypt_text`/`is_happ`/`is_incy`
  как единственный источник, вызываемый только ядром.
- `bot/main.py` — `_process_input`: убрать локальный блок decrypt (456-470); детект после decrypt;
  формировать ответ из dict, возвращаемого `process_input` (включая `servers`).
  `extract_subscription_name` вызывать post-hoc из расшифрованного URL.
- `web/routes/convert.py` — POST + GET `/api/convert`: убрать встроенные блоки decrypt
  (POST ~126-138, GET ~198-210); вызывать `core.logic.process_input`, вернуть его dict.
  Сохранить проброс `device_on`->headers и `tag_prefix`.
- `cli/main.py` — `do_convert`: убрать `_decrypt_input`; вызывать `process_input`
  (обёртка `asyncio.run`). `cmd_sub`/`cmd_batch` — через ядро (`fetch_subscription` уже там).
- `web/routes/decrypt.py` — НЕ менять (`/api/incy/*`, `/api/happ/*` остаются как есть).
- `tests/` — добавить `tests/test_logic_process.py`; обновить `test_web_routes.py`, `test_cli.py`.

## Подход (упорядоченные шаги)
1. `core.logic.decrypt_input(raw: str) -> str`
   - Чистая, офлайн. Заменяет все `happ://`/`incy://` ссылки через существующие
     `core.happ.decrypt_text` и `core.incy.decrypt_text`.
   - Не пробрасывает исключения наружу (per-link ошибки глушатся внутри, как сейчас).
2. `core.logic.process_input(raw, fmt=None, device_headers=None, timeout=None) -> dict`
   - `raw = decrypt_input(raw)`
   - `_detect_input(raw)` -> link / sub / config
   - link: `parse_text_input` (+ фильтр error-узлов) -> `convert`
   - sub: `await fetch_subscription(url, headers=device_headers, timeout=timeout)`
          -> `parse_subscription_text` (fallback `from_config`) -> `convert`
   - config: `from_config` -> `convert`
   - возвращает `{"ok":True, "format":..., "nodes":n, "result":...,
                   "servers":[_node_to_dict(n)...], "sub_headers":[...]}`
     (форма как у веба сейчас — фронтенд не меняется).
   - разрешение `fmt` через `load_settings()` когда None.
   - `_node_to_dict` перенести из `web/routes/convert.py` в `core/logic.py` (или импортировать),
     чтобы ядро могло строить `servers`.
3. Защитная дешифровка в ядре:
   - в `parse_text_input` и `parse_subscription_text` первой строкой `text = decrypt_input(text)`
     (идемпотентно для уже-расшифрованного).
4. Рефактор точек вызова на `process_input`:
   - bot: передать расшифрованный текст в `process_input`, отформатировать ответ из dict
     (`servers`, `result`); `extract_subscription_name` — post-hoc.
   - web POST/GET: собрать device-заголовки, вызвать `process_input`, вернуть dict.
   - cli: `do_convert` -> `process_input` через `asyncio.run`.
5. Удалить мёртвый код: локальные блоки decrypt в боте/вебе; `_decrypt_input` в cli.
6. Тесты:
   - `tests/test_logic_process.py` (новый): decrypt_input (incy + happ passthrough),
     process_input на incy-подписке (mock fetch), process_input на incy share-link (без сети).
   - обновить `test_web_routes.py` / `test_cli.py` под новый путь (без дублирования decrypt).

## Валидация
- `pytest -q` — весь набор зелёный (цель >= текущего 103 passed).
- `tests/test_logic_process.py::test_decrypt_input_incy` — реальная ссылка из
  `data/incy_vectors.json` -> исходный URL.
- `tests/test_logic_process.py::test_process_input_incy_sub` — с mock `fetch_subscription`
  возвращает `vless://` в `result`, корректный `nodes`.
- `tests/test_logic_process.py::test_process_input_incy_share` — обёртка share-link конвертируется без сети.
- Ручной smoke: `uv run python -m bot.main` / `web` / `cli` с одной `incy://` ссылкой на каждом.

## Открытые вопросы / решения (закрыто)
- Детект по расшифрованному тексту: ДА.
- `servers` в возврате `process_input`: ДА (богатый dict, бот переиспользует).
- Публичное API `decrypt_link`/`decrypt_text` стабильно: сохраняем (веб API не трогаем).
- Защитный `decrypt_input` в `parse_text_input`/`parse_subscription_text`: ДА, в scope.
