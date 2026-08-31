# Сторонние компоненты

Оригинальные файлы EzOpenPN распространяются по MIT License. Этот файл не меняет лицензии сторонних компонентов. Полные тексты и дополнительные notices внутри контейнеров и пакетов сохраняют силу. Release SBOM содержит полный состав каждого опубликованного образа.

## Закреплённые образы и бинарные компоненты

| Закреплённый источник | Версия | Основная лицензия | Форма использования |
|---|---|---|---|
| `docker.io/library/caddy` | `2.11.4-alpine` | Apache-2.0 для Caddy, лицензии Alpine packages отдельно | Базовый образ `gateway` с неизменённым бинарным Caddy |
| `gcr.io/distroless/base-debian12` | `nonroot` | Apache-2.0 для Distroless tooling, лицензии Debian files отдельно | Минимальный финальный образ Go helpers |
| `docker.io/library/golang` | `1.26.7-bookworm` | BSD-3-Clause для packaging и Go, лицензии Debian files отдельно | Только стадия сборки, не входит целиком в финальный образ |
| `docker.io/tobyxdd/hysteria` | `v2.12.2` | MIT | Неизменённый runtime-образ Hysteria2 |
| `docker.io/library/python` | `3.12.11-slim-bookworm` | MIT для packaging, PSF-2.0 для Python, лицензии Debian files отдельно | База сборки и runtime `control` |
| `ghcr.io/xtls/xray-core` | `26.3.27` | MPL-2.0 | Версия и официальный digest служат upstream lock; финальный бинарный файл собирается из commit этой версии с закреплёнными security updates модулей |

Основные upstream-источники:

- Caddy: <https://github.com/caddyserver/caddy>
- Distroless: <https://github.com/GoogleContainerTools/distroless>
- Go image packaging: <https://github.com/docker-library/golang>
- Go language: <https://github.com/golang/go>
- Hysteria2: <https://github.com/apernet/hysteria>
- Python image packaging: <https://github.com/docker-library/python>
- Python: <https://github.com/python/cpython>
- Xray-core: <https://github.com/XTLS/Xray-core>

## Сокращённые схемы Xray

Файлы `proto/xray/**/*.proto` сокращены из XTLS/Xray-core `v26.3.27`, commit `d2758a023cd7f4174a5a5fa4ff66e487d4342ba0`. Они и сгенерированные Python derivatives в `control/src/ezopenpn/integrations/xray_proto` остаются под MPL-2.0. Полный текст находится в `proto/xray/LICENSE`; точные upstream-ссылки перечислены в `proto/xray/UPSTREAM.md`.

Runtime Xray собирается из того же commit. Архив source закреплён checksum в `runtime/xray-source.lock`; `runtime/xray-patched.mod` фиксирует `golang.org/x/crypto` v0.55.0, `golang.org/x/net` v0.58.0, `golang.org/x/text` v0.41.0 и `google.golang.org/grpc` v1.82.1 для устранения известных проблем release-зависимостей. Эти производные module files остаются под MPL-2.0.

## Прямые Python-зависимости runtime

| Пакет | Версия | Лицензия |
|---|---|---|
| `alembic` | 1.19.1 | MIT |
| `argon2-cffi` | 25.1.0 | MIT |
| `fastapi` | 0.141.1 | MIT |
| `grpcio` | 1.83.1 | Apache-2.0 |
| `httpx` | 0.28.1 | BSD-3-Clause |
| `jinja2` | 3.1.6 | BSD-3-Clause |
| `protobuf` | 7.36.0 | BSD-3-Clause |
| `pydantic-settings` | 2.15.0 | MIT |
| `pynacl` | 1.6.2 | Apache-2.0 |
| `python-multipart` | 0.0.32 | Apache-2.0 |
| `pyyaml` | 6.0.3 | MIT |
| `segno` | 1.6.6 | BSD-3-Clause |
| `sqlalchemy` | 2.0.52 | MIT |
| `uvicorn` | 0.52.4 | BSD-3-Clause |

Транзитивные Python-пакеты фиксируются в `uv.lock`; их точные версии и лицензии входят в SPDX SBOM выпуска.

## Go runtime helpers

`runtime/go.mod` не содержит внешних Go modules. `xray-supervisor` и `cert-sync` используют стандартную библиотеку Go под BSD-3-Clause и оригинальный код EzOpenPN под MIT.

## Дополнительные компоненты образов

Финальный Python-образ устанавливает Debian packages `ca-certificates` и `tini`. Caddy image включает Alpine components. Distroless и Debian base layers содержат файлы под несколькими совместимыми лицензиями. Их package-level notices и license files сохраняются в соответствующих образах и перечисляются в per-image SPDX SBOM.
