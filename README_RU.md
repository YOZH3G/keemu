# KEEMU

[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/runtime-Docker-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
![AArch64](https://img.shields.io/badge/AArch64-supported-success)
![MIPSEL](https://img.shields.io/badge/MIPSEL-partial-yellow)
![MIPS](https://img.shields.io/badge/MIPS-partial-yellow)
![Status](https://img.shields.io/badge/status-MVP%20in%20progress-orange)

**Воспроизводимый стенд для проверки Entware-приложений без обязательного доступа к физическому роутеру Keenetic.**

KEEMU запускает зафиксированные целевые окружения через Docker и QEMU, устанавливает и проверяет Entware-пакеты, выполняет объявленные проверки и сохраняет доказательства, связанные с точными хешами входных данных.

> KEEMU — **не полный эмулятор прошивки Keenetic**. Успешный запуск подтверждает только проверенный сценарий и не считается доказательством полной совместимости с физическим роутером.

[English](README.md) · [Спецификация MVP](KEEMU_MVP1_updated.md) · [Traceability](docs/traceability.md) · [Evidence](docs/evidence/)

---

## Зачем нужен KEEMU

Тестирование Entware-программ на физических роутерах зависит от конкретного оборудования, плохо масштабируется и затрудняет воспроизведение ошибок. KEEMU переносит значительную часть проверки пакетов в контролируемое окружение и явно показывает, какие свойства удалось проверить, а какие пока недоступны.

Проект строится вокруг пяти принципов:

- **Зафиксированные входные данные.** Пакеты, профили, образы и важные артефакты привязаны к хешам.
- **Реальное исполнение целевого кода.** Где это поддерживается, целевые `opkg`, BusyBox, ELF-бинарники и скрипты запускаются через QEMU/binfmt.
- **Одноразовые и постоянные окружения.** Можно выполнить изолированный тест или оставить контролируемое окружение запущенным для диагностики.
- **Доказательства важнее предположений.** Отчёт фиксирует, что именно было запущено и какие проверки выполнить не удалось.
- **Безопасный отказ.** Пропущенная, недоступная или неподдерживаемая проверка не превращается в `PASS`.

---

## Статус архитектур

| Target | Текущий статус | Общие `init` / одиночный `test` | Исполнение target-кода |
| --- | --- | --- | --- |
| **AArch64** | Основной путь MVP | ✅ Да | ✅ QEMU/binfmt подтверждены |
| **MIPSEL** | Частичная поддержка | ⛔ `BLOCKED` в общем lifecycle | ✅ Ограниченные QEMU/PRoot и Docker/binfmt probes |
| **MIPS** | Частичная поддержка | ⛔ `BLOCKED` в общем lifecycle | ✅ Ограниченные QEMU/PRoot и Docker/binfmt probes |

Для MIPSEL/MIPS уже есть generic-профили, rootfs/SDK/fixture/image locks, проверки ELF32 и подтверждённые target probes. Общий путь `keemu init` и одиночного `keemu test` для этих архитектур пока не включён.

---

## Быстрый старт

Требования:

- Python 3.12;
- `uv`;
- Docker Engine;
- регистрация соответствующего binfmt для сценариев, где выполняется код чужой архитектуры.

Подготовка окружения:

```bash
uv sync --python 3.12
```

Тесты:

```bash
uv run pytest -q
```

Линтер:

```bash
uv run ruff check .
```

Самая простая проверка IPK без установки:

```bash
uv run keemu inspect path/to/package.ipk --profile generic-aarch64
```

---

## Основные сценарии

### Ограниченный запуск shell-скриптов

MVP 1D добавляет общий script runner с проверкой принадлежности ресурсов для одноразовых AArch64-окружений и уже запущенных persistent-окружений.

Одноразовый запуск:

```bash
uv run keemu script fixtures/scripts/mvp1d/success.sh \
  --profile generic-aarch64 \
  --repo . \
  -- arg1
```

Запуск внутри owner-verified persistent-окружения:

```bash
uv run keemu exec demo \
  --script fixtures/scripts/mvp1d/success.sh \
  --repo . \
  -- arg1
```

Обе формы поддерживают `--timeout`, `--cwd`, `--expect-exit-code` и повторяемые параметры `--stdout-contains`, `--stderr-not-contains`, `--expect-file`, `--expect-file-absent`.

Путь должен указывать на обычный project-contained файл `.sh`. KEEMU открывает его без перехода по symlink, привязывает к SHA-256, повторно проверяет перед staging и передаёт только проверенные байты в приватный no-clobber путь под `/opt/tmp` в target. Target `/bin/sh` получает literal argv и минимальное окружение; содержимое скрипта никогда не передаётся host shell. В отчёте сохраняются типизированный статус, размеры, хеши, признаки усечения, assertions и cleanup — без raw argv и вывода.

Scenario версии 1 также может содержать SHA-256-locked проверку `kind: script`. Для AArch64 есть реальные Docker/binfmt-доказательства. MIPS/MIPSEL используют тот же secure input/report contract, но сейчас честно возвращают `BLOCKED` до выделения Docker-ресурсов, поскольку общий locked lifecycle для них недоступен.

Независимый аудит MVP 1D фиксирует D01/D03/D04/D05/D06/D08 как `PASS` в ограниченном подтверждённом scope. D02/D07 и release MVP 1D остаются `BLOCKED` из-за двух явных пробелов: атомарной безопасности cleanup при враждебном конкурентном same-UID процессе внутри target и production recovery/reporting для persistent script artifacts, оставшихся после `SIGKILL`.

См.:

- `docs/specifications/KEEMU_MVP1D_script_execution.md`;
- `docs/evidence/mvp1d-m1d13-final-audit.md`;
- `docs/limitations.md`.

### Статический анализ IPK

```bash
uv run keemu inspect path/to/package.ipk --profile generic-aarch64
```

С dependency-complete rootfs:

```bash
uv run keemu inspect path/to/package.ipk \
  --profile generic-aarch64 \
  --rootfs path/to/dependency-complete-rootfs
```

`inspect` возвращает SHA-256, метаданные пакета, содержимое архивов, сведения об ELF, findings, итоговый статус и ограничения.

Статический `PASS` **не равен** runtime-приёмке и сам по себе не разрешает установку.

### Locked-база AArch64

```bash
uv run keemu init --profile generic-aarch64 --locked
uv run keemu init --profile generic-aarch64 --locked --offline
```

Locked-путь использует заранее проверенный локальный bootstrap-набор Entware. Он не обновляет live feed и не устанавливает пакеты на хост.

### Одноразовый тест пакета

```bash
uv run keemu test \
  --scenario path/to/scenario.yaml \
  --lock path/to/scenario-lock.json \
  --repo .
```

`keemu test`:

1. проверяет scenario, lock и их хеши;
2. статически анализирует IPK;
3. создаёт новое контролируемое target-окружение;
4. устанавливает пакет через целевой `opkg`;
5. выполняет объявленные проверки;
6. останавливает сервис, если это требуется;
7. удаляет пакет;
8. проверяет остаточные изменения файловой системы;
9. выполняет owner-checked cleanup даже после ошибки.

Отчёты сохраняются в:

```text
reports/<run-id>/
├── report.json
├── report.md
└── operation-log.jsonl
```

### Постоянное target-окружение

```bash
uv run keemu up \
  --name demo \
  --scenario path/to/scenario.yaml \
  --lock path/to/scenario-lock.json \
  --repo .

uv run keemu status demo --repo .
uv run keemu exec demo --repo . -- /opt/bin/example
uv run keemu logs demo --repo .
uv run keemu restart demo --repo .
uv run keemu down demo --repo .
```

Удаление:

```bash
uv run keemu destroy demo --repo .
```

Явное восстановление после failed/interrupted state:

```bash
uv run keemu recover demo --repo . --yes
```

KEEMU отказывается работать с чужими или подменёнными контейнерами и при неоднозначной принадлежности ресурсов не пытается угадывать, что нужно удалить.

### Матрица архитектур

```bash
uv run keemu test \
  --matrix path/to/matrix.yaml \
  --strict \
  --repo .
```

Matrix v1 требует для каждого случая один `profile`, один `scenario` и явный `lock`.

Для полного покрытия target-архитектур используются:

- `generic-aarch64`;
- `generic-mipsel`;
- `generic-mips`.

Неподдерживаемые обязательные случаи остаются `BLOCKED`.

---

## Проверки в сценариях

Текущая модель поддерживает, в частности:

- target-команды с ожидаемым кодом возврата;
- проверку существования файлов;
- HTTP/HTTPS probes;
- UDP probes;
- readiness и проверку остановки сервиса.

Пример:

```yaml
checks:
  - id: version
    kind: command
    command:
      argv:
        - /opt/bin/example
        - --version
      timeout_seconds: 30
    expected_exit_code: 0
```

Shell-интерпретация разрешается только явно:

```yaml
argv:
  - /bin/sh
  - -c
  - 'test -f /opt/etc/example.conf'
```

Persistent runner также позволяет выполнять явный `argv` через `keemu exec`.

---

## Модель результатов

| Статус | Значение |
| --- | --- |
| `PASS` | Проверка выполнена и результат совпал с ожиданием |
| `WARN` | Проверка завершилась, но обнаружено некритичное замечание |
| `BLOCKED` | Обязательную проверку нельзя выполнить с доступными capabilities или входными данными |
| `FAIL` | Поведение target/package противоречит ожидаемому результату |
| `ERROR` | Неожиданно завершился harness или путь исполнения |

Приоритет итогового состояния:

```text
ERROR → FAIL → BLOCKED → WARN → PASS
```

Примеры:

- IPK неверной архитектуры → `FAIL`, exit `1`;
- обязательный, но пока неподдерживаемый MIPS/MIPSEL lifecycle → `BLOCKED`, exit `4`;
- только `WARN` при `--strict` → exit `5`.

---

## Текущий снимок приёмки

Эксперименты P0 по основным техническим рискам завершены. Реализованы ограниченные срезы MVP 1A, MVP 1B и MVP 1C. **MVP 1 целиком пока не завершён.**

В сохранённом снимке:

- A01 получил `PASS` для оговорённой проверки исполнения на трёх generic-target;
- A02–A21 остаются `BLOCKED` в final-28 whole-ID ledger;
- итог final-29 — `BLOCKED`;
- final-29: 238 случаев, из них 233 `PASS`, 2 `FAIL` из-за отсутствующих locked images и 3 намеренных `SKIP`;
- исходный portable-прогон MVP 1: 208 `PASS` и 30 opt-in `SKIP`;
- portable-прогон MVP 1D: 339 `PASS` и 44 намеренных opt-in `SKIP`;
- сохранённый реальный AArch64-прогон MVP 1D: 39 `PASS`, 0 `FAIL`, 0 `SKIP`;
- evidence-аудит MVP 1D завершён, но release остаётся `BLOCKED`.

Подробности:

- `docs/evidence/final28-acceptance.json`;
- `docs/evidence/final29-release.json`;
- `docs/traceability.md`.

---

## Что подтверждено на target

В текущем Debian/Docker-окружении сохранены доказательства для:

- AArch64 Entware package index и bootstrap-набора из 20 пакетов, проверенных по SHA-256;
- реального AArch64 Entware `opkg` и BusyBox через QEMU user-mode;
- непривилегированной PRoot-цепочки `shell → дочерний AArch64 ELF → shell-скрипт с target shebang`;
- AArch64 Docker/binfmt execution для target shell, `opkg`, вложенного ELF и прямого shebang;
- передачи и обработки сигналов native init и контролируемого owner-checked shutdown в P0-05;
- MIPSEL/MIPS target shell, `opkg`, вложенного ELF/shebang, hello и fixture arguments;
- ограниченных Docker/binfmt probes MIPSEL/MIPS после отдельно разрешённой регистрации host binfmt.

Офлайн-проверка MIPS/MIPSEL:

```bash
uv run python -m scripts.verify_m1b18
```

См.:

- `docs/evidence/m1b18-targets-pass.json`;
- `docs/evidence/m1b18-targets.md`.

---

## Сетевые проверки

Для HTTP/HTTPS/UDP есть отдельные ограниченные fixtures.

```bash
make -f fixtures/recipes/aarch64/https-frontend-m1a15.mk \
  KEEMU_TOOLCHAIN_ROOT="$PWD/.runtime/p0/cross-toolchain/root"

KEEMU_M1A15_LIVE=1 \
  uv run pytest -q tests/integration/test_m1a15_https.py
```

Fixture использует зафиксированные SDK artifacts, создаёт временный локальный CA и сертификат, публикует сервис только на localhost и проверяет доверенный TLS, неверный hostname, недоверенный CA и HTTP/HTTPS/UDP после restart.

Это **не означает**, что общий `test`/`up` уже поддерживает HTTPS, UDP и host publication для любых сценариев.

Прямой target NFQUEUE пока остаётся:

```text
BLOCKED: Protocol not supported
```

Отдельный packet fixture через substitutions не считается доказательством общей NFQUEUE-совместимости.

---

## P0-диагностика

PRoot diagnostic:

```bash
KEEMU_RUN_P0_DIAGNOSTIC=1 \
  uv run pytest -q tests/integration/test_p0_diagnostic.py
```

P0-04 image audit:

```bash
KEEMU_RUN_P0_IMAGE_AUDIT=1 \
  uv run pytest -q tests/integration/test_p0_image.py
```

P0-05 runtime probe:

```bash
uv run python tests/integration/p0_runtime_probe.py
```

Probe создаёт и очищает только ресурсы с owner labels KEEMU.

---

## Воспроизводимость

`RunReport` schema v2 хранит неизменяемые метаданные для artifacts, scenarios, profiles, runtimes, capabilities, substitutions, checks, operation logs, coverage и partial failures.

Report bundles используют Linux `renameat2(..., RENAME_NOREPLACE)` для атомарной публикации без перезаписи. Если необходимый no-replace primitive недоступен, публикация завершается безопасным отказом.

Сгенерированные отчёты, загруженные IPK, rootfs, сохранённые образы и runtime state исключены из Git. Зафиксированные данные и метаданные образов хранятся в `locks/`.

---

## Граница безопасности

Target-окружения не должны использовать:

- privileged containers;
- host network namespace;
- host PID namespace;
- Docker socket mounts;
- `SYS_MODULE`;
- глобальный сброс firewall;
- `docker system prune`.

Host networking разрешён только ограниченным evidence observers с owner labels для проверки Docker-host loopback. Тестируемый пакет там не запускается.

Отсутствующая capability никогда не считается доказательством совместимости.

---

## Известные ограничения

В текущем MVP ещё не завершены:

- полная эмуляция прошивки Keenetic;
- доказательство совместимости со всеми физическими моделями Keenetic;
- общий MIPS/MIPSEL `init` и одиночный `test`;
- универсальная scenario-driven публикация localhost;
- полные гарантии изоляции;
- автоматическое восстановление одноразового запуска после прерывания;
- атомарный cleanup script artifacts при враждебном конкурентном same-UID процессе внутри target;
- автоматический recovery и interrupted report для persistent script artifacts после `SIGKILL`;
- общий запуск скриптов на MIPS/MIPSEL помимо честного pre-allocation `BLOCKED`;
- generic target NFQUEUE;
- полная приёмка A10 matrix;
- финальные строгие NDM/event contracts;
- полная приёмка MVP 1 и release gate.

---

## Структура репозитория

```text
profiles/generic/        Generic target profiles
locks/                   Locked artifacts and image metadata
docs/evidence/           Сохранённые доказательства проверок
docs/traceability.md     Связь «требование → тест → доказательство»
src/keemu/               Реализация KEEMU
tests/                   Unit и integration tests
fixtures/                Ограниченные target/network fixtures
reports/                 Сгенерированные write-once reports, не коммитятся
.runtime/                Локальное runtime state и рабочие locked assets
```

---

## Источник истины

Нормативный объём MVP и критерии приёмки находятся в:

```text
KEEMU_MVP1_updated.md
docs/specifications/KEEMU_MVP1D_script_execution.md
```

`KEEMU_MVP1_updated.md` определяет историческую приёмку исходного MVP 1, а спецификация MVP 1D — ограниченный запуск скриптов. Если README расходится с применимой спецификацией, приоритет имеет спецификация.
