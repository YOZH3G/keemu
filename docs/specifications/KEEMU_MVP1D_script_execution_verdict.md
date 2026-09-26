# KEEMU MVP addendum — итоговая оценка script execution

**Дата оценки:** 2026-09-25  
**Исходный документ:** `/opt/data/attachments/KEEMU_MVP_addendum_script_execution.md`  
**Статус:** отложенный следующий milestone; не входит в frozen-план первоначального MVP  
**Условие возврата к обсуждению:** после завершения `final-31`

## Итоговый вердикт

Функцию запуска пользовательских shell-скриптов внутри целевого Entware-окружения KEEMU реализовывать стоит. Она естественно расширяет KEEMU от package/lifecycle harness до воспроизводимого стенда для проверки установщиков, init-скриптов, сервисных скриптов и другой shell-логики Entware.

Это не небольшое CLI-расширение. Общая сложность оценивается как **высокая — около 8/10**. Реализацию следует оформить отдельным frozen milestone, условно **MVP 1D**, после закрытия всех исходных задач текущего плана. Не следует задним числом включать дополнение в критерии первоначального MVP или менять его финальный evidence audit.

Документ достаточно хорошо определяет функциональные требования, границы безопасности, статусы результата, cleanup и acceptance criteria. Основная неопределённость находится не в продуктовой формулировке, а в безопасной реализации staging, timeout и target-process cleanup.

## Что уже имеется в KEEMU

Существующая архитектура предоставляет значительную часть необходимых примитивов:

- ограничение и разрешение host input paths — `src/keemu/input_paths.py`;
- bounded target argv и target working directory — `src/keemu/docker_runtime.py`;
- отдельные stdout/stderr, timeout и bounded output — `src/keemu/docker_runtime.py`;
- существующий механизм `docker cp` staging для IPK — `DockerRuntime.copy_file()`;
- persistent execution в running environment — `src/keemu/persistent.py`;
- CLI `keemu exec` — `src/keemu/cli.py`;
- scenario checks `CommandCheck` и `FileCheck` — `src/keemu/scenarios.py`;
- `RunReport`, operation log, coverage и общая классификация PASS/FAIL/BLOCKED/ERROR — `src/keemu/models.py`;
- owner labels, exact container identity и ownership-safe cleanup — `DockerRuntime` и persistent registry.

Отдельный container runtime создавать не требуется. Однако существующие примитивы нельзя использовать без изменений: текущий staging специально ограничен IPK-контрактом, а timeout локального процесса `docker exec` сам по себе не доказывает остановку target process.

## Основные источники сложности

### 1. Secure input и TOCTOU

Нужна отдельная абстракция `ScriptInput`, обеспечивающая:

- только regular file;
- запрет symlink, FIFO, device и unsupported special files;
- containment внутри разрешённого project root;
- bounded file size;
- secure open без следования symlink;
- SHA-256 exact bytes;
- повторную идентификацию перед staging;
- `BLOCKED` при изменении inode/metadata/bytes между validation и copy;
- отсутствие чтения файла через небезопасную цепочку path reopen.

Простого вызова `Path.read_bytes()` после предварительной проверки недостаточно.

### 2. Безопасный staging

Текущий `DockerRuntime.copy_file()` принимает только target paths, соответствующие `STAGED_IPK`. Для скриптов нужен отдельный typed staging contract, а не ослабление IPK regex.

Новый контракт должен гарантировать:

- target path генерируется KEEMU из SHA-256;
- target path находится только под `/opt/tmp`;
- существующий target object не перезаписывается;
- container identity проверяется до и после mutation;
- target bytes или безопасный readback совпадают с исходным SHA-256;
- cleanup удаляет только exact staged path текущего run;
- ошибка cleanup фиксируется честно и не маскируется как PASS.

### 3. Timeout и target-process cleanup

Это наиболее трудная runtime-часть. Текущий timeout может завершить локальный Docker CLI process, но не является достаточным доказательством, что target shell и его дочерние процессы прекратились.

Нужен bounded target execution wrapper или эквивалентный механизм, который позволяет:

- идентифицировать target process;
- ограниченно послать TERM/KILL только этому process tree;
- дождаться завершения;
- доказать отсутствие оставшихся потомков;
- не убить чужой процесс persistent environment;
- классифицировать timeout отдельно от harness failure.

### 4. Два lifecycle

Нужно поддержать разные режимы:

1. одноразовый `keemu script SCRIPT --profile ...`;
2. `keemu exec NAME --script SCRIPT -- ...` для существующего running environment.

Одноразовый режим может удалить весь owner-verified container после отчёта. Persistent режим обязан удалить только staged script и связанные exact temporary artifacts, не меняя состояние среды и её сервисов.

### 5. Статусы и отчётность

Нужно сохранить строгую классификацию:

- неожиданный exit code или assertion mismatch → `FAIL`;
- input mutation, unavailable target/capability или lock mismatch → `BLOCKED`;
- ошибка контракта/staging/reporting самого harness → `ERROR`;
- успешное реальное target execution со всеми обязательными assertions и cleanup → `PASS`.

RunReport должен фиксировать script SHA-256, profile/target/runtime identity, interpreter, argv, cwd, timeout, exit code, stdout/stderr, truncation flags, duration и cleanup result. Вероятно, потребуется отдельная typed metadata-модель, а не укладывание всех данных в свободный текст evidence.

### 6. Scenario schema

`kind: script` затронет:

- Pydantic discriminated union checks;
- host path validation;
- committed JSON schemas и parity tests;
- lifecycle dispatcher;
- report generation;
- backward compatibility существующего schema version;
- scenario lock/immutable-input semantics.

Не следует преобразовывать содержимое файла в `/bin/sh -c '<content>'`.

### 7. Архитектуры

AArch64 должен быть обязательной первой архитектурой. MIPS и MIPSEL следует подключать через тот же runtime contract, без отдельных обходных реализаций.

На момент оценки generic MIPS/MIPSEL direct и Docker probes уже проходили в текущем проекте. Поэтому перед заморозкой нового milestone нужно явно решить:

- либо первая итерация ограничена `generic-aarch64`, а MIPS/MIPSEL честно возвращают `BLOCKED`;
- либо acceptance сразу требует единый runner на всех трёх target architectures.

Второй вариант архитектурно предпочтительнее, но увеличивает regression scope и трудоёмкость.

## Оценка трудоёмкости

### Узкий core

One-shot AArch64 runner с secure input, staging, `/bin/sh`, argv, cwd, exit/stdout/stderr, bounded output, cleanup и базовым report:

**5–8 инженерных дней.**

### Полный обязательный MVP дополнения

One-shot + persistent mode, robust timeout/reaping, input mutation, filesystem assertion, typed reporting, status classification и полные acceptance tests:

**10–15 инженерных дней.**

### Полная hardened-версия

Scenario `kind: script`, committed schemas, три архитектуры, negative/race/interruption/recovery tests, документация и release evidence:

**15–25 инженерных дней.**

Для автономного durable execution рекомендуется план из **10–14 изолированных подзадач**. Основной риск срока — не объём CLI-кода, а environment-backed проверки TOCTOU, timeout, descendant cleanup и three-target parity.

## Рекомендуемая декомпозиция

1. Заморозить scope, threat model и обязательные architectures.
2. Добавить `ScriptInput` и secure reader.
3. Реализовать отдельный typed script staging contract.
4. Добавить target-copy integrity и no-overwrite proof.
5. Добавить typed execution result model.
6. Реализовать target timeout и descendant cleanup.
7. Реализовать one-shot AArch64 lifecycle.
8. Добавить CLI `keemu script`.
9. Добавить persistent `keemu exec --script`.
10. Интегрировать результат в RunReport и operation log.
11. Добавить exit-code и filesystem assertions.
12. Добавить scenario `kind: script` и schema parity.
13. Проверить MIPS/MIPSEL через общий runtime contract.
14. Выполнить race, interruption, cleanup и host-isolation verification.

## Рекомендуемый порядок

1. Завершить `final-31` первоначального frozen-плана.
2. Зафиксировать исходный MVP без ретроспективного расширения acceptance criteria.
3. Обсудить и заморозить scope нового milestone.
4. Начать с secure execution kernel, а не с CLI-команды.
5. Добавить one-shot lifecycle.
6. Затем persistent и scenario integrations.
7. Завершить отдельным evidence audit нового milestone.

## Финальное решение

**GO после завершения исходного плана**, но только как отдельный milestone с собственным frozen scope, routing, acceptance ledger и environment-backed evidence.

Не рекомендуется:

- реализовывать дополнение одной монолитной задачей;
- начинать с поверхностного CLI wrapper;
- ослаблять существующий IPK staging contract;
- считать убийство локального `docker exec` доказательством target cleanup;
- автоматически повышать успешный userspace script run до доказательства совместимости с физическим Keenetic;
- менять итоговый статус первоначального MVP на основании этого будущего дополнения.
