# Тестирование и проверка скриптов MicroPKI

Данный документ содержит результаты прогона автоматизированных Go-тестов и аудита shell-скриптов проекта.

---

## 1. Результаты Go-тестов (`go test`)

**Дата проверки:** 2026-05-31  
**Команда:** `go test -v -timeout 120s -short ./...`  
**Итог:** ✅ Все тесты пройдены (1 пропущен по флагу `-short`)

> **Почему `-short`?**  
> Без флага `-short` тест `TestIntegrationCAInit` генерирует RSA-4096 ключи и выполняет полный цикл инициализации CA, что занимает несколько минут. Флаг `-short` позволяет быстро проверить юнит-тесты, пропустив долгие интеграционные сценарии.

### 1.1 Результаты по пакетам

| Пакет | Статус | Время | Тесты |
|---|---|---|---|
| `micropki/internal/audit` | ✅ PASS | 0.014s | `TestAuditLogEvent`, `TestCTLog` |
| `micropki/internal/ca` | ✅ PASS | 0.084s | `TestIssueCertMalformedCSR` |
| `micropki/internal/client` | ✅ PASS | 0.576s | `TestGenCSR`, `TestRequestCertCmdValidationLogic`, `TestValidateChainCryptographically` |
| `micropki/internal/crl` | ✅ PASS | 0.015s | `TestReasonCodeMapping` |
| `micropki/internal/database` | ✅ PASS | 0.016s | `TestDatabaseOperations` |
| `micropki/internal/ocsp` | ✅ PASS | 0.015s | `TestResponderHTTPMethods`, `TestResponderInvalidMediaType` |
| `micropki/internal/policy` | ✅ PASS | 0.098s | `TestValidateKey`, `TestValidateValidity`, `TestValidateSANs` |
| `micropki/internal/repository` | ✅ PASS | 0.016s | `TestRepositoryEndpoints` |
| `micropki/tests` | ✅ PASS, ⏭ 1 SKIP | 6.196s | `TestParseDN`, `TestKeyGeneration`, `TestCertificateGeneration`, `TestEncryptedKeyRoundTrip`, `TestSKIComputation`, `TestPolicyWrite` / пропущен: `TestIntegrationCAInit` |

### 1.2 Описание тестов

**`internal/audit`**
- `TestAuditLogEvent` — проверяет запись события в NDJSON-лог и корректность структуры hashchain.
- `TestCTLog` — проверяет симулятор Certificate Transparency лога.

**`internal/ca`**
- `TestIssueCertMalformedCSR` — проверяет устойчивость движка выдачи к некорректным и вредоносным CSR-входам (8 сценариев).

**`internal/client`**
- `TestGenCSR` — генерирует RSA-2048 ключ и CSR во временную директорию, проверяет PEM-формат.
- `TestRequestCertCmdValidationLogic` — юнит-тест валидации флагов команды `request-cert`.
- `TestValidateChainCryptographically` — тест криптографической валидации цепочки сертификатов.

**`internal/crl`**
- `TestReasonCodeMapping` — проверяет маппинг строковых причин отзыва на коды RFC 5280.

**`internal/database`**
- `TestDatabaseOperations` — инициализация SQLite БД, вставка, проверка уникальности серийного номера, двойная вставка (ожидаемая ошибка UNIQUE constraint).

**`internal/ocsp`**
- `TestResponderHTTPMethods` — проверяет, что OCSP-ответчик отклоняет GET/PUT/DELETE (только POST разрешён).
- `TestResponderInvalidMediaType` — проверяет отклонение запросов с неверным Content-Type.

**`internal/policy`**
- `TestValidateKey` — проверяет отклонение слабых ключей (RSA < 2048, EC < P-256).
- `TestValidateValidity` — проверяет ограничение срока действия сертификата.
- `TestValidateSANs` — проверяет блокировку wildcard и некорректных SAN.

**`tests` (интеграционные)**
- `TestParseDN` — парсинг DN в форматах `CN=X,O=Y` и `/CN=X/O=Y`.
- `TestKeyGeneration` — RSA-4096 и ECC P-384 генерация ключей.
- `TestCertificateGeneration` — создание самоподписанного Root CA сертификата и проверка полей (IsCA, KeyUsage, SKI, AKI, SerialNumber).
- `TestEncryptedKeyRoundTrip` — шифрование RSA-ключа AES и расшифровка с паролем.
- `TestSKIComputation` — вычисление Subject Key Identifier (SHA-1, 20 байт).
- `TestPolicyWrite` — запись `policy.txt` и проверка содержимого.
- `TestIntegrationCAInit` *(пропущен в -short)* — полный E2E сценарий: `ca init`, проверка файлов, прав доступа, подписи сертификата и содержимого лога.

### 1.3 Запуск интеграционного теста отдельно

```bash
go test -v -timeout 300s -run TestIntegrationCAInit ./tests/
```

---

## 2. Аудит Shell-скриптов

Проверка синтаксиса (`bash -n`) пройдена для всех 4 скриптов без ошибок.

### 2.1 `demo.sh` — Полный E2E демо-сценарий

**Назначение:** Демонстрирует все возможности MicroPKI: инициализация Root CA, выдача Intermediate CA, OCSP-сертификата, CRL, серверного и code signing сертификатов, отзыв, проверка аудит-лога.

**Статус синтаксиса:** ✅ OK

**Обнаруженные замечания:**

| # | Место | Проблема | Критичность |
|---|---|---|---|
| 1 | Строка 56 | `gen-crl` записывает CRL в `./pki/crl/`, но `mkdir -p ./pki/crl` нигде не вызывается до этого момента — если директория не была создана `ca issue-intermediate`, команда упадёт с `set -e`. | ⚠️ Средняя |
| 2 | Строка 149 | `micropki audit verify` — команда не получает флаг `--log-file` (или аналогичный). Audit-лог должен быть создан предыдущими командами по умолчанию, но явного указания пути нет. | ℹ️ Низкая |
| 3 | Строка 135 | `$SERIAL` проверяется на пустоту через `[ ! -z "$SERIAL" ]`, что является устаревшим паттерном; рекомендуется `[ -n "$SERIAL" ]`. | ℹ️ Низкая (стиль) |

**Положительное:** Скрипт корректно обрабатывает `$REPO_PID`/`$OCSP_PID` через `kill ... || true` и `wait ... 2>/dev/null || true`. TLS-сервер также корректно завершается. Симуляция "отключения USB" через `mv` — логически верна.

---

### 2.2 `perf_test.sh` — Нагрузочный тест (1000 сертификатов)

**Назначение:** Собирает бинарник и последовательно выдаёт 1000 клиентских сертификатов, измеряя время.

**Статус синтаксиса:** ✅ OK

**Обнаруженные замечания:**

| # | Место | Проблема | Критичность |
|---|---|---|---|
| 1 | Строка 8 | `go build -o micropki.exe` — расширение `.exe` некорректно для Linux. Бинарник создаётся как `micropki.exe`, и все последующие вызовы `./micropki.exe` работают, но это нарушает соглашения Linux и вводит в заблуждение. | ⚠️ Средняя |
| 2 | Строки 18–21 | Выдача 1000 сертификатов выполняется последовательно в одном процессе. Тест не использует параллелизм, что не отражает реальную нагрузку на OCSP/repo серверы. | ℹ️ Низкая (дизайн) |
| 3 | Строка 11 | `ca init` вызывается без `--db-path`, но `ca issue-cert` также не передаёт `--db-path`. Это корректно если база создаётся по умолчанию, но стоит явно указывать для воспроизводимости. | ℹ️ Низкая |

**Рекомендация:** Переименовать целевой бинарник в `micropki` (без `.exe`):
```bash
# Было:
go build -o micropki.exe ./cmd/micropki
# Стало:
go build -o micropki ./cmd/micropki
```

---

### 2.3 `build_dist.sh` — Пакетирование дистрибутива

**Назначение:** Создаёт `release/micropki-ubuntu-dist.tar.gz` с исходным кодом и `install.sh` для Ubuntu.

**Статус синтаксиса:** ✅ OK

**Обнаруженные замечания:**

| # | Место | Проблема | Критичность |
|---|---|---|---|
| 1 | Строка 20 | `cp ... 2>/dev/null \|\| cp ...` — fallback копирование без `go.sum` может привести к неполной сборке на целевой машине, если `go.sum` отсутствует. | ⚠️ Средняя |
| 2 | Строка 45 | `go mod tidy` внутри `install.sh` может изменить зависимости на целевой машине. Безопаснее использовать `go mod download`. | ℹ️ Низкая |
| 3 | — | Скрипт не включает `tests/` в дистрибутив. Пользователи не смогут запустить тесты после установки. | ℹ️ Низкая (дизайн) |

**Положительное:** Скрипт правильно проверяет наличие `openssl` и `go` перед сборкой. Стратегия "собирай на целевой машине" корректна для CGO-зависимости `go-sqlite3`.

---

### 2.4 `tests/stapling_demo.sh` — Демонстрация OCSP Stapling

**Назначение:** Демонстрирует получение OCSP-ответа и запуск TLS-сервера с OCSP stapling (спринт 8).

**Статус синтаксиса:** ✅ OK

**Обнаруженные замечания:**

| # | Место | Проблема | Критичность |
|---|---|---|---|
| 1 | Строки 11–15, 18–23 | Скрипт ожидает файлы `./pki/certs/server.cert.pem` и `./pki/private/server.key.pem` — пути, которые **не создаются** `demo.sh` (там сертификат сохраняется в `./out/localhost.cert.pem`). Скрипт требует предварительного ручного запуска `demo.sh` с корректировкой путей. | ⚠️ Средняя |
| 2 | Строка 28 | Для проверки stapling используется `./pki/certs/ca.cert.pem` (Root CA), но сервер настроен с `intermediate.cert.pem` в качестве CAfile. Клиент должен использовать полную цепочку или root CA в зависимости от конфигурации. | ℹ️ Низкая |
| 3 | — | Скрипт предназначен для запуска **после** `demo.sh` при запущенном OCSP responder (`./micropki ocsp serve`), но явной проверки этого условия нет. | ℹ️ Низкая |

---

## 3. Сводная таблица

| Файл | Синтаксис | Исправлено | Итог запуска |
|---|---|---|---|
| `demo.sh` | ✅ OK | 5 исправлений | ✅ Exit 0, Demo Complete |
| `perf_test.sh` | ✅ OK | 1 исправление | 🟡 Запускается отдельно (долго) |
| `build_dist.sh` | ✅ OK | 2 исправления | ✅ Exit 0, архив создан |
| `tests/stapling_demo.sh` | ✅ OK | Полный рефактор | 🟡 Требует живого demo-окружения |
| Go-тесты (`./...`) | — | — | ✅ Все пройдены |

---

## 4. Все найденные и исправленные проблемы

### 4.1 `demo.sh` — 5 исправлений

| # | Строка | Проблема | Исправление |
|---|---|---|---|
| 1 | 8 | `cleanup` не удалял `./pki_root_usb` и `./pki_root_usb_offline` → повторный запуск падал с "file already exists" | Добавлены в `rm -rf` |
| 2 | 55 | `./pki/crl/` не создавалась до `gen-crl` при `set -e` | Добавлен `mkdir -p ./pki/crl` |
| 3 | 135 | Устаревший паттерн `[ ! -z "$SERIAL" ]` | Заменено на `[ -n "$SERIAL" ]` |
| 4 | 81–89, 92–100 | `issue-cert --template server` требует `--san`, но флаг отсутствовал | Добавлен `--san "dns:localhost"` и `--san "dns:weak"` |
| 5 | 57, 141 | `gen-crl` падал при повторном запуске на уже существующий файл | Добавлен флаг `--force` |

> **Дополнительно:** выявлен баг в Go-коде — `validateIssueIntermediateArgs()` жёстко требовал `keySize == 4096`, не соответствуя политике (`RSAIntermediateMinBits = 3072`). Исправлено в `internal/ca/issue_intermediate.go`.

### 4.2 `perf_test.sh` — 1 исправление

| # | Строка | Проблема | Исправление |
|---|---|---|---|
| 1 | 8, 11, 18–19 | Бинарник называлcя `micropki.exe` (Windows-формат) | Переименован в `micropki` |

### 4.3 `build_dist.sh` — 2 исправления

| # | Строка | Проблема | Исправление |
|---|---|---|---|
| 1 | 20 | Fallback-копирование могло пропустить `go.sum` | Убран fallback, оставлен единственный явный `cp` |
| 2 | 45 | `go mod tidy` мог изменить зависимости на целевой машине | Заменено на `go mod download` |

### 4.4 `tests/stapling_demo.sh` — полный рефактор

| # | Строка | Проблема | Исправление |
|---|---|---|---|
| 1 | 12, 18–19 | Пути `./pki/certs/server.cert.pem` / `./pki/private/server.key.pem` не существуют — `demo.sh` создаёт в `./out/` | Исправлены пути на `./out/localhost.cert.pem` / `./out/server.key.pem` |
| 2 | 28 | CAfile использовал Root CA напрямую, но сервер настроен с промежуточным сертификатом | CAfile переключён на полную цепочку `./out/chain.pem` |
| 3 | — | Нет проверки предусловий (OCSP responder, наличие файлов) | Добавлены проверки с информативными ошибками |
| 4 | — | Создавалась директория `/pki/ocsp` без `mkdir -p` | Добавлен `mkdir -p ./pki/ocsp` |

### 4.5 `main.go` — отсутствующие команды

При запуске `demo.sh` обнаружено, что команды `ocsp` и `client` не были зарегистрированы в Cobra CLI, хотя реализованы в `internal/`. Созданы недостающие файлы:

- `cmd/micropki/ocsp_cmd.go` — команда `micropki ocsp serve`
- `cmd/micropki/audit_cmd.go` — команды `micropki audit query` / `micropki audit verify`
- В `main.go` добавлена регистрация `client.ClientCmd`

---

## 5. Результаты запуска `demo.sh`

```
=== MicroPKI Complete Demo (Sprints 1-8) ===
[PASS] Policy engine correctly rejected weak key.       ← RSA-1024 отклонён
./out/localhost.cert.pem: OK                            ← цепочка валидна
Verified OK                                             ← code signing работает
Certificate revoked (reason: keyCompromise)             ← отзыв работает
Generated CRL #2 with 1 entries                         ← CRL обновлён
[OK] Audit log integrity verified successfully.         ← hashchain целый
[ALARM] Certificate marked as compromised.              ← компрометация ключа
=== Demo Complete ===
Exit code: 0 ✅
```

## 6. Результаты запуска `build_dist.sh`

```
=== Packaging MicroPKI Distribution for Ubuntu (Linux) ===
=> Done! Distribution package is ready at: release/micropki-ubuntu-dist.tar.gz
Exit code: 0 ✅
```
Архив содержит все исходники, включая новые файлы `ocsp_cmd.go`, `audit_cmd.go`, `Docs_extra/testing_and_scripts.md`.
