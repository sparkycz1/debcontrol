# debcontrol

Webová aplikace pro správu Debian strojů přes SSH. Zatím bez přihlašování —
běží se v důvěryhodné síti / na localhostu, dokud se nepřidá autentizace.

## Technologie

| Vrstva | Volba | Poznámka |
|---|---|---|
| Jazyk | Python 3.14.7 | |
| Web framework | FastAPI | async, OpenAPI schéma zdarma |
| Šablony / UI | Jinja2 + [htmx](https://htmx.org) (vendorováno lokálně) | žádný SPA build, žádný CDN |
| DB | PostgreSQL 18 | přes `asyncpg` + SQLAlchemy 2.0 (async) |
| Migrace | Alembic | async engine |
| Cache / fronta úloh | Redis 8.8 | fronta přes [`arq`](https://github.com/python-arq/arq) |
| SSH klient | [AsyncSSH](https://asyncssh.readthedocs.io/) | async, striktní ověření host klíče |
| Balíčky / lockfile | [`uv`](https://docs.astral.sh/uv/) | `uv.lock` je commitnutý |
| Kontejnery | Docker (multi-stage build) + Docker Compose | |

### Poznámky k verzím závislostí

- **`redis-py` (klientská knihovna) je záměrně na řadě `<6`**, i když Redis
  *server* v `docker-compose.yml` běží na `redis:8.8`. Verze klientské
  knihovny a verze serveru jsou nezávislé věci — `arq` (fronta úloh) k
  srpnu 2026 podporuje jen `redis-py <6` (viz jeho `pyproject.toml`), ale
  redis-py 5.x umí s Redis 8.x serverem komunikovat bez problémů. Až/pokud
  `arq` zvedne horní hranici, dá se `redis[hiredis]` v `pyproject.toml`
  odpinout.
- `arq` je aktuálně v "maintenance only" režimu (nepřibývají nové
  funkce, jen opravy). Pro v1 je to v pořádku — je to nejlehčí volba nad
  Redisem, která nevyžaduje Celery. Pokud by to v budoucnu vadilo, alternativa
  je `Celery` nebo `ReArq` (fork navazující na `arq`).
- Verze v `pyproject.toml` jsou dolní meze (`>=`); přesné, reprodukovatelné
  verze pro instalaci drží `uv.lock`.

## Bezpečnostní rozhodnutí (v1)

Aplikace nemá přihlašování, ale i tak řeší několik věcí od začátku, protože
se s nimi špatně přidává dodatečně:

- **Žádné "trust on first use" u SSH host klíčů.** Otisk klíče serveru se
  musí explicitně zjistit (`Zjistit otisk klíče`) a ručně potvrdit (mimo
  aplikaci, např. přes konzoli poskytovatele). Teprve poté se k němu smí
  cokoliv připojit. Neshoda otisku při pozdějším spojení = tvrdé odmítnutí
  (možný MITM), nikdy tichá ignorace. Viz [`app/ssh/client.py`](app/ssh/client.py).
- **Hesla/privátní klíče se v DB ukládají šifrovaně** (Fernet/AES z balíčku
  `cryptography`, klíč jen v `ENCRYPTION_KEY` v prostředí). Viz
  [`app/core/security.py`](app/core/security.py).
- **CSRF ochrana** (double-submit cookie) na všech formulářích, i bez
  session/přihlášení. Viz [`app/core/csrf.py`](app/core/csrf.py).
- **Přísná Content-Security-Policy** a další security hlavičky
  (`X-Frame-Options`, `X-Content-Type-Options`, ...) — žádné inline
  skripty/styly, žádný externí CDN. Viz [`app/main.py`](app/main.py).
- **Non-root uživatel v Dockeru**, minimální multi-stage image, žádné
  DB/Redis porty publikované na hostitele ve výchozím `docker-compose.yml`.
- **Validace konfigurace při startu** — aplikace odmítne nastartovat s
  placeholder/krátkými secrets z `.env.example` (viz `Settings` v
  [`app/core/config.py`](app/core/config.py)).
- V produkci (`APP_ENV=production`) se vypíná `/docs` a `/openapi.json`.

Co **zatím chybí** a je to vědomě odloženo na další fázi (přihlašování):
autentizace/autorizace uživatelů aplikace, audit log akcí, rate limiting.
Do té doby aplikaci nevystavuj do nedůvěryhodné sítě/internetu.

## Rychlý start (Docker)

```bash
cp .env.example .env
python scripts/generate_secrets.py
```

Vypsané hodnoty (`SECRET_KEY`, `ENCRYPTION_KEY`, `POSTGRES_PASSWORD`,
`REDIS_PASSWORD`) ručně vlož do `.env` — a `DATABASE_URL`/`REDIS_URL` uprav
tak, aby obsahovaly stejné heslo jako `POSTGRES_PASSWORD`/`REDIS_PASSWORD`.

```bash
docker compose up --build
```

Tím se: postaví image, rozjede Postgres 18 a Redis 8.8, spustí se
jednorázová služba `migrate` (Alembic `upgrade head`) a až po jejím úspěšném
doběhnutí naběhnou `web` (http://localhost:8000) a `worker` (arq).

Pro vývoj s hot-reloadem a bez rebuildu image při každé změně:

```bash
cp docker-compose.override.yml.example docker-compose.override.yml
docker compose up --build
```

## Lokální vývoj bez Dockeru (jen aplikace, DB/Redis přes Docker)

```bash
uv sync
docker compose up -d db redis
uv run alembic upgrade head
uv run uvicorn app.main:app --reload
# v druhém terminálu:
uv run arq app.tasks.worker.WorkerSettings
```

## Testy a kontrola kvality

```bash
uv run pytest
uv run ruff check .
uv run mypy app
```

Testy neběží proti reálné Postgres/Redis — `get_db` se v testech přepojuje
na izolovanou in-memory SQLite (viz [`tests/conftest.py`](tests/conftest.py)),
takže jedou rychle a bez vedlejších závislostí. SSH k reálným strojům je
otestované jen na úrovni logiky (odmítnutí spojení bez připnutého otisku) —
end-to-end ověření proti skutečnému Debian stroji je potřeba udělat ručně
přes UI (`Otestovat spojení`).

## Struktura projektu

```
app/
  core/       konfigurace, logování, šifrování, CSRF
  db/         SQLAlchemy modely + async session
  schemas/    Pydantic schémata pro formuláře
  ssh/        AsyncSSH klient (host key pinning)
  tasks/      arq worker + úlohy na pozadí
  web/        FastAPI routery, Jinja2 šablony, statické soubory
alembic/      DB migrace
tests/        pytest (async, izolované od reálné infrastruktury)
scripts/      pomocné skripty (generování secrets)
```

## Co je záměrně prázdné / na později

- Přihlašování a autorizace uživatelů aplikace.
- Spouštění libovolných příkazů / hromadné operace na více strojích
  (základ ve `app/tasks/jobs.py` a `app/ssh/client.py` už existuje).
- Audit log.
- Import stávajících `known_hosts` / hromadné přidání strojů.
