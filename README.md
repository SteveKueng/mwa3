# MWA3 - MunkiWebAdmin 3

MunkiWebAdmin 3 (MWA3) is a Django-based web administration tool for Munki.

## Deployment Guides

MWA3 supports a few common ways to run/deploy:

- **macOS (native)**: run the Django dev server in a local venv (best for Munki admins on macOS).
- **Docker / Docker Compose**: runs the full stack locally or on a server using the provided production image.
- **Azure App Service (Zip Deploy / Oryx)**: deploys the repo as a zip artifact; the Dockerfile is not used.

---

## Guide 1: macOS (Run Natively)

This is the most convenient way to run MWA3 if you manage Munki on macOS, because Munki’s Python client libraries are available after installing Munki.

### Prerequisites

- macOS
- Python 3.11+ (3.11/3.12/3.13 are known-good; avoid unreleased/preview versions)
- Munki installed (so `munkilib` exists under `/usr/local/munki`)
	- After installing Munki, you should have `/usr/local/munki/munkilib/`

Optional (only if you want stronger MIME detection for uploads):

- Homebrew `libmagic` (`brew install libmagic`)

### Run steps

From the repo root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Then start the dev server with the provided script (sets sensible defaults for macOS):

```bash
./devScripts/startDevServer.sh
```

Defaults used by the script:

- `MUNKITOOLS_DIR=/usr/local/munki`
- `MUNKI_REPO_URL=file:///Users/Shared/munkirepo`
- `MUNKI_REPO_PLUGIN=FileRepo`

It also runs `python manage.py migrate` automatically before starting `runserver`.

---

## Guide 2: Docker (Local/Server)

### Prerequisites

- Docker + Docker Compose v2

### 1) Configure environment

Docker Compose loads environment variables from munkiwebadmin/.env (see docker/docker-compose.prod.yml).

### 2) Build + start

From the repo root:

```bash
docker compose -f docker/docker-compose.prod.yml up -d --build
```

App will be available on `http://localhost:8080` by default.

- Override port with `MWA_PORT`, for example: `MWA_PORT=8080`
- On Apple Silicon, you may need `DOCKER_PLATFORM=linux/amd64`

### 3) Create an admin user

```bash
docker compose -f docker/docker-compose.prod.yml exec munkiwebadmin python manage.py createsuperuser
```

### Optional: disable AzureRepo plugin in the image

If you are not using Azure Blob storage repos, you can build a smaller image:

```bash
INSTALL_AZUREREPO_PLUGIN=false docker compose -f docker/docker-compose.prod.yml build munkiwebadmin
```

---

## Guide 3: Azure App Service (Zip Deploy / Oryx)

This repo includes a GitHub Actions workflow that produces a zip artifact and deploys it to Azure App Service.

### Important notes

- Zip Deploy uses Oryx to build; the Dockerfile is **not** used.
- Startup logic is handled by entrypoint.azure.sh.
- Do **not** rely on `apt-get` at runtime in Azure App Service.

### 1) Configure Azure Web App settings

In Azure Portal → Web App → Configuration → Application settings, set the same environment variables you use in Docker (database, Munki repo, etc.).

### 2) Set the Startup Command

Set the Web App Startup Command to:

```bash
./entrypoint.azure.sh
```

Azure provides the port via `PORT` (or `WEBSITES_PORT`); entrypoint.azure.sh binds to it.

### 3) Decide whether to include AzureRepo plugin

The workflow can optionally include the `AzureRepo.py` Munki plugin in the deployed artifact.

In GitHub repo Variables (Settings → Secrets and variables → Actions → Variables), set:

- `INSTALL_AZUREREPO_PLUGIN=false` to skip it

If unset (default), the workflow includes the plugin.

---

## Other ways to run MunkiWebAdmin

Besides the guides above, these are common ways to start the webadmin depending on what you’re trying to do:

- **Plain Django dev server (any OS)**: activate your venv, configure env vars, then run `python manage.py runserver`.
- **Gunicorn (no Docker)**: run `gunicorn --bind 0.0.0.0:8000 munkiwebadmin.wsgi` (you’ll usually put Nginx in front for TLS/static files).
- **Production Docker image entrypoint**: the production container uses `entrypoint.prod.sh` (migrations + gunicorn + nginx).
- **Azure App Service entrypoint**: Zip Deploy uses `entrypoint.azure.sh` (migrations + collectstatic + gunicorn).

If you want a “native Linux” setup, you can follow the macOS steps but you’ll need a compatible `munkilib` available on that host (macOS installs it for you; Linux typically doesn’t unless you provide it).

---

## Configuration

MWA3 is configured primarily via environment variables. Values are read from the process environment and/or an `.env` file.

Lists like `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` are **space-separated**.

### Required variables (minimum)

- `SECRET_KEY`: Django secret key (required for production)
- `ALLOWED_HOSTS`: Space-separated hostnames
- Database variables (see below)
- Munki repo variables (see below)

### Database (Postgres example)

```bash
DB=postgres
DB_NAME=munkiwebadmin_db
DB_USER=munkiwebadmin_user
DB_PASS=change-me
DB_HOST=db
DB_PORT=5432
```

### Munki repository

- `MUNKI_REPO_URL` (default `file:///munkirepo`)
- `MUNKI_REPO_PLUGIN` (default `FileRepo`)
- `MUNKITOOLS_DIR` (default `/munkitools`, falls back to `./munkitools` if missing)

If you use the Azure Blob plugin (`AzureRepo`), the plugin expects additional Azure-related environment variables (for example a SAS token). The exact variable names/format are defined by the MunkiAzurePlugin implementation.

---

## Final-State Examples

### Example A: Docker environment file

Example munkiwebadmin/.env (local Postgres via Compose + local file repo):

```bash
SECRET_KEY=change-me
DEBUG=False
ALLOWED_HOSTS=localhost 127.0.0.1

DB=postgres
DB_NAME=munkiwebadmin_db
DB_USER=munkiwebadmin_user
DB_PASS=munkiwebadmin_pass
DB_HOST=db
DB_PORT=5432

MUNKI_REPO_URL=file:///munkirepo
MUNKI_REPO_PLUGIN=FileRepo
```

### Example B: Azure configuration

1) Azure Web App Application settings (example using Postgres + AzureRepo):

```bash
SECRET_KEY=change-me
DEBUG=False
ALLOWED_HOSTS=munkiwebadmin.example.com
CSRF_TRUSTED_ORIGINS=https://munkiwebadmin.example.com

DB=postgres
DB_NAME=munkiwebadmin_db
DB_USER=munkiwebadmin_user
DB_PASS=***
DB_HOST=***
DB_PORT=5432

MUNKI_REPO_URL=AzureRepo://your-container
MUNKI_REPO_PLUGIN=AzureRepo
SAS_TOKEN=***
AZURE_STORAGE_BLOB_ENDPOINT=***
```

2) GitHub Actions variable:

```bash
INSTALL_AZUREREPO_PLUGIN=false
```

3) Workflow snippet (from .github/workflows/main_munkiwebadmin.yml):

```yaml
- name: Install AzureRepo plugin
	# Default: enabled. Set repo variable INSTALL_AZUREREPO_PLUGIN=false to skip.
	if: ${{ vars.INSTALL_AZUREREPO_PLUGIN != 'false' }}
	run: |
		curl -Lk -o /tmp/MunkiAzurePlugin.zip "$(curl --silent https://api.github.com/repos/SteveKueng/MunkiAzurePlugin/releases/latest | awk '/zipball_url/ { print $2 }' | sed 's/[\",]//g')"
		unzip /tmp/MunkiAzurePlugin.zip -d /tmp/MunkiAzurePlugin
		cp /tmp/MunkiAzurePlugin/SteveKueng-MunkiAzurePlugin-*/payload/usr/local/munki/munkilib/munkirepo/AzureRepo.py munkitools/munkilib/munkirepo/
```

Note: YAML indentation must be spaces (tabs are invalid). If you copy this snippet, replace the leading tabs with spaces.

---

## REST API

Endpoints:

- `/api/catalogs/`
- `/api/manifests/`
- `/api/pkgsinfo/`
- `/api/pkgs/`
- `/api/icons/`

---

## Troubleshooting

### Common issues

- **Unauthorized / redirects to login**: most UI and API endpoints require authentication.
- **Database connection failed**: verify DB env vars and connectivity.
- **Static files not loading**: ensure `collectstatic` ran (Docker image runs it at build time; Azure runs it at startup).
