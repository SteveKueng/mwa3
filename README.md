# MWA3 - MunkiWebAdmin 3

## Introduction
MunkiWebAdmin 3 (MWA3) is a modern, Django-based web administration tool for [Munki](https://github.com/munki/munki). It provides a comprehensive interface for managing Munki repositories, including package information, manifests, catalogs, and icons.

<img width="1505" alt="ScreenShot1" src="https://github.com/SteveKueng/munkiwebadmin/assets/5426904/f5773913-3b24-4cef-bc1c-f5e78c1f98df">

## Features

- **Package Management**: Upload, edit, and manage package information (pkgsinfo)
- **Manifest Management**: Create and manage client manifests
- **Catalog Management**: View and manage Munki catalogs
- **Icon Management**: Upload and manage application icons
- **Vulnerability Scanning**: Integrated CVE/NIST vulnerability scanning for packages
- **REST API**: Full REST API for programmatic access
- **Authentication**: Support for Azure AD/ADFS and LDAP authentication
- **Multi-Storage**: Support for local filesystem, Azure Blob Storage
- **Docker Support**: Production-ready Docker containers

## Quick Start

### Docker (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/SteveKueng/munkiwebadmin.git
cd munkiwebadmin
```

2. Create a `.env` file with your configuration:
```bash
SECRET_KEY=your-secure-secret-key-here
DB=postgres
DB_NAME=munkiwebadmin
DB_USER=munkiwebadmin_user
DB_PASS=your-secure-password
DB_HOST=db
DB_PORT=5432
ALLOWED_HOSTS=localhost 127.0.0.1
```

3. Start with Docker Compose:
```bash
cd docker
docker-compose -f docker-compose.prod.yml up -d
```

4. Access at `http://localhost:80`

### Manual Installation

#### Requirements
- Python 3.14+
- PostgreSQL, MySQL, or SQLite
- libmagic (for file type validation)

#### Installation Steps

1. Install system dependencies (Ubuntu/Debian):
```bash
apt-get install python3.14 python3-pip libmagic1 postgresql-client
```

2. Clone and install Python dependencies:
```bash
git clone https://github.com/SteveKueng/munkiwebadmin.git
cd munkiwebadmin
pip install -r requirements.txt
```

3. Configure environment variables (see Configuration section)

4. Run migrations:
```bash
python manage.py migrate
```

5. Create superuser:
```bash
python manage.py createsuperuser
```

6. Collect static files:
```bash
python manage.py collectstatic
```

7. Start the development server:
```bash
python manage.py runserver
```

## Configuration

### Required Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Django secret key (MUST be set in production) | N/A |
| `ALLOWED_HOSTS` | Space-separated list of allowed hosts | `localhost 127.0.0.1` |
| `MUNKI_REPO_URL` | Munki repository URL | `file:///munkirepo` |

### Database Configuration

Choose your database backend:

**PostgreSQL (Recommended):**
```bash
DB=postgres
DB_NAME=munkiwebadmin
DB_USER=munkiwebadmin_user
DB_PASS=your-password
DB_HOST=localhost
DB_PORT=5432
```

**MySQL:**
```bash
DB=mysql
DB_NAME=munkiwebadmin
DB_USER=munkiwebadmin_user
DB_PASS=your-password
DB_HOST=localhost
DB_PORT=3306
```

**SQLite (Development only):**
```bash
# No additional configuration needed
```

### Security Settings

```bash
# HTTPS/SSL
SECURE_SSL_REDIRECT=True
CSRF_COOKIE_SECURE=True
SECURE_HSTS_SECONDS=31536000

# CSRF Protection
CSRF_TRUSTED_ORIGINS=https://yourdomain.com

# Rate Limiting
THROTTLE_ANON=100/hour
THROTTLE_USER=1000/hour
THROTTLE_UPLOADS=10/hour
```

### Authentication

**Azure AD/ADFS:**
```bash
CLIENT_ID=your-azure-client-id
CLIENT_SECRET=your-azure-client-secret
TENANT_ID=your-azure-tenant-id
ENTRA_ONLY=True
```

**LDAP:**
Set `USE_LDAP=True` in settings.py and configure LDAP settings.

### Optional Settings

```bash
# Application
APPNAME=MunkiWebAdmin
DEBUG=False
LANGUAGE_CODE=en-us
TIME_ZONE=UTC

# Package Display
ENABLE_REPO_VIEW=True
CATALOGS_TO_DISPLAY=production testing development
SHOW_ICONS=True

# Vulnerability Scanning
NIST_API_KEY=your-nist-api-key
```

## REST API

MWA3 provides a full REST API for programmatic access:

- **Authentication**: Basic Auth, Session Auth, or Azure AD Token
- **Endpoints**:
  - `/api/catalogs/` - Catalog management
  - `/api/manifests/` - Manifest management
  - `/api/pkgsinfo/` - Package info management
  - `/api/pkgs/` - Package uploads
  - `/api/icons/` - Icon management

### API Example

```bash
# List all catalogs
curl -u username:password https://yourserver/api/catalogs/

# Upload a package
curl -X POST -F "file=@package.pkg" \
  -u username:password \
  https://yourserver/api/pkgs/packages/apps/
```

## Security Best Practices

### Production Deployment Checklist

- [ ] Set unique `SECRET_KEY` (never use default!)
- [ ] Set `DEBUG=False`
- [ ] Configure proper `ALLOWED_HOSTS`
- [ ] Use HTTPS/SSL (`SECURE_SSL_REDIRECT=True`)
- [ ] Enable CSRF protection (`CSRF_COOKIE_SECURE=True`)
- [ ] Configure rate limiting
- [ ] Use strong database passwords
- [ ] Run container as non-root user (already configured)
- [ ] Keep dependencies updated (enable Dependabot)
- [ ] Regular security audits

### Known Security Considerations

- File uploads are validated using magic bytes (not just extensions)
- Access tokens are never logged
- CSRF protection is enabled for all state-changing operations
- Rate limiting prevents abuse
- Security headers (HSTS, X-Frame-Options) are configured

## Development

### Running Tests

```bash
python manage.py test
```

### Code Style

```bash
# Install development dependencies
pip install flake8 black

# Format code
black .

# Lint
flake8 .
```

### Project Structure

```
mwa3/
├── api/              # REST API endpoints
├── catalogs/         # Catalog management
├── manifests/        # Manifest management
├── pkgsinfo/         # Package info management
├── icons/            # Icon management
├── vulnerabilities/  # CVE scanning
├── munkiwebadmin/    # Main Django project
└── docker/           # Docker configuration
```

## Troubleshooting

### Common Issues

**1. Database Connection Failed**
- Check database credentials in environment variables
- Ensure database service is running
- Verify network connectivity

**2. Static Files Not Loading**
- Run `python manage.py collectstatic`
- Check `STATIC_ROOT` and `STATIC_URL` settings

**3. Unauthorized API Access**
- Verify authentication credentials
- Check API permissions in Django admin

**4. File Upload Fails**
- Check `MUNKI_REPO_URL` configuration
- Verify write permissions on repository directory
- Ensure file is valid PKG or DMG format

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## Support

- **Documentation**: Check the [wiki](https://github.com/SteveKueng/munkiwebadmin/wiki)
- **Issues**: Report bugs on [GitHub Issues](https://github.com/SteveKueng/munkiwebadmin/issues)
- **Discussions**: Join discussions in the [Munki community](https://www.munki.org/munki/)

## License

See LICENSE file for details.

## Credits

MunkiWebAdmin is built on:
- [Django](https://www.djangoproject.com/)
- [Django REST Framework](https://www.django-rest-framework.org/)
- [Munki](https://github.com/munki/munki)

---

**Note**: This is version 3 of MunkiWebAdmin, a complete rewrite with modern architecture and security best practices.

## Environment Variables (Review)

This project is configured primarily via environment variables. Values are read from your shell environment and/or an `.env` file (Docker Compose uses `env_file`). Lists like `ALLOWED_HOSTS` and `CSRF_TRUSTED_ORIGINS` are **space-separated**.

### Docker Compose Variables

These control how Compose runs locally and are optional:

- `MWA_PORT` (default `8080`): Host port published to container port 80.
- `DOCKER_PLATFORM` (default `linux/amd64`): Useful on Apple Silicon when an image or dependency is amd64-only.

### Django / App Variables

Minimum recommended variables:

- `SECRET_KEY`: Required for production (set a unique value).
- `DEBUG` (`True`/`False`): Defaults to `False`.
- `APPNAME`: Visible app name.

Host/CSRF (important when running behind a real hostname):

- `ALLOWED_HOSTS`: Space-separated, e.g. `munkiwebadmin.example.com`.
- `CSRF_TRUSTED_ORIGINS`: Space-separated origins (scheme + host), e.g. `https://munkiwebadmin.example.com`.
- `SECURE_SSL_REDIRECT` (`True`/`False`): Enable if you are serving HTTPS (often behind a reverse proxy).
- `CSRF_COOKIE_SECURE` (`True`/`False`): Optional override. If unset, it defaults to the value of `SECURE_SSL_REDIRECT`.
- `CSRF_COOKIE_HTTPONLY` (`True`/`False`): Defaults to `True`. The UI reads the CSRF token from a `<meta>` tag, so this can stay `True`.

### Database Variables

For Postgres (Docker Compose example):

- `DB=postgres`
- `DB_HOST=db`
- `DB_PORT=5432`
- `DB_NAME=munkiwebadmin`
- `DB_USER=munkiwebadmin_user`
- `DB_PASS=...`

### Munki Repository Variables

- `MUNKI_REPO_URL`: Defaults to `file:///munkirepo`.
- `MUNKI_REPO_PLUGIN`: Defaults to `FileRepo`.

If you use the Azure Blob plugin (`AzureRepo`), the plugin expects additional Azure-related environment variables (for example a SAS token). The exact variable names and format are defined by the MunkiAzurePlugin implementation.
