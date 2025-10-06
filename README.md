# WordPress Docker Development Environment

A Docker-based WordPress development setup with MySQL database.

## Setup Instructions

### 1. Environment Configuration
1. Copy the environment example file:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` file and set secure passwords:
   ```bash
   nano .env
   ```

### 2. Directory Structure
- `mysql-data/` - MySQL database files (auto-generated)
- `wp-content/` - WordPress content directory
- `wp-config/` - WordPress configuration files
- `docker-compose.yml` - Docker services configuration
- `uploads.ini` - PHP upload configuration

### 3. Start Services
```bash
docker-compose up -d
```

### 4. Stop Services
```bash
docker-compose down
```

## Security Notes

- Never commit `.env` files to version control
- The `mysql-data/` directory contains sensitive database information
- Always use strong, unique passwords in production
- SSL certificates and private keys are excluded from version control

## Development

This repository is configured to be safe for public GitHub repositories:
- Sensitive files are excluded via `.gitignore`
- Example configuration files are provided
- Database files are not tracked in version control

