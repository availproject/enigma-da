# Local Development Setup

This guide explains how to run the enigma-da service locally in debug mode.

## Prerequisites

- Docker and Docker Compose installed
- Certificate files (CA, server certificates and keys)

## Setup

### 1. Create Certificate Directory

```bash
mkdir -p certs
```

**Note:** The `certs/` directory is gitignored to prevent accidental commits of sensitive files.

### 2. Add Certificate Files

Place your certificate files in the `certs/` directory:

```bash
certs/
├── ca.crt        # CA certificate
├── server.crt    # Server certificate
└── server.key    # Server private key
```

You can generate test certificates using the provided scripts:

```bash
# For local testing
./scripts/certificates_local.sh

# Move generated certificates to certs directory
mv ca.crt server.crt server.key certs/
```

### 3. Build and Run

```bash
# Build the debug image
docker-compose -f docker-compose.local.yml build

# Start the service
docker-compose -f docker-compose.local.yml up

# Or run in detached mode
docker-compose -f docker-compose.local.yml up -d
```

### 4. Stop the Service

```bash
docker-compose -f docker-compose.local.yml down
```

## Key Differences: Local vs Production

| Feature | Local (docker-compose.local.yml) | Production (docker-compose.yml) |
|---------|----------------------------------|----------------------------------|
| **Build Type** | Debug (`cargo build`) | Release (`cargo build --release`) |
| **Dockerfile** | `Dockerfile.local` | `Dockerfile` |
| **Logging** | `RUST_LOG=debug` | `RUST_LOG=info` |
| **Backtrace** | `RUST_BACKTRACE=full` | `RUST_BACKTRACE=1` |
| **Certificates** | Mounted from `./certs/` directory | Loaded from environment variables |
| **Image Name** | `enigma-da-service:local` | `enigma-da-service:latest` |
| **Container Name** | `enigma-da-service-local` | `enigma-da-service` |

## Debug Features

The local setup includes:

- **Full debug logging** - See all trace, debug, info, warn, and error messages
- **Full backtraces** - Complete stack traces for debugging
- **File-based certificates** - No need to set environment variables
- **Hot data directory** - SQLite database persists in `./data/`
- **Faster builds** - Debug builds compile faster (but run slower)

## Troubleshooting

### Port Already in Use

If port 3000 is already in use:

```bash
# Check what's using port 3000
lsof -i :3000

# Stop the production container if running
docker-compose down

# Or change the port in docker-compose.local.yml
ports:
  - "3001:3000"  # Map host port 3001 to container port 3000
```

### Certificate Files Not Found

Ensure certificate files exist and have correct permissions:

```bash
ls -la certs/
# Should show ca.crt, server.crt, server.key with read permissions
```

### Database Issues

Remove the database and restart:

```bash
rm -rf data/
docker-compose -f docker-compose.local.yml down
docker-compose -f docker-compose.local.yml up
```

## Production Deployment

For production deployments, use the main docker-compose.yml:

```bash
docker-compose build
docker-compose up -d
```

Production setup uses environment variables for certificates (set in `.env` file or environment).
