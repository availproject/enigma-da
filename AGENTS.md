# ENIGMA-DA - PROJECT KNOWLEDGE BASE

**Generated:** 2025-01-15
**Version:** 0.1.12

## OVERVIEW
Rust-based encryption/decryption service with multi-party threshold cryptography, TEE attestation, and mTLS. Uses Axum web framework, SQLite for persistence, and nightly Rust compiler.

## STRUCTURE
```
/Volumes/Personal/Avail/enigma-da/
├── src/                    # Main Rust source code
├── scripts/                # Certificate generation scripts
├── certs/                  # TLS certificates (mounted volumes)
├── data/                   # SQLite database (enigma.db)
├── target/                 # Rust build artifacts
├── Dockerfile              # Production build (nightly Rust + RocksDB)
├── Dockerfile.local        # Debug build (development)
├── docker-compose.yml      # Production orchestration
├── docker-compose.local.yml # Development orchestration
├── local-dev.sh            # Local dev helper (setup/build/start/stop)
├── start.sh                # Container entry point
└── Cargo.toml              # Dependencies & metadata
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Server entry point | src/main.rs | Axum router, mTLS setup |
| API routes | src/api/*.rs | encrypt, decrypt, participant endpoints |
| Database | src/db.rs | SQLite schema, migrations, queries |
| Configuration | src/config.rs | Environment-based config |
| Types/DTOs | src/types.rs | Request/response structures |
| Crypto utilities | src/utils.rs | ECIES, ECDSA, TEE quotes |
| Error handling | src/error.rs | Custom error types |
| Logging | src/tracer.rs | Tracing configuration |
| Tests | src/tests/*.rs | Integration tests with in-memory DB |
| Build/deploy | Dockerfile, docker-compose.yml | Multi-stage builds, cert mounts |

## CONVENTIONS

**Unconventional Patterns:**
- Tests in `src/tests/` instead of `tests/` root directory
- Nightly Rust compiler (unstable features required)
- No rustfmt.toml, .editorconfig, or lint configs - uses defaults
- Database migrations embedded in `db.rs` (no migrations/ folder)

**Security Model:**
- Release mode: Full mTLS with client certificate verification
- Debug mode: Plain HTTP (no TLS)
- Certificates loaded from environment variables OR files (CA_CERT, SERVER_CERT, SERVER_KEY)
- Certificate normalization handles malformed PEM formatting

**Database:**
- SQLite with in-memory mode for tests (`:memory:`)
- Production uses file-based at `/app/data/enigma.db`
- Max 5 connections, 3s acquire timeout
- Auto-migration on startup (checks table existence)

**Build:**
- Requires `librocksdb-dev` (native dependency)
- Multi-stage Docker builds
- No Makefile - all via Docker or cargo commands

## ANTI-PATTERNS (THIS PROJECT)
- No anti-pattern warnings found in code comments

## UNIQUE STYLES

**Multi-Party Cryptography:**
- Threshold-based decryption (N participants, K signatures required)
- ECIES for encryption, ECDSA for signatures
- TEE attestation quotes on successful decryption (dstack-sdk)

**Certificate Management:**
- `scripts/certificates_local.sh` - automated localhost certs
- `scripts/certificates_prod.sh` - interactive production certs (custom SAN entries)
- Docker volumes mount certs into containers

**Data Persistence:**
- `data/` directory for SQLite (unusual to commit data files)
- `start.sh` ensures 777 permissions on data directory

## COMMANDS
```bash
# Local development
./local-dev.sh setup      # Generate certs, setup environment
./local-dev.sh build      # Build debug image
./local-dev.sh start      # Start containers
./local-dev.sh stop       # Stop containers
./local-dev.sh cleanup    # Remove all artifacts

# Docker
docker-compose -f docker-compose.local.yml up          # Local dev
docker-compose up                                     # Production

# Cargo
cargo test                                          # Run tests (in-memory DB)
cargo build --release                                # Production build
```

## NOTES

**Gotchas:**
- Nightly compiler means potential breakage on updates
- Certificates must have proper PEM formatting; app normalizes malformed certs
- `normalize_cert()` function handles various PEM edge cases (single-line, embedded newlines)
- mTLS verification uses CA cert from environment or file
- `utils::quote()` generates TEE attestation - depends on dstack-sdk

**Dependencies:**
- `dstack-sdk`: Git dependency (https://github.com/Dstack-TEE/dstack.git)
- Crypto stack: k256 (secp256k1), secp256k1, ecies, sha2, sha3
- Web: axum 0.8.4, tower, rustls 0.23.34
- DB: sqlx 0.8 with SQLite

**Test Organization:**
- 24 async tests using `#[tokio::test]`
- Tests use real crypto (no mocks) with in-memory SQLite
- Hardcoded Hardhat test private keys for signature creation
- Tests in `src/tests/` submodules organized by feature (encrypt.rs, decrypt.rs)
