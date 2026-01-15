# ENIGMA-DA - SOURCE CODE

**Generated:** 2025-01-15

## OVERVIEW
Core application code for encryption/decryption service with multi-party cryptography, TEE attestation, and threshold-based decryption.

## STRUCTURE
```
src/
├── main.rs              # Entry point (296 lines) - Axum server, mTLS setup
├── api/                # API endpoint handlers
├── config.rs           # Environment-based server config
├── db.rs              # SQLite schema, migrations, queries (405 lines)
├── error.rs           # Custom error types
├── tracer.rs          # Tracing/logging setup
├── types.rs           # Request/response DTOs
├── utils.rs           # Crypto utilities (ECIES, ECDSA, TEE quotes)
└── tests/             # Integration tests (24 async tests)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Server startup | main.rs | Tokio runtime, router, mTLS config |
| mTLS setup | main.rs:90-174 | Certificate loading, client verification |
| Encryption | api/encrypt.rs:12-97 | ECIES + ECDSA signing |
| Decryption flow | api/decrypt.rs:149-428 | Threshold check, signature collection, TEE quote |
| Schema | db.rs:30-144 | Auto-migration on startup |
| Crypto core | utils.rs | Shared encrypt/decrypt, ECDSA verify, TEE quote |
| Test setup | tests.rs | In-memory DB, cleanup helpers |

## CONVENTIONS

**Async Patterns:**
- All handlers async with `Result<impl IntoResponse, AppError>`
- Database queries use `sqlx` with type-safe queries
- Signature verification in decrypt endpoint triggers threshold decryption

**Error Handling:**
- Custom `AppError` enum with variants: InvalidInput, Database, EncryptionError, DecryptionError, RequestNotFound, Internal
- All database errors logged with context
- Tracing spans for all operations with request IDs

**Module Organization:**
- `pub mod` declarations in main.rs
- Re-exports in api/mod.rs for cleaner imports
- Test modules in `src/tests/` (non-standard - typically in `tests/`)

## ANTI-PATTERNS (THIS PROJECT)
- No anti-patterns documented

## UNIQUE STYLES

**Certificate Normalization (main.rs:190-295):**
- Handles malformed PEM (single-line, embedded newlines, improper headers/footers)
- 5 header/footer patterns each for certs and keys
- Splits on whitespace, reassembles with proper newlines

**Threshold Decryption (api/decrypt.rs:318-413):**
- Tracks signature count vs threshold
- Auto-decrypts when threshold met
- Generates TEE attestation quote on success
- Stores plaintext in DB after decryption

**Database Migrations (db.rs:30-144):**
- Embedded in code, not separate migration files
- Checks table existence on startup
- Creates indexes: `idx_turbo_da_app_id`, `idx_decryption_status`

**Test Pattern:**
- Tests in `src/tests/` with `setup_test_db()` for in-memory SQLite
- Real cryptographic operations (no mocks)
- Uses hardcoded Hardhat test private keys
- Cleanup of P2P test artifacts

## NOTES

**Key Functions:**
- `utils::encrypt()` - ECIES encryption with app_id-derived key
- `utils::decrypt()` - Threshold decryption with signature verification
- `utils::quote()` - TEE attestation via dstack-sdk
- `utils::verify_ecdsa_signature()` - Signature verification

**Request Flow:**
1. Register app + participants + threshold
2. Encrypt (checks participants exist)
3. Create decrypt request (checks threshold)
4. Submit signatures (verifies, tracks count)
5. Auto-decrypt when threshold met + TEE quote

**Testing:**
- 24 tests: 23 decrypt.rs, 1 encrypt.rs
- In-memory SQLite via `:memory:`
- Tests edge cases: threshold=0, 1MB ciphertext, concurrent requests
