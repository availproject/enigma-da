# ENIGMA-DA - API ENDPOINTS

**Generated:** 2025-01-15

## OVERVIEW
Axum-based REST API for multi-party encryption/decryption with threshold cryptography and TEE attestation.

## STRUCTURE
```
src/api/
├── mod.rs          # Module exports, health endpoint (15 lines)
├── encrypt.rs      # POST /v1/encrypt (98 lines)
├── decrypt.rs      # Decrypt request lifecycle (464 lines)
└── participant.rs  # App/participant management
```

## WHERE TO LOOK
| Endpoint | Handler | Function |
|----------|---------|----------|
| POST /health | mod.rs:12 | Health check |
| POST /v1/register | participant.rs | Register app with threshold |
| POST /v1/add_participant | participant.rs | Add signer to app |
| DELETE /v1/delete_participant | participant.rs | Remove signer |
| POST /v1/encrypt | encrypt.rs:12 | Encrypt with ECIES + sign |
| POST /v1/create_decrypt_request | decrypt.rs:19 | Initiate threshold decryption |
| GET /v1/decrypt_requests | decrypt.rs:430 | List requests (paginated) |
| GET /v1/decrypt_request/{id} | decrypt.rs:116 | Get request status |
| POST /v1/decrypt_request/{id}/signatures | decrypt.rs:149 | Submit signature |

## CONVENTIONS

**Request Validation:**
- Empty plaintext/ciphertext rejected
- App must be registered before operations
- Participants must exist before encryption
- Signers verified against app's participant list

**Response Format:**
- All return `Result<impl IntoResponse, AppError>`
- JSON responses with structured data
- Errors logged with context (request_id, participant_address)

**Tracing:**
- All handlers create info spans with request IDs
- Debug-level logging for internal operations
- Error-level with full error chain

## ANTI-PATTERNS (THIS PROJECT)
- None documented

## UNIQUE STYLES

**Encryption (encrypt.rs:12-97):**
- Checks participants exist before encrypting
- Uses `utils::encrypt()` for ECIES
- Signs both ciphertext AND plaintext hash
- Returns ephemeral public key for decryption

**Threshold Decryption (decrypt.rs:318-413):**
- Tracks signatures in JSON column (`submitted_signatures`)
- Auto-checks threshold on each signature submission
- Decrypts immediately when threshold met
- Generates TEE attestation quote via `utils::quote()`

**Signature Verification (decrypt.rs:149-214):**
- Verifies signer is authorized participant
- ECDSA verification with keccak256 hash
- Rejects duplicate signatures
- Only accepts signatures in "pending" state

**Pagination (decrypt.rs:430-463):**
- Default limit 50, max 100
- Offset-based pagination
- Returns total count

## NOTES

**Validation Order (encrypt.rs):**
1. Plaintext not empty
2. app_id is valid (not zero UUID)
3. Participants exist for app

**Validation Order (create_decrypt_request):**
1. Ciphertext not empty
2. App registered (has threshold)
3. Participants exist
4. Create request record

**Threshold Logic:**
- Comparison: `signatures_count >= threshold`
- Triggers decryption in same transaction
- Updates status to "completed"
- Generates TEE quote on success

**TEE Quote Generation:**
- Format: `{request_id}:{hex(plaintext)}`
- Hashed with keccak256
- Quote stored in response `tee_attestion` field
