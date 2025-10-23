# ATP Keyserver Architecture

## Overview

A specialized AT Protocol (ATProto) service for secure storage and distribution of cryptographic keys. This keyserver manages both asymmetric keypairs (Ed25519) for public key cryptography and symmetric keys (XChaCha20-Poly1305) for group-based encrypted communication.

## Technology Stack

### Runtime & Core
- **Bun** (v1.0+) - JavaScript runtime and toolkit
- **itty-router** (v5.0.18) - Lightweight HTTP router with CORS support
- **SQLite** - Embedded database with WAL mode for persistence

### AT Protocol Integration
- `@atproto/did` - DID validation and parsing
- `@atproto/identity` - DID resolution with caching
- `@atproto/xrpc-server` - JWT verification for XRPC protocol

### Cryptography
- `@noble/ed25519` - Ed25519 asymmetric key operations
- `@noble/ciphers` - XChaCha20-Poly1305 symmetric encryption

## Architecture Components

### 1. Entry Point (`main.ts`)

The main application file that:
- Initializes the HTTP router with CORS middleware
- Exposes service identity via `.well-known/did.json`
- Defines public and authenticated API endpoints
- Implements a middleware authentication wall
- Serves HTTP requests on configurable port (default: 4000)

**Authentication Wall Pattern:**
```
Public Endpoints (lines 22-75)
    ↓
Auth Middleware (line 82)
    ↓
Protected Endpoints (lines 85-87)
```

### 2. Database Layer (`lib/db.ts`)

SQLite database with three normalized tables:

```sql
keys
├── did (PRIMARY KEY)
├── public_key (TEXT)
└── private_key (TEXT)

groups
├── id (PRIMARY KEY)
├── owner_did (TEXT)
└── secret_key (TEXT)

group_members
├── group_id (FOREIGN KEY → groups.id)
└── member_did (TEXT)
```

**Features:**
- WAL (Write-Ahead Logging) mode enabled for better concurrency
- Type-safe schema definitions using TypeScript
- Single database file (`keyserver.db`)
- Exported DBSchema type for type-safe queries throughout the application

### 3. Authentication Middleware (`lib/authMiddleware.ts`)

JWT-based authentication following AT Protocol standards:

**Flow:**
1. Validates request path starts with `/xrpc/`
2. Extracts Bearer token from Authorization header
3. Parses XRPC lexicon (lxm) from URL path
4. Verifies JWT signature using issuer's signing key via `getSigningKey()`
5. Resolves DID to retrieve signing key (with caching via IdResolver)
6. Attaches JWT payload and DID to request context

**DID Resolution:**
- In-memory cache: 1 hour TTL, 24 hour maximum
- Uses `@atproto/identity` IdResolver with MemoryCache
- Resolves AT Protocol-specific DID data
- Extracts signing key from DID document
- Returns 403 errors for invalid or missing authorization

### 4. Asymmetric Cryptography (`lib/keys/asymmetric.ts`)

Ed25519 keypair management:

**Key Features:**
- **Lazy Generation**: Keypairs created on first request per DID
- **Persistent Storage**: Keys stored in SQLite for reuse
- **Hex Encoding**: Keys encoded as hexadecimal strings
- **Per-DID Isolation**: Each DID has a unique keypair

**Functions:**
- `createKeypair()` - Generates new random Ed25519 keypair
- `getKeypair(did)` - Retrieves or creates keypair for DID
- `getPublicKey(did)` - Gets just the public key

### 5. Symmetric Cryptography (`lib/keys/symmetric.ts`)

XChaCha20-Poly1305 authenticated encryption for group messaging:

**Encryption Scheme:**
- 32-byte secret keys (256-bit) encoded as hex
- 24-byte nonces (unique per message)
- Additional authenticated data (AAD) using message ID
- Format: `hex(nonce) + hex(ciphertext)`

**Group Management:**
- Groups identified by `{owner_did}#{group_name}` format
- Owner has full control (add/remove members)
- Members can retrieve group keys
- Lazy group creation on first access by owner
- Type-safe database queries with DBSchema

**Error Handling:**
- Uses itty-router's `error()` function for HTTP errors
- 404 errors for non-existent groups
- 403 errors for unauthorized access
- 409 errors for duplicate member additions

**Exported Functions:**
- `createSecretKey()` - Generate random 256-bit key (hex-encoded)
- `encryptMessage(id, key, plaintext)` - Encrypt with AAD
- `decryptMessage(id, key, ciphertext)` - Decrypt with AAD
- `getGroupKey(group_id, authed_did)` - Get key with access control
- `addMember(group_id, member_did, authed_did)` - Add member (owner only)
- `removeMember(group_id, member_did, authed_did)` - Remove member (owner only)

**Internal Helpers:**
- `getGroup(group_id)` - Fetch group from database
- `checkMembership(group_id, member_did)` - Verify member status
- `createGroup(group_id, owner_did)` - Create new group with secret key

## API Endpoints

### Public Endpoints (No Authentication)

#### `GET /`
Returns service metadata from package.json:
```json
{
  "name": "atp-keyserver",
  "version": "1.0.0"
}
```

#### `GET /.well-known/did.json`
Returns service DID document per AT Protocol specification:
```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "{service-did}",
  "service": [
    {
      "id": "#atp_keyserver",
      "type": "AtpKeyserver",
      "serviceEndpoint": "{service-url}"
    }
  ]
}
```

#### `GET /xrpc/chat.roomy.v0.key.public?did={did}`
Retrieve any user's public key without authentication.

**Query Parameters:**
- `did` (required) - DID of user (must be `did:web:*` or `did:plc:*`)

**Response:**
```json
{
  "publicKey": "hex-encoded-public-key"
}
```

**Validation:**
- DID format validation using `isDid()`
- Only supports `did:web` and `did:plc` methods
- URL-decodes the DID parameter

### Protected Endpoints (Require JWT Authentication)

#### `GET /xrpc/chat.roomy.v0.key`
Retrieve the authenticated user's complete keypair.

**Headers:**
- `Authorization: Bearer {jwt}`

**Response:**
```json
{
  "publicKey": "hex-encoded-public-key",
  "privateKey": "hex-encoded-private-key"
}
```

**Implementation:** Calls `getKeypair(did)` from `lib/keys/asymmetric.ts` which returns or creates the user's Ed25519 keypair.

## Security Model

### Authentication & Authorization
1. **Public Key Distribution**: Open access for discovering public keys
2. **Private Key Access**: Strict JWT authentication required
3. **DID-Based Identity**: All operations tied to AT Protocol DIDs
4. **Self-Service**: Users can only access their own private keys via authenticated endpoint

### Cryptographic Security
- **Ed25519**: Modern elliptic curve signature scheme (128-bit security)
- **XChaCha20-Poly1305**: Authenticated encryption (256-bit keys)
- **Random Generation**: Cryptographically secure randomness via `@noble/*`
- **Nonce Uniqueness**: Fresh random nonce per encrypted message

### Group Access Control
- **Owner Authorization**: Only group owners can modify membership
- **Member Verification**: Key access validated against membership table
- **Namespace Isolation**: Group IDs scoped by owner DID

## Configuration

### Environment Variables
- `DID` (required) - Service's own DID identifier
- `PORT` (optional) - HTTP server port (default: 4000)

### Database
- File: `keyserver.db`
- Mode: WAL (Write-Ahead Logging)
- Auto-created on first run

## Development Workflow

### Scripts
- `bun run dev` - Development mode with auto-reload (uses `DID=test`)
- `bun start` - Production mode
- `bun run format` - Format code with Prettier

### Dependencies
- Uses Bun's native package management
- Lock file: `bun.lock`
- Separate dev dependencies for tooling

## Design Patterns

### Lazy Initialization
Keypairs are generated on-demand rather than during registration:
- Reduces upfront computational cost
- Simplifies user onboarding
- Maintains backward compatibility with existing DIDs

### Middleware Authentication Wall
Clear separation between public and protected endpoints:
- All routes after `router.all('*', authMiddleware)` require authentication
- Makes security boundaries explicit in code
- Prevents accidental exposure of protected endpoints

### Hex-Encoded Keys
All cryptographic material encoded as hexadecimal strings:
- Consistent encoding across the API
- URL-safe without additional encoding
- Human-readable for debugging

### Type-Safe Database Queries
Database schema exported as TypeScript types:
- Compile-time type checking for queries
- IntelliSense support in IDEs
- Reduces runtime errors

## Project Structure

```
atp-keyserver/
├── main.ts                     # Entry point and routing
├── package.json                # Dependencies and scripts
├── bun.lock                    # Dependency lock file
├── README.md                   # Project documentation
├── CLAUDE.md                   # Architecture documentation (this file)
├── keyserver.db                # SQLite database (generated at runtime)
├── lib/
│   ├── db.ts                   # Database schema and connection
│   ├── authMiddleware.ts       # JWT authentication with DID resolution
│   └── keys/
│       ├── asymmetric.ts       # Ed25519 keypair management
│       └── symmetric.ts        # XChaCha20 encryption & group management
└── lexicons/
    └── dev/
        └── atpkeyserver/
            └── defs.json       # XRPC lexicon definitions (placeholder)
```

## Code Quality

### Strengths
- Clean separation of concerns (database, auth, crypto)
- Type-safe database queries with TypeScript
- Modern cryptography libraries (@noble/ed25519, @noble/ciphers)
- Consistent error handling using itty-router's error()
- Good use of AT Protocol standards
- Proper DID validation and method checking
- WAL mode enabled for SQLite (better concurrency)
- Direct imports eliminate unnecessary module layers

### Considerations for Future Development
- Database error handling could be more comprehensive
- Input validation beyond DID format checking
- Lexicon names are hard-coded (`chat.roomy.v0`)
- No unit tests or integration tests currently
- Rate limiting not implemented
- No database migration strategy for schema updates

## Scalability Considerations

### Current Limitations
- Single SQLite database limits horizontal scaling
- In-memory DID cache not shared across instances
- No connection pooling (single-file SQLite)

### Potential Improvements
- Consider distributed database for multi-instance deployments
- External cache (Redis) for DID resolution across instances
- Load balancer with sticky sessions for single-instance deployments

## Key Rotation & Recovery

### Current State
- No mechanism for rotating keys
- Keys are permanent once created
- No key escrow or recovery mechanism

### Future Considerations
- Versioning scheme for key rotation
- Key revocation mechanism
- Backup and recovery strategy
- Encrypted backup for private keys

## AT Protocol Integration

This keyserver implements a custom AT Protocol service type:

**Service Type**: `AtpKeyserver`
**Lexicon Scope**: `chat.roomy.v0`

The service follows AT Protocol conventions:
- DID-based identity
- JWT authentication with signing key verification
- XRPC method naming (`/xrpc/{lexicon}.{method}`)
- Service discovery via DID documents

This allows AT Protocol applications to discover and interact with the keyserver using standard DID resolution.
