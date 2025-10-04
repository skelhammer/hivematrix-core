# HiveMatrix Core

**Identity and Access Management (IAM) Hub**

Core is the central IAM service for the HiveMatrix ecosystem. It acts as an abstraction layer in front of Keycloak, handling all authentication and authorization for the platform.

---

## Quick Start

**For first-time setup of the entire HiveMatrix ecosystem:**

👉 **Start with [hivematrix-helm](../hivematrix-helm/README.md)** 👈

Helm is the orchestration center that will guide you through setting up Keycloak, Core, Nexus, and all other services.

---

## What Core Does

- **Authentication Proxy**: Abstracts Keycloak behind a simple API
- **JWT Minting**: Issues HiveMatrix JWTs for authenticated users and service-to-service calls
- **User Management**: Provides unified user information across all services
- **Permission Levels**: Manages admin, technician, billing, and client access levels
- **Public Key Distribution**: Exposes JWKS endpoint for JWT verification by other services

---

## Architecture

See [ARCHITECTURE.md](../hivematrix-helm/ARCHITECTURE.md) for complete system architecture and development guidelines.

### Authentication Flow

1. User accesses protected resource in Nexus
2. Nexus redirects to Core `/login`
3. Core redirects to Keycloak for authentication
4. Keycloak authenticates user and returns to Core `/auth` callback
5. Core mints HiveMatrix JWT with user info and permission level
6. Core redirects back to Nexus with JWT
7. Nexus stores JWT and user can access protected resources
8. Services verify JWT using Core's public key from `/.well-known/jwks.json`

---

## Prerequisites

- **Python 3.8+**
- **Keycloak 26.0.5+** (managed by Helm)
- **OpenSSL** (for generating RSA keys)

---

## Installation

### 1. Clone and Setup

```bash
cd /home/david/work/hivematrix-core
python3 -m venv pyenv
source pyenv/bin/activate
pip install -r requirements.txt
```

### 2. Generate RSA Keys

Core uses RS256 JWT signing. Generate the key pair:

```bash
# Generate 2048-bit RSA private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

# Extract public key
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

### 3. Configure Environment

Create `.flaskenv`:

```bash
FLASK_APP=run.py
FLASK_ENV=development
SECRET_KEY='a-very-secret-key-for-flask-sessions'

# Keycloak OIDC Settings
KEYCLOAK_SERVER_URL='http://localhost:8080/realms/hivematrix'
KEYCLOAK_CLIENT_ID='core-client'
KEYCLOAK_CLIENT_SECRET='<YOUR_CLIENT_SECRET_FROM_KEYCLOAK>'

# JWT Signing Settings
JWT_PRIVATE_KEY_FILE='private_key.pem'
JWT_PUBLIC_KEY_FILE='public_key.pem'
JWT_ISSUER='hivematrix.core'
JWT_ALGORITHM='RS256'
```

**Get the client secret from Keycloak:**
1. Go to Keycloak Admin Console (http://localhost:8080)
2. Navigate to: Realms → hivematrix → Clients → core-client → Credentials tab
3. Copy the Client Secret value

### 4. Run Core

```bash
flask run
```

Core runs on **http://localhost:5000**

---

## API Endpoints

### Authentication

- `GET /login` - Initiates Keycloak login flow
- `GET /auth` - Keycloak callback (receives auth code, mints JWT)
- `GET /logout` - Ends user session and redirects to Keycloak logout

### Public Key Distribution

- `GET /.well-known/jwks.json` - Public keys for JWT verification (used by all services)

### Service Token Minting

- `POST /service-token` - Mints short-lived service-to-service JWTs

Request body:
```json
{
  "calling_service": "treasury",
  "target_service": "codex"
}
```

Response:
```json
{
  "token": "eyJ..."
}
```

### User Information

- `GET /userinfo` - Returns current user's information (requires valid JWT)

---

## Keycloak Configuration

Core requires the following Keycloak setup (automatically done by Helm):

### Realm: `hivematrix`

### Client: `core-client`
- Client authentication: **ON**
- Standard flow: **ENABLED**
- Valid redirect URIs: `http://127.0.0.1:5000/auth`

### Groups (for permission levels)
- `admins` - Full system access
- `technicians` - Technical operations
- `billing` - Financial operations
- Default (no group) - Client level access

### Client Scope: `core-client-dedicated`
- Group Membership mapper:
  - Token Claim Name: `groups`
  - Full group path: **OFF**
  - Add to userinfo: **ON**

---

## Development

### Adding New Permission Levels

Edit `app/routes.py`, function `mint_hivematrix_jwt()`:

```python
def get_permission_level(groups):
    """Map Keycloak groups to HiveMatrix permission levels."""
    if '/admins' in groups or 'admins' in groups:
        return 'admin'
    elif '/technicians' in groups or 'technicians' in groups:
        return 'technician'
    elif '/billing' in groups or 'billing' in groups:
        return 'billing'
    # Add new levels here
    else:
        return 'client'
```

### Testing JWT Creation

```bash
curl http://localhost:5000/login
# Follow login flow in browser
# Check cookies/session for JWT
```

### Verifying JWT

```bash
curl http://localhost:5000/.well-known/jwks.json
# Returns public keys for verification
```

---

## Security

- **Private Keys**: Never commit `private_key.pem` to version control (in `.gitignore`)
- **Client Secrets**: Store in `.flaskenv` (also in `.gitignore`)
- **Session Keys**: Use strong random value for `SECRET_KEY`
- **HTTPS**: Use SSL/TLS in production
- **Key Rotation**: Periodically regenerate RSA keys and update all services

---

## Troubleshooting

### "Invalid client secret" error

1. Regenerate client secret in Keycloak
2. Update `.flaskenv` with new secret
3. Restart Core

### JWT verification fails in other services

1. Check that services can reach `http://localhost:5000/.well-known/jwks.json`
2. Verify services are using correct issuer: `hivematrix.core`
3. Check JWT hasn't expired (default: 1 hour)

### "Group mapper not found" error

1. Go to Keycloak: Clients → core-client → Client scopes → core-client-dedicated
2. Add Group Membership mapper with token claim name `groups`
3. Ensure "Full group path" is OFF

---

## Related Documentation

- **[HiveMatrix Helm](../hivematrix-helm/README.md)** - Service orchestration and setup
- **[Architecture Guide](../hivematrix-helm/ARCHITECTURE.md)** - Complete system architecture
- **[HiveMatrix Nexus](../hivematrix-nexus/README.md)** - API Gateway

---

## License

See main HiveMatrix LICENSE file
