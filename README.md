# HiveMatrix Core

Authentication service and JWT token manager for HiveMatrix.

## Overview

Core handles all authentication flows, working with Keycloak to authenticate users and issuing HiveMatrix-specific JWTs that services use for authorization.

**Port:** 5000

## Features

- **Token Exchange** - Converts Keycloak tokens to HiveMatrix JWTs
- **Session Management** - Tracks active sessions with revocation support
- **Token Validation** - Verifies JWT signatures and expiration
- **Service Tokens** - Issues service-to-service authentication tokens
- **JWKS Endpoint** - Public key distribution for JWT verification

## Tech Stack

- Flask + Gunicorn
- PostgreSQL
- PyJWT with RS256 signing

## Key Endpoints

- `POST /api/token/exchange` - Exchange Keycloak token for HiveMatrix JWT
- `POST /api/token/validate` - Validate a JWT token
- `POST /api/token/revoke` - Revoke a session
- `GET /.well-known/jwks.json` - Public keys for JWT verification
- `POST /service-token` - Get service-to-service token

## Environment Variables

- `KEYCLOAK_SERVER_URL` - Keycloak server URL
- `KEYCLOAK_REALM` - Keycloak realm name
- `KEYCLOAK_CLIENT_ID` - OAuth client ID
- `KEYCLOAK_CLIENT_SECRET` - OAuth client secret
- `JWT_PRIVATE_KEY_FILE` - Path to RSA private key
- `JWT_PUBLIC_KEY_FILE` - Path to RSA public key

## Documentation

For complete installation, configuration, and architecture documentation:

**[HiveMatrix Documentation](https://skelhammer.github.io/hivematrix-docs/)**

## License

MIT License - See LICENSE file
