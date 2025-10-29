# HiveMatrix Core

Authentication service and JWT token manager for HiveMatrix.

Core's job is to handle authentication flows working with Keycloak:
- **Token Exchange** - Converts Keycloak tokens to HiveMatrix JWTs
- **Session Management** - Tracks active sessions with revocation support
- **Token Validation** - Verifies JWT signatures and expiration
- **Service Registry** - Maintains list of available services for Nexus
- **Public Key Distribution** - Provides JWKS endpoint for JWT verification

Core works with Keycloak to authenticate users, then issues HiveMatrix-specific JWTs that services use for authorization.

## Documentation

For installation, configuration, and architecture documentation, please visit:

**[HiveMatrix Documentation](https://Troy Pound.github.io/hivematrix-docs/ARCHITECTURE/)**

## Quick Start

This service is deployed as part of the HiveMatrix Helm chart. See the documentation link above for setup instructions.
