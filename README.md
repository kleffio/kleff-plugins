# idp-keycloak

Kleff identity provider plugin for [Keycloak](https://www.keycloak.org/). SSO, MFA, and self-hosted user management.

## Features

- Direct Access Grant (headless login)
- OIDC redirect login (SSO, MFA, social login)
- User registration via Keycloak Admin REST API
- RS256 JWT verification via JWKS endpoint
- Multi-realm support
- Bundled Keycloak companion container for zero-config setup

## Quick Start

Install via the Kleff panel marketplace, or via the API:

```bash
curl -X POST http://localhost:8080/api/v1/admin/plugins \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "idp-keycloak",
    "version": "1.0.0",
    "config": {}
  }'
```

Leave all config blank to use the bundled Keycloak. Set `KEYCLOAK_URL` to connect to your own.

## Configuration

All fields are optional — defaults are provided for zero-config startup with the bundled companion.

| Key | Label | Type | Default | Description |
|-----|-------|------|---------|-------------|
| `KEYCLOAK_URL` | Keycloak URL | `url` | — | Set to connect to an external Keycloak |
| `KEYCLOAK_PUBLIC_URL` | Public URL | `url` | — | Browser-reachable URL (if different from internal) |
| `KEYCLOAK_REALM` | Realm | `string` | `kleff` | Keycloak realm name |
| `KEYCLOAK_CLIENT_ID` | Client ID | `string` | `kleff-panel` | Client with Direct Access Grants enabled |
| `KEYCLOAK_CLIENT_SECRET` | Client Secret | `secret` | — | For confidential clients |
| `KEYCLOAK_ADMIN_USER` | Admin Username | `string` | `admin` | Admin for user registration |
| `KEYCLOAK_ADMIN_PASSWORD` | Admin Password | `secret` | `admin` | Admin password |
| `AUTH_MODE` | Login Mode | `select` | `headless` | `headless` or `redirect` |

## Building

```bash
docker build -t ghcr.io/kleffio/idp-keycloak:dev .
```

## Architecture

Hexagonal architecture — see [docs.kleff.io/plugins/idp-keycloak](https://docs.kleff.io/plugins/idp-keycloak).

## License

MIT
