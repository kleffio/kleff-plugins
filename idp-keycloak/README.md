# idp-keycloak

Kleff IDP plugin for [Keycloak](https://www.keycloak.org/).
Implements the `IdentityPlugin` gRPC service over port `50051`.

## Quick start (local dev)

```bash
# 1. Start a local Keycloak instance
docker run -d \
  --name keycloak \
  --network kleff \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -p 8080:8080 \
  quay.io/keycloak/keycloak:25.0 start-dev

# 2. Build and run the plugin
docker build \
  --build-context platform=../../platform \
  -f Dockerfile \
  -t kleff/idp-keycloak:dev \
  .

docker run -d \
  --name kleff-idp-keycloak \
  --network kleff \
  -e KEYCLOAK_URL=http://keycloak:8080 \
  -e KEYCLOAK_REALM=master \
  -e KEYCLOAK_CLIENT_ID=admin-cli \
  -e KEYCLOAK_ADMIN_USER=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  kleff/idp-keycloak:dev

# 3. Health check
grpcurl -plaintext localhost:50051 kleff.plugins.v1.IdentityPlugin/Health

# 4. Install via the Kleff API (requires platform running)
curl -X POST http://localhost:8080/api/v1/admin/plugins \
  -H "Authorization: Bearer <admin-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "idp-keycloak",
    "version": "1.0.0",
    "config": {
      "KEYCLOAK_URL": "http://keycloak:8080",
      "KEYCLOAK_REALM": "master",
      "KEYCLOAK_CLIENT_ID": "admin-cli",
      "KEYCLOAK_ADMIN_USER": "admin",
      "KEYCLOAK_ADMIN_PASSWORD": "admin"
    }
  }'

# 5. Set as active IDP
curl -X POST http://localhost:8080/api/v1/admin/plugins/idp-keycloak/set-active \
  -H "Authorization: Bearer <admin-token>"

# 6. Test login
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'
```

## Environment variables

| Variable               | Required | Description                                 |
|------------------------|----------|---------------------------------------------|
| `KEYCLOAK_URL`         | Yes      | Keycloak root URL                           |
| `KEYCLOAK_REALM`       | No       | Realm name (default: `master`)              |
| `KEYCLOAK_CLIENT_ID`   | No       | Client ID (default: `kleff-panel`)          |
| `KEYCLOAK_CLIENT_SECRET` | No     | Client secret (for confidential clients)    |
| `KEYCLOAK_ADMIN_USER`  | No       | Admin username for user registration        |
| `KEYCLOAK_ADMIN_PASSWORD` | No    | Admin password                              |
| `PLUGIN_PORT`          | No       | gRPC listen port (default: `50051`)         |
