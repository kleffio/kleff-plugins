FROM golang:1.25-alpine AS builder
WORKDIR /build

# Copy local module dependencies (referenced by replace directives in go.mod)
COPY plugin-sdk/ plugin-sdk/

# Copy the plugin source
COPY plugins/idp-keycloak/ plugins/idp-keycloak/

WORKDIR /build/plugins/idp-keycloak
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /plugin ./cmd/plugin

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /plugin /plugin

EXPOSE 50051
ENTRYPOINT ["/plugin"]
