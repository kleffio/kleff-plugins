// Command plugin starts the idp-keycloak gRPC server.
package main

import (
	"log"
	"log/slog"
	"net"
	"os"

	pluginsv1 "github.com/kleff/platform/api/plugins/v1"
	"github.com/kleff/idp-keycloak/internal/keycloak"
	"github.com/kleff/idp-keycloak/internal/server"
	"google.golang.org/grpc"
)

func main() {
	port := env("PLUGIN_PORT", "50051")
	level := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	cfg := keycloak.Config{
		BaseURL:       mustEnv("KEYCLOAK_URL"),
		PublicBaseURL: os.Getenv("KEYCLOAK_PUBLIC_URL"), // browser-reachable URL; falls back to KEYCLOAK_URL
		Realm:         env("KEYCLOAK_REALM", "master"),
		ClientID:      env("KEYCLOAK_CLIENT_ID", "kleff-panel"),
		ClientSecret:  os.Getenv("KEYCLOAK_CLIENT_SECRET"),
		AdminUser:     env("KEYCLOAK_ADMIN_USER", "admin"),
		AdminPassword: os.Getenv("KEYCLOAK_ADMIN_PASSWORD"),
	}

	kc := keycloak.New(cfg)
	srv := server.New(kc)

	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("listen :%s: %v", port, err)
	}

	gs := grpc.NewServer()
	pluginsv1.RegisterIdentityPluginServer(gs, srv)
	pluginsv1.RegisterPluginHealthServer(gs, srv)

	slog.Info("idp-keycloak plugin listening", "port", port,
		"realm", cfg.Realm, "keycloak_url", cfg.BaseURL)

	if err := gs.Serve(lis); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required environment variable %s is not set", key)
	}
	return v
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
