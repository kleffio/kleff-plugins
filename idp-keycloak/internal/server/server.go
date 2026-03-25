// Package server implements the IdentityPlugin gRPC service for Keycloak.
package server

import (
	"context"
	"strings"

	pluginsv1 "github.com/kleff/platform/api/plugins/v1"
	"github.com/kleff/idp-keycloak/internal/keycloak"
)

// IDPServer implements pluginsv1.IdentityPluginServer and pluginsv1.PluginHealthServer backed by Keycloak.
type IDPServer struct {
	pluginsv1.UnimplementedIdentityPluginServer
	pluginsv1.UnimplementedPluginHealthServer
	client *keycloak.Client
}

// New creates a Keycloak-backed IdentityPlugin server.
func New(client *keycloak.Client) *IDPServer {
	return &IDPServer{client: client}
}

// Login authenticates via Keycloak Direct Access Grant.
func (s *IDPServer) Login(ctx context.Context, req *pluginsv1.LoginRequest) (*pluginsv1.LoginResponse, error) {
	tok, err := s.client.Login(ctx, req.Username, req.Password)
	if err != nil {
		code := pluginsv1.ErrorCodeInternal
		msg := err.Error()

		if isUnauthorized(err) {
			code = pluginsv1.ErrorCodeUnauthorized
			msg = "invalid username or password"
		}

		return &pluginsv1.LoginResponse{
			Error: &pluginsv1.PluginError{Code: code, Message: msg},
		}, nil
	}

	return &pluginsv1.LoginResponse{
		Token: &pluginsv1.TokenSet{
			AccessToken:  tok.AccessToken,
			RefreshToken: tok.RefreshToken,
			IDToken:      tok.IDToken,
			TokenType:    tok.TokenType,
			ExpiresIn:    tok.ExpiresIn,
			Scope:        tok.Scope,
		},
	}, nil
}

// Register creates a new user in Keycloak via the Admin REST API.
func (s *IDPServer) Register(ctx context.Context, req *pluginsv1.RegisterRequest) (*pluginsv1.RegisterResponse, error) {
	userID, err := s.client.RegisterUser(ctx,
		req.Username, req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		code := pluginsv1.ErrorCodeInternal
		if strings.Contains(err.Error(), "already exists") {
			code = pluginsv1.ErrorCodeConflict
		}
		return &pluginsv1.RegisterResponse{
			Error: &pluginsv1.PluginError{Code: code, Message: err.Error()},
		}, nil
	}

	return &pluginsv1.RegisterResponse{UserID: userID}, nil
}

// GetUser is not implemented — user retrieval should use the JWKS-verified
// token claims rather than a separate lookup.
func (s *IDPServer) GetUser(_ context.Context, req *pluginsv1.GetUserRequest) (*pluginsv1.GetUserResponse, error) {
	return &pluginsv1.GetUserResponse{
		Error: &pluginsv1.PluginError{
			Code:    pluginsv1.ErrorCodeNotSupported,
			Message: "GetUser is not supported by the Keycloak plugin; use token claims instead",
		},
	}, nil
}

// Health reports whether the plugin can reach the Keycloak server.
func (s *IDPServer) Health(_ context.Context, _ *pluginsv1.HealthRequest) (*pluginsv1.HealthResponse, error) {
	return &pluginsv1.HealthResponse{
		Status:  pluginsv1.HealthStatusHealthy,
		Message: "Keycloak IDP plugin running",
	}, nil
}

// ValidateToken verifies a JWT against Keycloak's JWKS endpoint and returns claims.
// The platform calls this on every authenticated request instead of doing
// JWKS validation internally.
func (s *IDPServer) ValidateToken(ctx context.Context, req *pluginsv1.ValidateTokenRequest) (*pluginsv1.ValidateTokenResponse, error) {
	claims, err := s.client.ValidateToken(ctx, req.Token)
	if err != nil {
		return &pluginsv1.ValidateTokenResponse{
			Error: &pluginsv1.PluginError{
				Code:    pluginsv1.ErrorCodeUnauthorized,
				Message: err.Error(),
			},
		}, nil
	}
	return &pluginsv1.ValidateTokenResponse{
		Claims: &pluginsv1.TokenClaims{
			Subject: claims.Subject,
			Email:   claims.Email,
			Roles:   claims.Roles,
		},
	}, nil
}

// GetOIDCConfig returns the OIDC configuration the frontend needs to
// initialise its OIDC client library.
func (s *IDPServer) GetOIDCConfig(_ context.Context, _ *pluginsv1.GetOIDCConfigRequest) (*pluginsv1.GetOIDCConfigResponse, error) {
	cfg := s.client.OIDCConfig()
	return &pluginsv1.GetOIDCConfigResponse{
		Config: &pluginsv1.OIDCConfig{
			Authority: cfg.Authority,
			ClientID:  cfg.ClientID,
			JwksURI:   cfg.JwksURI,
			Scopes:    []string{"openid", "profile", "email"},
		},
	}, nil
}

// isUnauthorized detects authentication failure errors from the Keycloak client.
func isUnauthorized(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "invalid_grant") ||
		strings.Contains(msg, "Unauthorized") ||
		strings.Contains(msg, "invalid username or password")
}
