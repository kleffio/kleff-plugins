// Package keycloak provides a minimal Keycloak client for the idp-keycloak plugin.
// It implements Direct Access Grant (headless login) and Admin REST API calls
// (user creation) without any third-party Keycloak SDK.
package keycloak

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config holds the Keycloak connection parameters injected as environment variables.
type Config struct {
	BaseURL       string // e.g. "http://keycloak:8080" — used for server-to-server calls
	PublicBaseURL string // e.g. "http://localhost:8080" — used in OIDC config returned to the browser; falls back to BaseURL
	Realm         string // e.g. "kleff"
	ClientID      string // e.g. "kleff-panel"
	ClientSecret  string // optional, for confidential clients
	AdminUser     string // e.g. "admin"
	AdminPassword string
}

// TokenResponse mirrors Keycloak's token endpoint JSON response.
type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	IDToken          string `json:"id_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int64  `json:"expires_in"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Client is a lightweight Keycloak REST API client.
type Client struct {
	cfg    Config
	http   *http.Client
}

// New creates a Keycloak client from the provided config.
func New(cfg Config) *Client {
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: 15 * time.Second},
	}
}

// Login authenticates a user via the Direct Access Grant (Resource Owner Password Credentials).
func (c *Client) Login(ctx context.Context, username, password string) (*TokenResponse, error) {
	endpoint := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token",
		strings.TrimRight(c.cfg.BaseURL, "/"), c.cfg.Realm)

	data := url.Values{
		"grant_type": {"password"},
		"client_id":  {c.cfg.ClientID},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid profile email"},
	}
	if c.cfg.ClientSecret != "" {
		data.Set("client_secret", c.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("keycloak login: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak login: request: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var tok TokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("keycloak login: parse response: %w", err)
	}

	if tok.Error != "" {
		return nil, fmt.Errorf("keycloak login: %s: %s", tok.Error, tok.ErrorDescription)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak login: unexpected status %d", resp.StatusCode)
	}
	return &tok, nil
}

// RegisterUser creates a new user in the Keycloak realm via the Admin REST API.
// Returns the provider-assigned user ID (extracted from the Location header).
func (c *Client) RegisterUser(ctx context.Context, username, email, password, firstName, lastName string) (string, error) {
	adminToken, err := c.adminToken(ctx)
	if err != nil {
		return "", fmt.Errorf("keycloak register: get admin token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/admin/realms/%s/users",
		strings.TrimRight(c.cfg.BaseURL, "/"), c.cfg.Realm)

	body, err := json.Marshal(map[string]any{
		"username":  username,
		"email":     email,
		"firstName": firstName,
		"lastName":  lastName,
		"enabled":   true,
		"credentials": []map[string]any{{
			"type":      "password",
			"value":     password,
			"temporary": false,
		}},
	})
	if err != nil {
		return "", fmt.Errorf("keycloak register: marshal body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("keycloak register: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("keycloak register: request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusCreated:
		// User ID is in the Location header: .../users/{id}
		loc := resp.Header.Get("Location")
		parts := strings.Split(strings.TrimRight(loc, "/"), "/")
		return parts[len(parts)-1], nil
	case http.StatusConflict:
		return "", fmt.Errorf("user already exists")
	default:
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("keycloak register: status %d: %s", resp.StatusCode, string(b))
	}
}

// ── OIDC config & token validation ────────────────────────────────────────────

// OIDCConfigResult holds the OIDC parameters derived from this client's config.
type OIDCConfigResult struct {
	Authority string
	ClientID  string
	JwksURI   string
}

// OIDCConfig returns the OIDC parameters for this Keycloak realm.
// Authority and JwksURI use PublicBaseURL (the browser-reachable address) if set,
// falling back to BaseURL.
func (c *Client) OIDCConfig() OIDCConfigResult {
	public := strings.TrimRight(c.cfg.PublicBaseURL, "/")
	if public == "" {
		public = strings.TrimRight(c.cfg.BaseURL, "/")
	}
	return OIDCConfigResult{
		Authority: fmt.Sprintf("%s/realms/%s", public, c.cfg.Realm),
		ClientID:  c.cfg.ClientID,
		JwksURI:   fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs", public, c.cfg.Realm),
	}
}

// TokenClaimsResult carries verified claims extracted from a JWT.
type TokenClaimsResult struct {
	Subject string
	Email   string
	Roles   []string
}

// ValidateToken verifies an RS256 JWT against Keycloak's JWKS endpoint.
// Keys are fetched lazily and cached; a cache miss triggers one re-fetch.
func (c *Client) ValidateToken(ctx context.Context, rawToken string) (*TokenClaimsResult, error) {
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("malformed JWT")
	}

	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := decodeJWTSegment(parts[0], &header); err != nil {
		return nil, fmt.Errorf("decode header: %w", err)
	}
	if header.Alg != "RS256" {
		return nil, fmt.Errorf("unsupported algorithm %q", header.Alg)
	}

	key, err := c.getJWKSKey(ctx, header.Kid)
	if err != nil {
		return nil, err
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sigBytes); err != nil {
		return nil, fmt.Errorf("invalid signature: %w", err)
	}

	var claims struct {
		Sub         string   `json:"sub"`
		Email       string   `json:"email"`
		Exp         int64    `json:"exp"`
		Roles       []string `json:"roles"`
		RealmAccess struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
	}
	if err := decodeJWTSegment(parts[1], &claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	if claims.Sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}
	if claims.Exp > 0 && time.Now().Unix() > claims.Exp {
		return nil, fmt.Errorf("token expired")
	}

	roles := append(claims.Roles, claims.RealmAccess.Roles...)
	return &TokenClaimsResult{Subject: claims.Sub, Email: claims.Email, Roles: roles}, nil
}

// jwksCache caches RSA public keys by key ID.
var (
	jwksMu   sync.RWMutex
	jwksKeys = map[string]*rsa.PublicKey{}
)

func (c *Client) getJWKSKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	jwksMu.RLock()
	key, ok := jwksKeys[kid]
	jwksMu.RUnlock()
	if ok {
		return key, nil
	}
	if err := c.fetchJWKS(ctx); err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	jwksMu.RLock()
	key, ok = jwksKeys[kid]
	jwksMu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown key id %q", kid)
	}
	return key, nil
}

func (c *Client) fetchJWKS(ctx context.Context) error {
	uri := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/certs",
		strings.TrimRight(c.cfg.BaseURL, "/"), c.cfg.Realm)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			Use string `json:"use"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return err
	}

	jwksMu.Lock()
	defer jwksMu.Unlock()
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			continue
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			continue
		}
		jwksKeys[k.Kid] = &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: int(new(big.Int).SetBytes(eBytes).Int64()),
		}
	}
	return nil
}

func decodeJWTSegment(seg string, v any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// adminToken obtains a short-lived admin access token from the master realm.
func (c *Client) adminToken(ctx context.Context) (string, error) {
	endpoint := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token",
		strings.TrimRight(c.cfg.BaseURL, "/"))

	data := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {c.cfg.AdminUser},
		"password":   {c.cfg.AdminPassword},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint,
		strings.NewReader(data.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tok TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return "", err
	}
	if tok.Error != "" {
		return "", fmt.Errorf("%s: %s", tok.Error, tok.ErrorDescription)
	}
	return tok.AccessToken, nil
}
