// Package auth implements the OAuth2 device authorization flow and refresh-token
// exchange against NetCup's Keycloak realm.
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	realmBase   = "https://www.servercontrolpanel.de/realms/scp/protocol/openid-connect"
	deviceURL   = realmBase + "/auth/device"
	tokenURL    = realmBase + "/token"
	revokeURL   = realmBase + "/revoke"
	clientID    = "scp"
	deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

// DeviceAuth is the response from the device authorization endpoint.
type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Token is a token endpoint response.
type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
}

// tokenError is the OAuth error shape returned by the token endpoint.
type tokenError struct {
	Err  string `json:"error"`
	Desc string `json:"error_description"`
}

// StartDeviceAuth begins the device flow, returning the codes and verification URI.
func StartDeviceAuth(ctx context.Context) (*DeviceAuth, error) {
	form := url.Values{
		"client_id": {clientID},
		"scope":     {"offline_access openid"},
	}
	var da DeviceAuth
	if err := postForm(ctx, deviceURL, form, &da); err != nil {
		return nil, fmt.Errorf("starting device authorization: %w", err)
	}
	if da.Interval <= 0 {
		da.Interval = 5
	}
	return &da, nil
}

// PollToken polls the token endpoint until the user completes the grant, the
// device code expires, or ctx is cancelled. It honors authorization_pending and
// slow_down per RFC 8628.
func PollToken(ctx context.Context, da *DeviceAuth) (*Token, error) {
	interval := time.Duration(da.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(da.ExpiresIn) * time.Second)

	form := url.Values{
		"grant_type":  {deviceGrant},
		"device_code": {da.DeviceCode},
		"client_id":   {clientID},
	}

	for {
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("device code expired before authorization completed")
		}

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		var tok Token
		errCode, err := postFormAllowErr(ctx, tokenURL, form, &tok)
		if err != nil {
			return nil, err
		}
		switch errCode {
		case "":
			return &tok, nil
		case "authorization_pending":
			// keep waiting
		case "slow_down":
			interval += 5 * time.Second
		default:
			return nil, fmt.Errorf("device authorization failed: %s", errCode)
		}
	}
}

// Refresh exchanges a refresh token for a fresh access token. The returned Token
// may carry a rotated refresh token, which the caller should persist.
func Refresh(ctx context.Context, refreshToken string) (*Token, error) {
	form := url.Values{
		"client_id":     {clientID},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	var tok Token
	if err := postForm(ctx, tokenURL, form, &tok); err != nil {
		return nil, fmt.Errorf("refreshing access token: %w", err)
	}
	return &tok, nil
}

// Revoke revokes a refresh token.
func Revoke(ctx context.Context, refreshToken string) error {
	form := url.Values{
		"client_id":       {clientID},
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
	}
	if err := postForm(ctx, revokeURL, form, nil); err != nil {
		return fmt.Errorf("revoking refresh token: %w", err)
	}
	return nil
}

// postForm POSTs a form and decodes a 2xx JSON body into out. Non-2xx is an error.
func postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	_, err := postFormAllowErr(ctx, endpoint, form, out)
	return err
}

// postFormAllowErr POSTs a form. On a 2xx it decodes into out and returns "".
// On a 4xx carrying an OAuth "error" field it returns that error code (no Go
// error), letting callers branch on authorization_pending/slow_down. Other
// failures are returned as a Go error.
func postFormAllowErr(ctx context.Context, endpoint string, form url.Values, out any) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if out != nil && len(data) > 0 {
			if err := json.Unmarshal(data, out); err != nil {
				return "", fmt.Errorf("decoding token response: %w", err)
			}
		}
		return "", nil
	}

	var te tokenError
	if err := json.Unmarshal(data, &te); err == nil && te.Err != "" {
		// Surface pending/slow_down as a code; treat other codes as errors upstream.
		if te.Err == "authorization_pending" || te.Err == "slow_down" {
			return te.Err, nil
		}
		desc := te.Desc
		if desc == "" {
			desc = te.Err
		}
		return "", fmt.Errorf("%s (%s)", desc, te.Err)
	}
	return "", fmt.Errorf("token request failed: %s: %s", resp.Status, string(data))
}
