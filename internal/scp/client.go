package scp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// BaseURL is the SCP API root.
const BaseURL = "https://www.servercontrolpanel.de/scp-core"

// Client is a typed HTTP client for the SCP API. AccessToken is sent as a
// bearer token on every request.
type Client struct {
	BaseURL     string
	AccessToken string
	HTTP        *http.Client
}

// NewClient returns a Client with sensible defaults.
func NewClient(accessToken string) *Client {
	return &Client{
		BaseURL:     BaseURL,
		AccessToken: accessToken,
		HTTP:        &http.Client{Timeout: 30 * time.Second},
	}
}

// APIError represents a non-2xx response, decoding the ResponseError /
// ValidationError shapes the API uses.
type APIError struct {
	StatusCode int
	Code       string       `json:"code"`
	Message    string       `json:"message"`
	Errors     []FieldError `json:"errors"`
}

// FieldError is a single field-level validation error.
type FieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	s := fmt.Sprintf("scp api error %d: %s", e.StatusCode, msg)
	for _, fe := range e.Errors {
		s += fmt.Sprintf("\n  - %s: %s", fe.Field, fe.Message)
	}
	return s
}

// do executes a request against path (relative to BaseURL). If body is non-nil
// it is JSON-encoded. On a 2xx status, out (if non-nil) is JSON-decoded from the
// response. Non-2xx responses are returned as *APIError.
// The API serializes firewall changes per user, so a run touching several
// policies in a row routinely collides with its own previous write; without
// retrying, the run aborts half-applied.
//
// The interface-update task that follows a write is the long pole — it can take
// several minutes to settle, and every write during that window is rejected. The
// budget below (exponential backoff, capped) waits up to ~5 minutes, which
// covers what has been observed in practice.
// Variables rather than constants so tests can shrink them.
var (
	writeRetryInitialDelay = 2 * time.Second
	writeRetryMaxDelay     = 30 * time.Second
	writeRetryBudget       = 5 * time.Minute
)

// IsConcurrentWrite reports whether err is the API's "a write is already
// running" rejection, which is transient and worth retrying.
func IsConcurrentWrite(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	// The API signals this as a 400/409 whose message names a running write; the
	// code field is not stable enough to match on. The observed wording is
	// "Another firewall policy update is running. Try again later.", but the
	// phrasing varies across endpoints, so match the stable part: something is
	// running.
	msg := strings.ToLower(apiErr.Message)
	return strings.Contains(msg, "is running") || strings.Contains(msg, "already running")
}

// do executes a request, retrying transient concurrent-write rejections with
// exponential backoff until the budget is spent.
func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	deadline := time.Now().Add(writeRetryBudget)
	delay := writeRetryInitialDelay

	for {
		err := c.doOnce(ctx, method, path, body, out)
		if err == nil || !IsConcurrentWrite(err) {
			return err
		}

		// Stop once another wait would run past the budget, so the caller gets
		// the API's own error rather than a timeout of ours.
		if time.Now().Add(delay).After(deadline) {
			return fmt.Errorf("%w (still blocked after retrying for %s)", err, writeRetryBudget)
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}

		if delay *= 2; delay > writeRetryMaxDelay {
			delay = writeRetryMaxDelay
		}
	}
}

func (c *Client) doOnce(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encoding request body: %w", err)
		}
		reader = bytes.NewReader(buf)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode}
		_ = json.Unmarshal(data, apiErr) // best-effort; body may be empty/non-JSON
		return apiErr
	}

	if out != nil && len(data) > 0 {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}
	}
	return nil
}

// ListPolicies returns the user's firewall policies, optionally filtered by the
// substring query q (matched by the server against name/description).
func (c *Client) ListPolicies(ctx context.Context, userID int, q string) ([]FirewallPolicy, error) {
	path := fmt.Sprintf("/api/v1/users/%d/firewall-policies", userID)
	if q != "" {
		path += "?q=" + url.QueryEscape(q)
	}
	var policies []FirewallPolicy
	if err := c.do(ctx, http.MethodGet, path, nil, &policies); err != nil {
		return nil, err
	}
	return policies, nil
}

// CreatePolicy creates a firewall policy and returns the created entity.
func (c *Client) CreatePolicy(ctx context.Context, userID int, save FirewallPolicySave) (*FirewallPolicy, error) {
	path := fmt.Sprintf("/api/v1/users/%d/firewall-policies", userID)
	var out FirewallPolicy
	if err := c.do(ctx, http.MethodPost, path, save, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UpdatePolicy updates an existing firewall policy in place.
func (c *Client) UpdatePolicy(ctx context.Context, userID, policyID int, save FirewallPolicySave) error {
	path := fmt.Sprintf("/api/v1/users/%d/firewall-policies/%d", userID, policyID)
	return c.do(ctx, http.MethodPut, path, save, nil)
}

// GetFirewall reads the firewall configuration for a server interface.
func (c *Client) GetFirewall(ctx context.Context, serverID int, mac string) (*ServerFirewall, error) {
	path := fmt.Sprintf("/api/v1/servers/%d/interfaces/%s/firewall", serverID, url.PathEscape(mac))
	var out ServerFirewall
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SaveFirewall writes the firewall configuration for a server interface,
// returning the async task descriptor.
func (c *Client) SaveFirewall(ctx context.Context, serverID int, mac string, save ServerFirewallSave) (*TaskInfo, error) {
	path := fmt.Sprintf("/api/v1/servers/%d/interfaces/%s/firewall", serverID, url.PathEscape(mac))
	var out TaskInfo
	if err := c.do(ctx, http.MethodPut, path, save, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// UserInfoURL is the Keycloak userinfo endpoint used to resolve the SCP user id.
const UserInfoURL = "https://www.servercontrolpanel.de/realms/scp/protocol/openid-connect/userinfo"

// GetUserID resolves the SCP user id for the current access token.
func (c *Client) GetUserID(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, UserInfoURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+c.AccessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("reading userinfo: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return 0, fmt.Errorf("userinfo request failed: %s: %s", resp.Status, strconv.Quote(string(data)))
	}

	var info UserInfo
	if err := json.Unmarshal(data, &info); err != nil {
		return 0, fmt.Errorf("decoding userinfo: %w", err)
	}
	if info.ID == "" {
		return 0, fmt.Errorf("userinfo response contained no id")
	}
	id, err := strconv.Atoi(info.ID)
	if err != nil {
		return 0, fmt.Errorf("userinfo id %q is not numeric: %w", info.ID, err)
	}
	return id, nil
}
