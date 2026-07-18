package scp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// shrinkBackoff makes the retry timings test-fast, returning a restore func.
func shrinkBackoff(t *testing.T, initial, max, budget time.Duration) func() {
	t.Helper()
	oldInitial, oldMax, oldBudget := writeRetryInitialDelay, writeRetryMaxDelay, writeRetryBudget
	writeRetryInitialDelay, writeRetryMaxDelay, writeRetryBudget = initial, max, budget
	return func() {
		writeRetryInitialDelay, writeRetryMaxDelay, writeRetryBudget = oldInitial, oldMax, oldBudget
	}
}

func TestIsConcurrentWrite(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "the API's concurrent-write rejection",
			err:  &APIError{StatusCode: 400, Message: "Another firewall policy update is running. Try again later."},
			want: true,
		},
		{
			name: "matched case-insensitively",
			err:  &APIError{StatusCode: 409, Message: "A WRITE IS ALREADY RUNNING"},
			want: true,
		},
		{
			name: "an unrelated API error",
			err:  &APIError{StatusCode: 404, Message: "Resource not found"},
			want: false,
		},
		{
			name: "a non-API error",
			err:  errors.New("connection refused"),
			want: false,
		},
		{name: "no error", err: nil, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsConcurrentWrite(tt.err); got != tt.want {
				t.Errorf("IsConcurrentWrite(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

// A run touching several policies collides with its own previous write, so a
// transient rejection must be retried rather than aborting the run half-applied.
func TestDoRetriesConcurrentWrite(t *testing.T) {
	// Keep the test fast: shrink the backoff for this run only.
	restore := shrinkBackoff(t, time.Millisecond, 2*time.Millisecond, time.Second)
	defer restore()

	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts < 3 {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `{"message":"Another firewall policy update is running. Try again later."}`)
			return
		}
		fmt.Fprint(w, `{"id":42}`)
	}))
	defer srv.Close()

	client := NewClient("token")
	client.BaseURL = srv.URL

	var out struct {
		ID int `json:"id"`
	}
	if err := client.do(context.Background(), http.MethodPut, "/policy", nil, &out); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3 (two rejections then success)", attempts)
	}
	if out.ID != 42 {
		t.Errorf("decoded id = %d, want 42", out.ID)
	}
}

// An error that is not a concurrent-write rejection must surface immediately.
func TestDoDoesNotRetryOtherErrors(t *testing.T) {
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Resource not found"}`)
	}))
	defer srv.Close()

	client := NewClient("token")
	client.BaseURL = srv.URL

	err := client.do(context.Background(), http.MethodGet, "/thing", nil, nil)
	if err == nil {
		t.Fatal("expected an error")
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1 (no retry for a 404)", attempts)
	}
}

// Once the budget is spent the caller sees the API's own error, not a bare timeout.
func TestDoGivesUpAfterBudget(t *testing.T) {
	restore := shrinkBackoff(t, time.Millisecond, 2*time.Millisecond, 20*time.Millisecond)
	defer restore()

	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"message":"Another firewall policy update is running. Try again later."}`)
	}))
	defer srv.Close()

	client := NewClient("token")
	client.BaseURL = srv.URL

	err := client.do(context.Background(), http.MethodPut, "/policy", nil, nil)
	if err == nil {
		t.Fatal("expected an error once the budget was spent")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Errorf("error %v does not wrap *APIError; the caller should see the API's reason", err)
	}
	if attempts < 2 {
		t.Errorf("attempts = %d, want at least 2 (it should have retried)", attempts)
	}
}
