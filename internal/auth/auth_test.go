package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headers   http.Header
		wantKey   string
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid API key header",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "ApiKey test-key-123")
				return h
			}(),
			wantKey:   "test-key-123",
			wantError: false,
		},
		{
			name:      "missing authorization header",
			headers:   make(http.Header),
			wantKey:   "",
			wantError: true,
			errorMsg:  "no authorization header included",
		},
		{
			name: "malformed header - wrong prefix",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "Bearer test-key-123")
				return h
			}(),
			wantKey:   "",
			wantError: true,
			errorMsg:  "malformed authorization header",
		},
		{
			name: "malformed header - only prefix",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "ApiKey")
				return h
			}(),
			wantKey:   "",
			wantError: true,
			errorMsg:  "malformed authorization header",
		},
		{
			name: "valid API key with multiple spaces in value",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "ApiKey my-api-key-with-special-chars")
				return h
			}(),
			wantKey:   "my-api-key-with-special-chars",
			wantError: false,
		},
		{
			name: "case sensitive - wrong case prefix",
			headers: func() http.Header {
				h := make(http.Header)
				h.Set("Authorization", "apikey test-key-123")
				return h
			}(),
			wantKey:   "",
			wantError: true,
			errorMsg:  "malformed authorization header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := GetAPIKey(tt.headers)

			if (err != nil) != tt.wantError {
				t.Errorf("GetAPIKey() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if err != nil && tt.errorMsg != "" {
				if err.Error() != tt.errorMsg {
					t.Errorf("GetAPIKey() error = %v, want error message %v", err.Error(), tt.errorMsg)
				}
			}

			if got != tt.wantKey {
				t.Errorf("GetAPIKey() got = %v, want %v", got, tt.wantKey)
			}
		})
	}
}

func TestGetAPIKey_EmptyAuthorization(t *testing.T) {
	headers := make(http.Header)
	headers.Set("Authorization", "")

	_, err := GetAPIKey(headers)
	if err != ErrNoAuthHeaderIncluded {
		t.Errorf("GetAPIKey() with empty header should return ErrNoAuthHeaderIncluded, got %v", err)
	}
}
