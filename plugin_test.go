
package traefik_cas_auth

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// mockHandler implements http.Handler for testing
type mockHandler struct {
	called bool
}

func (h *mockHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	h.called = true
	rw.WriteHeader(http.StatusOK)
}

// setupTest creates a new plugin instance with test configuration
func setupTest(t *testing.T, config *Config) (*CASAuth, *mockHandler) {
	next := &mockHandler{}
	auth, err := New(context.Background(), next, config, "test")
	if err != nil {
		t.Fatalf("Failed to create middleware: %v", err)
	}
	return auth.(*CASAuth), next
}

// mockCASServer creates a test CAS server
func mockCASServer(t *testing.T) *httptest.Server {
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/p3/serviceValidate":
			ticket := r.URL.Query().Get("ticket")
			if ticket == "valid-ticket" {
				response := ServiceResponse{
					Success: &AuthSuccess{
						User: "testuser",
					},
				}
				w.Header().Set("Content-Type", "application/xml")
				xml.NewEncoder(w).Encode(response)
			} else {
				response := ServiceResponse{
					Failure: &AuthFailure{
						Code:        "INVALID_TICKET",
						Description: "Invalid ticket provided",
					},
				}
				w.Header().Set("Content-Type", "application/xml")
				xml.NewEncoder(w).Encode(response)
			}
		}
	}))
}

// Config Tests
func TestCreateConfig(t *testing.T) {
	config := CreateConfig()
	if config.SessionTimeout != "24h" {
		t.Errorf("Expected default session timeout '24h', got '%s'", config.SessionTimeout)
	}
	if config.Rule != "PathPrefix(`/`)" {
		t.Errorf("Expected default rule 'PathPrefix(`/`)', got '%s'", config.Rule)
	}
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "Empty CAS Server URL",
			config:  &Config{},
			wantErr: true,
		},
		{
			name: "Valid Config",
			config: &Config{
				CASServerURL: "https://cas.example.com",
				Rule:         "PathPrefix(`/`)",
			},
			wantErr: false,
		},
		{
			name: "Invalid Exception Rule",
			config: &Config{
				CASServerURL:   "https://cas.example.com",
				ExceptionRule:  "Invalid(Rule",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.ValidateConfig()
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Authentication Flow Tests
func TestUnauthenticatedFlow(t *testing.T) {
	config := &Config{
		CASServerURL: "https://cas.example.com",
	}
	auth, _ := setupTest(t, config)

	req := httptest.NewRequest("GET", "https://app.example.com/protected", nil)
	w := httptest.NewRecorder()

	auth.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected redirect status 302, got %d", w.Code)
	}

	location := w.Header().Get("Location")
	if location == "" {
		t.Error("Expected redirect location header")
	}
}

func TestSuccessfulAuthentication(t *testing.T) {
	casServer := mockCASServer(t)
	defer casServer.Close()

	config := &Config{
		CASServerURL: casServer.URL,
	}
	auth, next := setupTest(t, config)

	req := httptest.NewRequest("GET", "https://app.example.com/protected?ticket=valid-ticket", nil)
	w := httptest.NewRecorder()

	auth.ServeHTTP(w, req)

	if !next.called {
		t.Error("Expected next handler to be called")
	}
}

// Rule Matching Tests
func TestRuleMatching(t *testing.T) {
	tests := []struct {
		name         string
		rule         string
		path         string
		shouldMatch  bool
	}{
		{
			name:         "Path Prefix Match",
			rule:         "PathPrefix(`/api`)",
			path:         "/api/users",
			shouldMatch:  true,
		},
		{
			name:         "Path Prefix No Match",
			rule:         "PathPrefix(`/api`)",
			path:         "/public/users",
			shouldMatch:  false,
		},
		{
			name:         "Host Rule Match",
			rule:         "Host(`app.example.com`)",
			path:         "/anything",
			shouldMatch:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				CASServerURL: "https://cas.example.com",
				Rule:        tt.rule,
			}
			auth, next := setupTest(t, config)

			req := httptest.NewRequest("GET", fmt.Sprintf("https://app.example.com%s", tt.path), nil)
			w := httptest.NewRecorder()

			auth.ServeHTTP(w, req)

			if tt.shouldMatch && next.called {
				t.Error("Expected authentication to be required")
			}
			if !tt.shouldMatch && !next.called {
				t.Error("Expected request to pass through")
			}
		})
	}
}

// Security Tests
func TestCSRFProtection(t *testing.T) {
	config := &Config{
		CASServerURL: "https://cas.example.com",
	}
	auth, _ := setupTest(t, config)

	// Create a session with CSRF token
	sessionID := generateSessionID()
	csrfToken := generateCSRFToken()
	auth.sessions[sessionID] = sessionInfo{
		username:   "testuser",
		expiry:    time.Now().Add(24 * time.Hour),
		csrfToken: csrfToken,
	}

	// Test POST request without CSRF token
	req := httptest.NewRequest("POST", "https://app.example.com/protected", nil)
	req.AddCookie(&http.Cookie{Name: "cas_session", Value: sessionID})
	w := httptest.NewRecorder()

	auth.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected forbidden status 403, got %d", w.Code)
	}

	// Test POST request with valid CSRF token
	req = httptest.NewRequest("POST", "https://app.example.com/protected", nil)
	req.AddCookie(&http.Cookie{Name: "cas_session", Value: sessionID})
	req.Header.Set("X-CSRF-Token", csrfToken)
	w = httptest.NewRecorder()

	auth.ServeHTTP(w, req)

	if w.Code == http.StatusForbidden {
		t.Error("Expected request to be allowed with valid CSRF token")
	}
}