// Package traefik_cas_auth implements a Traefik middleware plugin for CAS authentication
package traefik_cas_auth

import (
    "context"
    "fmt"
    "net/http"
    "net/url"
    "strings"
    "time"
)

// Config holds the plugin configuration
type Config struct {
    CASServerURL string `json:"casServerURL,omitempty"`
    ServiceURLPattern string `json:"serviceURLPattern,omitempty"`
    SessionTimeout time.Duration `json:"sessionTimeout,omitempty"`
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
    return &Config{
        SessionTimeout: 24 * time.Hour,
    }
}

type CASAuth struct {
    next    http.Handler
    name    string
    config  *Config
    sessions map[string]sessionInfo
}

type sessionInfo struct {
    username string
    expiry   time.Time
}

// New creates a new CAS auth middleware plugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
    if len(config.CASServerURL) == 0 {
        return nil, fmt.Errorf("CASServerURL cannot be empty")
    }

    return &CASAuth{
        next:     next,
        name:     name,
        config:   config,
        sessions: make(map[string]sessionInfo),
    }, nil
}

func (c *CASAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    // Check if request matches service pattern
    if !strings.Contains(req.Host, c.config.ServiceURLPattern) {
        c.next.ServeHTTP(rw, req)
        return
    }

    // Check for existing session
    cookie, err := req.Cookie("cas_session")
    if err == nil {
        if session, exists := c.sessions[cookie.Value]; exists && time.Now().Before(session.expiry) {
            // Valid session exists, proceed
            c.next.ServeHTTP(rw, req)
            return
        }
    }

    // Check for CAS ticket in query params
    ticket := req.URL.Query().Get("ticket")
    if ticket != "" {
        // Validate ticket with CAS server
        if validated, username := c.validateTicket(ticket, req.Host); validated {
            // Create new session
            sessionID := generateSessionID()
            c.sessions[sessionID] = sessionInfo{
                username: username,
                expiry:   time.Now().Add(c.config.SessionTimeout),
            }

            // Set session cookie
            http.SetCookie(rw, &http.Cookie{
                Name:     "cas_session",
                Value:    sessionID,
                Path:     "/",
                Expires:  time.Now().Add(c.config.SessionTimeout),
                HttpOnly: true,
                Secure:   true,
                SameSite: http.SameSiteStrictMode,
            })

            // Redirect to original URL without ticket
            redirectURL := *req.URL
            q := redirectURL.Query()
            q.Del("ticket")
            redirectURL.RawQuery = q.Encode()
            http.Redirect(rw, req, redirectURL.String(), http.StatusFound)
            return
        }
    }

    // No valid session or ticket, redirect to CAS login
    serviceURL := fmt.Sprintf("https://%s%s", req.Host, req.URL.Path)
    loginURL := fmt.Sprintf("%s/login?service=%s", 
        c.config.CASServerURL, 
        url.QueryEscape(serviceURL))
    http.Redirect(rw, req, loginURL, http.StatusFound)
}

func (c *CASAuth) validateTicket(ticket, service string) (bool, string) {
    // Implement CAS ticket validation logic here
    // This should make a request to CAS server's /serviceValidate endpoint
    // Parse XML response and return validation status and username
    return true, "example_user"
}

func generateSessionID() string {
    // Implement secure session ID generation
    return "example_session_id"
}