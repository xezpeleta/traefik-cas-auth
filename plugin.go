// Package traefik_cas_auth implements a Traefik middleware plugin for CAS authentication
package traefik_cas_auth

import (
    "context"
    "fmt"
    "net/http"
    "net/url"
    "strings"
    "time"
    "encoding/xml"
    "io/ioutil"
)

// Config holds the plugin configuration
type Config struct {
    CASServerURL string `json:"casServerURL,omitempty"`
    ServiceURLPattern string `json:"serviceURLPattern,omitempty"`
    SessionTimeout string `json:"sessionTimeout,omitempty"` // Changed to string type
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
    return &Config{
        SessionTimeout: "24h",  // Default timeout as string
    }
}

type CASAuth struct {
    next     http.Handler
    name     string
    config   *Config
    sessions map[string]sessionInfo
    timeout  time.Duration    // Add this field
}

type sessionInfo struct {
    username string
    expiry   time.Time
    ticket   string    // Add ticket storage
}

// Add these structures for CAS validation response
type ServiceResponse struct {
    XMLName     xml.Name    `xml:"serviceResponse"`
    Success     *AuthSuccess `xml:"authenticationSuccess"`
    Failure     *AuthFailure `xml:"authenticationFailure"`
}

type AuthSuccess struct {
    User        string      `xml:"user"`
    Attributes  *Attributes `xml:"attributes"`
}

type AuthFailure struct {
    Code        string      `xml:",attr"`
    Description string      `xml:",chardata"`
}

type Attributes struct {
    Email       string      `xml:"email"`
    // Add more attributes as needed
}

// New creates a new CAS auth middleware plugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
    fmt.Printf("Initializing CAS Auth middleware with CAS server: %s\n", config.CASServerURL)
    if len(config.CASServerURL) == 0 {
        return nil, fmt.Errorf("CASServerURL cannot be empty")
    }

    // Parse session timeout
    timeout, err := time.ParseDuration(config.SessionTimeout)
    if err != nil {
        return nil, fmt.Errorf("invalid SessionTimeout format: %v", err)
    }

    cas := &CASAuth{
        next:     next,
        name:     name,
        config:   config,
        sessions: make(map[string]sessionInfo),
        timeout:  timeout,
    }

    // Start session cleanup goroutine with cas.timeout
    go cleanupSessions(cas.sessions, cas.timeout)
    
    return cas, nil
}

func (c *CASAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    fmt.Printf("Processing request for: %s%s\n", req.Host, req.URL.Path)

    // Check if request matches service pattern
    if (!strings.Contains(req.Host, c.config.ServiceURLPattern)) {
        fmt.Printf("Request does not match service pattern: %s\n", c.config.ServiceURLPattern)
        c.next.ServeHTTP(rw, req)
        return
    }

    // Check for CAS single logout request
    if req.URL.Path == "/cas/logout" {
        c.handleLogout(rw, req)
        return
    }

    // Check for existing valid session
    if cookie, err := req.Cookie("cas_session"); err == nil {
        if session, exists := c.sessions[cookie.Value]; exists && time.Now().Before(session.expiry) {
            fmt.Printf("Valid session found for user: %s\n", session.username)
            c.next.ServeHTTP(rw, req)
            return
        } else if exists {
            fmt.Printf("Session expired for user: %s\n", session.username)
            delete(c.sessions, cookie.Value)
            c.clearSessionCookie(rw)
        }
    }

    // Check for CAS ticket in query params
    ticket := req.URL.Query().Get("ticket")
    if ticket != "" {
        fmt.Printf("Processing CAS ticket: %s\n", ticket)
        // Build service URL with original query parameters (excluding ticket)
        q := req.URL.Query()
        q.Del("ticket")
        serviceURL := fmt.Sprintf("https://%s%s", req.Host, req.URL.Path)
        if len(q) > 0 {
            serviceURL += "?" + q.Encode()
        }

        // Validate ticket with CAS server
        if validated, username := c.validateTicket(ticket, serviceURL); validated {
            fmt.Printf("Ticket validated successfully for user: %s\n", username)
            // Create new session
            sessionID := generateSessionID()
            c.sessions[sessionID] = sessionInfo{
                username: username,
                ticket:   ticket,
                expiry:   time.Now().Add(c.timeout),    // Use c.timeout here
            }

            // Set session cookie
            http.SetCookie(rw, &http.Cookie{
                Name:     "cas_session",
                Value:    sessionID,
                Path:     "/",
                Expires:  time.Now().Add(c.timeout),    // Use c.timeout here
                HttpOnly: true,
                Secure:   true,
                SameSite: http.SameSiteStrictMode,
            })

            // Serve the content directly after successful validation
            c.next.ServeHTTP(rw, req)
            return
        }
    }

    // No valid session or ticket, redirect to CAS login
    serviceURL := fmt.Sprintf("https://%s%s", req.Host, req.URL.Path)
    
    // Create new query parameters without any 'ticket' parameters
    q := req.URL.Query()
    q.Del("ticket")
    if len(q) > 0 {
        serviceURL += "?" + q.Encode()
    }
    
    loginURL := fmt.Sprintf("%s/login?service=%s", 
        c.config.CASServerURL, 
        url.QueryEscape(serviceURL))
    fmt.Printf("Redirecting to CAS login: %s\n", loginURL)
    http.Redirect(rw, req, loginURL, http.StatusFound)
}

func (c *CASAuth) handleLogout(rw http.ResponseWriter, req *http.Request) {
    cookie, err := req.Cookie("cas_session")
    if err == nil {
        delete(c.sessions, cookie.Value)
    }
    c.clearSessionCookie(rw)
    logoutURL := fmt.Sprintf("%s/logout", c.config.CASServerURL)
    http.Redirect(rw, req, logoutURL, http.StatusFound)
}

func (c *CASAuth) clearSessionCookie(rw http.ResponseWriter) {
    http.SetCookie(rw, &http.Cookie{
        Name:     "cas_session",
        Value:    "",
        Path:     "/",
        Expires:  time.Unix(0, 0),
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteStrictMode,
    })
}

func (c *CASAuth) validateTicket(ticket, service string) (bool, string) {
    validateURL := fmt.Sprintf("%s/p3/serviceValidate?ticket=%s&service=%s",
        c.config.CASServerURL,
        url.QueryEscape(ticket),
        url.QueryEscape(service))

    resp, err := http.Get(validateURL)
    if err != nil {
        fmt.Printf("Error validating ticket: %v\n", err)
        return false, ""
    }
    defer resp.Body.Close()

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        fmt.Printf("Error reading validation response: %v\n", err)
        return false, ""
    }

    var serviceResponse ServiceResponse
    if err := xml.Unmarshal(body, &serviceResponse); err != nil {
        fmt.Printf("Error parsing validation response: %v\n", err)
        return false, ""
    }

    if serviceResponse.Success != nil {
        fmt.Printf("Ticket validation successful for user: %s\n", serviceResponse.Success.User)
        return true, serviceResponse.Success.User
    }

    if serviceResponse.Failure != nil {
        fmt.Printf("Ticket validation failed: %s - %s\n", 
            serviceResponse.Failure.Code, 
            serviceResponse.Failure.Description)
    }

    return false, ""
}

func generateSessionID() string {
    // Implement secure session ID generation
    return "example_session_id"
}

// Update cleanupSessions function parameters
func cleanupSessions(sessions map[string]sessionInfo, cleanupInterval time.Duration) {
    ticker := time.NewTicker(cleanupInterval / 2)
    for range ticker.C {
        now := time.Now()
        for id, session := range sessions {
            if now.After(session.expiry) {
                delete(sessions, id)
            }
        }
    }
}