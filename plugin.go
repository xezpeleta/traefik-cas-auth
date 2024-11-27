// Package traefik_cas_auth implements a Traefik middleware plugin for CAS authentication
package traefik_cas_auth

import (
    "context"
    "crypto/tls"
    "fmt"
    "net/http"
    "net/url"
    "strings"
    "time"
    "encoding/xml"
    "io/ioutil"
    "crypto/rand"
    "encoding/hex"
    "path/filepath"
    "regexp"
)

// Config holds the plugin configuration
type Config struct {
    CASServerURL string `json:"casServerURL,omitempty"`
    ServiceURLPatterns []string `json:"serviceURLPatterns,omitempty"`
    SessionTimeout string `json:"sessionTimeout,omitempty"`
    InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
    return &Config{
        SessionTimeout: "24h",  // Default timeout as string
        InsecureSkipVerify: false,  // Default to secure verification
    }
}

func (c *Config) ValidateServicePattern() error {
    if len(c.ServiceURLPatterns) == 0 {
        return fmt.Errorf("at least one service URL pattern must be specified")
    }

    // Validate all patterns are valid regex
    for _, pattern := range c.ServiceURLPatterns {
        if _, err := regexp.Compile(pattern); err != nil {
            return fmt.Errorf("invalid regex pattern '%s': %v", pattern, err)
        }
    }

    return nil
}

type CASAuth struct {
    next     http.Handler
    name     string
    config   *Config
    sessions map[string]sessionInfo
    timeout  time.Duration    // Add this field
    client   *http.Client
}

type sessionInfo struct {
    username string
    expiry   time.Time
    ticket   string    // Add ticket storage
    csrfToken string    // Add CSRF token
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

func validateServiceURL(patterns []string, serviceURL string) bool {
    parsedURL, err := url.Parse(serviceURL)
    if err != nil {
        return false
    }

    // Check if URL is absolute and has https scheme
    if !parsedURL.IsAbs() || parsedURL.Scheme != "https" {
        return false
    }

    testString := parsedURL.Host + parsedURL.Path

    // Try to match any of the patterns
    for _, pattern := range patterns {
        if regexp, err := regexp.Compile(pattern); err == nil {
            if regexp.MatchString(testString) {
                return true
            }
        }
    }

    return false
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

    if err := config.ValidateServicePattern(); err != nil {
        return nil, err
    }

    // Create custom HTTP client with TLS configuration
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: config.InsecureSkipVerify,
        },
    }
    client := &http.Client{Transport: tr}

    cas := &CASAuth{
        next:     next,
        name:     name,
        config:   config,
        sessions: make(map[string]sessionInfo),
        timeout:  timeout,
        client:   client,
    }

    // Start session cleanup goroutine with the timeout value
    go cas.cleanupSessions()
    
    return cas, nil
}

func (c *CASAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    fmt.Printf("Processing request for: %s%s\n", req.Host, req.URL.Path)

    // First declaration of serviceURL
    serviceURL := fmt.Sprintf("https://%s%s", req.Host, req.URL.Path)
    if !validateServiceURL(c.config.ServiceURLPatterns, serviceURL) {
        fmt.Printf("Invalid service URL: %s\n", serviceURL)
        http.Error(rw, "Invalid service URL", http.StatusBadRequest)
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
            // Validate CSRF token for POST requests
            if req.Method == "POST" {
                csrfToken := req.Header.Get("X-CSRF-Token")
                if csrfToken == "" || csrfToken != session.csrfToken {
                    http.Error(rw, "Invalid CSRF token", http.StatusForbidden)
                    return
                }
            }
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
    csrfToken := req.URL.Query().Get("csrf")
    if ticket != "" {
        // Verify CSRF token if present in session
        if cookie, err := req.Cookie("cas_session"); err == nil {
            if session, exists := c.sessions[cookie.Value]; exists {
                if csrfToken == "" || csrfToken != session.csrfToken {
                    http.Error(rw, "Invalid CSRF token", http.StatusForbidden)
                    return
                }
            }
        }
        
        fmt.Printf("Processing CAS ticket: %s\n", ticket)
        // Build service URL with original query parameters (excluding ticket)
        q := req.URL.Query()
        q.Del("ticket")
        serviceURL = fmt.Sprintf("https://%s%s", req.Host, req.URL.Path)
        if len(q) > 0 {
            serviceURL += "?" + q.Encode()
        }

        // Validate ticket with CAS server
        if validated, username := c.validateTicket(ticket, serviceURL); validated {
            fmt.Printf("Ticket validated successfully for user: %s\n", username)
            // Create new session with CSRF token
            sessionID := generateSessionID()
            csrfToken := generateCSRFToken()
            c.sessions[sessionID] = sessionInfo{
                username: username,
                ticket:   ticket,
                expiry:   time.Now().Add(c.timeout),    // Use c.timeout here
                csrfToken: csrfToken,
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

    // Use = instead of := for serviceURL reassignment
    serviceURL = fmt.Sprintf("https://%s%s", req.Host, req.URL.Path)
    
    // Generate CSRF token for new session
    sessionID := generateSessionID()
    // Use = instead of := for csrfToken reassignment
    csrfToken = generateCSRFToken()
    c.sessions[sessionID] = sessionInfo{
        expiry: time.Now().Add(c.timeout),
        csrfToken: csrfToken,
    }
    
    // Set session cookie before redirect
    http.SetCookie(rw, &http.Cookie{
        Name:     "cas_session",
        Value:    sessionID,
        Path:     "/",
        Expires:  time.Now().Add(c.timeout),
        HttpOnly: true,
        Secure:   true,
        SameSite: http.SameSiteStrictMode,
    })
    
    // Create new query parameters without any 'ticket' parameters
    q := req.URL.Query()
    q.Del("ticket")
    q.Set("csrf", csrfToken)
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
    if !validateServiceURL(c.config.ServiceURLPatterns, service) {
        fmt.Printf("Invalid service URL during ticket validation: %s\n", service)
        return false, ""
    }

    validateURL := fmt.Sprintf("%s/p3/serviceValidate?ticket=%s&service=%s",
        c.config.CASServerURL,
        url.QueryEscape(ticket),
        url.QueryEscape(service))

    resp, err := c.client.Get(validateURL)  // Use custom client instead of http.Get
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
    // Generate 32 random bytes (256 bits)
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        // Fall back to timestamp if random generation fails
        return fmt.Sprintf("%d", time.Now().UnixNano())
    }
    return hex.EncodeToString(bytes)
}

// Add new function to generate CSRF token
func generateCSRFToken() string {
    bytes := make([]byte, 32)
    if _, err := rand.Read(bytes); err != nil {
        return fmt.Sprintf("%d", time.Now().UnixNano())
    }
    return hex.EncodeToString(bytes)
}

// Move cleanupSessions to be a method of CASAuth
func (c *CASAuth) cleanupSessions() {
    ticker := time.NewTicker(c.timeout / 2)
    for range ticker.C {
        now := time.Now()
        for id, session := range c.sessions {
            if now.After(session.expiry) {
                delete(c.sessions, id)
            }
        }
    }
}