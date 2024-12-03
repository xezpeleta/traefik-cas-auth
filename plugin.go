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
    "github.com/traefik/traefik/v2/pkg/rules"
)

// Config holds the plugin configuration
type Config struct {
    CASServerURL string `json:"casServerURL,omitempty"`
    Rule string `json:"rule,omitempty"`
    SessionTimeout string `json:"sessionTimeout,omitempty"`
    InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
    ExceptionRule string `json:"exceptionRule,omitempty"`
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
    return &Config{
        SessionTimeout: "24h",  // Default timeout as string
        InsecureSkipVerify: false,  // Default to secure verification
        Rule: "PathPrefix(`/`)",  // By default, protect everything
        ExceptionRule: "",  // Empty by default
    }
}

func (c *Config) ValidateConfig() error {
    // Only CASServerURL is required
    if len(c.CASServerURL) == 0 {
        return fmt.Errorf("CASServerURL cannot be empty")
    }

    // Only validate exception rule if provided
    if c.ExceptionRule != "" {
        _, err := rules.NewRule(c.ExceptionRule)
        if err != nil {
            return fmt.Errorf("invalid exception rule syntax: %v", err)
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
    ticketMap map[string]string // maps CAS tickets to session IDs
    matcher  *rules.Rule
    exceptionMatcher *rules.Rule
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

type LogoutRequest struct {
    XMLName   xml.Name `xml:"LogoutRequest"`
    SessionID string   `xml:"SessionIdentifier"`
}

func validateServiceURL(allowedHosts []string, pathPatterns []string, excludedPaths []string, serviceURL string) bool {
    parsedURL, err := url.Parse(serviceURL)
    if err != nil {
        return false
    }

    // Security: Always validate URL format first
    if (!parsedURL.IsAbs() || parsedURL.Scheme != "https") {
        return false
    }

    // Security: Always validate host before checking paths
    hostMatched := false
    for _, allowedHost := range allowedHosts {
        if strings.HasPrefix(allowedHost, "*.") {
            suffix := allowedHost[1:] 
            if strings.HasSuffix(parsedURL.Host, suffix) {
                hostMatched = true
                break
            }
        } else if parsedURL.Host == allowedHost {
            hostMatched = true
            break
        }
    }
    if !hostMatched {
        return false
    }

    // Security: Check excluded paths only after host is validated
    for _, pattern := range excludedPaths {
        if regexp, err := regexp.Compile(pattern); err == nil {
            if regexp.MatchString(parsedURL.Path) {
                return true // Allow access without authentication
            }
        }
    }

    // Check path patterns last
    for _, pattern := range pathPatterns {
        if regexp, err := regexp.Compile(pattern); err == nil {
            if regexp.MatchString(parsedURL.Path) {
                return true
            }
        }
    }

    return len(pathPatterns) == 0
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

    if err := config.ValidateConfig(); err != nil {
        return nil, err
    }

    // Always create the rule matcher with default rule if not provided
    if config.Rule == "" {
        config.Rule = "PathPrefix(`/`)"
    }
    matcher, err := rules.NewRule(config.Rule)
    if err != nil {
        return nil, fmt.Errorf("failed to create rule matcher: %v", err)
    }

    // Create the exception rule matcher if configured
    var exceptionMatcher *rules.Rule
    if config.ExceptionRule != "" {
        var err error
        exceptionMatcher, err = rules.NewRule(config.ExceptionRule)
        if err != nil {
            return nil, fmt.Errorf("failed to create exception rule matcher: %v", err)
        }
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
        ticketMap: make(map[string]string), // Initialize ticketMap
        matcher:  matcher,
        exceptionMatcher: exceptionMatcher,
    }

    // Start session cleanup goroutine with the timeout value
    go cas.cleanupSessions()
    
    return cas, nil
}

func (c *CASAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
    fmt.Printf("Processing request for: %s%s\n", req.Host, req.URL.Path)

    // Check exception rule first if configured
    if c.exceptionMatcher != nil && c.exceptionMatcher.Match(req) {
        fmt.Printf("Request matches exception rule, bypassing authentication\n")
        c.next.ServeHTTP(rw, req)
        return
    }

    // Check if the request matches the protection rule
    if !c.matcher.Match(req) {
        // Pass through without authentication
        c.next.ServeHTTP(rw, req)
        return
    }

    // Check for excluded paths first
    serviceURL := fmt.Sprintf("https://%s%s", req.Host, req.URL.Path)
    for _, pattern := range c.config.ExcludedPaths {
        if regexp, err := regexp.Compile(pattern); err == nil {
            if regexp.MatchString(req.URL.Path) {
                fmt.Printf("Path excluded from authentication: %s\n", req.URL.Path)
                c.next.ServeHTTP(rw, req)
                return
            }
        }
    }

    // Add SLO handler right after the first few lines
    if req.Method == "POST" && req.URL.Path == "/cas/logout" {
        c.handleSLO(rw, req)
        return
    }

    // First declaration of serviceURL
    serviceURL = fmt.Sprintf("https://%s%s", req.Host, req.URL.Path)
    if !validateServiceURL(c.config.AllowedHosts, c.config.PathPatterns, c.config.ExcludedPaths, serviceURL) {
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
            // Store ticket mapping when validation is successful
            c.ticketMap[ticket] = sessionID

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
    if !validateServiceURL(c.config.AllowedHosts, c.config.PathPatterns, c.config.ExcludedPaths, service) {
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
        // Store ticket mapping when validation is successful
        c.ticketMap[ticket] = "" // Will be updated when session is created
        return true, serviceResponse.Success.User
    }

    if serviceResponse.Failure != nil {
        fmt.Printf("Ticket validation failed: %s - %s\n", 
            serviceResponse.Failure.Code, 
            serviceResponse.Failure.Description)
    }

    return false, ""
}

func (c *CASAuth) handleSLO(rw http.ResponseWriter, req *http.Request) {
    fmt.Printf("Received SLO request from: %s\n", req.RemoteAddr)
    
    body, err := ioutil.ReadAll(req.Body)
    if err != nil {
        fmt.Printf("Error reading SLO request body: %v\n", err)
        http.Error(rw, "Error reading request body", http.StatusBadRequest)
        return
    }
    
    fmt.Printf("SLO request body: %s\n", string(body))

    var logoutReq LogoutRequest
    if err := xml.Unmarshal(body, &logoutReq); err != nil {
        fmt.Printf("Error parsing SLO request XML: %v\n", err)
        http.Error(rw, "Error parsing logout request", http.StatusBadRequest)
        return
    }

    fmt.Printf("Parsed SLO request - SessionID: %s\n", logoutReq.SessionID)

    // Get session ID from ticket
    if sessionID, exists := c.ticketMap[logoutReq.SessionID]; exists {
        fmt.Printf("Found matching session ID: %s for ticket: %s\n", sessionID, logoutReq.SessionID)
        // Delete both session and ticket mapping
        delete(c.sessions, sessionID)
        delete(c.ticketMap, logoutReq.SessionID)
        fmt.Printf("Successfully removed session and ticket mapping\n")
    } else {
        fmt.Printf("No session found for ticket: %s\n", logoutReq.SessionID)
    }

    rw.WriteHeader(http.StatusOK)
    fmt.Printf("SLO request completed successfully\n")
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
                // Also cleanup ticket mapping
                if session.ticket != "" {
                    delete(c.ticketMap, session.ticket)
                }
                delete(c.sessions, id)
            }
        }
    }
}