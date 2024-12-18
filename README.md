# Traefik CAS Auth

> [!WARNING]
> This is a work in progress and is probably not ready for production use.

A Traefik middleware plugin that enables seamless authentication with Apereo CAS (Central Authentication Service). This plugin allows you to protect your web applications and APIs behind Traefik with enterprise-grade single sign-on using your existing CAS infrastructure.

## Features

- *Secure Authentication*: Integrates with CAS 3.0 protocol for robust authentication
- *Flexible URL Protection*: Use regex patterns to protect specific domains and paths
- *Session Management*: Configurable session duration with secure cookie handling
- *CSRF Protection*: Built-in CSRF token validation for enhanced security
- *Single Sign-Out*: Support for CAS single logout
- *TLS Support*: Optional TLS certificate verification for secure connections
- *Performance*: In-memory session storage for fast authentication checks
- *Pattern Matching*: Granular control over which URLs require authentication

## Configuration

The middleware requires minimal configuration. Only the CAS server URL is required:

| Option | Type | Required | Default | Description |
|--------|------|----------|---------|-------------|
| `casServerURL` | string | Yes | - | The base URL of your CAS server |
| `rule` | string | No | `"PathPrefix(`/`)"` | Traefik rule to determine which requests require authentication |
| `exceptionRule` | string | No | - | Traefik rule to determine which requests to exclude from authentication |
| `sessionTimeout` | string | No | "24h" | Session duration (e.g., "24h", "30m") |
| `insecureSkipVerify` | bool | No | false | Skip TLS certificate verification |

### Rules

The `rule` field accepts Traefik rule syntax to determine which requests require CAS authentication. Any request not matching the rule will be passed through without authentication.

The `exceptionRule` field accepts the same Traefik rule syntax but defines which requests should be explicitly excluded from authentication. Exception rules have higher priority than normal rules.

Common exception rule examples:
- `"Path(`/public`)"` - Allow public access to /public path
- `"PathPrefix(`/assets/`) || PathPrefix(`/images/`)"` - Allow public access to static assets
- `"Host(`public.example.com`)"` - Allow public access to entire domain
- `"Headers(`X-Public-Access`, `true`)"` - Allow public access based on headers

[See Traefik documentation for more rule syntax](https://doc.traefik.io/traefik/routing/routers/#rule)

### Minimal Configuration Example

The simplest configuration only requires the CAS server URL:

## Usage

To use this plugin, you would configure it in your Traefik static configuration as follows:

```yaml
experimental:
    plugins:
        cas-auth:
            moduleName: "github.com/xezpeleta/traefik-cas-auth"
            version: "v0.0.16"
```

Then, you would configure the plugin in your dynamic configuration as follows:

```yaml
http:
    middlewares:
        cas-auth:
            plugin:
                cas-auth:
                    casServerUrl: "https://cas.example.com"
                    rule: "PathPrefix(`/`)"
                    sessionTimeout: 24h
    routers:
        my-service:
            rule: "Host(`*.example.com`)"
            middlewares:
                - cas-auth
            service:
                name: "my-service"
```

### Docker Compose Example

Here's a complete example using docker-compose to protect the Traefik whoami service with CAS authentication:

```yaml
version: '3'

services:
  traefik:
    image: traefik:v2.4
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.myresolver.acme.tlschallenge=true"
      - "--certificatesresolvers.myresolver.acme.email=your-email@example.com"
      - "--certificatesresolvers.myresolver.acme.storage=/letsencrypt/acme.json"
      - "--experimental.plugins.cas-auth.moduleName=github.com/xezpeleta/traefik-cas-auth"
      - "--experimental.plugins.cas-auth.version=v0.0.16"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock"
      - "./letsencrypt:/letsencrypt"

  whoami:
    image: containous/whoami
    labels:
      - "traefik.http.routers.whoami.rule=Host(`whoami.example.com`)"
      - "traefik.http.routers.whoami.entrypoints=websecure"
      # Enable CAS Auth middleware
      - "traefik.http.routers.whoami.middlewares=cas-auth"
      # CAS Auth middleware configuration
      - "traefik.http.middlewares.cas-auth.plugin.cas-auth.rule=PathPrefix(`/`)"
```

### Mixed configuration with docker-compose labels and dynamic configuration file

The following example shows how to mix the configuration of the middleware using docker-compose labels and a dynamic configuration file:

- The CAS middleware is configured using Docker Compose labels.
- A protected service (whoami) is configured using Docker Compose labels.
- A protected site (protectedsite.example.com) is configured using a dynamic configuration file.

The `docker-compose.yml` file uses both Docker Compose labels and a dynamic configuration file (`dynamic.yml`):

```yaml
# docker-compose.yml

services:
  traefik:
    image: traefik:v2.4
    command:
      - "--api.insecure=true"
      - "--providers.docker=true"
      - "--providers.file.filename=/etc/traefik/dynamic.yml"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--certificatesresolvers.myresolver.acme.tlschallenge=true"
      - "--certificatesresolvers.myresolver.acme.email=your-email@example.com"
      - "--certificatesresolvers.myresolver.acme.storage=/letsencrypt/acme.json"
      # Load CAS Auth middleware plugin
      - "--experimental.plugins.cas-auth.moduleName=github.com/xezpeleta/traefik-cas-auth"
      # Specify the version of the plugin
      - "--experimental.plugins.cas-auth.version=v0.0.16"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock"
      - "./dynamic.yml:/etc/traefik/dynamic.yml"
      - "./letsencrypt:/letsencrypt"

  whoami:
    image: containous/whoami
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.whoami.rule=Host(`whoami.example.com`)"
      - "traefik.http.routers.whoami.entrypoints=websecure"
      - "traefik.http.routers.whoami.tls.certresolver=myresolver"
      # Enable CAS Auth middleware
      - "traefik.http.routers.whoami.middlewares=cas-auth"
      # CAS Auth middleware configuration
      - "traefik.http.middlewares.cas-auth.plugin.cas-auth.rule=PathPrefix(`/`)"
```

The dynamic configuration file (`dynamic.yml`) configures the protected site `protectedsite.example.com` using the CAS middleware:

```yaml
# dynamic.yml

http:
  middlewares:
    cas-auth:
      plugin:
        cas-auth:
          casServerUrl: "https://cas.example.com"
          rule: "PathPrefix(`/`)"
          sessionTimeout: 24h

  routers:
    protected-site:
      rule: "Host(`protectedsite.example.com`)"
      service: protected-site
      middlewares:
        - cas-auth
      tls:
        certResolver: myresolver

  services:
    protected-site:
      loadBalancer:
        servers:
          - url: "http://internal-protected-site:8080"
```

## Todo

### Security

- [ ] Session storage in Redis for better performance and scalability.
- [ ] Rate limiting login attempts
- [ ] Protection against session fixation attacks
- [ ] Configurable cookie attributes (secure, httpOnly, sameSite)

### Features

- [x] Support whitelist path patterns for unprotected paths
- [ ] Currently only CAS 3.0 is supported. Support for CAS 1.0 and 2.0.
- [ ] Improve error responses to clients