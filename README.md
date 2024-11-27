# Traefik CAS Auth

This is a simple [Traefik](https://traefik.io/) middleware that allows you to authenticate users using a [Apereo CAS](https://apereo.github.io/cas) server.

## Usage

To use this plugin, you would configure it in your Traefik static configuration as follows:

```yaml
experimental:
    plugins:
        cas-auth:
            moduleName: "github.com/xezpeleta/traefik-cas-auth"
            version: "v0.0.1"
```

Then, you would configure the plugin in your dynamic configuration as follows:

```yaml
http:
    middlewares:
        cas-auth:
            plugin:
                cas-auth:
                    casServerUrl: "https://cas.example.com"
                    serviceUrlPattern: "https://*.example.com/*"
                    sessionTimeout: 24h
    routers:
        my-service:
            rule: "Host(`*.example.com`)"
            middlewares:
                - cas-auth
            service:
                name: "my-service"
```

## Docker Compose Example

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
      - "--experimental.plugins.cas-auth.version=v0.0.1"
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
      - "traefik.http.routers.whoami.tls.certresolver=myresolver"
      - "traefik.http.middlewares.cas-auth.plugin.cas-auth.casServerUrl=https://cas.example.com"
      - "traefik.http.middlewares.cas-auth.plugin.cas-auth.serviceUrlPattern=https://*.example.com/*"
      - "traefik.http.middlewares.cas-auth.plugin.cas-auth.sessionTimeout=24h"
      - "traefik.http.routers.whoami.middlewares=cas-auth"
```

## Todo

- [ ] Proper session ID generation and secure storage
- [ ] Ticket validation logic for different CAS protocols
- [ ] Enhance security (CSRF, etc)# traefik-cas-auth
