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


## Todo

- [ ] Proper session ID generation and secure storage
- [ ] Ticket validation logic for different CAS protocols
- [ ] Enhance security (CSRF, etc)# traefik-cas-auth
