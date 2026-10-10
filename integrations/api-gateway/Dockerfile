# REVIEW BRANCH ONLY. This is not a production deployment.
# Pin the Caddy release and the complete plugin source commit.
FROM caddy:2.11.7-builder-alpine AS builder
WORKDIR /src
COPY integrations/api-gateway/guard /src/guard
RUN cd /src/guard/policy && GO111MODULE=off go test ./...
RUN xcaddy build v2.11.7 \
    --with github.com/mholt/caddy-ratelimit@5625512f24f6f59d6f64fb3aafe5eecff0b286db \
    --with github.com/Bagirov24/Cli-Proxy-API-Management-Center/integrations/api-gateway/guard=./guard \
    --output /usr/bin/caddy

FROM caddy:2.11.7-alpine
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY integrations/api-gateway/Caddyfile /etc/caddy/Caddyfile

# Fail during build if the extra module or Caddyfile syntax is invalid.
RUN caddy list-modules | grep -Fx http.handlers.rate_limit \
    && caddy list-modules | grep -Fx http.handlers.cpa_key_guard \
    && caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile --validate >/dev/null
EXPOSE 8080
