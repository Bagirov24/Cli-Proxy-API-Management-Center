FROM caddy:2.11.7-alpine
COPY integrations/api-gateway/Caddyfile /etc/caddy/Caddyfile
# Reject invalid configuration during image build before the old deployment is replaced.
RUN caddy adapt --config /etc/caddy/Caddyfile --adapter caddyfile --validate >/dev/null
EXPOSE 8080
