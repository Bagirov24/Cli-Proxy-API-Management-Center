# Isolated RU/EN build. Keep Dockerfile as the original upstream fallback.
FROM node:20-bookworm AS localized-web
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates && rm -rf /var/lib/apt/lists/*
ARG CPA_KEY_POLICY_COMMIT=c041a48bb5e3c3ab44b24d05fa2a27c77c55caf5
RUN git clone https://github.com/origin652/cpa-plugin-key-policy.git /upstream \
    && cd /upstream \
    && git checkout --detach "$CPA_KEY_POLICY_COMMIT" \
    && test "$(git rev-parse HEAD)" = "$CPA_KEY_POLICY_COMMIT"
COPY integrations/cpa-key-policy/ru-overlay /overlay
RUN node /overlay/apply-ru.mjs /upstream
RUN cd /upstream/web \
    && npm ci --no-audit --no-fund \
    && npm test \
    && VITE_HOSTED=1 npm run build \
    && cp dist/index.html ../internal/plugin/web/dist/index.html

FROM golang:1.25-bookworm AS localized-plugin
WORKDIR /src
COPY --from=localized-web /upstream /src
RUN go test ./...
RUN mkdir -p /out \
    && CGO_ENABLED=1 GOOS=linux GOARCH=amd64 go build \
       -trimpath -buildvcs=false -tags cshared -buildmode=c-shared \
       -ldflags="-s -w" \
       -o /out/cpa-key-policy.so ./cmd/cpa-key-policy

FROM eceasy/cli-proxy-api:v8.0.23
COPY --from=localized-plugin /out/cpa-key-policy.so /CLIProxyAPI/plugins/linux/amd64/cpa-key-policy.so
COPY integrations/cpa-key-policy/THIRD_PARTY_LICENSE.txt /usr/share/licenses/cpa-key-policy/LICENSE
