FROM alpine:3.21 AS plugin-download

RUN apk add --no-cache ca-certificates curl unzip

# Pinned upstream release; SHA-256 is published by GitHub Releases.
ARG CPA_KEY_POLICY_VERSION=0.5.1
ARG CPA_KEY_POLICY_SHA256=bae8d56b57ffa8b3e9c7373750881d496c87309dd739e225a75a9dd3b3bc5a8d

RUN set -eu; \
    asset="cpa-key-policy_${CPA_KEY_POLICY_VERSION}_linux_amd64.zip"; \
    curl --fail --location --retry 3 --silent --show-error \
      "https://github.com/origin652/cpa-plugin-key-policy/releases/download/v${CPA_KEY_POLICY_VERSION}/${asset}" \
      --output /tmp/plugin.zip; \
    printf '%s  %s\n' "${CPA_KEY_POLICY_SHA256}" /tmp/plugin.zip | sha256sum -c -; \
    mkdir -p /tmp/plugin /out; \
    unzip -q /tmp/plugin.zip -d /tmp/plugin; \
    count="$(find /tmp/plugin -type f -name '*.so' | wc -l)"; \
    test "$count" -eq 1; \
    library="$(find /tmp/plugin -type f -name '*.so' -print -quit)"; \
    cp "$library" /out/cpa-key-policy.so

# The original CLIProxyAPI image remains the base. Never bake auth/config secrets into images.
FROM eceasy/cli-proxy-api:v8.0.23

# Intentionally outside /data: a Railway volume mounted at /data hides image files there.
COPY --from=plugin-download /out/cpa-key-policy.so /CLIProxyAPI/plugins/linux/amd64/cpa-key-policy.so
COPY integrations/cpa-key-policy/THIRD_PARTY_LICENSE.txt /usr/share/licenses/cpa-key-policy/LICENSE
