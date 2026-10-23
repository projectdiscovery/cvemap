FROM alpine:latest

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="Modern CLI for exploring vulnerability data with powerful search, filtering, and analysis capabilities"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="vulnx"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/vulnx"

RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/vulnx /usr/local/bin/

ENTRYPOINT ["vulnx"]
