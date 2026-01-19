FROM alpine:3.18.2
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY vulnx /usr/local/bin/

ENTRYPOINT ["vulnx"]
