# Base
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache build-base
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build ./cmd/cvemap

# Release
FROM alpine:3.18.2
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /app/cvemap /usr/local/bin/

ENTRYPOINT ["cvemap"]
