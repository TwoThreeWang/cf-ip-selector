# syntax=docker/dockerfile:1.6
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
ARG GOPROXY=https://proxy.golang.org,direct
ENV GOPROXY=$GOPROXY
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o cf-ip-selector

FROM alpine:3.19 AS certs
RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories && apk update && apk add --no-cache ca-certificates

FROM scratch
WORKDIR /app
COPY --from=builder /app/cf-ip-selector /app/cf-ip-selector
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENTRYPOINT ["/app/cf-ip-selector"]
