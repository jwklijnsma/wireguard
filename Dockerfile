# syntax=docker/dockerfile:1
# WG2FA server: WireGuard + 2FA + web GUI
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN go mod tidy \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/wg2fa-server ./cmd/wg2fa-server \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/wireguard-go golang.zx2c4.com/wireguard

FROM alpine:3.24
RUN apk upgrade --no-cache \
 && apk add --no-cache wireguard-tools-wg iproute2-minimal iptables ca-certificates-bundle tzdata
COPY --from=build /out/wg2fa-server /out/wireguard-go /usr/local/bin/
COPY packaging/downloads/ /usr/share/wg2fa/downloads/
COPY packaging/docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENV WG2FA_DATA=/data WG2FA_LISTEN=:8080 WG2FA_WG_PORT=51820 WG2FA_SUBNET=10.8.0.0/24
VOLUME /data
EXPOSE 8080/tcp 51820/udp
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8080/healthz || exit 1
ENTRYPOINT ["/entrypoint.sh"]
