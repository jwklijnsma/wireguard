# syntax=docker/dockerfile:1@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# WG2FA server: WireGuard + 2FA + web GUI
FROM --platform=$BUILDPLATFORM golang:1.27-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
ARG TARGETOS TARGETARCH VERSION=dev
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download || true
COPY . .
RUN go mod tidy \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o /out/wg2fa-server ./cmd/wg2fa-server \
 && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags "-s -w" -o /out/wireguard-go golang.zx2c4.com/wireguard

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
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
