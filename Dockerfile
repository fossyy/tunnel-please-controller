FROM golang:1.25.7-alpine AS go_builder

ARG VERSION=dev
ARG BUILD_DATE=unknown
ARG COMMIT=unknown

RUN apk update && apk upgrade && \
    apk add --no-cache ca-certificates tzdata git && \
    update-ca-certificates

WORKDIR /src

COPY go.mod go.sum ./

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download && go mod verify

COPY . .

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-w -s" \
    -o /app/tunnel-please-controller \
    .

RUN adduser -D -u 10001 -g '' appuser && \
    mkdir -p /app/certs/ssh /app/certs/tls && \
    chown -R appuser:appuser /app

FROM scratch

ARG VERSION=dev
ARG BUILD_DATE=unknown
ARG COMMIT=unknown

COPY --from=go_builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=go_builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=go_builder /etc/passwd /etc/passwd
COPY --from=go_builder /etc/group /etc/group
COPY --from=go_builder --chown=appuser:appuser /app /app

WORKDIR /app

USER appuser

ENV TZ=Asia/Jakarta

LABEL org.opencontainers.image.title="Tunnel Please Controller" \
      org.opencontainers.image.description="Orchestrator for Tunnel Please" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${BUILD_DATE}"

ENTRYPOINT ["/app/tunnel-please-controller"]
