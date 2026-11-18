# syntax=docker/dockerfile:1

# muster-alerts: alerts to muster tasks, as a standalone image.
# The build stage runs on the BUILD platform and cross-compiles for TARGETARCH,
# so `docker buildx build --platform linux/amd64,linux/arm64` emulates nothing.

FROM --platform=$BUILDPLATFORM golang:1.26.11-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
COPY internal/ ./internal/
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build -trimpath \
    -ldflags="-s -w" -o /muster-alerts . && mkdir /state

# distroless/static: CA certificates for muster's HTTPS, no shell, non-root.
# Mount a volume at /state: it holds the outbox and the open episodes.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /muster-alerts /muster-alerts
# Owned by distroless's nonroot user, so a named volume mounted here is writable.
COPY --from=build --chown=65532:65532 /state /state
ENV STATE_DIR=/state
# Inside a container the webhook must listen beyond the container's own
# loopback to be reachable at all, so the image listens on 0.0.0.0:9095. It
# does NOT set ALERTS_ALLOW_NON_LOOPBACK: the plugin refuses that address until
# you pass -e ALERTS_ALLOW_NON_LOOPBACK=1 at run time, as the decision that the
# plain-HTTP webhook is published on the host's loopback
# (docker run -p 127.0.0.1:9095:9095) or a private network only.
ENV ALERTS_LISTEN=0.0.0.0:9095
EXPOSE 9095
VOLUME ["/state"]
ENTRYPOINT ["/muster-alerts"]
