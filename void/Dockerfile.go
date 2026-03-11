FROM golang:1.22-alpine AS builder
WORKDIR /src

# Copy dependency files first for better layer caching.
# Docker will reuse this layer as long as go.mod/go.sum don't change.
COPY go/go.mod go/go.sum ./go/
RUN cd go && go mod download

# Now copy the full source and build.
COPY go/ ./go/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    cd go && go build -ldflags="-s -w" -o /out/void .

FROM alpine:3.19
WORKDIR /fuzzer
COPY --from=builder /out/void /usr/local/bin/void
ENTRYPOINT ["/usr/local/bin/void"]
