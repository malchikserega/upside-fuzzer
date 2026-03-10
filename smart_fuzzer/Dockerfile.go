FROM golang:1.22-alpine AS builder
WORKDIR /src
COPY go/ ./go/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    cd go && go build -o /out/smart-fuzzer-go .

FROM alpine:3.19
WORKDIR /fuzzer
COPY --from=builder /out/smart-fuzzer-go /usr/local/bin/smart-fuzzer-go
ENTRYPOINT ["/usr/local/bin/smart-fuzzer-go"]
