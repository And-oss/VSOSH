# syntax=docker/dockerfile:1

FROM golang:1.23 AS builder
WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

ENV CGO_ENABLED=0
RUN go build -o /out/k8s-audit ./cmd/k8s-audit

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /out/k8s-audit /k8s-audit
USER nonroot:nonroot
ENTRYPOINT ["/k8s-audit"]
