FROM golang:1.26 AS builder
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} go build \
    -ldflags "-s -w \
      -X github.com/Mithweth/csr-approver/internal/version.Version=${VERSION} \
      -X github.com/Mithweth/csr-approver/internal/version.Commit=${COMMIT} \
      -X github.com/Mithweth/csr-approver/internal/version.Date=${BUILD_DATE}" \
    -a -o csr-approver ./cmd

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/csr-approver .
ENTRYPOINT ["/csr-approver"]
