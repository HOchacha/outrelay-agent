# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 BoanLab @ Dankook University

FROM golang:1.25-alpine AS build

# git is needed for the direct module fetch driven by GOPRIVATE below.
RUN apk add --no-cache git

# VERSION is stamped into main.Version of the binary at link time.
# Override with `docker build --build-arg VERSION=v1.2.3 ...`; the
# Makefile passes $(TAG) here on `make build-image`.
ARG VERSION=dev
ENV VERSION=$VERSION

# boanlab/* modules are fetched directly from GitHub rather than the
# Go module proxy. The proxy treats published versions as immutable;
# any in-place tag update needs a direct fetch to surface.
ENV GOPRIVATE=github.com/boanlab/*

WORKDIR /src

COPY . .

RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.Version=${VERSION}" \
      -o /out/outrelay-agent ./cmd/outrelay-agent

FROM gcr.io/distroless/static:nonroot

COPY --from=build /out/outrelay-agent /usr/local/bin/

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/outrelay-agent"]
