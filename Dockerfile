FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/hnsdns ./cmd/hnsdns \
 && mkdir -p /out/data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/hnsdns /hnsdns
COPY --from=build --chown=65532:65532 /out/data /data
VOLUME /data
EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/hnsdns"]
CMD ["-listen=0.0.0.0:53", "-tld-cache=/data/tlds.txt"]
