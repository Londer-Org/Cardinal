FROM golang:1.25-alpine AS build
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/oidc-client .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/oidc-client /usr/local/bin/oidc-client
USER nonroot:nonroot
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/oidc-client"]
