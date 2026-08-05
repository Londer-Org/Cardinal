FROM golang:1.25-alpine AS build
WORKDIR /build
COPY main.go .
RUN go mod init protected-app && \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/protected-app .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/protected-app /usr/local/bin/protected-app
USER nonroot:nonroot
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/protected-app"]
