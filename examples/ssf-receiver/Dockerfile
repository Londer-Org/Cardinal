FROM golang:1.25-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/ssf-receiver ./examples/ssf-receiver

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/ssf-receiver /usr/local/bin/ssf-receiver
USER nonroot:nonroot
EXPOSE 8000
ENTRYPOINT ["/usr/local/bin/ssf-receiver"]
