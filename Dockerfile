FROM golang:alpine AS builder

RUN apk add --no-cache ca-certificates && rm -rf /var/cache/apk/*

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o eap-server main.go && go clean -cache -modcache

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/eap-server /eap-server

EXPOSE 8080
ENTRYPOINT ["/eap-server"]
