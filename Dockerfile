FROM golang:1.23-alpine AS builder

RUN apk add --no-cache gcc musl-dev git

WORKDIR /app

# Copy everything including vendor directory
COPY . .

# Build with vendor mode (no network required)
RUN CGO_ENABLED=1 go build -mod=vendor -o /goat-relayer ./cmd

FROM alpine:3.18

WORKDIR /app

RUN mkdir -p /app/db

COPY --from=builder /goat-relayer /app/goat-relayer

EXPOSE 8080 50051 4001

CMD ["/app/goat-relayer"]
