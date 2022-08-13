FROM golang:alpine AS builder
WORKDIR /src

COPY go.mod .
COPY go.sum .
RUN go mod download

RUN apk --update --upgrade --no-cache add git gcc g++ ca-certificates && update-ca-certificates

COPY . .

ENTRYPOINT ["go", "run", "server.go", "main.go"]
