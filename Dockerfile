FROM golang:alpine AS builder
WORKDIR /src

ENV USER=vpn-webauth
ENV UID=10001 

COPY go.mod .
COPY go.sum .
RUN go mod download

RUN apk --update --upgrade --no-cache add git gcc g++ ca-certificates && update-ca-certificates
RUN adduser \    
    --disabled-password \    
    --gecos "" \    
    --home "/nonexistent" \    
    --shell "/sbin/nologin" \    
    --no-create-home \    
    --uid "${UID}" \    
    "${USER}"

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o /out/vpn-webauth .


FROM alpine AS bin
COPY --from=builder /out/vpn-webauth /
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /src/templates /templates/

USER vpn-webauth
ENTRYPOINT ["/vpn-webauth"]
