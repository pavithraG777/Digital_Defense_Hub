FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ddh-api ./cmd/api

FROM alpine:3.22

RUN adduser -D -H -s /sbin/nologin ddh
WORKDIR /app
COPY --from=build /out/ddh-api /app/ddh-api
RUN chown ddh:ddh /app/ddh-api
USER ddh

EXPOSE 10000
ENTRYPOINT ["/app/ddh-api"]