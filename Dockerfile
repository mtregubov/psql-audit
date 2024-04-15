FROM golang:1.22-alpine as builder
WORKDIR /build
COPY . .
RUN go build -o /psql-audit main.go


FROM alpine:3
WORKDIR /app
COPY --from=builder psql-audit /app
ENTRYPOINT ["/app/psql-audit"]