FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY packages/ui/templ ./packages/ui/templ
RUN go mod download
COPY server ./server
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authkit ./cmd/authkit

FROM alpine:3.22
RUN adduser -D -u 10001 authkit && mkdir /data && chown authkit /data
USER authkit
COPY --from=build /out/authkit /usr/local/bin/authkit
ENV AUTHKIT_STORE=/data/store.json AUTHKIT_ADDR=:4000
EXPOSE 4000
ENTRYPOINT ["/usr/local/bin/authkit"]
