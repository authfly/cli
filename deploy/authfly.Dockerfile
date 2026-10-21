FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY packages/ui/templ ./packages/ui/templ
RUN go mod download
COPY server ./server
COPY cmd ./cmd
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/authfly ./cmd/authfly

FROM alpine:3.22
RUN adduser -D -u 10001 authfly && mkdir /data && chown authfly /data
USER authfly
COPY --from=build /out/authfly /usr/local/bin/authfly
ENV AUTHFLY_STORE=/data/store.json AUTHFLY_ADDR=:4000
EXPOSE 4000
ENTRYPOINT ["/usr/local/bin/authfly"]
