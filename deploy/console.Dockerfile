FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
COPY packages/ui/templ ./packages/ui/templ
RUN go mod download
COPY server ./server
COPY apps/console ./apps/console
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/console ./apps/console

FROM alpine:3.22
RUN adduser -D -u 10001 console && mkdir /data && chown console /data
USER console
COPY --from=build /out/console /usr/local/bin/console
ENV CONSOLE_DATA=/data CONSOLE_ADDR=:4500
EXPOSE 4500
ENTRYPOINT ["/usr/local/bin/console"]
