# Release image from a prebuilt, checksum-listed static binary (tools/release.sh). One file for both images:
#   docker build --build-arg BIN=authfly -f deploy/release.Dockerfile dist/<version>
FROM alpine:3.22
ARG BIN=authfly
RUN adduser -D -u 10001 app && mkdir -p /data && chown app /data
COPY ${BIN}-linux-amd64 /usr/local/bin/app
USER 10001
ENV AUTHFLY_STORE=/data/store.json CONSOLE_DATA=/data
ENTRYPOINT ["/usr/local/bin/app"]
