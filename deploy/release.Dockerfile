# Release image from prebuilt, checksum-listed static binaries (tools/release-public.sh, tools/release.sh).
# One file for both images and every platform:
#   docker buildx build --platform linux/amd64,linux/arm64 --build-arg BIN=authfly -f deploy/release.Dockerfile dist/release/<v>
# The binaries are cross-compiled by Go (<bin>-linux-<arch> in the context), so no stage runs foreign-arch code:
# the only RUN executes on the build host's platform and its output (user + /data) is copied into the target image.
FROM --platform=$BUILDPLATFORM alpine:3.22 AS prep
RUN adduser -D -u 10001 app && mkdir -p /data && chown app /data

FROM alpine:3.22
ARG BIN=authfly
ARG TARGETARCH
COPY --from=prep /etc/passwd /etc/group /etc/shadow /etc/
COPY --from=prep --chown=10001 /data /data
COPY ${BIN}-linux-${TARGETARCH} /usr/local/bin/app
USER 10001
ENV AUTHFLY_STORE=/data/store.json CONSOLE_DATA=/data
ENTRYPOINT ["/usr/local/bin/app"]
