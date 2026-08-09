FROM caddy:2.11.4-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648

# ATF only listens on unprivileged ports. Removing the upstream privileged-port
# file capability lets the edge run with no-new-privileges and cap_drop: ALL.
RUN setcap -r /usr/bin/caddy

RUN mkdir -p /ca && chown 1001:1001 /ca
COPY --chmod=0755 deploy/docker/local/edge.sh /usr/local/bin/atf-local-edge

ENTRYPOINT ["/usr/local/bin/atf-local-edge"]
