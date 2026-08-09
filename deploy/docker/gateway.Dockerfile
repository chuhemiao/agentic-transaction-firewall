FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder

# The workspace's production release profile uses full LTO. Keep optimized
# binaries for the local Shadow stack, but avoid a multi-minute single-threaded
# link that makes the supported contributor path impractical.
ENV RUSTUP_TOOLCHAIN=1.95.0 \
    CARGO_PROFILE_RELEASE_LTO=false

WORKDIR /workspace
COPY . .
RUN --mount=type=cache,id=atf-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=atf-cargo-target,target=/workspace/target \
    cargo build --release --locked \
        --package atf-gateway --bin atf-gateway \
        --package atf-store --bin atf-store-migrate \
        --package atf-cli --bin atf --bin atf-shadow-load \
    && mkdir -p /opt/atf-build \
    && cp target/release/atf-gateway target/release/atf-store-migrate \
        target/release/atf target/release/atf-shadow-load /opt/atf-build/

FROM postgres:17.10@sha256:7958605b474b3d264a969cb3a123d6aa00ad1e1fe9da8a69984dabb704d93317

ENV PATH="/opt/atf/bin:${PATH}"
WORKDIR /opt/atf

RUN mkdir -p /opt/atf/bin /opt/atf/fixtures /opt/atf/policies /opt/atf/risk-rules /state /backups \
    && chown -R postgres:postgres /state /backups

COPY --from=builder /opt/atf-build/ /opt/atf/bin/
COPY deploy/docker/fixtures/ /opt/atf/fixtures/
COPY policies/examples/ /opt/atf/policies/current/
COPY risk-rules/default.json /opt/atf/risk-rules/default.json
COPY deploy/docker/local/bootstrap.sh /opt/atf/local/bootstrap.sh

USER postgres
ENTRYPOINT []
CMD ["/opt/atf/bin/atf-gateway"]
