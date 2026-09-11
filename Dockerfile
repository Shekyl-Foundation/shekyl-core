# Multistage docker build, requires docker 17.05
#
# Running the image. shekyld serves RPC on loopback only — a wildcard or
# network bind is refused at start (docs/design/RPC_TRANSPORT_POSTURE.md
# RT-1/RT-2) — so the container shares the host's network namespace:
#
#   docker run --network host shekyl-core
#
# 127.0.0.1 inside the container is then host loopback, P2P is reachable,
# and nothing in the daemon changes. The image exposes no RPC port on
# purpose; a daemon UDS listener for the no-host-networking case is filed in
# docs/FOLLOWUPS.md with its trigger, not built speculatively.

# builder stage
FROM ubuntu:20.04 as builder

RUN set -ex && \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get --no-install-recommends --yes install \
        automake \
        autotools-dev \
        bsdmainutils \
        build-essential \
        ca-certificates \
        ccache \
        cmake \
        curl \
        git \
        libtool \
        python3 \
        pkg-config \
        gperf

WORKDIR /src
COPY . .

ARG NPROC
RUN set -ex && \
    git submodule init && git submodule update && \
    rm -rf build && \
    if [ -z "$NPROC" ] ; \
    then make -j$(nproc) depends target=x86_64-linux-gnu ; \
    else make -j$NPROC depends target=x86_64-linux-gnu ; \
    fi

# runtime stage
FROM ubuntu:20.04

RUN set -ex && \
    apt-get update && \
    apt-get --no-install-recommends --yes install ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt
COPY --from=builder /src/build/x86_64-linux-gnu/release/bin /usr/local/bin/

RUN adduser --system --group --disabled-password shekyl && \
	mkdir -p /wallet /home/shekyl/.shekyl && \
	chown -R shekyl:shekyl /home/shekyl/.shekyl && \
	chown -R shekyl:shekyl /wallet

VOLUME /home/shekyl/.shekyl

VOLUME /wallet

EXPOSE 11021
# No RPC port: RPC is loopback only; run with --network host (see the header).

USER shekyl

ENTRYPOINT ["shekyld"]
CMD ["--p2p-bind-ip=0.0.0.0", "--p2p-bind-port=11021", "--rpc-bind-port=11029", "--non-interactive", "--restricted-rpc"]
