# Multistage docker build, requires docker 17.05
#
# Running the image. shekyld's plaintext listeners are loopback only — a
# wildcard or network bind is refused at start (docs/design/RPC_TRANSPORT_
# POSTURE.md RT-1/RT-2) — so the container shares the host's network
# namespace:
#
#   docker run --network host shekyl-core
#
# 127.0.0.1 inside the container is then host loopback, and P2P is
# reachable. The image serves the view listener alone, at the network's view
# port (11030 on mainnet), with no plaintext admin listener. The entrypoint
# creates this account's session directory and runs the daemon as shekyl, so
# `docker exec -u shekyl … shekyl-cli` reaches the node on its owner's
# socket. The image exposes no RPC port on purpose; another machine reaches
# the node over the authenticated channel (rpc-listen), which an operator adds.

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
	chown -R shekyl:shekyl /home/shekyl/.shekyl /wallet

COPY contrib/packaging/docker/entrypoint.sh /usr/local/bin/shekyld-entrypoint
RUN chmod 0755 /usr/local/bin/shekyld-entrypoint

VOLUME /home/shekyl/.shekyl

VOLUME /wallet

EXPOSE 11021
# No RPC port: the plaintext listeners are loopback only; run with
# --network host (see the header).

# Root for the entrypoint, which creates /run/user/<uid> and drops to shekyl.
ENTRYPOINT ["shekyld-entrypoint"]
# P2P listens on the default (every address, the network's P2P port).
CMD ["--rpc-admin-listen", "none", "--rpc-view-listen", "127.0.0.1"]
