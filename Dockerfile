# Multistage docker build, requires docker 17.05

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
EXPOSE 11029

USER shekyl

ENTRYPOINT ["shekyld"]
CMD ["--p2p-bind-ip=0.0.0.0", "--p2p-bind-port=11021", "--rpc-bind-ip=0.0.0.0", "--rpc-bind-port=11029", "--non-interactive", "--confirm-external-bind", "--restricted-rpc"]
