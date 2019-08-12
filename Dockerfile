FROM debian:10-slim
LABEL author="Andrew Mackintosh <amackint@waikato.ac.nz>"

# Install dependencies for building openwrt and NetStinky
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get -y install --no-install-recommends \
        build-essential \
        libavahi-client3 libavahi-client-dev \
        libavahi-common3 libavahi-common-dev \
        libssl-dev \
        libc6-dev \
        libcurl4 libcurl4-openssl-dev \
        libuv1 libuv1-dev \
        libpcap0.8 libpcap0.8-dev \
        vim \
        && rm -rf /var/lib/apt/lists/*

COPY bls/ /usr/local/src/netstinky/bls/
COPY src/ /usr/local/src/netstinky/src/
COPY test/ /usr/local/src/netstinky/test/

WORKDIR /usr/local/src/netstinky/
CMD "/bin/bash"

