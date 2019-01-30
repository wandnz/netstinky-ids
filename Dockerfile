FROM debian:9-slim

LABEL author="Andrew Mackintosh <amackint@waikato.ac.nz>"

RUN mkdir -p /usr/local/src

# Install dependencies for building openwrt and NetStinky
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    apt-get -y install --no-install-recommends \
        build-essential \
        ccache \
        gawk flex gettext \
        wget findutils unzip zip \
        git-core bzr cvs mercurial subversion \
        libncurses5-dev libxml-parser-perl \
        zlib1g-dev libssl-dev \
        libc6-dev libc6-dev-i386 \
        libpcap0.8 libpcap0.8-dev \
        gcc-multilib \
        man ssh vim \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/local/src

# Clone Turris OpenWrt fork
RUN git clone "turris url" openwrt && \
    cd openwrt && \
    git checkout stable

# Build the toolchain
# Including adding board configuration in-line
RUN cd openwrt && \
    echo "CONFIG_TARGET_mvebu=y
CONFIG_TARGET_mvebu_Turris-Omnia=y
CONFIG_TARGET_BOARD=\"mvebu\"" > .config && \
    make defconfig && \
    make download && \
    make prepare -j4 -j1 V=s

# Copy the NetStinky package code into the container
COPY ./packages/ packages/
COPY ./src netstinky/

# Build the NetStinky package
# CONFIG_PACKAGE_netstinky=m
RUN cd openwrt && \
    echo "src-link wand /usr/local/src/netstinky/package/wand" > feeds.conf && \
    ./scripts/feeds update -a && \
    ./scripts/feeds install netstinky && \
    echo "CONFIG_PACKAGE_libpcap=m
CONFIG_PACKAGE_netstinky=m" >> .config && \
    make defconfig && \
    make package/netstinky/{clean,compile}

