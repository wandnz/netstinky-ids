# NetStinky Intrusion Detection System (IDS)
This project is a component of the [NetStinky](https://git.cms.waikato.ac.nz/NetStinky) suite.

The NetStinky IDS is intended to be installed in a CPE device and provide
real-time monitoring of network traffic for Indicators of Compromise (IoCs).

# Building for Linux
For testing on a Linux machine, you can simply run `make` in the source
directory.

```bash
cd src/
make
```

You will need to ensure that you have `libpcap` and the development headers
installed for compilation to succeed. On a Debian/Ubuntu system run
```bash
apt-get update
apt-get -y install libpcap libpcap-dev
```

# Building for OpenWRT
In order to build a package for OpenWRT, you will need to ensure that you have
the OpenWRT toolchain installed. This includes a cross-compilation suite for the
target architecture.

## Using Docker
To get started (relatively) quickly, you can use the included `Dockerfile` to
create an image with the toolchain configured and the NetStinky IDS pre-compiled
into a package.

```bash
docker build -t netstinky-ids .
docker run -it --name netstinky-ids netstinky-ids /bin/bash
```

Creating the image may take a significant amount of time, as it is necessary to
build the full toolchain from source.

## Manually
In order to manually build the package, you will need to ensure that you have
the development dependencies installed. These are listed in the first `RUN`
command in the Dockerfile.

Obtain a copy of the Turris fork of OpenWRT and checkout the `stable` branch.
```bash
git clone "https://gitlab.labs.nic.cz/turris/openwrt.git" openwrt
cd openwrt
git checkout stable
```

### Building the Toolchain

Configure the toolchain with `make menuconfig`. In the menu, set the `Target
System` to `Marvell Armada 37x/38x/XP` and the `Target Profile` to `Turris
Omnia` then save and exit.

To actually build the toolchain execute:
```bash
make toolchain/download
make toolchain/install -j4 -j1 V=s
```
This will likely take some time.

### Building NetStinky IDS
In the `openwrt` directory create a file `feeds.conf` and set the contents to be
```
src-link wand <src-directory>/package/wand
```
Where `<src-directory>` is the absolute path to the source code of this
repository.

You will need to update the package feeds in the OpenWRT toolchain
```bash
./scripts/feeds update -a
./scripts/feeds install netstinky
make menuconfig
```
In the menu under `Networks`, find `netstinky` and press `M` to include it as a
module. This will cause a package to be built that can be installed into the
Omnia device.
```bash
make -j1 V=s package/netstinky/clean
make -j1 V=s package/netstinky/compile
```

Once compilation has completed, you should be able to find the produced package
at `openwrt/bin/mvebu/packages/wand/`. This can then be copied to the device and
installed. Note that you may also require the `libpcap` package under
`openwrt/bin/mvebu/packages/base/`
