# NetStinky Intrusion Detection System (IDS)
This project is a component of the [NetStinky](https://git.cms.waikato.ac.nz/NetStinky) suite.

The NetStinky IDS is intended to be installed in a CPE device and provide
real-time monitoring of network traffic for Indicators of Compromise (IoCs).

# Building with Autotools
This project uses GNU Autotools in order to provide a configurable build. In order to generate the Makefile, you will need to have the following tools installed:
- autoconf
- automake
- libtool
- pkg-config

To generate the `./configure` script on a Unix-like OS, run the following command inside the `src/` directory:

```bash
$ autoreconf -i
```

You will only have to do this once, after which you should then be able to do a typical
```bash
./configure
make
```
Which will generate the `nsids` binary.

## Minimal build
For a minimal build, you will need to ensure that you have the `libpcap` and `libuv` development
headers installed for compilation to succeed. On a Debian/Ubuntu system, run

```
apt-get update
apt-get -y install libpcap-dev libuv1-dev
./configure --disable-mdns --disable-updates
```

## Enabling extra features
For the mDNS adversisement feature, you will need to have the `avahi` daemon installed and running (which also requires D-Bus)
```
apt-get update
apt-get -y install avahi-daemon libavahi-common-dev \
    libavahi-client-dev
```

For live updates on the blacklists, you will need `openssl` version 1.1.0 or
later.
```
apt-get update
apt-get -y install libssl-dev
```

## Running the tests
Once the main source has been built (as above) run the Makefile in the test
directory to build the `runner` binary which can be executed to run the unit
tests for the code.

```bash
cd test/
make
./runner
```

# Copyright
Copyright (c) 2020 The University of Waikato, Hamilton, New Zealand.
All rights reserved.

This code has been developed by the University of Waikato WAND
research group. For further information please see https://netstinky.wand.net.nz/.

This project is made available under the BSD 2-Clause license. For more information, see the `LICENSE` file.