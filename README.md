# NetStinky Intrusion Detection System (IDS)
This project is a component of the [NetStinky](https://git.cms.waikato.ac.nz/NetStinky) suite.

The NetStinky IDS is intended to be installed in a CPE device and provide
real-time monitoring of network traffic for Indicators of Compromise (IoCs).

# Building for \*nix
For testing on a \*nix machine, you can simply run `make` in the source
directory.

```bash
cd src/
make
```

You will need to ensure that you have the `libpcap` and `libuv` development
headers installed for compilation to succeed. On a Debian/Ubuntu system, run

```bash
apt-get update
apt-get -y install libpcap-dev libuv1-dev
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

