# openenclave-ECIES-secp256k1 Demo
Demo of ECIES asymmetric encrypt w/ secp256k1 on OpenEnclave

## Implementation

Please refer to function `test_ecp_secp256k1()` in the source file `enclave/openssl_src/enclave_ecalls.cpp`.

## Build and run

The steps required to build and run the samples on Linux are described in [BuildSamplesLinux.md](https://github.com/openenclave/openenclave/blob/master/samples/BuildSamplesLinux.md). In order to build and run the samples on Windows, please see [BuildSamplesWindows.md](https://github.com/openenclave/openenclave/blob/master/samples/BuildSamplesWindows.md).

Currently only test on Linux (Ubuntu 20.04 w/ simulate mode):

```bash
. /opt/openenclave/share/openenclave/openenclaverc
mkdir build && cd build && cmake ..
make -j 20 && make simulate
```

#### Note

The demo can run under OE simulation mode.
