# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run simulate

# OE_CRYPTO_LIB := mbedtls
OE_CRYPTO_LIB := openssl
export OE_CRYPTO_LIB

all: build

build:
	$(MAKE) -C enclave
	$(MAKE) -C host

clean:
	$(MAKE) -C enclave clean
	$(MAKE) -C host clean

run:
	host/file-encryptorhost testfile ./enclave/file-encryptorenc.signed

simulate:
	host/file-encryptorhost testfile ./enclave/file-encryptorenc.signed --simulate

