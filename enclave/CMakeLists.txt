# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
set(CMAKE_CXX_STANDARD 14)

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT enclave_t.h enclave_t.c enclave_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/enclave.edl
  COMMAND
    openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/enclave.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

set(CRYPTO_SRC ${OE_CRYPTO_LIB}_src)
add_executable(
  enclave
          # common/ecalls.cpp ${CRYPTO_SRC}/encryptor.cpp
          # ${CRYPTO_SRC}/ecp_encryptor.cpp
          ${CRYPTO_SRC}/ecp/contract.cpp
          ${CRYPTO_SRC}/ecp/ec_key.cpp
          ${CRYPTO_SRC}/ecp/ECDSAKey.cpp
          ${CRYPTO_SRC}/ecp/ECIES.cpp
          ${CRYPTO_SRC}/enclave_ecalls.cpp
          # ${CRYPTO_SRC}/keys.cpp
          ${CMAKE_CURRENT_BINARY_DIR}/enclave_t.c)
if (WIN32)
  maybe_build_using_clangw(enclave)
endif ()

target_compile_definitions(enclave PUBLIC OE_API_VERSION=2)

target_include_directories(
  enclave
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} # Needed for #include "../shared.h"
          ${CMAKE_CURRENT_BINARY_DIR}
          ${CMAKE_SOURCE_DIR})

target_link_libraries(
  enclave openenclave::oeenclave openenclave::oecrypto${OE_CRYPTO_LIB}
  openenclave::oelibcxx)
