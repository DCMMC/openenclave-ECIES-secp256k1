# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.
set(CMAKE_CXX_STANDARD 17)

add_custom_command(
  OUTPUT enclave_u.h enclave_u.c enclave_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/enclave.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/enclave.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(file-encryptor_host
  # host.cpp
               main_erc20.cpp
               enclave_host.cpp
               div.cpp
               util.cpp
               processor.cpp
               keccak/KeccakHash.c
               keccak/KeccakP-1600-opt64.c
               keccak/KeccakSpongeWidth1600.c
               keccak/SimpleFIPS202.c
               ${CMAKE_CURRENT_BINARY_DIR}/enclave_u.c)

if (WIN32)
  copy_oedebugrt_target(file-encryptor_host_oedebugrt)
  add_dependencies(file-encryptor_host file-encryptor_host_oedebugrt)
endif ()

target_include_directories(
  file-encryptor_host
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} # Needed for #include "../shared.h"
          ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(file-encryptor_host openenclave::oehost)
