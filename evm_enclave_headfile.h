// Copyright (c) 2021 Tsinghua Shenzhen International Graduate School
// All rights reserved.

#pragma once

#define CAL_LOAD_STORE_TIME 0
#define CAL_CREATE_ENCLAVE_TIME 0
#define CAL_EVME_TIME 0
#define CAL_FE_TIME 0
#define CAL_FO_TIME 0

#define PRINT_OPCODE 0
#define PRINT_STACK_MEM 0

#define GLOBALSTATE_PATH globalstate.json
#define TAINT_PATH taint.json

/* storage */
typedef struct _storage_struct {
  unsigned char* key;
  unsigned char* value;
}storage_struct;
/* storage */

/* account */
typedef struct _account_struct {
  unsigned char* account_address;
  unsigned char* account_balance;
  uint8_t* account_code;  // bytecode
  unsigned char* account_code_size;  // size_t
  unsigned char* account_nonce;  // size_t

  storage_struct* storage;
  unsigned char* storage_size;  // size_t
}account_struct;
/* account */

/* block */
typedef struct _gs_block_struct {
  uint64_t number;
  uint64_t difficulty;
  uint64_t gas_limit;
  uint64_t timestamp;
  unsigned char* coinbase;
}gs_block_struct;
/* block */

/* gs */
typedef struct _gs_accounts_struct {
  unsigned char* address;
  account_struct account;
}gs_accounts_struct;

typedef struct _gs_struct {
  gs_block_struct currentBlock;
  gs_accounts_struct* accounts;
  unsigned char* accounts_size;  // size_t
}gs_struct;
/* gs */

/* tx */
typedef struct _tx_struct {
  unsigned char* origin;  // tx.origin
  uint64_t value;  // tx.value
  uint64_t gas_price;  // tx.gas_price
  uint64_t gas_limit;  // tx.gas_limit

  unsigned char** selfdestruct_list; // tx.selfdestruct_list
  unsigned char* selfdestruct_list_size;  // size_t
}tx_struct;
/* tx */

/* Result */
typedef struct _exec_result_struct {
  uint8_t er;
  unsigned char* exmsg;
  uint8_t* output;
  unsigned char* output_size;  // size_t
}exec_result_struct;
/* Result */