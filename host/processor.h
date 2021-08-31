#pragma once

#include "bigint.h"
#include "util.h"

#include <nlohmann/json.hpp>
#include <fmt/ostream.h>
#include <fmt/format_header_only.h>

#include <iostream>
#include <stdio.h>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <random>
#include <memory>
#include <utility>
#include <ctime>

#include "../evm_enclave_headfile.h"

// ==================== enclave headfiles ====================
#include <openenclave/host.h>
#include "enclave_u.h"
// ==================== enclave headfiles ====================



namespace eevm
{

  /**
   * Ethereum bytecode processor.
   */
  class Processor
  {
  private:
	gs_struct gs;
	int run_number;
	nlohmann::json taint_json;

	oe_enclave_t* enclave;

	tx_struct tx;


  public:
	Processor();

	Processor(gs_struct& gs, tx_struct& tx);

	void init();

	void save();

	void create_enclave(char *enclave_name);

	void close_enclave();

	exec_result_struct run(
	  const Address& caller,
	  const Address& callee,
	  const std::vector<uint8_t>& input_uint8,
	  const std::string& input_raw,
	  const uint256_t& call_value);

	Address deploy(
	  const Address& _caller_address,
	  const Code& _constructor);

	void create_account(
	  const Address& account_address,
	  const uint256_t& account_balance,
	  const Code& account_code,
	  const size_t& account_nonce);

	void printf_gs(bool code = false, bool storage = false);

	gs_struct get_gs();
  };

} // namespace eevm

/* uint256_t -> unsigned char* */
unsigned char* uint2562charx(uint256_t n);

/* unsigned char* -> uint256_t */
uint256_t charx2uint256(unsigned char* n);

/* uint64_t -> unsigned char* */
unsigned char* uint642charx(uint64_t n);

/* unsigned char* -> uint64_t */
uint64_t charx2uint64(unsigned char* n);

/* vector<uint8_t> -> uint8_t* */
uint8_t* vector2arr(std::vector<uint8_t> code);

/* uint8_t* -> vector<uint8_t> */
std::vector<uint8_t> arr2vector(uint8_t* code_arr, size_t code_size);

/* uint8_t* -> char*/
unsigned char* arr2charx(uint8_t* code, size_t code_size);

/* char* -> uint8_t* */
uint8_t* charx2arr(unsigned char* s);

unsigned char* enc_data_store(unsigned char* s);

unsigned char* enc_data_load(unsigned char* s);
