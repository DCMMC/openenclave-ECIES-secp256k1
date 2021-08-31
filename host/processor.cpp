// Copyright (c) 2021 Tsinghua Shenzhen International Graduate School
// All rights reserved.

#include "processor.h"

// ==================== enclave init setting ====================
oe_enclave_t* enclave = NULL;

oe_result_t create_enclave_enclave(
  const char* enclave_name,
  oe_enclave_t** out_enclave)
{
  oe_enclave_t* enclave = NULL;
  uint32_t enclave_flags = 0;
  oe_result_t result;

  *out_enclave = NULL;

  // Create the enclave
#ifdef _DEBUG
  enclave_flags |= OE_ENCLAVE_FLAG_DEBUG;
#endif
  result = oe_create_enclave_enclave(
	enclave_name, OE_ENCLAVE_TYPE_AUTO, enclave_flags, NULL, 0, &enclave);
  if (result != OE_OK)
  {
	printf(
	  "Error %d creating enclave, trying simulation mode...\n", result);
	enclave_flags |= OE_ENCLAVE_FLAG_SIMULATE;
	result = oe_create_enclave_enclave(
	  enclave_name,
	  OE_ENCLAVE_TYPE_AUTO,
	  enclave_flags,
	  NULL,
	  0,
	  &enclave);
  }
  if (result != OE_OK)
  {
	return result;
  }

  *out_enclave = enclave;
  return OE_OK;
}
// ==================== enclave init setting ====================



/* uint256_t -> unsigned char* */
unsigned char* uint2562charx(uint256_t n) {
  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  if (n == 0) {
	res[0] = '0';
	return res;
  }
  std::vector<unsigned char> tmp;
  while (n != 0) {
	tmp.push_back(static_cast<unsigned char>(n % 10 + '0'));
	n /= 10;
  }
  for (int i = tmp.size() - 1, j = 0; i >= 0; i--, j++) {
	res[j] = tmp[i];
  }
  return res;
}

/* unsigned char* -> uint256_t */
uint256_t charx2uint256(unsigned char* n) {
  uint256_t res = 0;
  int end = 0;
  while (*(n + end) != 0) {
	res *= 10;
	res += static_cast<uint8_t>(*(n + end) - '0');
	end += 1;
  }
  return res;
}

/* unsigned char* -> uint64_t */
uint64_t charx2uint64(unsigned char* n) {
  uint64_t res = 0;
  int end = 0;
  while (*(n + end) != 0) {
	res *= 10;
	res += static_cast<uint8_t>(*(n + end) - '0');
	end += 1;
  }
  return res;
}

/* uint64_t -> unsigned char* */
unsigned char* uint642charx(uint64_t n) {
  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  if (n == 0) {
	res[0] = '0';
	return res;
  }
  std::vector<unsigned char> tmp;
  while (n != 0) {
	tmp.push_back(static_cast<unsigned char>(n % 10 + '0'));
	n /= 10;
  }
  for (int i = tmp.size() - 1, j = 0; i >= 0; i--, j++) {
	res[j] = tmp[i];
  }
  return res;
}

/* vector<uint8_t> -> uint8_t* */
uint8_t* vector2arr(std::vector<uint8_t> code) {
  uint8_t* code_arr = new uint8_t[code.size()];
  memset(code_arr, 0, sizeof(uint8_t) * code.size());
  if (code.size() > 0) {
	memcpy(code_arr, &code[0], sizeof(uint8_t) * code.size());
  }
  return code_arr;
}

/* uint8_t* -> vector<uint8_t> */
std::vector<uint8_t> arr2vector(uint8_t* code_arr, size_t code_size) {
  std::vector<uint8_t> vec(code_arr, code_arr + code_size);
  return vec;
}

/* uint8_t* -> char*/
unsigned char* arr2charx(uint8_t* code, size_t code_size) {
  unsigned char* res = new unsigned char[90000];
  memset(res, 0, sizeof(unsigned char) * 90000);
  for (int i = 0, j = 0; i < code_size; i++, j += 3) {
	int v = (int)code[i];
	res[j + 2] = v % 10 + '0';
	res[j + 1] = (v / 10) % 10 + '0';
	res[j] = (v / 100) % 10 + '0';
  }
  return res;
}

/* char* -> uint8_t* */
uint8_t* charx2arr(unsigned char* s) {
  std::vector<uint8_t> res;
  int i = 0;
  while (s[i] != 0) {
	uint8_t n = (s[i] - '0') * 100 + (s[i + 1] - '0') * 10 + (s[i + 2] - '0');
	res.push_back(std::move(n));
	i += 3;
  }
  uint8_t* _res = new uint8_t[30000];
  memset(_res, 0, sizeof(uint8_t) * 30000);
  if (res.size() > 0) {
	memcpy(_res, &res[0], sizeof(uint8_t) * res.size());
  }
  return _res;
}

unsigned char* enc_data_store(unsigned char* s) {
  unsigned char* res = new unsigned char[1000];
  memset(res, 0, sizeof(unsigned char) * 1000);
  for (int i = 0, j = 0; i < 200; i++, j += 3) {
	int v = (int)s[i];
	res[j + 2] = v % 10 + '0';
	res[j + 1] = (v / 10) % 10 + '0';
	res[j] = (v / 100) % 10 + '0';
  }
  return res;
}

unsigned char* enc_data_load(unsigned char* s) {
  std::vector<unsigned char> res;
  int i = 0;
  while (s[i] != 0) {
	unsigned char n = (s[i] - '0') * 100 + (s[i + 1] - '0') * 10 + (s[i + 2] - '0');
	res.push_back(std::move(n));
	i += 3;
  }
  unsigned char* _res = new unsigned char[200];
  memset(_res, 0, sizeof(unsigned char) * 200);
  memcpy(_res, &res[0], sizeof(unsigned char) * res.size());
  return _res;
}



namespace eevm
{
  Processor::Processor() {}

  Processor::Processor(gs_struct& gs, tx_struct& tx) : gs(gs), tx(tx) {}

  void Processor::init() {
	long start_time = clock();
	// create gs
	gs.currentBlock = { 0,0,0,0,new unsigned char[100] };
	memcpy(gs.currentBlock.coinbase, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	gs.accounts = new gs_accounts_struct[100];
	for (int i = 0; i < 100; i++) {
	  gs.accounts[i].address = new unsigned char[100];
	  gs.accounts[i].account.account_address = new unsigned char[100];
	  gs.accounts[i].account.account_balance = new unsigned char[100];
	  gs.accounts[i].account.account_code = new uint8_t[30000];
	  gs.accounts[i].account.account_code_size = new unsigned char[100];
	  gs.accounts[i].account.account_nonce = new unsigned char[100];
	  gs.accounts[i].account.storage = new storage_struct[100];
	  for (int j = 0; j < 100; j++) {
		gs.accounts[i].account.storage[j].key = new unsigned char[200];
		memset(gs.accounts[i].account.storage[j].key, 0, sizeof(unsigned char) * 200);
		gs.accounts[i].account.storage[j].value = new unsigned char[200];
		memset(gs.accounts[i].account.storage[j].value, 0, sizeof(unsigned char) * 200);
	  }
	  gs.accounts[i].account.storage_size = uint642charx(0);
	}
	gs.accounts_size = uint642charx(0);

	// copy gs
	std::ifstream gs_json_file("globalstate.json");
	if (gs_json_file) {
	  nlohmann::json gs_json_copy;
	  gs_json_file >> gs_json_copy;

	  std::string _number = gs_json_copy["currentBlock"]["number"].get<std::string>();
	  gs.currentBlock.number = charx2uint64((unsigned char*)_number.c_str());
	  std::string _difficulty = gs_json_copy["currentBlock"]["difficulty"].get<std::string>();
	  gs.currentBlock.difficulty = charx2uint64((unsigned char*)_difficulty.c_str());
	  std::string _gas_limit = gs_json_copy["currentBlock"]["gas_limit"].get<std::string>();
	  gs.currentBlock.gas_limit = charx2uint64((unsigned char*)_gas_limit.c_str());
	  std::string _timestamp = gs_json_copy["currentBlock"]["timestamp"].get<std::string>();
	  gs.currentBlock.timestamp = charx2uint64((unsigned char*)_timestamp.c_str());
	  std::string __coinbase = gs_json_copy["currentBlock"]["coinbase"].get<std::string>();
	  unsigned char* _coinbase = (unsigned char*)__coinbase.c_str();
	  memcpy(gs.currentBlock.coinbase, _coinbase, strlen((char*)_coinbase) + 1);

	  int i = 0;
	  for (; i < gs_json_copy["accounts"].size(); i++) {
		std::string __address_str = gs_json_copy["accounts"][i]["address"].get<std::string>();
		unsigned char* __address = (unsigned char*)__address_str.c_str();
		std::string _address_str = gs_json_copy["accounts"][i]["account"]["address"].get<std::string>();
		unsigned char* _address = (unsigned char*)_address_str.c_str();
		std::string _balance_str = gs_json_copy["accounts"][i]["account"]["balance"].get<std::string>();
		unsigned char* _balance = (unsigned char*)_balance_str.c_str();
		std::string _code_str = gs_json_copy["accounts"][i]["account"]["code"].get<std::string>();
		uint8_t* _code = charx2arr((unsigned char*)_code_str.c_str());
		std::string _code_size_str = gs_json_copy["accounts"][i]["account"]["code_size"].get<std::string>();
		unsigned char* _code_size = (unsigned char*)_code_size_str.c_str();
		std::string _nonce_str = gs_json_copy["accounts"][i]["account"]["nonce"].get<std::string>();
		unsigned char* _nonce = (unsigned char*)_nonce_str.c_str();

		memcpy(gs.accounts[i].address, __address, strlen((char*)__address) + 1);
		memcpy(gs.accounts[i].account.account_address, _address, strlen((char*)_address) + 1);
		memcpy(gs.accounts[i].account.account_balance, _balance, strlen((char*)_balance) + 1);
		memcpy(gs.accounts[i].account.account_code, _code, sizeof(uint8_t) * charx2uint64(_code_size));
		memcpy(gs.accounts[i].account.account_code_size, _code_size, strlen((char*)_code_size) + 1);
		memcpy(gs.accounts[i].account.account_nonce, _nonce, strlen((char*)_nonce) + 1);

		int j = 0;
		for (auto& it : gs_json_copy["accounts"][i]["storage"].items()) {
		  std::string _key_str = gs_json_copy["accounts"][i]["storage"][j]["key"].get<std::string>();
		  std::string _value_str = gs_json_copy["accounts"][i]["storage"][j]["value"].get<std::string>();
		  unsigned char* _key = enc_data_load((unsigned char*)_key_str.c_str());
		  unsigned char* _value = enc_data_load((unsigned char*)_value_str.c_str());
		  memcpy(gs.accounts[i].account.storage[j].key, _key, sizeof(unsigned char) * 200);
		  memcpy(gs.accounts[i].account.storage[j].value, _value, sizeof(unsigned char) * 200);
		  j += 1;
		}
		memcpy(gs.accounts[i].account.storage_size, uint642charx(j), strlen((char*)uint642charx(j)) + 1);
	  }
	  memcpy(gs.accounts_size, uint642charx(i), strlen((char*)uint642charx(i)) + 1);
	}
	long end_time = clock();
	if (CAL_LOAD_STORE_TIME) printf("Load store: %f\n", ((double)end_time - start_time) / 1000);

	// taint analysis result
	std::ifstream taint_json_file("taint.json");
	if (taint_json_file) {
	  taint_json_file >> taint_json;
	}

	// run_number
	run_number = 1;
  }

  void Processor::save() {
	nlohmann::json gs_json_store;
	gs_json_store["currentBlock"]["number"] = (char*)uint642charx(gs.currentBlock.number);
	gs_json_store["currentBlock"]["difficulty"] = (char*)uint642charx(gs.currentBlock.difficulty);
	gs_json_store["currentBlock"]["gas_limit"] = (char*)uint642charx(gs.currentBlock.gas_limit);
	gs_json_store["currentBlock"]["timestamp"] = (char*)uint642charx(gs.currentBlock.timestamp);
	gs_json_store["currentBlock"]["coinbase"] = (char*)gs.currentBlock.coinbase;

	for (int i = 0; i < charx2uint64(gs.accounts_size); i++) {
	  gs_json_store["accounts"][i]["address"] = (char*)gs.accounts[i].address;
	  gs_json_store["accounts"][i]["account"]["address"] = (char*)gs.accounts[i].account.account_address;
	  gs_json_store["accounts"][i]["account"]["balance"] = (char*)gs.accounts[i].account.account_balance;
	  unsigned char* _code = arr2charx(gs.accounts[i].account.account_code, charx2uint64(gs.accounts[i].account.account_code_size));
	  gs_json_store["accounts"][i]["account"]["code"] = (char*)_code;
	  gs_json_store["accounts"][i]["account"]["code_size"] = (char*)gs.accounts[i].account.account_code_size;
	  gs_json_store["accounts"][i]["account"]["nonce"] = (char*)gs.accounts[i].account.account_nonce;

	  for (int j = 0; j < charx2uint64(gs.accounts[i].account.storage_size); j++) {
		unsigned char* _key = enc_data_store(gs.accounts[i].account.storage[j].key);
		unsigned char* _value = enc_data_store(gs.accounts[i].account.storage[j].value);
		gs_json_store["accounts"][i]["storage"][j]["key"] = (char*)_key;
		gs_json_store["accounts"][i]["storage"][j]["value"] = (char*)_value;
	  }
	}
	std::ofstream o("globalstate.json");
	o << std::setw(2) << gs_json_store << std::endl;
  }

  void Processor::create_enclave(char *enclave_name) {
	// ==================== enclave create ====================
	long start_time = clock();
	oe_result_t oe_result = create_enclave_enclave(
      enclave_name,
	  & enclave);
	if (oe_result != OE_OK)
	{
	  fprintf(
		stderr,
		"oe_create_enclave(): result=%u (%s)\n",
		oe_result,
		oe_result_str(oe_result));
	}
	long end_time = clock();
	if (CAL_CREATE_ENCLAVE_TIME) printf("Create Enclave: %f\n", ((double)end_time - start_time) / 1000);
	// ==================== enclave create ====================
  }

  void Processor::close_enclave() {
	if (enclave != NULL)
	{
	  oe_terminate_enclave(enclave);
	}
  }

  exec_result_struct Processor::run(
	const Address& _caller,
	const Address& _callee,
	const std::vector<uint8_t>& _input_uint8,
	const std::string& _input_raw,
	const uint256_t& _call_value) {

	// 每50次保存一次
	run_number += 1;
	if (run_number % 50 == 0) save();

	// init result
	exec_result_struct result;
	result.exmsg = new unsigned char[100];
	result.output = new uint8_t[30000];
	result.output_size = uint2562charx(0);

	// init tx
	tx = { uint2562charx(_caller),0,0,0 };
	tx.selfdestruct_list = new unsigned char* [100];
	for (int i = 0; i < 100; i++) {
	  tx.selfdestruct_list[i] = new unsigned char[100];
	}
	tx.selfdestruct_list_size = uint642charx(0);

	// init information
	unsigned char* caller = uint2562charx(_caller);
	unsigned char* callee = uint2562charx(_callee);
	uint8_t* input = new uint8_t[3000];
	memcpy(input, vector2arr(_input_uint8), sizeof(uint8_t) * _input_uint8.size());
	unsigned char* call_value = uint2562charx(_call_value);

	// init function's taint list
	std::string function_key;
	bool find_flag = false;
	if (_input_raw.substr(0, 2) == "0x") {
	  function_key = _input_raw.substr(2, 8);
	}
	else {
	  function_key = _input_raw.substr(0, 8);
	}
	for (nlohmann::json::iterator it = taint_json.begin(); it != taint_json.end(); it++) {
	  if (it.key() == function_key) {
		find_flag = true;
		break;
	  }
	}
	if (!find_flag) function_key = "ffffffff";
	std::string _taint_list = taint_json[function_key].get<std::string>();
	uint8_t* taint_list = new uint8_t[256];
	for (int i = 0; i < _taint_list.size(); i++) {
	  taint_list[i] = _taint_list[i] - '0';
	}

	// ==================== enclave run ====================
	long start_time = clock();
	enclave_run(enclave, &result, &gs, &tx, caller, callee, input, _input_uint8.size(), call_value, taint_list);
	long end_time = clock();
	if (CAL_EVME_TIME) printf("EVM-E: %f\n", ((double)end_time - start_time) / 1000);
	// ==================== enclave run ====================

	return result;
  }

  Address Processor::deploy(
	const Address& _caller_address,
	const Code& _constructor) {

	  // (DCMMC) test entrance, defined in enclave/enclave_ecalls.cpp
	  // uint8_t ret;
	  // test_ecp_secp256k1(enclave, &ret);
      std::cout << "start of Processor::deploy\n";

	// 每50次保存一次
	run_number += 1;
	if (run_number % 50 == 0) save();

	// init tx
	tx = { uint2562charx(_caller_address),0,0,0 };
	tx.selfdestruct_list = new unsigned char* [100];
	for (int i = 0; i < 100; i++) {
	  tx.selfdestruct_list[i] = new unsigned char[100];
	}
	tx.selfdestruct_list_size = uint642charx(0);

	// init information
	unsigned char* caller_address = uint2562charx(_caller_address);
	uint8_t* constructor = vector2arr(_constructor);
	unsigned char* contract_address = new unsigned char[100];
	memset(contract_address, 0, sizeof(unsigned char) * 100);

	// init function's taint list
	std::string _taint_list = taint_json["constructor"].get<std::string>();
	uint8_t* taint_list = new uint8_t[256];
	for (int i = 0; i < _taint_list.size(); i++) {
	  taint_list[i] = _taint_list[i] - '0';
	}

	// ==================== enclave run ====================
	long start_time = clock();
	enclave_deploy(enclave, &gs, &tx, caller_address, constructor, _constructor.size(), contract_address, taint_list);
	long end_time = clock();
	if (CAL_EVME_TIME) printf("EVM-E: %f\n", ((double)end_time - start_time) / 1000);
	// ==================== enclave run ====================

	return charx2uint256(contract_address);
  }

  void Processor::create_account(
	const Address& account_address,
	const uint256_t& account_balance,
	const Code& account_code,
	const size_t& account_nonce) {

	// 每50次保存一次
	run_number += 1;
	if (run_number % 50 == 0) save(); 

	// 判断地址是否存在（一般不会被触发）
	for (int i = 0; i < charx2uint64(gs.accounts_size); i++) {
	  if (strcmp((char*)uint2562charx(account_address), (char*)(gs.accounts + i)->address) == 0) {
		return;
	  }
	}

	memcpy(gs.accounts[charx2uint64(gs.accounts_size)].address, uint2562charx(account_address), strlen((char*)uint2562charx(account_address)) + 1);
	memcpy(gs.accounts[charx2uint64(gs.accounts_size)].account.account_address, uint2562charx(account_address), strlen((char*)uint2562charx(account_address)) + 1);
	memcpy(gs.accounts[charx2uint64(gs.accounts_size)].account.account_balance, uint2562charx(account_balance), strlen((char*)uint2562charx(account_balance)) + 1);
	memcpy(gs.accounts[charx2uint64(gs.accounts_size)].account.account_code, {}, 0);
	memcpy(gs.accounts[charx2uint64(gs.accounts_size)].account.account_code_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(gs.accounts[charx2uint64(gs.accounts_size)].account.account_nonce, uint642charx(account_nonce), strlen((char*)uint642charx(account_nonce)) + 1);
	memcpy(gs.accounts[charx2uint64(gs.accounts_size)].account.storage_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(gs.accounts_size, uint642charx(charx2uint64(gs.accounts_size) + 1), strlen((char*)uint642charx(charx2uint64(gs.accounts_size) + 1)) + 1);
  }

  void Processor::printf_gs(bool code, bool storage) {
	printf("gs account size: ");
	std::cout << gs.accounts_size << std::endl;
	for (int i = 0; i < charx2uint64(gs.accounts_size); i++) {
	  printf("account: %d\n", i);
	  printf("address: ");
	  std::cout << eevm::to_checksum_address(charx2uint256(gs.accounts[i].address)) << std::endl;
	  printf("balance: ");
	  std::cout << gs.accounts[i].account.account_balance << std::endl;
	  if (code) {
		printf("code size: ");
		std::cout << gs.accounts[i].account.account_code_size << std::endl;
		printf("code: ");
		for (int j = 0; j < charx2uint64(gs.accounts[i].account.account_code_size); j++) {
		  printf("%d", gs.accounts[i].account.account_code[j]);
		}
		std::cout << std::endl;
	  }

	  if (storage) {
		printf("storage size: ");
		std::cout << gs.accounts[i].account.storage_size << std::endl;
		for (int j = 0; j < charx2uint64(gs.accounts[i].account.storage_size); j++) {
		  printf("key: ");
		  std::cout << gs.accounts[i].account.storage[j].key << std::endl;
		  printf("value: ");
		  std::cout << gs.accounts[i].account.storage[j].value << std::endl;
		}
	  }
	}
  }

  gs_struct Processor::get_gs() {
	return gs;
  }

} // namespace eevm
