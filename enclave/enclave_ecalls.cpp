// Copyright (c) 2021 Tsinghua Shenzhen International Graduate School
// All rights reserved.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <functional>
#include <vector>
#include <map>
#include <set>
#include <deque>
#include <time.h>

#include "opcode.h"
#include "myKeccak256.hpp"
#include "myBigInt.hpp"

#include "evm_enclave_headfile.h"

#include "ECIES.h"
#include "ECDSAKey.h"
#include "Blob.h"
#include "trace.h"
#include <string>

using namespace ripple;
using namespace std;

// ==================== enclave headfiles ====================
#include "enclave_t.h"
// ==================== enclave headfiles ====================

// ==================== enclave init setting ====================
#define HEAP_SIZE_BYTES (64 * 1024 * 1024) /* 8 MB 原 2 MB*/
#define STACK_SIZE_BYTES (1024 * 1024)      /* 64 KB 原 24 KB */

#define SGX_PAGE_SIZE (4 * 1024) /* 4 KB */

#define TA_UUID /* 4e3c0f91-4f56-452d-92d7-abc4c2c831fa */ {0x4e3c0f91,0x4f56,0x452d,{0x92,0xd7,0xab,0xc4,0xc2,0xc8,0x31,0xfa}}

OE_SET_ENCLAVE_OPTEE(
  TA_UUID,                                  /* UUID */
  HEAP_SIZE_BYTES,                          /* HEAP_SIZE */
  STACK_SIZE_BYTES,                         /* STACK_SIZE */
  TA_FLAG_MULTI_SESSION | TA_FLAG_EXEC_DDR, /* FLAGS */
  "1.0.0",                                  /* VERSION */
  "enclave TA");                      /* DESCRIPTION */

OE_SET_ENCLAVE_SGX(
  1, /* ProductID */
  1, /* SecurityVersion */
#ifdef _DEBUG
  1, /* Debug */
#else
  0, /* Debug */
#endif
  HEAP_SIZE_BYTES / SGX_PAGE_SIZE,  /* NumHeapPages */
  STACK_SIZE_BYTES / SGX_PAGE_SIZE, /* NumStackPages */
  1);                               /* NumTCS */
// ==================== enclave init setting ====================

void test_ecp_secp256k1(uint8_t* ret) {
	Blob256 secret_key;
	Blob288 public_key;
	int res = ec_generate_keypair(secret_key, public_key);
	string plain_text("Hello, world!");
	Blob plain_data;
	for (char i : plain_text)
	{
		plain_data.push_back((unsigned char)i);
	}
	TRACE_ENCLAVE("Plain data:");
	for (int i = 0; i < plain_data.size(); i++)
	{
		TRACE_ENCLAVE("%02X%s", plain_data[i],
			(i + 1) % 16 == 0 ? "\r\n" : " ");
	}
	Blob publicKey(public_key.data(), public_key.data() + public_key.size());
	Blob cipher_data = asymEncrypt(plain_data, publicKey);
	TRACE_ENCLAVE("Cipher data:");
	for (int i = 0; i < cipher_data.size(); i++)
	{
		TRACE_ENCLAVE("%02X%s", cipher_data[i],
			(i + 1) % 16 == 0 ? "\r\n" : " ");
	}
	Blob secretKey(secret_key.data(), secret_key.data() + secret_key.size());
	Blob decrypted_data = asymDecrypt(cipher_data, secretKey);
	TRACE_ENCLAVE("Decrypted data:");
	for (int i = 0; i < decrypted_data.size(); i++)
	{
		TRACE_ENCLAVE("%02X%s", decrypted_data[i],
			(i + 1) % 16 == 0 ? "\r\n" : " ");
	}
	*ret = 0;
}

/* uint8_t* -> vector<uint8_t> */
std::vector<uint8_t> arr2vector(uint8_t* code_arr, size_t code_size) {
  std::vector<uint8_t> vec(code_arr, code_arr + code_size);
  return vec;
}

/* vector<uint8_t> -> uint8_t* */
uint8_t* vector2arr(std::vector<uint8_t> code) {
  uint8_t* code_arr = new uint8_t[code.size()];
  memset(code_arr, 0, sizeof(uint8_t) * code.size());
  memcpy(code_arr, &code[0], sizeof(uint8_t) * code.size());
  return code_arr;
}

/* char* -> uint64_t */
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

/* uint64_t -> char* */
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

/* compare str */
int str_compare(unsigned char* a, unsigned char* b) {
  if (strlen((char*)a) > strlen((char*)b)) {
	return 1;
  }
  if (strlen((char*)a) < strlen((char*)b)) {
	return -1;
  }
  return strcmp((char*)a, (char*)b);
}

/* compare str */
int str_compare(unsigned char* a, const char* b) {
  unsigned char* _b = const_cast<unsigned char*>((unsigned char*)b);
  return str_compare(a, _b);
}



struct Stack {
  std::deque<unsigned char*> st;
  size_t MAX_SIZE = 1024;

  unsigned char* pop() {
	//if (st.empty()) {
	//  throw "Stack out of range";
	//}
	unsigned char* val = st.front();
	st.pop_front();
	return val;
  }

  void push(unsigned char* val) {
	if (size() == MAX_SIZE) {
	  throw "Stack mem exceeded";
	}

	try {
	  st.push_front(val);
	}
	catch (std::bad_alloc&) {
	  throw std::runtime_error("bad_alloc while pushing onto stack");
	}
  }

  uint64_t size() {
	return st.size();
  }

  void swap(uint64_t i) {
	if (i >= size()) {
	  throw "Swap out of range";
	}
	std::swap(st[0], st[i]);
  }

  void dup(uint64_t a) {
	if (a >= size()) {
	  throw "Dup out of range";
	}
	st.push_front(st[a]);
  }
};

struct Program {
  std::vector<uint8_t> code;
  std::set<uint64_t> jump_dests;

  Program() {}

  Program(std::vector<uint8_t> c) :
	code(c),
	jump_dests(compute_jump_dests_by_vector(c))
  {}

  Program(uint8_t* account_code, size_t account_code_size) :
	code(compute_code(account_code, account_code_size)),
	jump_dests(compute_jump_dests(account_code, account_code_size))
  {}

  std::vector<uint8_t> compute_code(uint8_t* account_code, size_t account_code_size) {
	return arr2vector(account_code, account_code_size);
  }

  std::set<uint64_t> compute_jump_dests(uint8_t* account_code, size_t account_code_size)
  {
	std::vector<uint8_t> code = arr2vector(account_code, account_code_size);
	std::set<uint64_t> dests;
	for (uint64_t i = 0; i < code.size(); i++)
	{
	  uint8_t op = code[i];
	  if (op >= PUSH1 && op <= PUSH32)
	  {
		uint8_t immediate_bytes = op - static_cast<uint8_t>(PUSH1) + 1;
		i += immediate_bytes;
	  }
	  else if (op == JUMPDEST)
		dests.insert(i);
	}
	return dests;
  }

  std::set<uint64_t> compute_jump_dests_by_vector(std::vector<uint8_t> code)
  {
	std::set<uint64_t> dests;
	for (uint64_t i = 0; i < code.size(); i++)
	{
	  const auto op = code[i];
	  if (op >= PUSH1 && op <= PUSH32)
	  {
		const uint8_t immediate_bytes = op - static_cast<uint8_t>(PUSH1) + 1;
		i += immediate_bytes;
	  }
	  else if (op == JUMPDEST)
		dests.insert(i);
	}
	return dests;
  }
};

struct Context {
  uint64_t pc;
  bool pc_changed = true;

  Stack s;
  std::vector<uint8_t> mem;

  unsigned char* caller;
  account_struct* as;
  std::vector<uint8_t> input;
  unsigned char* call_value;
  Program prog;

  using ReturnHandler = std::function<void(std::vector<uint8_t>)>;
  using HaltHandler = std::function<void()>;
  using ExceptionHandler = std::function<void(unsigned char* _exmsg)>;

  ReturnHandler rh;
  HaltHandler hh;
  ExceptionHandler eh;

  std::vector<uint8_t> taint_list;


  Context() {}

  Context(unsigned char* caller, account_struct* as, std::vector<uint8_t> input, unsigned char* call_value, Program prog, ReturnHandler&& rh, HaltHandler&& hh, ExceptionHandler&& eh, std::vector<uint8_t> taint_list) :
	pc(0),
	caller(caller),
	as(as),
	input(input),
	call_value(call_value),
	prog(prog),
	rh(rh),
	hh(hh),
	eh(eh),
	taint_list(taint_list)
  {}

  Context(unsigned char* caller, account_struct* as, uint8_t* input, size_t input_size, unsigned char* call_value, Program prog, ReturnHandler&& rh, HaltHandler&& hh, ExceptionHandler&& eh, uint8_t* taint_list) :
	pc(0),
	caller(caller),
	as(as),
	input(arr2vector(input, input_size)),
	call_value(call_value),
	prog(prog),
	rh(rh),
	hh(hh),
	eh(eh),
	taint_list(arr2vector(taint_list, 256))
  {}

  void step() {
	if (pc_changed) {
	  pc_changed = false;
	}
	else {
	  pc++;
	}
  }

  uint64_t get_pc() {
	return pc;
  }

  void set_pc(uint64_t pc_) {
	pc = pc_;
	pc_changed = true;
  }
};



/* print char* */
void printf_charx(unsigned char* arr) {
  uint8_t i = 0;
  while (*(arr + i) != 0) {
	printf("%c", *(arr + i));
	i += 1;
  }
  printf("\n");
}

/* print uint8* */
void printf_uint8x(uint8_t* arr, size_t arr_size) {
  for (int i = 0; i < arr_size; i++) {
	printf("%d", *(arr + i));
  }
  printf("\n");
}

/* print stack */
void printf_stack(Stack s) {
  printf("stack size %d\n", s.size());
  for (int i = 0; i < s.st.size(); i++) {
	printf_charx(s.st.at(i));
  }
}

/* print memory */
void printf_mem(std::vector<uint8_t> mem) {
  printf("mem size %d\n", mem.size());
  for (int i = 0; i < mem.size(); i++) {
	printf("%d: %d  ", i, mem[i]);
  }
  printf("\n\n");
}

/* print gs */
void printf_gs(gs_struct* _gs) {
  printf("gs account size: ");
  printf_charx(_gs->accounts_size);
  for (int i = 0; i < charx2uint64((_gs->accounts_size)); i++) {
	printf("account: %d\n", i);
	printf("address: ");
	printf_charx(_gs->accounts[i].address);
	printf("balance: ");
	printf_charx(_gs->accounts[i].account.account_balance);
	printf("code size: ");
	printf_charx(_gs->accounts[i].account.account_code_size);

	printf("storage size: ");
	printf_charx(_gs->accounts[i].account.storage_size);
	for (int j = 0; j < charx2uint64(_gs->accounts[i].account.storage_size); j++) {
	  printf("key: ");
	  printf_charx(_gs->accounts[i].account.storage[j].key);
	  printf("value: ");
	  printf_charx(_gs->accounts[i].account.storage[j].value);
	}
  }
}



std::map<char*, uint8_t> ExitReason = {
  {"returned", 0},
  {"halted", 1},
  {"threw", 2}
};

void push_context(
  std::vector<Context>* ctxts,
  Context** ctxt,
  unsigned char* caller,
  account_struct* callee,
  uint8_t* input,
  size_t input_size,
  unsigned char* call_value,
  Program prog,
  std::function<void(std::vector<uint8_t>)>&& rh,
  std::function<void()>&& hh,
  std::function<void(unsigned char* _exmsg)>&& eh,
  uint8_t* taint_list
) {
  Context c = Context(caller, callee, input, input_size, call_value, prog, std::move(rh), std::move(hh), std::move(eh), taint_list);
  ctxts->emplace_back(std::move(c));
  *ctxt = &ctxts->back();
}

void push_context(
  std::vector<Context>* ctxts,
  Context** ctxt,
  unsigned char* caller,
  account_struct* callee,
  std::vector<uint8_t> input,
  unsigned char* call_value,
  Program prog,
  std::function<void(std::vector<uint8_t>)>&& rh,
  std::function<void()>&& hh,
  std::function<void(unsigned char* _exmsg)>&& eh,
  std::vector<uint8_t> taint_list
) {
  Context c = Context(caller, std::move(callee), input, call_value, prog, std::move(rh), std::move(hh), std::move(eh), taint_list);
  ctxts->emplace_back(std::move(c));
  *ctxt = &ctxts->back();
}

Opcode get_op(uint64_t pc, std::vector<uint8_t> code) {
  return static_cast<Opcode>(code[pc]);
}

void copy_mem_raw(const uint64_t offDst, const uint64_t offSrc, const uint64_t size, std::vector<uint8_t>& dst, const std::vector<uint8_t>& src, const uint8_t pad = 0) {
  if (!size) {
	return;
  }

  auto lastDst = offDst + size;
  if (lastDst < offDst) {
	throw "Integer overflow in copy_mem";
  }
  if (lastDst > 1ull << 25) {
	throw "Memory limit exceeded";
  }

  if (lastDst > dst.size()) {
	dst.resize(lastDst);
  }

  auto lastSrc = offSrc + size;
  auto endSrc = std::min(lastSrc, static_cast<decltype(lastSrc)>(src.size()));
  uint64_t remaining;
  if (endSrc > offSrc) {
	copy(src.begin() + offSrc, src.begin() + endSrc, dst.begin() + offDst);
	remaining = lastSrc - endSrc;
  }
  else {
	remaining = size;
  }

  fill(dst.begin() + lastDst - remaining, dst.begin() + lastDst, pad);
}

void copy_mem(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src, const uint8_t pad, Context* ctxt) {
  auto offDst = charx2uint64(ctxt->s.pop());
  auto offSrc = charx2uint64(ctxt->s.pop());
  auto size = charx2uint64(ctxt->s.pop());

  copy_mem_raw(offDst, offSrc, size, dst, src, pad);
}

void prepare_mem_access(uint64_t offset, uint64_t size, std::vector<uint8_t>* mem) {
  uint64_t end = offset + size;
  if (end < offset) {
	throw "Integer overflow in memory access";
  }
  if (end > 1ull << 25) {
	throw "Memory limit exceeded";
  }

  if (end > mem->size()) {
	mem->resize(end);
  }
}

std::vector<uint8_t> copy_from_mem(uint64_t offset, uint64_t size, std::vector<uint8_t>* mem)
{
  prepare_mem_access(offset, size, mem);
  return { mem->begin() + offset, mem->begin() + offset + size };
}

void a_pay_b(account_struct* a, account_struct* b, unsigned char* value) {
  if (str_compare(a->account_balance, value) < 0) {
	throw "Insufficient funds to pay";
  }
  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  add_ocall(b->account_balance, value, res);
  memcpy(b->account_balance, res, strlen((char*)res) + 1);
  memset(res, 0, sizeof(unsigned char) * 100);
  sub_ocall(a->account_balance, value, res);
  memcpy(a->account_balance, res, strlen((char*)res) + 1);

  unsigned char* tmp1 = uint642charx(charx2uint64(a->account_nonce) + 1);
  memcpy(a->account_nonce, tmp1, strlen((char*)tmp1) + 1);
  unsigned char* tmp2 = uint642charx(charx2uint64(b->account_nonce) + 1);
  memcpy(b->account_nonce, tmp2, strlen((char*)tmp2) + 1);
}

void pop_context(std::vector<Context>* ctxts, Context** ctxt) {
  ctxts->pop_back();
  if (!ctxts->empty()) {
	*ctxt = &ctxts->back();
  }
  else {
	*ctxt = nullptr;
  }
}

unsigned char* pop_addr(unsigned char* n) {
  return myBigInt::and_(n, (unsigned char*)myBigInt::MASK_160);
}

void keccak_256(
  const unsigned char* input,
  unsigned int inputByteLen,
  unsigned char* output)
{
  // Ethereum started using Keccak and called it SHA3 before it was finalised.
  // Standard SHA3-256 (the FIPS accepted version) uses padding 0x06, but
  // Ethereum's "Keccak-256" uses padding 0x01.
  // All other constants are copied from Keccak_HashInitialize_SHA3_256 in
  // KeccakHash.h.
  Keccak_HashInstance hi;
  Keccak_HashInitialize(&hi, 1088, 512, 256, 0x01);
  Keccak_HashUpdate(
	&hi, input, inputByteLen * std::numeric_limits<unsigned char>::digits);
  Keccak_HashFinal(&hi, output);
}



void return_(std::vector<Context>* ctxts, Context** ctxt, exec_result_struct* result) {
  uint64_t offset = charx2uint64((*ctxt)->s.pop());
  uint64_t size = charx2uint64((*ctxt)->s.pop());

  (*ctxt)->rh(copy_from_mem(offset, size, &(*ctxt)->mem));

  pop_context(ctxts, ctxt);
}

void stop(std::vector<Context>* ctxts, Context** ctxt, exec_result_struct* result) {
  auto hh = (*ctxt)->hh;
  pop_context(ctxts, ctxt);
  hh();
}

void revert(std::vector<Context>* ctxts, Context** ctxt, exec_result_struct* result) {
  auto hh = (*ctxt)->hh;
  pop_context(ctxts, ctxt);
  hh();
}

void pop(Context* ctxt) {
  ctxt->s.pop();
}

void swap(Context* ctxt) {
  ctxt->s.swap(get_op(ctxt->get_pc(), ctxt->prog.code) - SWAP1 + 1);
}

void dup(Context* ctxt) {
  ctxt->s.dup(get_op(ctxt->get_pc(), ctxt->prog.code) - DUP1);
}

void log(Context* ctxt, tx_struct* _tx) {
  uint8_t n = get_op(ctxt->get_pc(), ctxt->prog.code) - Opcode::LOG0;
  uint64_t offset = charx2uint64(ctxt->s.pop());
  uint64_t size = charx2uint64(ctxt->s.pop());

  std::vector<uint8_t> mem_vector = copy_from_mem(offset, size, &ctxt->mem);
  uint8_t* mem = vector2arr(mem_vector);

  unsigned char** topics = new unsigned char* [n];
  for (int i = 0; i < n; i++) {
	topics[n] = new unsigned char[100];
  }
  for (int i = 0; i < n; i++) {
	*(topics + i) = ctxt->s.pop();
  }
}

void jump(Context* ctxt) {
  uint64_t newPc = charx2uint64(ctxt->s.pop());
  if (ctxt->prog.jump_dests.find(newPc) == ctxt->prog.jump_dests.end()) {
	throw "not a jump destination";
  }
  ctxt->set_pc(newPc);
}

void jumpi(Context* ctxt) {
  uint64_t newPc = charx2uint64(ctxt->s.pop());
  unsigned char* cond = ctxt->s.pop();
  if (str_compare(cond, "0") != 0) {
	if (ctxt->prog.jump_dests.find(newPc) == ctxt->prog.jump_dests.end()) {
	  throw "not a jump destination";
	}
	ctxt->set_pc(newPc);
  }
}

void pc(Context* ctxt) {
  ctxt->s.push(uint642charx(ctxt->get_pc()));
}

void msize(Context* ctxt) {
  ctxt->s.push(uint642charx(((ctxt->mem.size() + 32u - 1) / 32u) * 32));
}

void codesize(Context* ctxt) {
  ctxt->s.push(ctxt->as->account_code_size);
}

void codecopy(Context* ctxt) {
  copy_mem(ctxt->mem, ctxt->prog.code, Opcode::STOP, ctxt);
}

void extcodesize(Context* ctxt, gs_struct* _gs) {
  unsigned char* addr = pop_addr(ctxt->s.pop());

  account_struct* acc = nullptr;
  for (int i = 0; i < charx2uint64(_gs->accounts_size); i++) {
	if (str_compare(addr, (_gs->accounts + i)->address) == 0) {
	  acc = &((_gs->accounts + i)->account);
	  break;
	}
  }
  if (!acc) {
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].address, addr, strlen((char*)addr) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_address, addr, strlen((char*)addr) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_balance, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code, {}, 0);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_nonce, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.storage_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts_size, uint642charx(charx2uint64(_gs->accounts_size) + 1), strlen((char*)uint642charx(charx2uint64(_gs->accounts_size) + 1)) + 1);

	acc = &_gs->accounts[charx2uint64(_gs->accounts_size) - 1].account;
  }

  ctxt->s.push(acc->account_code_size);
}

void extcodecopy(Context* ctxt, gs_struct* _gs) {
  unsigned char* addr = pop_addr(ctxt->s.pop());

  account_struct* acc = nullptr;
  for (int i = 0; i < charx2uint64(_gs->accounts_size); i++) {
	if (str_compare(addr, (_gs->accounts + i)->address) == 0) {
	  acc = &((_gs->accounts + i)->account);
	  break;
	}
  }
  if (!acc) {
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].address, addr, strlen((char*)addr) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_address, addr, strlen((char*)addr) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_balance, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code, {}, 0);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_nonce, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.storage_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts_size, uint642charx(charx2uint64(_gs->accounts_size) + 1), strlen((char*)uint642charx(charx2uint64(_gs->accounts_size) + 1)) + 1);

	acc = &_gs->accounts[charx2uint64(_gs->accounts_size) - 1].account;
  }

  std::vector<uint8_t> code = arr2vector(acc->account_code, charx2uint64(acc->account_code_size));

  copy_mem(ctxt->mem, code, Opcode::STOP, ctxt);

  memcpy(acc->account_code, vector2arr(code), code.size() + 1);
  memcpy(acc->account_code_size, uint642charx(code.size()), strlen((char*)uint642charx(code.size())) + 1);
}

void sload(Context* ctxt) {
  unsigned char* k = ctxt->s.pop();
  bool flag = false;
  unsigned char* v = new unsigned char[200];
  memset(v, 0, sizeof(unsigned char) * 200);
  for (int i = 0; i < charx2uint64(ctxt->as->storage_size); i++) {
	if (str_compare((ctxt->as->storage + i)->key, k) == 0) {
	  memcpy(v, (ctxt->as->storage + i)->value, strlen((char*)(ctxt->as->storage + i)->value) + 1);
	  flag = true;
	  break;
	}
  }
  if (!flag) {
	v = new unsigned char[200];
	memset(v, 0, sizeof(unsigned char) * 200);
	v[0] = '0';
  }
  ctxt->s.push(v);
}

void sstore(Context* ctxt) {
  unsigned char* k = ctxt->s.pop();
  unsigned char* v = ctxt->s.pop();
  if (str_compare(v, "0") == 0) {
	std::vector<storage_struct> vec(ctxt->as->storage, ctxt->as->storage + charx2uint64(ctxt->as->storage_size));
	std::vector<storage_struct> res;
	for (int i = 0; i < vec.size(); i++) {
	  if (str_compare(vec[i].key, k) != 0) {
		res.push_back({ vec[i].key, vec[i].value });
	  }
	}
	for (int i = 0; i < res.size(); i++) {
	  memcpy(ctxt->as->storage[i].key, res[i].key, strlen((char*)res[i].key) + 1);
	  memcpy(ctxt->as->storage[i].value, res[i].value, strlen((char*)res[i].value) + 1);
	}
	memcpy(ctxt->as->storage_size, uint642charx(res.size()), strlen((char*)uint642charx(res.size())) + 1);
  }
  else {
	std::vector<storage_struct> res(ctxt->as->storage, ctxt->as->storage + charx2uint64(ctxt->as->storage_size));
	bool flag = true;
	for (int i = 0; i < res.size(); i++) {
	  if (strcmp((char*)res[i].key, (char*)k) == 0) {
		res[i] = { k, v };
		flag = false;
		break;
	  }
	}
	if (flag) {
	  res.push_back({ k,v });
	}
	for (int i = 0; i < res.size(); i++) {
	  memcpy(ctxt->as->storage[i].key, res[i].key, strlen((char*)res[i].key) + 1);
	  memcpy(ctxt->as->storage[i].value, res[i].value, strlen((char*)res[i].value) + 1);
	}
	memcpy(ctxt->as->storage_size, uint642charx(res.size()), strlen((char*)uint642charx(res.size())) + 1);
  }
}

void address(Context* ctxt) {
  ctxt->s.push(ctxt->as->account_address);
}

void balance(Context* ctxt, gs_struct* _gs) {
  unsigned char* addr = pop_addr(ctxt->s.pop());

  account_struct* acc = nullptr;
  for (int i = 0; i < charx2uint64(_gs->accounts_size); i++) {
	if (str_compare(addr, (_gs->accounts + i)->address) == 0) {
	  acc = &((_gs->accounts + i)->account);
	  break;
	}
  }

  if (!acc) {
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].address, addr, strlen((char*)addr) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_address, addr, strlen((char*)addr) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_balance, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code, {}, 0);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_nonce, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.storage_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts_size, uint642charx(charx2uint64(_gs->accounts_size) + 1), strlen((char*)uint642charx(charx2uint64(_gs->accounts_size) + 1)) + 1);

	acc = &_gs->accounts[charx2uint64(_gs->accounts_size) - 1].account;
  }

  ctxt->s.push(acc->account_balance);
}

void origin(Context* ctxt, tx_struct* _tx) {
  ctxt->s.push(_tx->origin);
}

void caller(Context* ctxt) {
  ctxt->s.push(ctxt->caller);
}

void callvalue(Context* ctxt) {
  ctxt->s.push(ctxt->call_value);
}

void calldatasize(Context* ctxt) {
  ctxt->s.push(uint642charx(ctxt->input.size()));
}

void calldatacopy(Context* ctxt) {
  copy_mem(ctxt->mem, ctxt->input, 0, ctxt);
}

void selfdestruct(std::vector<Context>* ctxts, Context** ctxt, exec_result_struct* result, gs_struct* _gs, tx_struct* _tx) {
  unsigned char* addr = pop_addr((*ctxt)->s.pop());

  account_struct* recipient = nullptr;
  for (int i = 0; i < charx2uint64(_gs->accounts_size); i++) {
	if (str_compare(addr, (_gs->accounts + i)->address) == 0) {
	  recipient = &((_gs->accounts + i)->account);
	  break;
	}
  }
  if (!recipient) {
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].address, addr, strlen((char*)addr) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_address, addr, strlen((char*)addr) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_balance, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code, {}, 0);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_nonce, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.storage_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts_size, uint642charx(charx2uint64(_gs->accounts_size) + 1), strlen((char*)uint642charx(charx2uint64(_gs->accounts_size) + 1)) + 1);

	recipient = &_gs->accounts[charx2uint64(_gs->accounts_size) - 1].account;
  }

  a_pay_b((*ctxt)->as, recipient, (*ctxt)->as->account_balance);

  memcpy(*(_tx->selfdestruct_list + charx2uint64(_tx->selfdestruct_list_size)), (*ctxt)->as->account_address, strlen((char*)(*ctxt)->as->account_address) + 1);
  memcpy(_tx->selfdestruct_list_size, uint642charx(charx2uint64(_tx->selfdestruct_list_size) + 1), strlen((char*)uint642charx(charx2uint64(_tx->selfdestruct_list_size) + 1)) + 1);

  stop(ctxts, ctxt, result);
}

void create(std::vector<Context>* ctxts, Context* ctxt, gs_struct* _gs) {
  unsigned char* contractValue = ctxt->s.pop();
  const uint64_t offset = charx2uint64(ctxt->s.pop());
  const uint64_t size = charx2uint64(ctxt->s.pop());
  std::vector<uint8_t> initCode = copy_from_mem(offset, size, &ctxt->mem);

  unsigned char* newAddress = new unsigned char[100];
  memset(newAddress, 0, sizeof(unsigned char) * 100);
  generate_address_ocall(ctxt->as->account_address, charx2uint64(ctxt->as->account_nonce), newAddress);

  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].address, newAddress, strlen((char*)newAddress) + 1);
  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_address, newAddress, strlen((char*)newAddress) + 1);
  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_balance, contractValue, strlen((char*)contractValue) + 1);
  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code, {}, 0);
  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_nonce, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.storage_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
  memcpy(_gs->accounts_size, uint642charx(charx2uint64(_gs->accounts_size) + 1), strlen((char*)uint642charx(charx2uint64(_gs->accounts_size) + 1)) + 1);

  account_struct* newAcc = &_gs->accounts[charx2uint64(_gs->accounts_size) - 1].account;

  a_pay_b(ctxt->as, newAcc, contractValue);

  Context* parentContext = ctxt;
  auto rh = [newAcc, parentContext](std::vector<uint8_t> output) {
	memcpy(newAcc->account_code, &output[0], sizeof(uint8_t) * output.size());
	memcpy(newAcc->account_code_size, uint642charx(output.size()), strlen((char*)uint642charx(output.size())) + 1);
	parentContext->s.push(newAcc->account_address);
  };
  auto hh = [parentContext]() { parentContext->s.push((unsigned char*)"0"); };
  auto eh = [parentContext](unsigned char* _exmsg) { parentContext->s.push((unsigned char*)"0"); };

  push_context(ctxts, &ctxt, ctxt->as->account_address, newAcc, {}, 0, (unsigned char*)"0", Program(initCode), rh, hh, eh, vector2arr(ctxt->taint_list));
}

void call(std::vector<Context>* ctxts, Context* ctxt, gs_struct* _gs) {
  const Opcode op = get_op(ctxt->get_pc(), ctxt->prog.code);
  ctxt->s.pop();
  unsigned char* addr = pop_addr(ctxt->s.pop());
  unsigned char* value = const_cast<unsigned char*>(op == DELEGATECALL ? (unsigned char*)"0" : ctxt->s.pop());
  const uint64_t offIn = charx2uint64(ctxt->s.pop());
  const uint64_t sizeIn = charx2uint64(ctxt->s.pop());
  const uint64_t offOut = charx2uint64(ctxt->s.pop());
  const uint64_t sizeOut = charx2uint64(ctxt->s.pop());

  if (str_compare(addr, "1") >= 0 && str_compare(addr, "8") <= 0) {
	throw "Precompiled contracts/native extensions are not implemented";
  }

  account_struct* callee = nullptr;
  for (int i = 0; i < charx2uint64(_gs->accounts_size); i++) {
	if (str_compare(addr, (_gs->accounts + i)->address) == 0) {
	  callee = &(((_gs->accounts + i))->account);
	  break;
	}
  }
  if (!callee) {
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].address, addr, strlen((char*)addr) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_address, addr, strlen((char*)addr) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_balance, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code, {}, 0);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_nonce, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.storage_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
	memcpy(_gs->accounts_size, uint642charx(charx2uint64(_gs->accounts_size) + 1), strlen((char*)uint642charx(charx2uint64(_gs->accounts_size) + 1)) + 1);

	callee = &_gs->accounts[charx2uint64(_gs->accounts_size) - 1].account;
  }

  a_pay_b(ctxt->as, callee, value);

  if (str_compare(callee->account_code_size, "0") == 0) {
	ctxt->s.push((unsigned char*)"1");
	return;
  }

  prepare_mem_access(offOut, sizeOut, &ctxt->mem);
  std::vector<uint8_t> input = copy_from_mem(offIn, sizeIn, &ctxt->mem);

  Context* parentContext = ctxt;
  auto rh = [offOut, sizeOut, parentContext](const std::vector<uint8_t>& output) {
	copy_mem_raw(offOut, 0, sizeOut, parentContext->mem, output);
	parentContext->s.push((unsigned char*)"1");
  };
  auto hh = [parentContext]() { parentContext->s.push((unsigned char*)"1"); };
  auto eh = [parentContext](unsigned char* _exmsg) { parentContext->s.push((unsigned char*)"0"); };

  switch (op)
  {
  case Opcode::CALL:
	push_context(ctxts, &ctxt, ctxt->as->account_address, callee, ctxt->input, value, Program(callee->account_code, charx2uint64(callee->account_code_size)), rh, hh, eh, ctxt->taint_list);
	break;
  case Opcode::CALLCODE:
	push_context(ctxts, &ctxt, ctxt->as->account_address, ctxt->as, ctxt->input, value, Program(callee->account_code, charx2uint64(callee->account_code_size)), rh, hh, eh, ctxt->taint_list);
	break;
  case Opcode::DELEGATECALL:
	push_context(ctxts, &ctxt, ctxt->caller, ctxt->as, ctxt->input, ctxt->call_value, Program(callee->account_code, charx2uint64(callee->account_code_size)), rh, hh, eh, ctxt->taint_list);
	break;
  default:
	throw "Unknown call opcode";
  }
}

void jumpdest(Context* ctxt) {}

void number(Context* ctxt, gs_struct* _gs) {
  ctxt->s.push(uint642charx(_gs->currentBlock.number));
}

void gasprice(Context* ctxt, tx_struct* _tx) {
  ctxt->s.push(uint642charx(_tx->gas_price));
}

void coinbase(Context* ctxt, gs_struct* _gs) {
  ctxt->s.push(_gs->currentBlock.coinbase);
}

void timestamp(Context* ctxt, gs_struct* _gs) {
  ctxt->s.push(uint642charx(_gs->currentBlock.timestamp));
}

void difficulty(Context* ctxt, gs_struct* _gs) {
  ctxt->s.push(uint642charx(_gs->currentBlock.difficulty));
}

void gaslimit(Context* ctxt, gs_struct* _gs) {
  ctxt->s.push(uint642charx(_gs->currentBlock.gas_limit));
}

void gas(Context* ctxt, tx_struct* _tx) {
  ctxt->s.push(uint642charx(_tx->gas_limit));
}

void add_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  ctxt->s.push(myBigInt::add(x, y));
}

void add_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  add_ocall(x, y, res);
  ctxt->s.push(res);
}

void addmod_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();
  unsigned char* m = ctxt->s.pop();

  if (strcmp((char*)m, "0") == 0) {
	ctxt->s.push((unsigned char*)"0");
  }
  else {
	unsigned char* n = myBigInt::mod(myBigInt::add(x, y), m);
	ctxt->s.push(myBigInt::get_lo(n, 256));
  }
}

void addmod_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();
  unsigned char* m = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  addmod_ocall(x, y, m, res);
  ctxt->s.push(res);
}

void and_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  ctxt->s.push(myBigInt::and_(x, y));
}

void and_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  and_ocall(x, y, res);
  ctxt->s.push(res);
}

void blockhash_e(Context* ctxt, gs_struct* _gs) {
  unsigned char* i = ctxt->s.pop();
  if (str_compare(i, "256") >= 0) {
	ctxt->s.push((unsigned char*)"0");
  }
  else {
	//ctxt->s.push(gs.get_block_hash(i % 256));
	ctxt->s.push((unsigned char*)"0");
  }
}

void blockhash_o(Context* ctxt, gs_struct* _gs) {
  unsigned char* i = ctxt->s.pop();
  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  blockhash_ocall(i, res);
  ctxt->s.push(res);
}

void byte_e(Context* ctxt) {
  unsigned char* idx = ctxt->s.pop();

  if (str_compare(idx, "32") >= 0) {
	ctxt->s.push((unsigned char*)"0");
  }
  else {
	unsigned char* shift = myBigInt::sub((unsigned char*)"248", myBigInt::mul((unsigned char*)"8", myBigInt::and_(idx, (unsigned char*)"255")));
	unsigned char* mask = myBigInt::leftmove((unsigned char*)"255", shift);
	ctxt->s.push(myBigInt::rightmove(myBigInt::and_(ctxt->s.pop(), mask), shift));
  }
}

void byte_o(Context* ctxt) {
  unsigned char* idx = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  byte_ocall(idx, ctxt->s.pop(), res);
  ctxt->s.push(res);
}

void calldataload_e(Context* ctxt) {
  uint64_t offset = charx2uint64(ctxt->s.pop());
  uint64_t sizeInput = ctxt->input.size();

  unsigned char* v = (unsigned char*)"0";
  for (uint8_t i = 0; i < 32u; i++)
  {
	const auto j = offset + i;
	if (j < sizeInput)
	{
	  v = myBigInt::add(myBigInt::leftmove(v, 8), uint642charx(ctxt->input[j]));
	}
	else
	{
	  v = myBigInt::leftmove(v, 8 * (32u - i));
	  break;
	}
  }
  ctxt->s.push(v);
}

void calldataload_o(Context* ctxt) {
  uint64_t offset = charx2uint64(ctxt->s.pop());
  uint64_t sizeInput = ctxt->input.size();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  calldataload_ocall(offset, sizeInput, vector2arr(ctxt->input), ctxt->input.size(), res);
  ctxt->s.push(res);
}

void div_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  if (strcmp((char*)y, "0") == 0) {
	ctxt->s.push((unsigned char*)"0");
  }
  else {
	ctxt->s.push(myBigInt::div(x, y));
  }
}

void div_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  div_ocall(x, y, res);
  ctxt->s.push(res);
}

void eq_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  if (str_compare(x, y) == 0) {
	ctxt->s.push((unsigned char*)"1");
  }
  else {
	ctxt->s.push((unsigned char*)"0");
  }
}

void eq_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  eq_ocall(x, y, res);
  ctxt->s.push(res);
}

void exp_e(Context* ctxt) {
  unsigned char* b = ctxt->s.pop();
  unsigned char* e = ctxt->s.pop();

  ctxt->s.push(myBigInt::exp(b, e));
}

void exp_o(Context* ctxt) {
  unsigned char* b = ctxt->s.pop();
  unsigned char* e = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  exp_ocall(b, e, res);
  ctxt->s.push(res);
}

void gt_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  if (str_compare(x, y) > 0) {
	ctxt->s.push((unsigned char*)"1");
  }
  else {
	ctxt->s.push((unsigned char*)"0");
  }
}

void gt_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  gt_ocall(x, y, res);
  ctxt->s.push(res);
}

void isZero_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();

  if (str_compare(x, "0") == 0) {
	ctxt->s.push((unsigned char*)"1");
  }
  else {
	ctxt->s.push((unsigned char*)"0");
  }
}

void isZero_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  isZero_ocall(x, res);
  ctxt->s.push(res);
}

void lt_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  if (str_compare(x, y) < 0) {
	ctxt->s.push((unsigned char*)"1");
  }
  else {
	ctxt->s.push((unsigned char*)"0");
  }
}

void lt_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  lt_ocall(x, y, res);
  ctxt->s.push(res);
}

void mload_e(Context* ctxt) {
  uint64_t offset = charx2uint64(ctxt->s.pop());
  prepare_mem_access(offset, 32u, &ctxt->mem);

  const auto start = ctxt->mem.data() + offset;
  ctxt->s.push(myBigInt::from_big_endian(start, 32u));
}

void mload_o(Context* ctxt) {
  uint64_t offset = charx2uint64(ctxt->s.pop());
  prepare_mem_access(offset, 32u, &ctxt->mem);

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  from_big_endian_ocall(ctxt->mem.data() + offset, 32u, ctxt->mem.size() - offset, res);
  ctxt->s.push(res);
}

void mod_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  if (strcmp((char*)y, "0") == 0) {
	ctxt->s.push((unsigned char*)"0");
  }
  else {
	ctxt->s.push(myBigInt::mod(x, y));
  }
}

void mod_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  mod_ocall(x, y, res);
  ctxt->s.push(res);
}

void mstore_e(Context* ctxt) {
  uint64_t offset = charx2uint64(ctxt->s.pop());
  unsigned char* word = ctxt->s.pop();
  prepare_mem_access(offset, 32u, &ctxt->mem);

  myBigInt::to_big_endian(word, ctxt->mem.data() + offset);
}

void mstore_o(Context* ctxt) {
  uint64_t offset = charx2uint64(ctxt->s.pop());
  unsigned char* word = ctxt->s.pop();
  prepare_mem_access(offset, 32u, &ctxt->mem);

  to_big_endian_ocall(word, ctxt->mem.data() + offset, ctxt->mem.size() - offset);
}

void mstore8_e(Context* ctxt) {
  uint64_t offset = charx2uint64(ctxt->s.pop());
  uint8_t b = 0;

  unsigned char* bb = myBigInt::and_(ctxt->s.pop(), (unsigned char*)"255");
  int end = 0;
  while (*(bb + end) != 0) {
	b *= 10;
	b += static_cast<uint8_t>(*(bb + end) - '0');
	end += 1;
  }

  prepare_mem_access(offset, sizeof(b), &ctxt->mem);
  ctxt->mem[offset] = b;
}

void mstore8_o(Context* ctxt) {
  uint64_t offset = charx2uint64(ctxt->s.pop());
  uint8_t b = 0;

  mstore8_ocall(&b, ctxt->s.pop());

  prepare_mem_access(offset, sizeof(b), &ctxt->mem);
  ctxt->mem[offset] = b;
}

void mul_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  ctxt->s.push(myBigInt::mul(x, y));
}

void mul_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  mul_ocall(x, y, res);
  ctxt->s.push(res);
}

void mulmod_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();
  unsigned char* m = ctxt->s.pop();

  if (strcmp((char*)m, "0") == 0) {
	ctxt->s.push(m);
  }
  else {
	unsigned char* n = myBigInt::mod(myBigInt::mul(x, y), m);
	ctxt->s.push(myBigInt::get_lo(n, 256));
  }
}

void mulmod_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();
  unsigned char* m = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  mulmod_ocall(x, y, m, res);
  ctxt->s.push(res);
}

void not_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();

  ctxt->s.push(myBigInt::not_(x));
}

void not_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  not_ocall(x, res);
  ctxt->s.push(res);
}

void or_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  ctxt->s.push(myBigInt::or_(x, y));
}

void or_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  or_ocall(x, y, res);
  ctxt->s.push(res);
}

void push_e(Context* ctxt) {
  uint8_t bytes = get_op(ctxt->get_pc(), ctxt->prog.code) - PUSH1 + 1;
  uint64_t end = ctxt->get_pc() + bytes;
  if (end < ctxt->get_pc()) {
	throw "Integer overflow in push";
  }
  if (end >= ctxt->prog.code.size()) {
	throw "Push immediate exceeds size of program";
  }

  uint64_t _pc = ctxt->get_pc() + 1;
  unsigned char* imm = new unsigned char[100];
  memset(imm, 0, sizeof(char) * 100);

  imm[0] = '0';
  for (int i = 0; i < bytes; i++) {
	imm = myBigInt::or_(myBigInt::leftmove(imm, 8), uint642charx(ctxt->prog.code[_pc]));
	_pc += 1;
  }

  ctxt->s.push(imm);
  ctxt->set_pc(_pc);
}

void push_o(Context* ctxt) {
  uint8_t bytes = get_op(ctxt->get_pc(), ctxt->prog.code) - PUSH1 + 1;
  uint64_t end = ctxt->get_pc() + bytes;
  if (end < ctxt->get_pc()) {
	throw "Integer overflow in push";
  }
  if (end >= ctxt->prog.code.size()) {
	throw "Push immediate exceeds size of program";
  }

  uint64_t _pc = ctxt->get_pc() + 1;
  unsigned char* imm = new unsigned char[100];
  memset(imm, 0, sizeof(char) * 100);

  push_ocall(&_pc, bytes, vector2arr(ctxt->prog.code), ctxt->prog.code.size(), imm);

  ctxt->s.push(imm);
  ctxt->set_pc(_pc);
}

void sdiv_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* min = myBigInt::add(myBigInt::div((unsigned char*)myBigInt::MAX, (unsigned char*)"2"), (unsigned char*)"1");
  if (strcmp((char*)y, "0") == 0) {
	ctxt->s.push((unsigned char*)"0");
  }
  else if (strcmp((char*)x, (char*)min) == 0 && strcmp((char*)y, "-1") == 0) {
	ctxt->s.push(x);
  }
  else {
	int signX = str_compare(myBigInt::rightmove(x, 255), "0") ? -1 : 1;
	int signY = str_compare(myBigInt::rightmove(y, 255), "0") ? -1 : 1;
	if (signX == -1) {
	  x = myBigInt::sub((unsigned char*)"0", x);
	}
	if (signY == -1) {
	  y = myBigInt::sub((unsigned char*)"0", y);
	}
	unsigned char* z = myBigInt::div(x, y);
	if (signX != signY) {
	  z = myBigInt::sub((unsigned char*)"0", z);
	}
	ctxt->s.push(z);
  }
}

void sdiv_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  sdiv_ocall(x, y, res);
  ctxt->s.push(res);
}

void sha3_e(Context* ctxt) {
  uint64_t offset = charx2uint64(ctxt->s.pop());
  uint64_t size = charx2uint64(ctxt->s.pop());
  prepare_mem_access(offset, size, &ctxt->mem);

  uint8_t h[32];
  keccak_256(ctxt->mem.data() + offset, static_cast<unsigned int>(size), h);

  ctxt->s.push(myBigInt::from_big_endian(h, sizeof(h)));
}

void sha3_o(Context* ctxt) {
  uint64_t offset = charx2uint64(ctxt->s.pop());
  uint64_t size = charx2uint64(ctxt->s.pop());
  prepare_mem_access(offset, size, &ctxt->mem);

  uint8_t h[32];
  keccak_256(ctxt->mem.data() + offset, static_cast<unsigned int>(size), h);

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  sha3_ocall(h, res);
  ctxt->s.push(res);
}

void shl_e(Context* ctxt) {
  unsigned char* arg1 = ctxt->s.pop();
  unsigned char* arg2 = ctxt->s.pop();

  if (str_compare(arg1, "256") >= 0) {
	ctxt->s.push((unsigned char*)"0");
	return;
  }
  unsigned char* val = myBigInt::leftmove(arg2, arg1);
  ctxt->s.push(val);
}

void shl_o(Context* ctxt) {
  unsigned char* arg1 = ctxt->s.pop();
  unsigned char* arg2 = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  shl_ocall(arg1, arg2, res);
  ctxt->s.push(res);
}

void shr_e(Context* ctxt) {
  unsigned char* arg1 = ctxt->s.pop();
  unsigned char* arg2 = ctxt->s.pop();

  if (str_compare(arg1, "256") >= 0) {
	ctxt->s.push((unsigned char*)"0");
	return;
  }
  unsigned char* val = myBigInt::rightmove(arg2, arg1);
  ctxt->s.push(val);
}

void shr_o(Context* ctxt) {
  unsigned char* arg1 = ctxt->s.pop();
  unsigned char* arg2 = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  shr_ocall(arg1, arg2, res);
  ctxt->s.push(res);
}

void signextend_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  if (str_compare(x, "32") >= 0) {
	ctxt->s.push(y);
  }
  else {
	unsigned char* idx = myBigInt::add(myBigInt::mul((unsigned char*)"8", myBigInt::and_(x, (unsigned char*)myBigInt::MAX)), (unsigned char*)"7");
	unsigned char* sign = myBigInt::and_(myBigInt::rightmove(y, idx), (unsigned char*)"1");
	unsigned char* zero = (unsigned char*)"0";
	unsigned char* mask = myBigInt::rightmove(myBigInt::not_(zero), myBigInt::sub((unsigned char*)"256", idx));
	unsigned char* yex = myBigInt::or_(myBigInt::leftmove(str_compare(sign, "0") ? myBigInt::not_(zero) : zero, idx), myBigInt::and_(y, mask));
	ctxt->s.push(yex);
  }
}

void signextend_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  signextend_ocall(x, y, res);
  ctxt->s.push(res);
}

void slt_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  if (str_compare(x, y) == 0) {
	ctxt->s.push((unsigned char*)"0");
  }
  else {
	int signX = str_compare(myBigInt::rightmove(x, 255), "0") ? -1 : 1;
	int signY = str_compare(myBigInt::rightmove(y, 255), "0") ? -1 : 1;
	if (signX != signY) {
	  if (signX == -1) {
		ctxt->s.push((unsigned char*)"1");
	  }
	  else {
		ctxt->s.push((unsigned char*)"0");
	  }
	}
	else {
	  if (str_compare(x, y) < 0) {
		ctxt->s.push((unsigned char*)"1");
	  }
	  else {
		ctxt->s.push((unsigned char*)"0");
	  }
	}
  }
}

void slt_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  slt_ocall(x, y, res);
  ctxt->s.push(res);
}

void smod_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  if (strcmp((char*)y, "0") == 0) {
	ctxt->s.push((unsigned char*)"0");
  }
  else {
	int signX = str_compare(myBigInt::rightmove(x, 255), "0") ? -1 : 1;
	int signY = str_compare(myBigInt::rightmove(y, 255), "0") ? -1 : 1;
	if (signX == -1) {
	  x = myBigInt::sub((unsigned char*)"0", x);
	}
	if (signY == -1) {
	  y = myBigInt::sub((unsigned char*)"0", y);
	}
	unsigned char* z = myBigInt::mod(x, y);
	if (signX == -1) {
	  z = myBigInt::sub((unsigned char*)"0", z);
	}
	ctxt->s.push(z);
  }
}

void smod_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  smod_ocall(x, y, res);
  ctxt->s.push(res);
}

void sub_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  ctxt->s.push(myBigInt::sub(x, y));
}

void sub_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  sub_ocall(x, y, res);
  ctxt->s.push(res);
}

void xor_e(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  ctxt->s.push(myBigInt::xor_(x, y));
}

void xor_o(Context* ctxt) {
  unsigned char* x = ctxt->s.pop();
  unsigned char* y = ctxt->s.pop();

  unsigned char* res = new unsigned char[100];
  memset(res, 0, sizeof(unsigned char) * 100);
  xor_ocall(x, y, res);
  ctxt->s.push(res);
}

void sgt(Context* ctxt) {
  ctxt->s.swap(1);
  slt_e(ctxt);
}



void dispatch(std::vector<Context>* ctxts, Context** ctxt, gs_struct* _gs, tx_struct* _tx, exec_result_struct* result)
{
  Opcode op = get_op((*ctxt)->get_pc(), (*ctxt)->prog.code);

  struct timespec start_time = { 0, 0 };
  struct timespec end_time = { 0, 0 };

  switch (op)
  {
  case Opcode::PUSH1:
  case Opcode::PUSH2:
  case Opcode::PUSH3:
  case Opcode::PUSH4:
  case Opcode::PUSH5:
  case Opcode::PUSH6:
  case Opcode::PUSH7:
  case Opcode::PUSH8:
  case Opcode::PUSH9:
  case Opcode::PUSH10:
  case Opcode::PUSH11:
  case Opcode::PUSH12:
  case Opcode::PUSH13:
  case Opcode::PUSH14:
  case Opcode::PUSH15:
  case Opcode::PUSH16:
  case Opcode::PUSH17:
  case Opcode::PUSH18:
  case Opcode::PUSH19:
  case Opcode::PUSH20:
  case Opcode::PUSH21:
  case Opcode::PUSH22:
  case Opcode::PUSH23:
  case Opcode::PUSH24:
  case Opcode::PUSH25:
  case Opcode::PUSH26:
  case Opcode::PUSH27:
  case Opcode::PUSH28:
  case Opcode::PUSH29:
  case Opcode::PUSH30:
  case Opcode::PUSH31:
  case Opcode::PUSH32:
	if ((*ctxt)->taint_list[PUSH1] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  push_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  push_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::POP:
	clock_gettime(CLOCK_REALTIME, &start_time);
	pop(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::SWAP1:
  case Opcode::SWAP2:
  case Opcode::SWAP3:
  case Opcode::SWAP4:
  case Opcode::SWAP5:
  case Opcode::SWAP6:
  case Opcode::SWAP7:
  case Opcode::SWAP8:
  case Opcode::SWAP9:
  case Opcode::SWAP10:
  case Opcode::SWAP11:
  case Opcode::SWAP12:
  case Opcode::SWAP13:
  case Opcode::SWAP14:
  case Opcode::SWAP15:
  case Opcode::SWAP16:
	clock_gettime(CLOCK_REALTIME, &start_time);
	swap(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::DUP1:
  case Opcode::DUP2:
  case Opcode::DUP3:
  case Opcode::DUP4:
  case Opcode::DUP5:
  case Opcode::DUP6:
  case Opcode::DUP7:
  case Opcode::DUP8:
  case Opcode::DUP9:
  case Opcode::DUP10:
  case Opcode::DUP11:
  case Opcode::DUP12:
  case Opcode::DUP13:
  case Opcode::DUP14:
  case Opcode::DUP15:
  case Opcode::DUP16:
	clock_gettime(CLOCK_REALTIME, &start_time);
	dup(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::LOG0:
  case Opcode::LOG1:
  case Opcode::LOG2:
  case Opcode::LOG3:
  case Opcode::LOG4:
	clock_gettime(CLOCK_REALTIME, &start_time);
	log(*ctxt, _tx);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::ADD:
	if ((*ctxt)->taint_list[ADDMOD] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  add_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  add_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::MUL:
	if ((*ctxt)->taint_list[MUL] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  mul_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  mul_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::SUB:
	if ((*ctxt)->taint_list[SUB] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  sub_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  sub_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::DIV:
	if ((*ctxt)->taint_list[DIV] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  div_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  div_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::SDIV:
	if ((*ctxt)->taint_list[SDIV] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  sdiv_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  sdiv_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::MOD:
	if ((*ctxt)->taint_list[MOD] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  mod_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  mod_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::SMOD:
	if ((*ctxt)->taint_list[SMOD] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  smod_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  smod_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::ADDMOD:
	if ((*ctxt)->taint_list[ADDMOD] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  addmod_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  addmod_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::MULMOD:
	if ((*ctxt)->taint_list[MULMOD] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  mulmod_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  mulmod_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::EXP:
	if ((*ctxt)->taint_list[EXP] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  exp_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  exp_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::SIGNEXTEND:
	if ((*ctxt)->taint_list[SIGNEXTEND] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  signextend_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  signextend_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::LT:
	if ((*ctxt)->taint_list[LT] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  lt_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  lt_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::GT:
	if ((*ctxt)->taint_list[GT] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  gt_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  gt_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::SLT:
	if ((*ctxt)->taint_list[SLT] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  slt_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  slt_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::SGT:
	clock_gettime(CLOCK_REALTIME, &start_time);
	sgt(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::EQ:
	if ((*ctxt)->taint_list[EQ] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  eq_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  eq_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::ISZERO:
	if ((*ctxt)->taint_list[ISZERO] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  isZero_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  isZero_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::AND:
	if ((*ctxt)->taint_list[AND] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  and_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  and_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::OR:
	if ((*ctxt)->taint_list[OR] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  or_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  or_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::XOR:
	if ((*ctxt)->taint_list[XOR] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  xor_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  xor_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::NOT:
	if ((*ctxt)->taint_list[NOT] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  not_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  not_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::BYTE:
	if ((*ctxt)->taint_list[BYTE] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  byte_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  byte_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::SHL:
	if ((*ctxt)->taint_list[SHL] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  shl_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  shl_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::SHR:
	if ((*ctxt)->taint_list[SHR] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  shr_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  shr_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::JUMP:
	clock_gettime(CLOCK_REALTIME, &start_time);
	jump(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::JUMPI:
	clock_gettime(CLOCK_REALTIME, &start_time);
	jumpi(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::PC:
	clock_gettime(CLOCK_REALTIME, &start_time);
	pc(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::MSIZE:
	clock_gettime(CLOCK_REALTIME, &start_time);
	msize(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::MLOAD:
	if ((*ctxt)->taint_list[MLOAD] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  mload_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  mload_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::MSTORE:
	if ((*ctxt)->taint_list[MSTORE] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  mstore_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  mstore_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::MSTORE8:
	if ((*ctxt)->taint_list[MSTORE8] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  mstore8_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  mstore8_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::CODESIZE:
	clock_gettime(CLOCK_REALTIME, &start_time);
	codesize(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::CODECOPY:
	clock_gettime(CLOCK_REALTIME, &start_time);
	codecopy(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::EXTCODESIZE:
	clock_gettime(CLOCK_REALTIME, &start_time);
	extcodesize(*ctxt, _gs);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::EXTCODECOPY:
	clock_gettime(CLOCK_REALTIME, &start_time);
	extcodecopy(*ctxt, _gs);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::SLOAD:
	clock_gettime(CLOCK_REALTIME, &start_time);
	sload(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::SSTORE:
	clock_gettime(CLOCK_REALTIME, &start_time);
	sstore(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::ADDRESS:
	clock_gettime(CLOCK_REALTIME, &start_time);
	address(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::BALANCE:
	clock_gettime(CLOCK_REALTIME, &start_time);
	balance(*ctxt, _gs);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::ORIGIN:
	clock_gettime(CLOCK_REALTIME, &start_time);
	origin(*ctxt, _tx);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::CALLER:
	clock_gettime(CLOCK_REALTIME, &start_time);
	caller(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::CALLVALUE:
	clock_gettime(CLOCK_REALTIME, &start_time);
	callvalue(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::CALLDATALOAD:
	if ((*ctxt)->taint_list[CALLDATALOAD] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  calldataload_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  calldataload_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::CALLDATASIZE:
	clock_gettime(CLOCK_REALTIME, &start_time);
	calldatasize(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::CALLDATACOPY:
	clock_gettime(CLOCK_REALTIME, &start_time);
	calldatacopy(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::RETURN:
	clock_gettime(CLOCK_REALTIME, &start_time);
	return_(ctxts, ctxt, result);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::SELFDESTRUCT:
	clock_gettime(CLOCK_REALTIME, &start_time);
	selfdestruct(ctxts, ctxt, result, _gs, _tx);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::CREATE:
	clock_gettime(CLOCK_REALTIME, &start_time);
	create(ctxts, *ctxt, _gs);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::CALL:
  case Opcode::CALLCODE:
  case Opcode::DELEGATECALL:
	clock_gettime(CLOCK_REALTIME, &start_time);
	call(ctxts, *ctxt, _gs);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::JUMPDEST:
	clock_gettime(CLOCK_REALTIME, &start_time);
	jumpdest(*ctxt);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::BLOCKHASH:
	if ((*ctxt)->taint_list[BLOCKHASH] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  blockhash_e(*ctxt, _gs);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  blockhash_o(*ctxt, _gs);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::NUMBER:
	clock_gettime(CLOCK_REALTIME, &start_time);
	number(*ctxt, _gs);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::GASPRICE:
	clock_gettime(CLOCK_REALTIME, &start_time);
	gasprice(*ctxt, _tx);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::COINBASE:
	clock_gettime(CLOCK_REALTIME, &start_time);
	coinbase(*ctxt, _gs);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::TIMESTAMP:
	clock_gettime(CLOCK_REALTIME, &start_time);
	timestamp(*ctxt, _gs);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::DIFFICULTY:
	clock_gettime(CLOCK_REALTIME, &start_time);
	difficulty(*ctxt, _gs);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::GASLIMIT:
	clock_gettime(CLOCK_REALTIME, &start_time);
	gaslimit(*ctxt, _gs);
	clock_gettime(CLOCK_REALTIME, &end_time);
	break;
  case Opcode::GAS:
	clock_gettime(CLOCK_REALTIME, &start_time);
	gas(*ctxt, _tx);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::SHA3:
	if ((*ctxt)->taint_list[SHA3] == 1) {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  sha3_e(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	else {
	  clock_gettime(CLOCK_REALTIME, &start_time);
	  sha3_o(*ctxt);
	  clock_gettime(CLOCK_REALTIME, &end_time);
	  if (CAL_FO_TIME) printf("Host: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	}
	break;
  case Opcode::STOP:
	clock_gettime(CLOCK_REALTIME, &start_time);
	stop(ctxts, ctxt, result);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  case Opcode::REVERT:
	clock_gettime(CLOCK_REALTIME, &start_time);
	revert(ctxts, ctxt, result);
	clock_gettime(CLOCK_REALTIME, &end_time);
	if (CAL_FE_TIME) printf("Enclave: %ld\n", (end_time.tv_nsec - start_time.tv_nsec) / 1000000);
	break;
  default:
	throw "Unknown/unsupported Opcode\n";
  };
}


void enclave_run(exec_result_struct* result, gs_struct* _gs, tx_struct* _tx, unsigned char* _caller, unsigned char* _callee, uint8_t* _input, size_t _input_size, unsigned char* _call_value, uint8_t* taint_list) {
  // find callee
  account_struct* callee = nullptr;
  for (int i = 0; i < charx2uint64(_gs->accounts_size); i++) {
	if (strcmp((char*)_gs->accounts[i].address, (char*)_callee) == 0) {
	  callee = &_gs->accounts[i].account;
	}
  }

  // function of setting result
  auto rh = [result](std::vector<uint8_t> output_) {
	result->er = ExitReason["returned"];
	memcpy(result->output, &output_[0], sizeof(uint8_t) * output_.size());
	unsigned char* tmp = uint642charx(output_.size());
	memcpy(result->output_size, tmp, strlen((char*)tmp) + 1);
  };
  auto hh = [result]() {
	result->er = ExitReason["halted"];
  };
  auto eh = [result](unsigned char* _exmsg) {
	result->er = ExitReason["threw"];
	memcpy(result->exmsg, _exmsg, strlen((char*)_exmsg) + 1);
  };

  // context
  std::vector<Context> ctxts;
  Context* ctxt;
  push_context(&ctxts, &ctxt, _caller, callee, _input, _input_size, _call_value, Program(callee->account_code, charx2uint64(callee->account_code_size)), rh, hh, eh, taint_list);

  // call value
  account_struct* caller_account = nullptr;
  for (int i = 0; i < charx2uint64(_gs->accounts_size); i++) {
	if (strcmp((char*)_gs->accounts[i].address, (char*)_caller) == 0) {
	  caller_account = &_gs->accounts[i].account;
	  break;
	}
  }
  a_pay_b(caller_account, callee, _call_value);

  // opcode
  while (ctxt->get_pc() < ctxt->prog.code.size()) {
	if (PRINT_OPCODE) printf("OPCODE: 0x%x\n", get_op(ctxt->get_pc(), ctxt->prog.code));
	try {
	  dispatch(&ctxts, &ctxt, _gs, _tx, result);
	}
	catch (unsigned char* msg) {
	  ctxt->eh(msg);
	  pop_context(&ctxts, &ctxt);
	}

	if (!ctxt) {
	  break;
	}
	ctxt->step();

	if (PRINT_STACK_MEM) printf_stack(ctxt->s);
	if (PRINT_STACK_MEM) printf_mem(ctxt->mem);
  }

  if (ctxt) {
	stop(&ctxts, &ctxt, result);
  }

  // some delete
  gs_accounts_struct* final_accounts = new gs_accounts_struct[100];
  size_t final_accounts_size = 0;
  for (int i = 0; i < charx2uint64(_gs->accounts_size); i++) {
	gs_accounts_struct t = _gs->accounts[i];
	bool flag = true;
	for (int j = 0; j < charx2uint64(_tx->selfdestruct_list_size); j++) {
	  unsigned char* a = _tx->selfdestruct_list[j];
	  if (str_compare(t.address, a) == 0) {
		flag = false;
		break;
	  }
	}
	if (flag) {
	  final_accounts[final_accounts_size] = t;
	  final_accounts_size += 1;
	}
  }

  memcpy(_gs->accounts, final_accounts, sizeof(gs_accounts_struct) * final_accounts_size);
  unsigned char* tmp = uint642charx(final_accounts_size);
  memcpy(_gs->accounts_size, tmp, strlen((char*)tmp) + 1);
}

void enclave_deploy(gs_struct* _gs, tx_struct* _tx, unsigned char* _caller, uint8_t* _constructor, size_t _constructor_size, unsigned char* contract_address, uint8_t* taint_list) {
  // get new contract address
  size_t caller_nonce = 0;
  for (int i = 0; i < charx2uint64(_gs->accounts_size); i++) {
	if (strcmp((char*)_gs->accounts[i].address, (char*)_caller) == 0) {
	  caller_nonce = charx2uint64(_gs->accounts[i].account.account_nonce);
	}
  }
  generate_address_ocall(_caller, caller_nonce, contract_address);

  // if contract address exist or not
  for (int i = 0; i < charx2uint64(_gs->accounts_size); i++) {
	if (str_compare(contract_address, (_gs->accounts + i)->address) == 0) {
	  return;
	}
  }

  // create new account
  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].address, contract_address, strlen((char*)contract_address) + 1);
  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_address, contract_address, strlen((char*)contract_address) + 1);
  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_balance, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code, _constructor, sizeof(uint8_t) * _constructor_size);
  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_code_size, uint642charx(_constructor_size), strlen((char*)uint642charx(_constructor_size)) + 1);
  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.account_nonce, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
  memcpy(_gs->accounts[charx2uint64(_gs->accounts_size)].account.storage_size, uint642charx(0), strlen((char*)uint642charx(0)) + 1);
  memcpy(_gs->accounts_size, uint642charx(charx2uint64(_gs->accounts_size) + 1), strlen((char*)uint642charx(charx2uint64(_gs->accounts_size) + 1)) + 1);

  // init result
  exec_result_struct _result;
  _result.exmsg = new unsigned char[100];
  _result.output = new uint8_t[30000];
  _result.output_size = new unsigned char[100];

  // find callee
  account_struct* callee = nullptr;
  for (int i = 0; i < charx2uint64(_gs->accounts_size); i++) {
	if (strcmp((char*)_gs->accounts[i].address, (char*)contract_address) == 0) {
	  callee = &_gs->accounts[i].account;
	  break;
	}
  }

  // do
  enclave_run(&_result, _gs, _tx, _caller, contract_address, {}, 0, (unsigned char*)"0", taint_list);

  //printf("account code\n");
 // for (int i = 0; i < 30000; i++) {
	//if (*(callee->account_code + i) == 0)break;
	//printf("%d ", *(callee->account_code + i));
 // }
 // printf("\n");

 // printf("output %d\n", charx2uint64(_result.output_size));
 // for (int i = 0; i < charx2uint64(_result.output_size); i++) {
	//printf("%d ", *(_result.output + i));
 // }
 // printf("\n");

  // set code
  memcpy(callee->account_code, _result.output, sizeof(uint8_t) * charx2uint64(_result.output_size));
  memcpy(callee->account_code_size, _result.output_size, strlen((char*)_result.output_size) + 1);
}