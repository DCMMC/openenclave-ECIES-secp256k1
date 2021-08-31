// Copyright (c) 2021 Tsinghua Shenzhen International Graduate School
// All rights reserved.

#include "processor.h"

// ==================== enclave headfiles ====================
#include <openenclave/host.h>
#include "enclave_u.h"
// ==================== enclave headfiles ====================

#pragma comment(lib, "Ws2_32.lib")
#pragma warning(disable : 4996)


void push_ocall(uint64_t* pc, uint8_t bytes, uint8_t* code_arr, size_t code_size, unsigned char* res) {
  uint256_t imm = 0;
  for (int i = 0; i < bytes; i++) {
	imm = (imm << 8) | *(code_arr + *pc);
	*pc += 1;
  }
  unsigned char* _res = uint2562charx(imm);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void add_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  unsigned char* _res = uint2562charx(_x + _y);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void mul_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  unsigned char* _res = uint2562charx(_x * _y);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void sub_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  unsigned char* _res = uint2562charx(_x - _y);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void div_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  if (!_y) {
	unsigned char* _res = uint2562charx(0);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
  else {
	unsigned char* _res = uint2562charx(_x / _y);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
}

void sdiv_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  uint256_t min = (std::numeric_limits<uint256_t>::max() / 2) + 1;
  if (_y == 0) {
	unsigned char* _res = uint2562charx(0);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
  else if (_x == min && _y == -1) {
	unsigned char* _res = uint2562charx(_x);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
  else {
	uint256_t signX = (_x >> 255) ? -1 : 1;
	uint256_t signY = (_y >> 255) ? -1 : 1;
	if (signX == -1) {
	  _x = 0 - _x;
	}
	if (signY == -1) {
	  _y = 0 - _y;
	}
	uint256_t _z = (_x / _y);
	if (signX != signY) {
	  _z = 0 - _z;
	}
	unsigned char* _res = uint2562charx(_z);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
}

void mod_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  if (!_y) {
	unsigned char* _res = uint2562charx(0);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
  else {
	unsigned char* _res = uint2562charx(_x % _y);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
}

void smod_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  if (_y == 0) {
	unsigned char* _res = uint2562charx(0);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
  else {
	uint256_t signX = (_x >> 255) ? -1 : 1;
	uint256_t signY = (_y >> 255) ? -1 : 1;
	if (signX == -1) {
	  _x = 0 - _x;
	}
	if (signY == -1) {
	  _y = 0 - _y;
	}
	uint256_t _z = (_x % _y);
	if (signX == -1) {
	  _z = 0 - _z;
	}
	unsigned char* _res = uint2562charx(_z);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
}

void addmod_ocall(unsigned char* x, unsigned char* y, unsigned char* m, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  uint256_t _m = charx2uint256(m);
  if (!_m) {
	unsigned char* _res = uint2562charx(0);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
  else {
	uint512_t _n = (_x + _y) % _m;
	unsigned char* _res = uint2562charx(_n.lo);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
}

void mulmod_ocall(unsigned char* x, unsigned char* y, unsigned char* m, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  uint256_t _m = charx2uint256(m);
  if (!_m) {
	unsigned char* _res = uint2562charx(_m);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
  else {
	uint512_t _n = (_x * _y) % _m;
	unsigned char* _res = uint2562charx(_n.lo);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
}

void exp_ocall(unsigned char* b, unsigned char* e, unsigned char* res) {
  uint256_t _b = charx2uint256(b);
  uint256_t _e = charx2uint256(e);
  unsigned char* _res = uint2562charx(intx::exp(_b, _e));
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void signextend_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  if (_x >= 32) {
	unsigned char* _res = uint2562charx(_y);
	memcpy(res, _res, strlen((char*)_res) + 1);
	return;
  }
  uint256_t idx = 8 * static_cast<uint256_t>(_x & std::numeric_limits<uint256_t>::max()) + 7;
  uint256_t sign = static_cast<uint256_t>((_y >> idx) & 1);
  uint256_t zero = 0;
  uint256_t mask = ~zero >> (256 - idx);
  uint256_t yex = ((sign ? ~zero : zero) << idx) | (_y & mask);
  unsigned char* _res = uint2562charx(yex);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void lt_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  unsigned char* _res = uint2562charx(_x < _y ? 1 : 0);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void gt_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  unsigned char* _res = uint2562charx(_x > _y ? 1 : 0);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void slt_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  if (_x == _y) {
	unsigned char* _res = uint2562charx(0);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
  else {
	int signX = (_x >> 255) ? -1 : 1;
	int signY = (_y >> 255) ? -1 : 1;
	if (signX != signY) {
	  if (signX == -1) {
		unsigned char* _res = uint2562charx(1);
		memcpy(res, _res, strlen((char*)_res) + 1);
	  }
	  else {
		unsigned char* _res = uint2562charx(0);
		memcpy(res, _res, strlen((char*)_res) + 1);
	  }
	}
	else {
	  if (_x < _y) {
		unsigned char* _res = uint2562charx(1);
		memcpy(res, _res, strlen((char*)_res) + 1);
	  }
	  else {
		unsigned char* _res = uint2562charx(0);
		memcpy(res, _res, strlen((char*)_res) + 1);
	  }
	}
  }
}

void eq_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  unsigned char* _res = uint2562charx(_x == _y ? 1 : 0);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void isZero_ocall(unsigned char* x, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  unsigned char* _res = uint2562charx(_x == 0 ? 1 : 0);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void and_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  unsigned char* _res = uint2562charx(_x & _y);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void or_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t __res = charx2uint256(x) | charx2uint256(y);
  unsigned char* _res = uint2562charx(__res);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void xor_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t __res = charx2uint256(x) ^ charx2uint256(y);
  unsigned char* _res = uint2562charx(__res);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void not_ocall(unsigned char* x, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  unsigned char* _res = uint2562charx(~_x);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void byte_ocall(unsigned char* idx, unsigned char* val, unsigned char* res) {
  uint256_t _idx = charx2uint256(idx);
  if (_idx >= 32) {
	unsigned char* _res = uint2562charx(0);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
  else {
	uint8_t shift = 256 - 8 - 8 * static_cast<uint8_t>(_idx & std::numeric_limits<uint8_t>::max());
	uint256_t mask = uint256_t(255) << shift;
	uint256_t __res = (charx2uint256(val) & mask) >> shift;
	unsigned char* _res = uint2562charx(__res);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
}

void shl_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);
  
  if (_x >= 256) {
	unsigned char* _res = uint2562charx(0);
	memcpy(res, _res, strlen((char*)_res) + 1);
	return;
  }
  unsigned char* _res = uint2562charx(_y << _x);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void shr_ocall(unsigned char* x, unsigned char* y, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  uint256_t _y = charx2uint256(y);

  if (_x >= 256) {
	unsigned char* _res = uint2562charx(0);
	memcpy(res, _res, strlen((char*)_res) + 1);
	return;
  }
  unsigned char* _res = uint2562charx(_y >> _x);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void mstore8_ocall(uint8_t* b, unsigned char* n) {
  *b = static_cast<uint8_t>(charx2uint256(n) & std::numeric_limits<uint8_t>::max());
}

void calldataload_ocall(uint64_t offset, uint64_t sizeInput, uint8_t* input, size_t input_size, unsigned char* res) {
  uint256_t v = 0;
  for (uint8_t i = 0; i < 32u; i++)
  {
	const auto j = offset + i;
	if (j < sizeInput)
	{
	  v = (v << 8) + *(input + j);  // 字符串不能&，但是单个字符可以表示成int形式，0x01&，得到最低位的二进制数
	}
	else
	{
	  v <<= 8 * (32u - i);
	  break;
	}
  }
  unsigned char* _res = uint2562charx(v);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void blockhash_ocall(unsigned char* x, unsigned char* res) {
  uint256_t _x = charx2uint256(x);
  if (_x >= 256) {
	unsigned char* _res = uint2562charx(0);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
  else {
	//ctxt->s.push(gs.get_block_hash(i % 256));
	unsigned char* _res = uint2562charx(0);
	memcpy(res, _res, strlen((char*)_res) + 1);
  }
}

void sha3_ocall(uint8_t* h, unsigned char* res) {
  uint256_t __res = eevm::from_big_endian(h, 32);
  unsigned char* _res = uint2562charx(__res);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void generate_address_ocall(unsigned char* sender, size_t nonce, unsigned char* newAddress) {
  const uint256_t _sender = charx2uint256(sender);
  uint256_t addr = eevm::generate_address(_sender, static_cast<uint64_t>(nonce));
  unsigned char* _res = uint2562charx(addr);
  memcpy(newAddress, _res, strlen((char*)_res) + 1);
}

void to_big_endian_ocall(unsigned char* v, uint8_t* out, size_t out_size) {
  uint256_t _v = charx2uint256(v);
  eevm::to_big_endian(_v, out);
}

void from_big_endian_ocall(uint8_t* begin, size_t size, size_t begin_size, unsigned char* res) {
  uint256_t __res = eevm::from_big_endian(begin, size);
  unsigned char* _res = uint2562charx(__res);
  memcpy(res, _res, strlen((char*)_res) + 1);
}

void connect_pwd_server(unsigned char* old_key, unsigned char* new_key) {
 // unsigned char keykey[32] = { 0xdd, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
 //                                     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };

 // for (int i = 0; i < 32; i++) {
	//old_key[i] = keykey[i];
	//new_key[i] = keykey[i];
 // }
  
  SOCKET sock_client;
  SOCKADDR_IN sock_addr;
  memset(&sock_addr, 0, sizeof(SOCKADDR_IN));

  WORD wVersionRequested;
  WSADATA wsaData;
  wVersionRequested = MAKEWORD(1, 1);
  int ret_init = WSAStartup(wVersionRequested, &wsaData);
  if (ret_init != 0) {
	printf("startup failed!\n");
	throw;
  }

  sock_client = socket(AF_INET, SOCK_STREAM, 0);
  if (sock_client == INVALID_SOCKET) {
	int error_code = WSAGetLastError();
	printf("socket create failed, error code : %d\n", error_code);
	throw;
  }

  sock_addr.sin_family = AF_INET;
  sock_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
  sock_addr.sin_port = htons(8000);

  int ret = connect(sock_client, (sockaddr*)&sock_addr, sizeof(SOCKADDR_IN));
  if (ret == SOCKET_ERROR) {
	printf("client connect failed\n");
	throw;
  }

  char buf[1000];
  memset(buf, 0, sizeof(char) * 1000);
  int bufsize = 1000;
  recv(sock_client, buf, bufsize, 0);
  closesocket(sock_client);

  int i = 0, j = 0, k = 0;
  int tmp = 0;
  while (buf[i] != 0 && j < 32) {
	if (buf[i] == ',') {
	  old_key[j++] = tmp;
	  tmp = 0;
	}
	else {
	  tmp *= 10;
	  tmp += buf[i] - '0';
	}
	i++;
  }
  while (buf[i] != 0 && k < 32) {
	if (buf[i] == ',') {
	  new_key[k++] = tmp;
	  tmp = 0;
	}
	else {
	  tmp *= 10;
	  tmp += buf[i] - '0';
	}
	i++;
  }
  new_key[k++] = tmp;
}