// Copyright (c) 2021 Tsinghua Shenzhen International Graduate School
// All rights reserved.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <vector>
using namespace std;



namespace myBigInt {

  const static char* MAX = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
  const static char* MAXP1 = "115792089237316195423570985008687907853269984665640564039457584007913129639936";
  const static char* MASK_160 = "1461501637330902918203684832716283019655932542975";

  /* 大数相减 */
  unsigned char* sub(unsigned char* a, unsigned char* b) {
    if (strcmp((char*)a, (char*)b) == 0) {
      return (unsigned char*)"0";
    }
    if (strlen((char*)b) > strlen((char*)a) || (strlen((char*)a) == strlen((char*)b) && strcmp((char*)b, (char*)a) > 0)) {
      return sub((unsigned char*)MAXP1, sub(b, a));
    }

    vector<unsigned char> _a(a, a + strlen((char*)a));
    vector<unsigned char> _b(b, b + strlen((char*)b));
    reverse(_a.begin(), _a.end());
    reverse(_b.begin(), _b.end());
    while (_a.size() != _b.size()) {
      _b.push_back('0');
    }

    vector<unsigned char> ans;
    unsigned char c;
    for (int i = 0; i < _a.size(); i++) {
      if (_a[i] < _b[i]) {
        _a[i] += 10;
        _a[i + 1] -= 1;
      }
      c = (_a[i] - _b[i]) + '0';
      ans.push_back(c);
    }
    while (ans[ans.size() - 1] == '0' && ans.size() > 1) {
      ans.erase(ans.end() - 1);
    }
    reverse(ans.begin(), ans.end());

    unsigned char* res = new unsigned char[100];
    memset(res, 0, sizeof(unsigned char) * 100);
    memcpy(res, &ans[0], sizeof(unsigned char) * ans.size());
    return res;
  }

  /* 大数相加 */
  unsigned char* add(unsigned char* a, unsigned char* b) {
    vector<unsigned char> _a(a, a + strlen((char*)a));
    vector<unsigned char> _b(b, b + strlen((char*)b));
    reverse(_a.begin(), _a.end());
    reverse(_b.begin(), _b.end());
    while (_a.size() < _b.size()) {
      _a.push_back('0');
    }
    while (_a.size() > _b.size()) {
      _b.push_back('0');
    }

    vector<unsigned char> ans;
    unsigned char p = 0, t = 0;
    for (int i = 0; i < _a.size() && i < _b.size(); i++) {
      t = _a[i] - '0' + _b[i] - '0' + p;
      ans.push_back(t % 10 + '0');
      p = t / 10;
    }
    if (p != 0) {
      ans.push_back(p + '0');
    }
    while (ans[ans.size() - 1] == '0' && ans.size() > 1) {
      ans.erase(ans.end() - 1);
    }
    reverse(ans.begin(), ans.end());

    unsigned char* res = new unsigned char[100];
    memset(res, 0, sizeof(unsigned char) * 100);
    memcpy(res, &ans[0], sizeof(unsigned char) * ans.size());

    if (strlen((char*)res) > strlen(MAX) || (strlen((char*)res) == strlen(MAX) && strcmp((char*)res, MAX) > 0)) {
      return sub(res, (unsigned char*)MAXP1);
    }

    return res;
  }

  /* 大数相乘 */
  unsigned char* mul(unsigned char* a, unsigned char* b) {
    if (strcmp((char*)a, "0") == 0 || strcmp((char*)b, "0") == 0) {
      return (unsigned char*)"0";
    }

    vector<unsigned char> _a(a, a + strlen((char*)a));
    vector<unsigned char> _b(b, b + strlen((char*)b));
    reverse(_a.begin(), _a.end());
    reverse(_b.begin(), _b.end());

    vector<int> v(_a.size() + _b.size(), 0);
    vector<unsigned char> ans;
    for (int i = 0; i < _a.size(); i++) {
      for (int j = 0; j < _b.size(); j++) {
        v[i + j] += (_a[i] - '0') * (_b[j] - '0');
      }
    }
    v.push_back(0);
    for (int i = 0; i < v.size() - 1; i++) {
      v[i + 1] += v[i] / 10;
      v[i] %= 10;
      ans.push_back(v[i] + '0');
    }
    ans.push_back(v[v.size() - 1] + '0');
    while (ans[ans.size() - 1] == '0' && ans.size() > 1) {
      ans.erase(ans.end() - 1);
    }
    reverse(ans.begin(), ans.end());

    unsigned char* res = new unsigned char[100];
    memset(res, 0, sizeof(unsigned char) * 100);
    memcpy(res, &ans[0], sizeof(unsigned char) * ans.size());

    while (strlen((char*)res) > strlen(MAX) || (strlen((char*)res) == strlen(MAX) && strcmp((char*)res, MAX) > 0)) {
      unsigned char* t = sub(res, (unsigned char*)MAXP1);
      res = t;
    }

    return res;
  }

  /* 大数相除 */
  unsigned char* div(unsigned char* a, unsigned char* b) {
    if (strcmp((char*)a, (char*)b) == 0) {
      return (unsigned char*)"1";
    }
    if (strlen((char*)a) < strlen((char*)b) || (strlen((char*)a) == strlen((char*)b) && strcmp((char*)a, (char*)b) < 0)) {
      return (unsigned char*)"0";
    }

    vector<unsigned char> _a(a, a + strlen((char*)a));
    vector<unsigned char> _b(b, b + strlen((char*)b));

    int num = _a.size() - _b.size();
    vector<unsigned char> tmp, tmp2;
    unsigned char* tmp3 = new unsigned char[100];
    unsigned char* tmp4 = new unsigned char[100];
    unsigned char* ans = new unsigned char[100];
    memset(ans, 0, sizeof(unsigned char) * 100);
    ans[0] = '0';
    for (int i = num; i >= 0; i--) {
      tmp = _b;
      tmp2.push_back('1');
      for (int j = 0; j < i; j++) {
        tmp.push_back('0');
        tmp2.push_back('0');
      }
      memset(tmp3, 0, sizeof(unsigned char) * 100);
      memcpy(tmp3, &tmp[0], sizeof(unsigned char) * tmp.size());
      memset(tmp4, 0, sizeof(unsigned char) * 100);
      memcpy(tmp4, &tmp2[0], sizeof(unsigned char) * tmp2.size());
      while (strlen((char*)a) > strlen((char*)tmp3) || (strlen((char*)a) == strlen((char*)tmp3) && strcmp((char*)a, (char*)tmp3) >= 0)) {
        a = sub(a, tmp3);
        ans = add(ans, tmp4);
      }
      tmp.clear();
      tmp2.clear();
    }

    vector<unsigned char> _ans(ans, ans + strlen((char*)ans));
    while (_ans[0] == '0' && _ans.size() > 1) {
      _ans.erase(_ans.begin());
    }

    unsigned char* res = new unsigned char[100];
    memset(res, 0, sizeof(unsigned char) * 100);
    memcpy(res, &_ans[0], sizeof(unsigned char) * _ans.size());
    return res;
  }

  /* 大数取余 */
  unsigned char* mod(unsigned char* a, unsigned char* b) {
    if (strcmp((char*)a, (char*)b) == 0) {
      return (unsigned char*)"0";
    }
    if (strlen((char*)a) < strlen((char*)b) || (strlen((char*)a) == strlen((char*)b) && strcmp((char*)a, (char*)b) < 0)) {
      return a;
    }

    vector<unsigned char> _a(a, a + strlen((char*)a));
    vector<unsigned char> _b(b, b + strlen((char*)b));

    int num = _a.size() - _b.size();
    vector<unsigned char> tmp, tmp2;
    unsigned char* tmp3 = new unsigned char[100];
    unsigned char* tmp4 = new unsigned char[100];
    unsigned char* ans = new unsigned char[100];
    memset(ans, 0, sizeof(unsigned char) * 100);
    ans[0] = '0';
    for (int i = num; i >= 0; i--) {
      tmp = _b;
      tmp2.push_back('1');
      for (int j = 0; j < i; j++) {
        tmp.push_back('0');
        tmp2.push_back('0');
      }
      memset(tmp3, 0, sizeof(unsigned char) * 100);
      memcpy(tmp3, &tmp[0], sizeof(unsigned char) * tmp.size());
      memset(tmp4, 0, sizeof(unsigned char) * 100);
      memcpy(tmp4, &tmp2[0], sizeof(unsigned char) * tmp2.size());
      while (strlen((char*)a) > strlen((char*)tmp3) || (strlen((char*)a) == strlen((char*)tmp3) && strcmp((char*)a, (char*)tmp3) >= 0)) {
        a = sub(a, tmp3);
        ans = add(ans, tmp4);
      }
      tmp.clear();
      tmp2.clear();
    }

    return a;
  }

  /* 大数幂运算 */
  unsigned char* exp(unsigned char* a, unsigned char* b) {
    if (strcmp((char*)b, "0") == 0) {
      return (unsigned char*)"1";
    }
    unsigned char* _a = new unsigned char[100];
    memset(_a, 0, sizeof(unsigned char) * 100);
    memcpy(_a, a, strlen((char*)a) + 1);
    b = sub(b, (unsigned char*)"1");
    while (strcmp((char*)b, "0") != 0) {
      a = mul(a, _a);
      b = sub(b, (unsigned char*)"1");
    }
    return a;
  }

  /*
    str: 被除数
    m: 除数
    n: 被除数进制
    remain: 余数
  */
  vector<unsigned char> division(vector<unsigned char> str, int m, int n, int& remain) {
    int a;
    remain = 0;
    for (int i = 0; i < str.size(); i++) {
      a = (n * remain + (str[i] - '0'));
      str[i] = a / m + '0';
      remain = a % m;
    }

    while (str[0] == '0') {
      str.erase(str.begin());
      if (str.size() == 0) {
        return str;
      }
    }

    return str;
  }

  /* 十进制 -> 二进制 */
  unsigned char* dec2bin(unsigned char* str) {
    int m = 2;
    int n = 10;

    vector<unsigned char> res;
    int a;

    vector<unsigned char> str_vec(str, str + strlen((char*)str));

    while (str_vec.size() != 0) {
      str_vec = division(str_vec, m, n, a);
      res.push_back((unsigned char)(a + '0'));
    }
    reverse(res.begin(), res.end());

    unsigned char* _res = new unsigned char[300];
    memset(_res, 0, sizeof(unsigned char) * 300);
    memcpy(_res, &res[0], sizeof(unsigned char) * res.size());

    return _res;
  }

  /* 二进制 -> 十进制 */
  unsigned char* bin2dec(unsigned char* str) {
    int m = 10;
    int n = 2;

    vector<unsigned char> res;
    int a;

    vector<unsigned char> str_vec(str, str + strlen((char*)str));

    while (str_vec.size() != 0) {
      str_vec = division(str_vec, m, n, a);
      res.push_back((unsigned char)(a + '0'));
    }
    reverse(res.begin(), res.end());

    unsigned char* _res = new unsigned char[100];
    memset(_res, 0, sizeof(unsigned char) * 100);
    memcpy(_res, &res[0], sizeof(unsigned char) * res.size());

    return _res;
  }

  /* 左移n位 */
  unsigned char* leftmove(unsigned char* str, int n) {
    unsigned char* bin_str = dec2bin(str);

    const char* fill = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    memcpy(bin_str + strlen((char*)bin_str), fill, sizeof(unsigned char) * n);

    if (strlen((char*)bin_str) > 256) {
      unsigned char* t = new unsigned char[300];
      memset(t, 0, sizeof(unsigned char) * 300);
      memcpy(t, bin_str + strlen((char*)bin_str) - 256, sizeof(unsigned char) * 256);
      return bin2dec(t);
    }

    return bin2dec(bin_str);
  }

  /* 左移n位 */
  unsigned char* leftmove(unsigned char* str, unsigned char* n) {
    if (strlen((char*)n) > 3 || (strlen((char*)n) == 3 && strcmp((char*)n, "256") >= 0)) {
      return (unsigned char*)"0";
    }
    int _n = 0;
    int end = 0;
    while (*(n + end) != 0) {
      _n *= 10;
      _n += static_cast<int>(*(n + end) - '0');
      end += 1;
    }
    leftmove(str, _n);
  }

  /* 右移n位 */
  unsigned char* rightmove(unsigned char* str, int n) {
    unsigned char* bin_str = dec2bin(str);

    if (n >= strlen((char*)bin_str)) {
      return (unsigned char*)"0";
    }

    unsigned char* have_move = new unsigned char[300];
    memset(have_move, 0, sizeof(unsigned char) * 300);
    memcpy(have_move, bin_str, sizeof(unsigned char) * (strlen((char*)bin_str) - n));

    return bin2dec(have_move);
  }

  /* 右移n位 */
  unsigned char* rightmove(unsigned char* str, unsigned char* n) {
    if (strlen((char*)n) > 3 || (strlen((char*)n) == 3 && strcmp((char*)n, "256") >= 0)) {
      return (unsigned char*)"0";
    }
    int _n = 0;
    int end = 0;
    while (*(n + end) != 0) {
      _n *= 10;
      _n += static_cast<int>(*(n + end) - '0');
      end += 1;
    }
    rightmove(str, _n);
  }

  /* 与 */
  unsigned char* and_(unsigned char* a, unsigned char* b) {
    unsigned char* _a = dec2bin(a);
    unsigned char* _b = dec2bin(b);

    vector<unsigned char> res;
    int i = strlen((char*)_a) - 1, j = strlen((char*)_b) - 1;
    for (; i >= 0 && j >= 0; i--, j--) {
      res.push_back(((_a[i] - '0') & (_b[j] - '0')) + '0');
    }
    reverse(res.begin(), res.end());

    unsigned char* _res = new unsigned char[300];
    memset(_res, 0, sizeof(unsigned char) * 300);
    memcpy(_res, &res[0], sizeof(unsigned char) * res.size());

    return bin2dec(_res);
  }

  /* 或 */
  unsigned char* or_(unsigned char* a, unsigned char* b) {
    unsigned char* _a = dec2bin(a);
    unsigned char* _b = dec2bin(b);

    vector<unsigned char> res;
    int i = strlen((char*)_a) - 1, j = strlen((char*)_b) - 1;
    for (; i >= 0 && j >= 0; i--, j--) {
      res.push_back(((_a[i] - '0') | (_b[j] - '0')) + '0');
    }
    for (; i >= 0; i--) {
      res.push_back(_a[i]);
    }
    for (; j >= 0; j--) {
      res.push_back(_b[j]);
    }
    reverse(res.begin(), res.end());

    unsigned char* _res = new unsigned char[300];
    memset(_res, 0, sizeof(unsigned char) * 300);
    memcpy(_res, &res[0], sizeof(unsigned char) * res.size());

    return bin2dec(_res);
  }

  /* 异或 */
  unsigned char* xor_(unsigned char* a, unsigned char* b) {
    unsigned char* _a = dec2bin(a);
    unsigned char* _b = dec2bin(b);

    vector<unsigned char> res;
    int i = strlen((char*)_a) - 1, j = strlen((char*)_b) - 1;
    for (; i >= 0 && j >= 0; i--, j--) {
      res.push_back(((_a[i] - '0') ^ (_b[j] - '0')) + '0');
    }
    for (; i >= 0; i--) {
      res.push_back((_a[i] - '0') ^ 0 + '0');
    }
    for (; j >= 0; j--) {
      res.push_back((_b[j] - '0') ^ 0 + '0');
    }
    reverse(res.begin(), res.end());

    unsigned char* _res = new unsigned char[300];
    memset(_res, 0, sizeof(unsigned char) * 300);
    memcpy(_res, &res[0], sizeof(unsigned char) * res.size());

    return bin2dec(_res);
  }

  /* 非 */
  unsigned char* not_(unsigned char* a) {
    unsigned char* tran = dec2bin(a);

    unsigned char* _a = new unsigned char[300];
    memset(_a, 0, sizeof(unsigned char) * 300);
    memset(_a, '0', sizeof(unsigned char) * 256);
    memcpy(_a + (256 - strlen((char*)tran)), tran, sizeof(unsigned char) * strlen((char*)tran));

    vector<unsigned char> res;
    for (int i = 0; i < strlen((char*)_a); i++) {
      res.push_back(((_a[i] - '0') ^ 1) + '0');
    }

    unsigned char* _res = new unsigned char[300];
    memset(_res, 0, sizeof(unsigned char) * 300);
    memcpy(_res, &res[0], sizeof(unsigned char) * res.size());

    return bin2dec(_res);
  }

  /* 获取该数的高一半位的值 */
  unsigned char* get_hi(unsigned char* n, int size) {
    unsigned char* tran = dec2bin(n);
    unsigned char* n_bin = new unsigned char[300];
    memset(n_bin, 0, sizeof(unsigned char) * 300);
    memset(n_bin, '0', sizeof(unsigned char) * size);
    memcpy(n_bin + (size - strlen((char*)tran)), tran, sizeof(unsigned char) * strlen((char*)tran));

    unsigned char* res = new unsigned char[300];
    memset(res, 0, sizeof(unsigned char) * 300);
    memcpy(res, n_bin, sizeof(unsigned char) * size / 2);

    return bin2dec(res);
  }

  /* 获取该数的低一半位的值 */
  unsigned char* get_lo(unsigned char* n, int size) {
    unsigned char* tran = dec2bin(n);
    unsigned char* n_bin = new unsigned char[300];
    memset(n_bin, 0, sizeof(unsigned char) * 300);
    memset(n_bin, '0', sizeof(unsigned char) * size);
    memcpy(n_bin + (size - strlen((char*)tran)), tran, sizeof(unsigned char) * strlen((char*)tran));

    unsigned char* res = new unsigned char[300];
    memset(res, 0, sizeof(unsigned char) * 300);
    memcpy(res, n_bin + size / 2, sizeof(unsigned char) * size / 2);

    return bin2dec(res);
  }

  /* 32位uint8_t数组（大端存储） -> 十进制（小端） */
  unsigned char* uint8x32big2decsmall(const uint8_t* begin) {
    unsigned char* res = new unsigned char[300];
    memset(res, 0, sizeof(unsigned char) * 300);
    res[0] = '0';

    uint8_t* begin_copy = new uint8_t[32];
    memcpy(begin_copy, begin, sizeof(uint8_t) * 32);
    unsigned char* t = new unsigned char[100];

    for (int k = 0; k < 32; k++) {
      memset(t, 0, sizeof(unsigned char) * 100);
      if (begin_copy[k] == 0) {
        t[0] = '0';
      }
      if (begin_copy[k] != 0) {
        std::vector<unsigned char> tmp;
        uint8_t begin_copy_k = begin_copy[k];
        while (begin_copy_k != 0) {
          tmp.push_back(static_cast<unsigned char>(begin_copy_k % 10 + '0'));
          begin_copy_k /= 10;
        }
        for (int i = tmp.size() - 1, j = 0; i >= 0; i--, j++) {
          t[j] = tmp[i];
        }
      }
      res = leftmove(res, 8);
      res = or_(res, t);
    }
    return res;
  }

  /* from_big_endian */
  unsigned char* from_big_endian(const uint8_t* begin, size_t size = 32u) {
    if (size == 32) {
      return uint8x32big2decsmall(begin);
    }
    else if (size > 32) {
      throw "Calling from_big_endian with oversized array";
    }
    else {
      uint8_t tmp[32] = {};
      const auto offset = 32 - size;
      memcpy(tmp + offset, begin, size);


      return uint8x32big2decsmall(tmp);
    }
  }

  /* to_big_endian */
  void to_big_endian(unsigned char* v, uint8_t* out) {
    unsigned char* tran = dec2bin(v);
    unsigned char* v_bin = new unsigned char[300];
    memset(v_bin, 0, sizeof(unsigned char) * 300);
    memset(v_bin, '0', sizeof(unsigned char) * 256);
    memcpy(v_bin + (256 - strlen((char*)tran)), tran, sizeof(unsigned char) * strlen((char*)tran));

    for (int i = 0; i < 32; i++) {
      unsigned char* t = new unsigned char[10];
      memset(t, 0, sizeof(unsigned char) * 10);
      memcpy(t, v_bin + 8 * i, sizeof(unsigned char) * 8);

      unsigned char* t2 = bin2dec(t);
      uint8_t t3 = 0;
      int end = 0;
      while (*(t2 + end) != 0) {
        t3 *= 10;
        t3 += static_cast<uint8_t>(*(t2 + end) - '0');
        end += 1;
      }
      out[i] = t3;
    }
  }
}