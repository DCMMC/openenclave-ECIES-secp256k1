#include <stdlib.h>
#include <string.h>


// align.h ----- start
#ifndef _align_h_
#define _align_h_

/* on Mac OS-X and possibly others, ALIGN(x) is defined in param.h, and -Werror chokes on the redef. */
#ifdef ALIGN
#undef ALIGN
#endif

#if defined(__GNUC__)
#define ALIGN(x) __attribute__ ((aligned(x)))
#elif defined(_MSC_VER)
#define ALIGN(x) __declspec(align(x))
#elif defined(__ARMCC_VERSION)
#define ALIGN(x) __align(x)
#else
#define ALIGN(x)
#endif

#endif
// align.h ----- end

// KeccakP-1600-opt64-config.h ----- start
#define KeccakP1600_implementation_config "all rounds unrolled"
#define KeccakP1600_fullUnrolling
// KeccakP-1600-opt64-config.h ----- end

// KeccakP-1600-SnP.h ----- start
#define KeccakP1600_stateSizeInBytes    200
#define KeccakP1600_stateAlignment      8
#define KeccakP1600_StaticInitialize()
void KeccakP1600_Initialize(void* state);
// KeccakP-1600-SnP.h ----- end

// KeccakSpongeWidth1600.c ----- start
#define SnP_width 1600
// KeccakSpongeWidth1600.c ----- end

// KeccakP-1600-opt64.c ----- start
typedef unsigned char UINT8;
typedef unsigned long long int UINT64;

#if defined(KeccakP1600_useLaneComplementing)
#define UseBebigokimisa
#endif

#if defined(_MSC_VER)
#define ROL64(a, offset) _rotl64(a, offset)
#elif defined(KeccakP1600_useSHLD)
#define ROL64(x,N) ({ \
    register UINT64 __out; \
    register UINT64 __in = x; \
    __asm__ ("shld %2,%0,%0" : "=r"(__out) : "0"(__in), "i"(N)); \
    __out; \
    })
#else
#define ROL64(a, offset) ((((UINT64)a) << offset) ^ (((UINT64)a) >> (64-offset)))
#endif

#include "KeccakP-1600-64.macros"
#ifdef KeccakP1600_fullUnrolling
#define FullUnrolling
#else
#define Unrolling KeccakP1600_unrolling
#endif
#include "KeccakP-1600-unrolling.macros"

static const UINT64 KeccakF1600RoundConstants[24] = {
    0x0000000000000001ULL,
    0x0000000000008082ULL,
    0x800000000000808aULL,
    0x8000000080008000ULL,
    0x000000000000808bULL,
    0x0000000080000001ULL,
    0x8000000080008081ULL,
    0x8000000000008009ULL,
    0x000000000000008aULL,
    0x0000000000000088ULL,
    0x0000000080008009ULL,
    0x000000008000000aULL,
    0x000000008000808bULL,
    0x800000000000008bULL,
    0x8000000000008089ULL,
    0x8000000000008003ULL,
    0x8000000000008002ULL,
    0x8000000000000080ULL,
    0x000000000000800aULL,
    0x800000008000000aULL,
    0x8000000080008081ULL,
    0x8000000000008080ULL,
    0x0000000080000001ULL,
    0x8000000080008008ULL };
// KeccakP-1600-opt64.c ----- end

// SnP-Relaned.h ----- start
#define SnP_AddBytes(state, data, offset, length, KeccakP1600_AddLanes, KeccakP1600_AddBytesInLane, KeccakP1600_laneLengthInBytes) \
    { \
        if ((offset) == 0) { \
            KeccakP1600_AddLanes(state, data, (length)/KeccakP1600_laneLengthInBytes); \
            KeccakP1600_AddBytesInLane(state, \
                (length)/KeccakP1600_laneLengthInBytes, \
                (data)+((length)/KeccakP1600_laneLengthInBytes)*KeccakP1600_laneLengthInBytes, \
                0, \
                (length)%KeccakP1600_laneLengthInBytes); \
        } \
        else { \
            unsigned int _sizeLeft = (length); \
            unsigned int _lanePosition = (offset)/KeccakP1600_laneLengthInBytes; \
            unsigned int _offsetInLane = (offset)%KeccakP1600_laneLengthInBytes; \
            const unsigned char *_curData = (data); \
            while(_sizeLeft > 0) { \
                unsigned int _bytesInLane = KeccakP1600_laneLengthInBytes - _offsetInLane; \
                if (_bytesInLane > _sizeLeft) \
                    _bytesInLane = _sizeLeft; \
                KeccakP1600_AddBytesInLane(state, _lanePosition, _curData, _offsetInLane, _bytesInLane); \
                _sizeLeft -= _bytesInLane; \
                _lanePosition++; \
                _offsetInLane = 0; \
                _curData += _bytesInLane; \
            } \
        } \
    }

#define SnP_ExtractBytes(state, data, offset, length, KeccakP1600_ExtractLanes, KeccakP1600_ExtractBytesInLane, KeccakP1600_laneLengthInBytes) \
    { \
        if ((offset) == 0) { \
            KeccakP1600_ExtractLanes(state, data, (length)/KeccakP1600_laneLengthInBytes); \
            KeccakP1600_ExtractBytesInLane(state, \
                (length)/KeccakP1600_laneLengthInBytes, \
                (data)+((length)/KeccakP1600_laneLengthInBytes)*KeccakP1600_laneLengthInBytes, \
                0, \
                (length)%KeccakP1600_laneLengthInBytes); \
        } \
        else { \
            unsigned int _sizeLeft = (length); \
            unsigned int _lanePosition = (offset)/KeccakP1600_laneLengthInBytes; \
            unsigned int _offsetInLane = (offset)%KeccakP1600_laneLengthInBytes; \
            unsigned char *_curData = (data); \
            while(_sizeLeft > 0) { \
                unsigned int _bytesInLane = KeccakP1600_laneLengthInBytes - _offsetInLane; \
                if (_bytesInLane > _sizeLeft) \
                    _bytesInLane = _sizeLeft; \
                KeccakP1600_ExtractBytesInLane(state, _lanePosition, _curData, _offsetInLane, _bytesInLane); \
                _sizeLeft -= _bytesInLane; \
                _lanePosition++; \
                _offsetInLane = 0; \
                _curData += _bytesInLane; \
            } \
        } \
    }
// SnP-Relaned.h ----- end



typedef unsigned char BitSequence;

typedef size_t BitLength;

typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHLEN = 2 } HashReturn;

ALIGN(KeccakP1600_stateAlignment) typedef struct KeccakWidth1600_SpongeInstanceStruct {
  unsigned char state[KeccakP1600_stateSizeInBytes];
  unsigned int rate;
  unsigned int byteIOIndex;
  int squeezing;
} KeccakWidth1600_SpongeInstance;

typedef struct {
  KeccakWidth1600_SpongeInstance sponge;
  unsigned int fixedOutputLength;
  unsigned char delimitedSuffix;
} Keccak_HashInstance;

void KeccakP1600_Initialize(void* state)
{
  memset(state, 0, 200);
#ifdef KeccakP1600_useLaneComplementing
  ((UINT64*)state)[1] = ~(UINT64)0;
  ((UINT64*)state)[2] = ~(UINT64)0;
  ((UINT64*)state)[8] = ~(UINT64)0;
  ((UINT64*)state)[12] = ~(UINT64)0;
  ((UINT64*)state)[17] = ~(UINT64)0;
  ((UINT64*)state)[20] = ~(UINT64)0;
#endif
}

void KeccakP1600_AddLanes(void* state, const unsigned char* data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
  unsigned int i = 0;
#ifdef NO_MISALIGNED_ACCESSES
  /* If either pointer is misaligned, fall back to byte-wise xor. */
  if (((((uintptr_t)state) & 7) != 0) || ((((uintptr_t)data) & 7) != 0)) {
    for (i = 0; i < laneCount * 8; i++) {
      ((unsigned char*)state)[i] ^= data[i];
    }
  }
  else
#endif
  {
    /* Otherwise... */
    for (; (i + 8) <= laneCount; i += 8) {
      ((UINT64*)state)[i + 0] ^= ((UINT64*)data)[i + 0];
      ((UINT64*)state)[i + 1] ^= ((UINT64*)data)[i + 1];
      ((UINT64*)state)[i + 2] ^= ((UINT64*)data)[i + 2];
      ((UINT64*)state)[i + 3] ^= ((UINT64*)data)[i + 3];
      ((UINT64*)state)[i + 4] ^= ((UINT64*)data)[i + 4];
      ((UINT64*)state)[i + 5] ^= ((UINT64*)data)[i + 5];
      ((UINT64*)state)[i + 6] ^= ((UINT64*)data)[i + 6];
      ((UINT64*)state)[i + 7] ^= ((UINT64*)data)[i + 7];
    }
    for (; (i + 4) <= laneCount; i += 4) {
      ((UINT64*)state)[i + 0] ^= ((UINT64*)data)[i + 0];
      ((UINT64*)state)[i + 1] ^= ((UINT64*)data)[i + 1];
      ((UINT64*)state)[i + 2] ^= ((UINT64*)data)[i + 2];
      ((UINT64*)state)[i + 3] ^= ((UINT64*)data)[i + 3];
    }
    for (; (i + 2) <= laneCount; i += 2) {
      ((UINT64*)state)[i + 0] ^= ((UINT64*)data)[i + 0];
      ((UINT64*)state)[i + 1] ^= ((UINT64*)data)[i + 1];
    }
    if (i < laneCount) {
      ((UINT64*)state)[i + 0] ^= ((UINT64*)data)[i + 0];
    }
  }
#else
  unsigned int i;
  const UINT8* curData = data;
  for (i = 0; i < laneCount; i++, curData += 8) {
    UINT64 lane = (UINT64)curData[0]
      | ((UINT64)curData[1] << 8)
      | ((UINT64)curData[2] << 16)
      | ((UINT64)curData[3] << 24)
      | ((UINT64)curData[4] << 32)
      | ((UINT64)curData[5] << 40)
      | ((UINT64)curData[6] << 48)
      | ((UINT64)curData[7] << 56);
    ((UINT64*)state)[i] ^= lane;
  }
#endif
}

void KeccakP1600_AddBytesInLane(void* state, unsigned int lanePosition, const unsigned char* data, unsigned int offset, unsigned int length)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
  UINT64 lane;
  if (length == 0)
    return;
  if (length == 1)
    lane = data[0];
  else {
    lane = 0;
    memcpy(&lane, data, length);
  }
  lane <<= offset * 8;
#else
  UINT64 lane = 0;
  unsigned int i;
  for (i = 0; i < length; i++)
    lane |= ((UINT64)data[i]) << ((i + offset) * 8);
#endif
  ((UINT64*)state)[lanePosition] ^= lane;
}

void KeccakP1600_ExtractLanes(const void* state, unsigned char* data, unsigned int laneCount)
{
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
  memcpy(data, state, laneCount * 8);
#else
  unsigned int i;

  for (i = 0; i < laneCount; i++)
    fromWordToBytes(data + (i * 8), ((const UINT64*)state)[i]);
#endif
#ifdef KeccakP1600_useLaneComplementing
  if (laneCount > 1) {
    ((UINT64*)data)[1] = ~((UINT64*)data)[1];
    if (laneCount > 2) {
      ((UINT64*)data)[2] = ~((UINT64*)data)[2];
      if (laneCount > 8) {
        ((UINT64*)data)[8] = ~((UINT64*)data)[8];
        if (laneCount > 12) {
          ((UINT64*)data)[12] = ~((UINT64*)data)[12];
          if (laneCount > 17) {
            ((UINT64*)data)[17] = ~((UINT64*)data)[17];
            if (laneCount > 20) {
              ((UINT64*)data)[20] = ~((UINT64*)data)[20];
            }
          }
        }
      }
    }
  }
#endif
}

void KeccakP1600_ExtractBytesInLane(const void* state, unsigned int lanePosition, unsigned char* data, unsigned int offset, unsigned int length)
{
  UINT64 lane = ((UINT64*)state)[lanePosition];
#ifdef KeccakP1600_useLaneComplementing
  if ((lanePosition == 1) || (lanePosition == 2) || (lanePosition == 8) || (lanePosition == 12) || (lanePosition == 17) || (lanePosition == 20))
    lane = ~lane;
#endif
#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
  {
    UINT64 lane1[1];
    lane1[0] = lane;
    memcpy(data, (UINT8*)lane1 + offset, length);
  }
#else
  unsigned int i;
  lane >>= offset * 8;
  for (i = 0; i < length; i++) {
    data[i] = lane & 0xFF;
    lane >>= 8;
  }
#endif
}

void KeccakP1600_AddBytes(void* state, const unsigned char* data, unsigned int offset, unsigned int length)
{
  SnP_AddBytes(state, data, offset, length, KeccakP1600_AddLanes, KeccakP1600_AddBytesInLane, 8);
}

void KeccakP1600_Permute_24rounds(void* state)
{
  declareABCDE
#ifndef KeccakP1600_fullUnrolling
    unsigned int i;
#endif
  UINT64* stateAsLanes = (UINT64*)state;

  copyFromState(A, stateAsLanes)
  rounds24
  copyToState(stateAsLanes, A)
}

void KeccakP1600_AddByte(void* state, unsigned char byte, unsigned int offset)
{
  UINT64 lane = byte;
  lane <<= (offset % 8) * 8;
  ((UINT64*)state)[offset / 8] ^= lane;
}

void KeccakP1600_ExtractBytes(const void* state, unsigned char* data, unsigned int offset, unsigned int length)
{
  SnP_ExtractBytes(state, data, offset, length, KeccakP1600_ExtractLanes, KeccakP1600_ExtractBytesInLane, 8);
}

int KeccakWidth1600_SpongeInitialize(KeccakWidth1600_SpongeInstance* instance, unsigned int rate, unsigned int capacity)
{
  if (rate + capacity != SnP_width)
    return 1;
  if ((rate <= 0) || (rate > SnP_width) || ((rate % 8) != 0))
    return 1;
  KeccakP1600_StaticInitialize();
  KeccakP1600_Initialize(instance->state);
  instance->rate = rate;
  instance->byteIOIndex = 0;
  instance->squeezing = 0;

  return 0;
}

int KeccakWidth1600_SpongeAbsorb(KeccakWidth1600_SpongeInstance* instance, const unsigned char* data, size_t dataByteLen)
{
  size_t i, j;
  unsigned int partialBlock;
  const unsigned char* curData;
  unsigned int rateInBytes = instance->rate / 8;

  if (instance->squeezing)
    return 1; /* Too late for additional input */

  i = 0;
  curData = data;
  while (i < dataByteLen) {
    if ((instance->byteIOIndex == 0) && (dataByteLen >= (i + rateInBytes))) {
#ifdef KeccakP1600_FastLoop_Absorb
      /* processing full blocks first */
      if ((rateInBytes % (SnP_width / 200)) == 0) {
        /* fast lane: whole lane rate */
        j = KeccakP1600_FastLoop_Absorb(instance->state, rateInBytes / (SnP_width / 200), curData, dataByteLen - i);
        i += j;
        curData += j;
      }
      else {
#endif
        for (j = dataByteLen - i; j >= rateInBytes; j -= rateInBytes) {
#ifdef KeccakReference
          displayBytes(1, "Block to be absorbed", curData, rateInBytes);
#endif
          KeccakP1600_AddBytes(instance->state, curData, 0, rateInBytes);
          KeccakP1600_Permute_24rounds(instance->state);
          curData += rateInBytes;
        }
        i = dataByteLen - j;
#ifdef KeccakP1600_FastLoop_Absorb
      }
#endif
    }
    else {
      /* normal lane: using the message queue */
      partialBlock = (unsigned int)(dataByteLen - i);
      if (partialBlock + instance->byteIOIndex > rateInBytes)
        partialBlock = rateInBytes - instance->byteIOIndex;
#ifdef KeccakReference
      displayBytes(1, "Block to be absorbed (part)", curData, partialBlock);
#endif
      i += partialBlock;

      KeccakP1600_AddBytes(instance->state, curData, instance->byteIOIndex, partialBlock);
      curData += partialBlock;
      instance->byteIOIndex += partialBlock;
      if (instance->byteIOIndex == rateInBytes) {
        KeccakP1600_Permute_24rounds(instance->state);
        instance->byteIOIndex = 0;
      }
    }
  }
  return 0;
}

int KeccakWidth1600_SpongeAbsorbLastFewBits(KeccakWidth1600_SpongeInstance* instance, unsigned char delimitedData)
{
  unsigned int rateInBytes = instance->rate / 8;

  if (delimitedData == 0)
    return 1;
  if (instance->squeezing)
    return 1; /* Too late for additional input */

#ifdef KeccakReference
  {
    unsigned char delimitedData1[1];
    delimitedData1[0] = delimitedData;
    displayBytes(1, "Block to be absorbed (last few bits + first bit of padding)", delimitedData1, 1);
  }
#endif
  /* Last few bits, whose delimiter coincides with first bit of padding */
  KeccakP1600_AddByte(instance->state, delimitedData, instance->byteIOIndex);
  /* If the first bit of padding is at position rate-1, we need a whole new block for the second bit of padding */
  if ((delimitedData >= 0x80) && (instance->byteIOIndex == (rateInBytes - 1)))
    KeccakP1600_Permute_24rounds(instance->state);
  /* Second bit of padding */
  KeccakP1600_AddByte(instance->state, 0x80, rateInBytes - 1);
#ifdef KeccakReference
  {
    unsigned char block[SnP_width / 8];
    memset(block, 0, SnP_width / 8);
    block[rateInBytes - 1] = 0x80;
    displayBytes(1, "Second bit of padding", block, rateInBytes);
  }
#endif
  KeccakP1600_Permute_24rounds(instance->state);
  instance->byteIOIndex = 0;
  instance->squeezing = 1;
#ifdef KeccakReference
  displayText(1, "--- Switching to squeezing phase ---");
#endif
  return 0;
}

int KeccakWidth1600_SpongeSqueeze(KeccakWidth1600_SpongeInstance* instance, unsigned char* data, size_t dataByteLen)
{
  size_t i, j;
  unsigned int partialBlock;
  unsigned int rateInBytes = instance->rate / 8;
  unsigned char* curData;

  if (!instance->squeezing)
    KeccakWidth1600_SpongeAbsorbLastFewBits(instance, 0x01);

  i = 0;
  curData = data;
  while (i < dataByteLen) {
    if ((instance->byteIOIndex == rateInBytes) && (dataByteLen >= (i + rateInBytes))) {
      for (j = dataByteLen - i; j >= rateInBytes; j -= rateInBytes) {
        KeccakP1600_Permute_24rounds(instance->state);
        KeccakP1600_ExtractBytes(instance->state, curData, 0, rateInBytes);
#ifdef KeccakReference
        displayBytes(1, "Squeezed block", curData, rateInBytes);
#endif
        curData += rateInBytes;
      }
      i = dataByteLen - j;
    }
    else {
      /* normal lane: using the message queue */
      if (instance->byteIOIndex == rateInBytes) {
        KeccakP1600_Permute_24rounds(instance->state);
        instance->byteIOIndex = 0;
      }
      partialBlock = (unsigned int)(dataByteLen - i);
      if (partialBlock + instance->byteIOIndex > rateInBytes)
        partialBlock = rateInBytes - instance->byteIOIndex;
      i += partialBlock;

      KeccakP1600_ExtractBytes(instance->state, curData, instance->byteIOIndex, partialBlock);
#ifdef KeccakReference
      displayBytes(1, "Squeezed block (part)", curData, partialBlock);
#endif
      curData += partialBlock;
      instance->byteIOIndex += partialBlock;
    }
  }
  return 0;
}



HashReturn Keccak_HashInitialize(Keccak_HashInstance* instance, unsigned int rate, unsigned int capacity, unsigned int hashbitlen, unsigned char delimitedSuffix)
{
  HashReturn result;

  if (delimitedSuffix == 0)
    return FAIL;
  result = (HashReturn)KeccakWidth1600_SpongeInitialize(&instance->sponge, rate, capacity);
  if (result != SUCCESS)
    return result;
  instance->fixedOutputLength = hashbitlen;
  instance->delimitedSuffix = delimitedSuffix;
  return SUCCESS;
}

HashReturn Keccak_HashUpdate(Keccak_HashInstance* instance, const BitSequence* data, BitLength databitlen)
{
  if ((databitlen % 8) == 0)
    return (HashReturn)KeccakWidth1600_SpongeAbsorb(&instance->sponge, data, databitlen / 8);
  else {
    HashReturn ret = (HashReturn)KeccakWidth1600_SpongeAbsorb(&instance->sponge, data, databitlen / 8);
    if (ret == SUCCESS) {
      /* The last partial byte is assumed to be aligned on the least significant bits */
      unsigned char lastByte = data[databitlen / 8];
      /* Concatenate the last few bits provided here with those of the suffix */
      unsigned short delimitedLastBytes = (unsigned short)((unsigned short)lastByte | ((unsigned short)instance->delimitedSuffix << (databitlen % 8)));
      if ((delimitedLastBytes & 0xFF00) == 0x0000) {
        instance->delimitedSuffix = delimitedLastBytes & 0xFF;
      }
      else {
        unsigned char oneByte[1];
        oneByte[0] = delimitedLastBytes & 0xFF;
        ret = (HashReturn)KeccakWidth1600_SpongeAbsorb(&instance->sponge, oneByte, 1);
        instance->delimitedSuffix = (delimitedLastBytes >> 8) & 0xFF;
      }
    }
    return ret;
  }
}

HashReturn Keccak_HashFinal(Keccak_HashInstance* instance, BitSequence* hashval)
{
  HashReturn ret = (HashReturn)KeccakWidth1600_SpongeAbsorbLastFewBits(&instance->sponge, instance->delimitedSuffix);
  if (ret == SUCCESS)
    return (HashReturn)KeccakWidth1600_SpongeSqueeze(&instance->sponge, hashval, instance->fixedOutputLength / 8);
  else
    return ret;
}