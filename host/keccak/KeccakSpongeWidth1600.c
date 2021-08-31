#include "keccak/KeccakSpongeWidth1600.h"

#ifdef KeccakReference
    #include "displayIntermediateValues.h"
#endif

#ifndef KeccakP1600_excluded
    #include "keccak/KeccakP-1600-SnP.h"

    #define prefix KeccakWidth1600
    #define SnP KeccakP1600
    #define SnP_width 1600
    #define SnP_Permute KeccakP1600_Permute_24rounds
    #if defined(KeccakF1600_FastLoop_supported)
        #define SnP_FastLoop_Absorb KeccakF1600_FastLoop_Absorb
    #endif
        #include "keccak/KeccakSponge.inc"
    #undef prefix
    #undef SnP
    #undef SnP_width
    #undef SnP_Permute
    #undef SnP_FastLoop_Absorb
#endif

#ifndef KeccakP1600_excluded
    #include "keccak/KeccakP-1600-SnP.h"

    #define prefix KeccakWidth1600_12rounds
    #define SnP KeccakP1600
    #define SnP_width 1600
    #define SnP_Permute KeccakP1600_Permute_12rounds
    #if defined(KeccakP1600_12rounds_FastLoop_supported)
        #define SnP_FastLoop_Absorb KeccakP1600_12rounds_FastLoop_Absorb
    #endif
        #include "keccak/KeccakSponge.inc"
    #undef prefix
    #undef SnP
    #undef SnP_width
    #undef SnP_Permute
    #undef SnP_FastLoop_Absorb
#endif
