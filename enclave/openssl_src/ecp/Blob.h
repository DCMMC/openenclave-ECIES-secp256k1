//------------------------------------------------------------------------------
/*
    This file is part of rippled: https://github.com/ripple/rippled
    Copyright (c) 2012, 2013 Ripple Labs Inc.

    Permission to use, copy, modify, and/or distribute this software for any
    purpose  with  or without fee is hereby granted, provided that the above
    copyright notice and this permission notice appear in all copies.

    THE  SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
    WITH  REGARD  TO  THIS  SOFTWARE  INCLUDING  ALL  IMPLIED  WARRANTIES  OF
    MERCHANTABILITY  AND  FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
    ANY  SPECIAL ,  DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
    WHATSOEVER  RESULTING  FROM  LOSS  OF USE, DATA OR PROFITS, WHETHER IN AN
    ACTION  OF  CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/
//==============================================================================

#ifndef RIPPLE_BASICS_BLOB_H_INCLUDED
#define RIPPLE_BASICS_BLOB_H_INCLUDED

#include <vector>
#include <array>

namespace ripple {

/** Storage for linear binary data.
    Blocks of binary data appear often in various idioms and structures.
*/
using Blob = std::vector<unsigned char>;
// [ref] https://github.com/ripple/rippled/blob/develop/src/ripple/basics/base_uint.h#L89
using Blob128 = std::array<unsigned char, 16>;
using Blob256 = std::array<unsigned char, 32>;
using Blob288 = std::array<unsigned char, 33>;

}  // namespace ripple

#endif
