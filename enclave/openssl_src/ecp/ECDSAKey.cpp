//------------------------------------------------------------------------------
/*
 This file is part of chainsqld: https://github.com/chainsql/chainsqld
 Copyright (c) 2016-2018 Peersafe Technology Co., Ltd.
 
	chainsqld is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.
 
	chainsqld is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	You should have received a copy of the GNU General Public License
	along with cpp-ethereum.  If not, see <http://www.gnu.org/licenses/>.
 */
//==============================================================================

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

// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.


#include "contract.h"
#include "ECDSAKey.h"
#include "common/trace.h"
#include <openssl/ec.h>
#include <openssl/hmac.h>

namespace ripple  {

using openssl::ec_key;

// https://stackoverflow.com/questions/48685191/separating-public-and-private-keys-of-ecdsa-keypair?rq=1
int ec_generate_keypair(Blob256 & secret_key, Blob288 & public_key)
{
    EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);

    if(!key)
    {
        TRACE_ENCLAVE("Error creating curve key");
        return -1;
    }
    EC_KEY_set_conv_form (key, POINT_CONVERSION_COMPRESSED);

    if(!EC_KEY_generate_key(key))
    {
        TRACE_ENCLAVE("Error generating curve key");
        EC_KEY_free(key);
        return -1;
    }

    BIGNUM const* sk = EC_KEY_get0_private_key(key);

    if(!sk)
    {
        TRACE_ENCLAVE("Error getting private key");
        EC_KEY_free(key);
        return -1;
    }
    int ret = 0;
    if ( !(ret = BN_bn2bin(sk, secret_key.data())) )
    {
        TRACE_ENCLAVE("BN_bn2bin for sk return NULL");
        return -1;
    }

    TRACE_ENCLAVE("Private key: %s", BN_bn2hex(sk));

    BIGNUM const* pk = EC_POINT_point2bn(EC_KEY_get0_group(key),
            EC_KEY_get0_public_key(key), POINT_CONVERSION_COMPRESSED,
            NULL, NULL);
    if(!pk)
    {
        TRACE_ENCLAVE("Error getting public key");
        EC_KEY_free(key);
        return -1;
    }

    TRACE_ENCLAVE("Public key: %s", BN_bn2hex(pk));
    if ( !(ret = BN_bn2bin(pk, public_key.data())) )
    {
        TRACE_ENCLAVE("BN_bn2bin for pk return NULL");
        return -1;
    }

    // EC_KEY_free(key);
    TRACE_ENCLAVE("done gen key.");
    return 0;
}

static EC_KEY* new_initialized_EC_KEY()
{
    EC_KEY* key = EC_KEY_new_by_curve_name (NID_secp256k1);

    if (key == nullptr)
        Throw<std::runtime_error> (
            "new_initialized_EC_KEY() : EC_KEY_new_by_curve_name failed");

    EC_KEY_set_conv_form (key, POINT_CONVERSION_COMPRESSED);

    return key;
}

// ec_key ECDSAPrivateKey (uint256 const& serialized)
ec_key ECDSAPrivateKey (Blob256 const& serialized)
{
    BIGNUM* bn = BN_bin2bn (serialized.data(), serialized.size(), nullptr);

    if (bn == nullptr)
        Throw<std::runtime_error> ("ec_key::ec_key: BN_bin2bn failed");

    EC_KEY* key = new_initialized_EC_KEY();
    ec_key::pointer_t ptr = nullptr;

    const bool ok = EC_KEY_set_private_key (key, bn);

    BN_clear_free (bn);

    if (ok)
        ptr = (ec_key::pointer_t) key;
    else
        EC_KEY_free (key);

    return ec_key(ptr);
}

ec_key ECDSAPublicKey (std::uint8_t const* data, std::size_t size)
{
    EC_KEY* key = new_initialized_EC_KEY();
    ec_key::pointer_t ptr = nullptr;

    if (o2i_ECPublicKey (&key, &data, size) != nullptr)
    {
        EC_KEY_set_conv_form (key, POINT_CONVERSION_COMPRESSED);
        ptr = (ec_key::pointer_t) key;
    }
    else
    {
        TRACE_ENCLAVE("o2i_ECPublicKey return NULL");
        EC_KEY_free (key);
    }

    return ec_key(ptr);
}

ec_key ECDSAPublicKey (Blob288 const& serialized)
{
    return ECDSAPublicKey (&serialized[0], serialized.size());
}

} // ripple
