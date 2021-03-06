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


#include "contract.h"
#include "ec_key.h"
// TODO (DCMMC) implement this.
// #include <ripple/crypto/RandomNumbers.h>
#include "ECIES.h"
#include "ECDSAKey.h"
#include "common/trace.h"

#include <openenclave/enclave.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>

// (DCMMC) must disable USE_LOW_OPENSSL. Because openclave does not support low version
// of openssl!
// #define USE_LOW_OPENSSL

namespace ripple {

// ECIES uses elliptic curve keys to send an encrypted message.

// A shared secret is generated from one public key and one private key.
// The same key results regardless of which key is public and which private.

// Anonymous messages can be sent by generating an ephemeral public/private
// key pair, using that private key with the recipient's public key to
// encrypt and publishing the ephemeral public key. Non-anonymous messages
// can be sent by using your own private key with the recipient's public key.

// A random IV is used to encrypt the message and an HMAC is used to ensure
// message integrity. If you need timestamps or need to tell the recipient
// which key to use (his, yours, or ephemeral) you must add that data.
// (Obviously, key information can't go in the encrypted portion anyway.)

// Our ciphertext is all encrypted except the IV. The encrypted data decodes as follows:
// 1) IV (unencrypted)
// 2) Encrypted: HMAC of original plaintext
// 3) Encrypted: Original plaintext
// 4) Encrypted: Rest of block/padding

// ECIES operations throw on any error such as a corrupt message or incorrect
// key. They *must* be called in try/catch blocks.

// Algorithmic choices:
#define ECIES_KEY_HASH      SHA512              // Hash used to expand shared secret
#define ECIES_KEY_LENGTH    (512/8)             // Size of expanded shared secret
#define ECIES_MIN_SEC       (128/8)             // The minimum equivalent security
#define ECIES_ENC_ALGO      EVP_aes_256_cbc()   // Encryption algorithm
// #define ECIES_ENC_KEY_TYPE  uint256             // Type used to hold shared secret
#define ECIES_ENC_KEY_TYPE  Blob256                // Type used to hold shared secret
#define ECIES_ENC_KEY_SIZE  (256/8)             // Encryption key size
#define ECIES_ENC_BLK_SIZE  (128/8)             // Encryption block size
// #define ECIES_ENC_IV_TYPE   uint128             // Type used to hold IV
#define ECIES_ENC_IV_TYPE   Blob128                // Type used to hold IV
#define ECIES_HMAC_ALGO     EVP_sha256()        // HMAC algorithm
// #define ECIES_HMAC_KEY_TYPE uint256             // Type used to hold HMAC key
#define ECIES_HMAC_KEY_TYPE Blob256                // Type used to hold HMAC key
#define ECIES_HMAC_KEY_SIZE (256/8)             // Size of HMAC key
// #define ECIES_HMAC_TYPE     uint256             // Type used to hold HMAC value
#define ECIES_HMAC_TYPE     Blob256                // Type used to hold HMAC value
#define ECIES_HMAC_SIZE     (256/8)             // Size of HMAC value


// returns a 32-byte secret unique to these two keys. At least one private key must be known.
static void getECIESSecret (const openssl::ec_key& secretKey, const openssl::ec_key& publicKey, ECIES_ENC_KEY_TYPE& enc_key, ECIES_HMAC_KEY_TYPE& hmac_key)
{
    EC_KEY* privkey = (EC_KEY*) secretKey.get();
    EC_KEY* pubkey  = (EC_KEY*) publicKey.get();

    // Retrieve a secret generated from an EC key pair. At least one private key must be known.
    if (privkey == nullptr || pubkey == nullptr)
        Throw<std::runtime_error> ("missing key");

    if (! EC_KEY_get0_private_key (privkey))
        Throw<std::runtime_error> ("not a private key");

    unsigned char rawbuf[512];
    int buflen = ECDH_compute_key (rawbuf, 512, EC_KEY_get0_public_key (pubkey), privkey, nullptr);

    if (buflen < ECIES_MIN_SEC)
        Throw<std::runtime_error> ("ecdh key failed");

    unsigned char hbuf[ECIES_KEY_LENGTH];
    ECIES_KEY_HASH (rawbuf, buflen, hbuf);
    memset (rawbuf, 0, ECIES_HMAC_KEY_SIZE);

    assert ((ECIES_ENC_KEY_SIZE + ECIES_HMAC_KEY_SIZE) >= ECIES_KEY_LENGTH);
    memcpy (enc_key.data (), hbuf, ECIES_ENC_KEY_SIZE);
    memcpy (hmac_key.data (), hbuf + ECIES_ENC_KEY_SIZE, ECIES_HMAC_KEY_SIZE);
    memset (hbuf, 0, ECIES_KEY_LENGTH);
}

/*
static void getECIESSecret (uint256 const& secretKey,
                            Blob const& publicKey,
                            ECIES_ENC_KEY_TYPE& enc_key,
                            ECIES_HMAC_KEY_TYPE& hmac_key)
*/
static void getECIESSecret (Blob256 const& secretKey,
                            Blob288 const& publicKey,
                            ECIES_ENC_KEY_TYPE& enc_key,
                            ECIES_HMAC_KEY_TYPE& hmac_key)
{
    getECIESSecret (ECDSAPrivateKey (secretKey), ECDSAPublicKey (publicKey), enc_key, hmac_key);
}

#ifndef USE_LOW_OPENSSL
static ECIES_HMAC_TYPE makeHMAC (const ECIES_HMAC_KEY_TYPE& secret, Blob const& data)
{
    HMAC_CTX *ctx = HMAC_CTX_new();

    if (HMAC_Init_ex (ctx, secret.data (), ECIES_HMAC_KEY_SIZE, ECIES_HMAC_ALGO, nullptr) != 1)
    {
        HMAC_CTX_free (ctx);
        Throw<std::runtime_error> ("init hmac");
    }

    if (HMAC_Update (ctx, & (data.front ()), data.size ()) != 1)
    {
        HMAC_CTX_free (ctx);
        Throw<std::runtime_error> ("update hmac");
    }

    ECIES_HMAC_TYPE ret;
    unsigned int ml = ECIES_HMAC_SIZE;

    if (HMAC_Final (ctx, ret.data (), &ml) != 1)
    {
        HMAC_CTX_free (ctx);
        Throw<std::runtime_error> ("finalize hmac");
    }

    assert (ml == ECIES_HMAC_SIZE);
    HMAC_CTX_free (ctx);

    return ret;
}

// Blob encryptECIES(uint256 const& secretKey, Blob const& publicKey, Blob const& plaintext)
Blob encryptECIES(Blob256 const& secretKey, Blob288 const& publicKey, Blob const& plaintext)
{
	if (plaintext.size() == 0)
		Throw<std::runtime_error>("plaintext is empty");
	ECIES_ENC_IV_TYPE iv;
    // TODO (DCMMC) implement this.
	// random_fill(iv.begin(), ECIES_ENC_BLK_SIZE);
    oe_random(iv.data(), ECIES_ENC_BLK_SIZE);

	ECIES_ENC_KEY_TYPE secret;
	ECIES_HMAC_KEY_TYPE hmacKey;

	getECIESSecret(secretKey, publicKey, secret, hmacKey);
	ECIES_HMAC_TYPE hmac = makeHMAC(hmacKey, plaintext);
	// hmacKey.zero();
    std::fill(hmacKey.begin(), hmacKey.end(), 0);

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	if (EVP_EncryptInit_ex(ctx, ECIES_ENC_ALGO, nullptr, secret.data(), iv.data()) != 1)
	{
		EVP_CIPHER_CTX_free(ctx);
		// secret.zero();
        std::fill(secret.begin(), secret.end(), 0);
		Throw<std::runtime_error>("init cipher ctx");
	}

	// secret.zero();
    std::fill(secret.begin(), secret.end(), 0);

	Blob out(plaintext.size() + ECIES_HMAC_SIZE + ECIES_ENC_KEY_SIZE + ECIES_ENC_BLK_SIZE, 0);
	int len = 0, bytesWritten;

	// output IV
	memcpy(&(out.front()), iv.data(), ECIES_ENC_BLK_SIZE);
	len = ECIES_ENC_BLK_SIZE;

	// Encrypt/output HMAC
	bytesWritten = out.capacity() - len;
	assert(bytesWritten > 0);

	if (EVP_EncryptUpdate(ctx, &(out.front()) + len, &bytesWritten, hmac.data(), ECIES_HMAC_SIZE) < 0)
	{
		EVP_CIPHER_CTX_free(ctx);
		Throw<std::runtime_error>("");
	}

	len += bytesWritten;

	// encrypt/output plaintext
	bytesWritten = out.capacity() - len;
	assert(bytesWritten > 0);

	if (EVP_EncryptUpdate(ctx, &(out.front()) + len, &bytesWritten, &(plaintext.front()), plaintext.size()) < 0)
	{
		EVP_CIPHER_CTX_free(ctx);
		Throw<std::runtime_error>("");
	}

	len += bytesWritten;

	// finalize
	bytesWritten = out.capacity() - len;

	if (EVP_EncryptFinal_ex(ctx, &(out.front()) + len, &bytesWritten) < 0)
	{
		EVP_CIPHER_CTX_free(ctx);
		Throw<std::runtime_error>("encryption error");
	}

	len += bytesWritten;

	// Output contains: IV, encrypted HMAC, encrypted data, encrypted padding
	assert(len <= (plaintext.size() + ECIES_HMAC_SIZE + (2 * ECIES_ENC_BLK_SIZE)));
	assert(len >= (plaintext.size() + ECIES_HMAC_SIZE + ECIES_ENC_BLK_SIZE)); // IV, HMAC, data
	out.resize(len);
	EVP_CIPHER_CTX_free(ctx);
	return out;
}

// Blob decryptECIES(uint256 const& secretKey, Blob const& publicKey, Blob const& ciphertext)
Blob decryptECIES(Blob256 const& secretKey, Blob288 const& publicKey, Blob const& ciphertext)
{
	// minimum ciphertext = IV + HMAC + 1 block
	if (ciphertext.size() < ((2 * ECIES_ENC_BLK_SIZE) + ECIES_HMAC_SIZE))
		Throw<std::runtime_error>("ciphertext too short");

	// extract IV
	ECIES_ENC_IV_TYPE iv;
	memcpy(iv.data(), &(ciphertext.front()), ECIES_ENC_BLK_SIZE);

	// begin decrypting
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	ECIES_ENC_KEY_TYPE secret;
	ECIES_HMAC_KEY_TYPE hmacKey;
	getECIESSecret(secretKey, publicKey, secret, hmacKey);

	if (EVP_DecryptInit_ex(ctx, ECIES_ENC_ALGO, nullptr, secret.data(), iv.data()) != 1)
	{
		// secret.zero();
		// hmacKey.zero();
        std::fill(secret.begin(), secret.end(), 0);
        std::fill(hmacKey.begin(), hmacKey.end(), 0);
		EVP_CIPHER_CTX_free(ctx);
		Throw<std::runtime_error>("unable to init cipher");
	}

	// decrypt mac
	ECIES_HMAC_TYPE hmac;
	int outlen = ECIES_HMAC_SIZE;

	if ((EVP_DecryptUpdate(ctx, hmac.data(), &outlen,
		&(ciphertext.front()) + ECIES_ENC_BLK_SIZE, ECIES_HMAC_SIZE + 1) != 1) || (outlen != ECIES_HMAC_SIZE))
	{
		// secret.zero();
		// hmacKey.zero();
        std::fill(secret.begin(), secret.end(), 0);
        std::fill(hmacKey.begin(), hmacKey.end(), 0);
		EVP_CIPHER_CTX_free(ctx);
		Throw<std::runtime_error>("unable to extract hmac");
	}

	// decrypt plaintext (after IV and encrypted mac)
	Blob plaintext(ciphertext.size() - ECIES_HMAC_SIZE - ECIES_ENC_BLK_SIZE);
	outlen = plaintext.size();

	if (EVP_DecryptUpdate(ctx, &(plaintext.front()), &outlen,
		&(ciphertext.front()) + ECIES_ENC_BLK_SIZE + ECIES_HMAC_SIZE + 1,
		ciphertext.size() - ECIES_ENC_BLK_SIZE - ECIES_HMAC_SIZE - 1) != 1)
	{
		// secret.zero();
		// hmacKey.zero();
        std::fill(secret.begin(), secret.end(), 0);
        std::fill(hmacKey.begin(), hmacKey.end(), 0);
		EVP_CIPHER_CTX_free(ctx);
		Throw<std::runtime_error>("unable to extract plaintext");
	}

	// decrypt padding
	int flen = 0;

	if (EVP_DecryptFinal(ctx, &(plaintext.front()) + outlen, &flen) != 1)
	{
        // secret.zero();
		// hmacKey.zero();
        std::fill(secret.begin(), secret.end(), 0);
        std::fill(hmacKey.begin(), hmacKey.end(), 0);
		EVP_CIPHER_CTX_free(ctx);
		Throw<std::runtime_error>("plaintext had bad padding");
	}

	plaintext.resize(flen + outlen);

	// verify integrity
	if (hmac != makeHMAC(hmacKey, plaintext))
	{
        // secret.zero();
		// hmacKey.zero();
        std::fill(secret.begin(), secret.end(), 0);
        std::fill(hmacKey.begin(), hmacKey.end(), 0);
		EVP_CIPHER_CTX_free(ctx);
		Throw<std::runtime_error>("plaintext had bad hmac");
	}

    // secret.zero();
    // hmacKey.zero();
    std::fill(secret.begin(), secret.end(), 0);
    std::fill(hmacKey.begin(), hmacKey.end(), 0);

	EVP_CIPHER_CTX_free(ctx);
	return plaintext;
}
#endif

#ifdef USE_LOW_OPENSSL
static ECIES_HMAC_TYPE makeHMAC_SSL102(const ECIES_HMAC_KEY_TYPE& secret, Blob const& data)
{
	HMAC_CTX ctx;
	HMAC_CTX_init(&ctx);

	if (HMAC_Init_ex(&ctx, secret.data(), ECIES_HMAC_KEY_SIZE, ECIES_HMAC_ALGO, nullptr) != 1)
	{
		HMAC_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("init hmac");
	}

	if (HMAC_Update(&ctx, &(data.front()), data.size()) != 1)
	{
		HMAC_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("update hmac");
	}

	ECIES_HMAC_TYPE ret;
	unsigned int ml = ECIES_HMAC_SIZE;

	if (HMAC_Final(&ctx, ret.data(), &ml) != 1)
	{
		HMAC_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("finalize hmac");
	}

	assert(ml == ECIES_HMAC_SIZE);
	HMAC_CTX_cleanup(&ctx);

	return ret;
}
// Blob encryptECIES_SSL102(uint256 const& secretKey, Blob const& publicKey, Blob const& plaintext)
Blob encryptECIES_SSL102(Blob256 const& secretKey, Blob288 const& publicKey, Blob const& plaintext)
{
	if (plaintext.size() == 0)
		Throw<std::runtime_error>("plaintext is empty");
	ECIES_ENC_IV_TYPE iv;
    // TODO (DCMMC) implement this.
	// random_fill(iv.begin(), ECIES_ENC_BLK_SIZE);

	ECIES_ENC_KEY_TYPE secret;
	ECIES_HMAC_KEY_TYPE hmacKey;

	getECIESSecret(secretKey, publicKey, secret, hmacKey);
	ECIES_HMAC_TYPE hmac = makeHMAC_SSL102(hmacKey, plaintext);
	// hmacKey.zero();
    std::fill(hmacKey.begin(), hmacKey.end(), 0);

	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	if (EVP_EncryptInit_ex(&ctx, ECIES_ENC_ALGO, nullptr, secret.data(), iv.data()) != 1)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		// secret.zero();
        std::fill(secret.begin(), secret.end(), 0);
		Throw<std::runtime_error>("init cipher ctx");
	}

	// secret.zero();
    std::fill(secret.begin(), secret.end(), 0);

	Blob out(plaintext.size() + ECIES_HMAC_SIZE + ECIES_ENC_KEY_SIZE + ECIES_ENC_BLK_SIZE, 0);
	int len = 0, bytesWritten;

	// output IV
	memcpy(&(out.front()), iv.data(), ECIES_ENC_BLK_SIZE);
	len = ECIES_ENC_BLK_SIZE;

	// Encrypt/output HMAC
	bytesWritten = out.capacity() - len;
	assert(bytesWritten > 0);

	if (EVP_EncryptUpdate(&ctx, &(out.front()) + len, &bytesWritten, hmac.data(), ECIES_HMAC_SIZE) < 0)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("");
	}

	len += bytesWritten;

	// encrypt/output plaintext
	bytesWritten = out.capacity() - len;
	assert(bytesWritten > 0);

	if (EVP_EncryptUpdate(&ctx, &(out.front()) + len, &bytesWritten, &(plaintext.front()), plaintext.size()) < 0)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("");
	}

	len += bytesWritten;

	// finalize
	bytesWritten = out.capacity() - len;

	if (EVP_EncryptFinal_ex(&ctx, &(out.front()) + len, &bytesWritten) < 0)
	{
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("encryption error");
	}

	len += bytesWritten;

	// Output contains: IV, encrypted HMAC, encrypted data, encrypted padding
	assert(len <= (plaintext.size() + ECIES_HMAC_SIZE + (2 * ECIES_ENC_BLK_SIZE)));
	assert(len >= (plaintext.size() + ECIES_HMAC_SIZE + ECIES_ENC_BLK_SIZE)); // IV, HMAC, data
	out.resize(len);
	EVP_CIPHER_CTX_cleanup(&ctx);
	return out;
}

// Blob decryptECIES_SSL102(uint256 const& secretKey, Blob const& publicKey, Blob const& ciphertext)
Blob decryptECIES_SSL102(Blob256 const& secretKey, Blob288 const& publicKey, Blob const& ciphertext)
{
	// minimum ciphertext = IV + HMAC + 1 block
	if (ciphertext.size() < ((2 * ECIES_ENC_BLK_SIZE) + ECIES_HMAC_SIZE))
		Throw<std::runtime_error>("ciphertext too short");

	// extract IV
	ECIES_ENC_IV_TYPE iv;
	memcpy(iv.data(), &(ciphertext.front()), ECIES_ENC_BLK_SIZE);

	// begin decrypting
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	ECIES_ENC_KEY_TYPE secret;
	ECIES_HMAC_KEY_TYPE hmacKey;
	getECIESSecret(secretKey, publicKey, secret, hmacKey);

	if (EVP_DecryptInit_ex(&ctx, ECIES_ENC_ALGO, nullptr, secret.data(), iv.data()) != 1)
	{
		// secret.zero();
		// hmacKey.zero();
        std::fill(secret.begin(), secret.end(), 0);
        std::fill(hmacKey.begin(), hmacKey.end(), 0);
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("unable to init cipher");
	}

	// decrypt mac
	ECIES_HMAC_TYPE hmac;
	int outlen = ECIES_HMAC_SIZE;

	if ((EVP_DecryptUpdate(&ctx, hmac.data(), &outlen,
		&(ciphertext.front()) + ECIES_ENC_BLK_SIZE, ECIES_HMAC_SIZE + 1) != 1) || (outlen != ECIES_HMAC_SIZE))
	{
		// secret.zero();
		// hmacKey.zero();
        std::fill(secret.begin(), secret.end(), 0);
        std::fill(hmacKey.begin(), hmacKey.end(), 0);
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("unable to extract hmac");
	}

	// decrypt plaintext (after IV and encrypted mac)
	Blob plaintext(ciphertext.size() - ECIES_HMAC_SIZE - ECIES_ENC_BLK_SIZE);
	outlen = plaintext.size();

	if (EVP_DecryptUpdate(&ctx, &(plaintext.front()), &outlen,
		&(ciphertext.front()) + ECIES_ENC_BLK_SIZE + ECIES_HMAC_SIZE + 1,
		ciphertext.size() - ECIES_ENC_BLK_SIZE - ECIES_HMAC_SIZE - 1) != 1)
	{
		// secret.zero();
		// hmacKey.zero();
        std::fill(secret.begin(), secret.end(), 0);
        std::fill(hmacKey.begin(), hmacKey.end(), 0);
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("unable to extract plaintext");
	}

	// decrypt padding
	int flen = 0;

	if (EVP_DecryptFinal(&ctx, &(plaintext.front()) + outlen, &flen) != 1)
	{
		// secret.zero();
		// hmacKey.zero();
        std::fill(secret.begin(), secret.end(), 0);
        std::fill(hmacKey.begin(), hmacKey.end(), 0);
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("plaintext had bad padding");
	}

	plaintext.resize(flen + outlen);

	// verify integrity
	if (hmac != makeHMAC_SSL102(hmacKey, plaintext))
	{
		// secret.zero();
		// hmacKey.zero();
        std::fill(secret.begin(), secret.end(), 0);
        std::fill(hmacKey.begin(), hmacKey.end(), 0);
		EVP_CIPHER_CTX_cleanup(&ctx);
		Throw<std::runtime_error>("plaintext had bad hmac");
	}

    // secret.zero();
    // hmacKey.zero();
    std::fill(secret.begin(), secret.end(), 0);
    std::fill(hmacKey.begin(), hmacKey.end(), 0);

	EVP_CIPHER_CTX_cleanup(&ctx);
	return plaintext;
}
#endif

// Blob asymEncrypt(Blob const& passBlob, PublicKey const& publicKey)
Blob asymEncrypt(Blob const& passBlob, Blob const& publicKey)
{
    int ret = 0;
    // auto const type = publicKeyType(publicKey);
    // auto const ephKeyPair = randomKeyPair(*type);
    Blob288 ephPublKey;
    Blob256 ephPrivKey;
    ret = ec_generate_keypair(ephPrivKey, ephPublKey);
    // PublicKey ephPublKey = ephKeyPair.first;
    Blob vucCipherText;
    if (ret)
    {
        TRACE_ENCLAVE("ec_generate_keypair failed in asymEncrypt!");
        return vucCipherText;
    }

    Blob288 publickBlob;
    for ( int i = 0; i < publickBlob.size(); i++ )
    {
        publickBlob[i] = publicKey[i];
    }

    // SecretKey ephPrivKey = ephKeyPair.second;
    // Blob privateBlob(ephPrivKey.data(), ephPrivKey.data() + ephPrivKey.size());
    // uint256 secretKey = uint256::fromVoid(privateBlob.data() + (privateBlob.size() - 32));
    // Blob secretKey(privateBlob.data() + (privateBlob.size() - 32));

    try
    {
#ifdef USE_LOW_OPENSSL
        vucCipherText = encryptECIES_SSL102(ephPrivKey, publickBlob, passBlob);
#else
        vucCipherText = encryptECIES(ephPrivKey, publickBlob, passBlob);
#endif
    }
    catch (std::exception const&)
    {
        // int i;
        // TODO: log this or explain why this is unimportant!
    }
    //combine with random publickey ahead
    Blob finalCipher;
    finalCipher.resize(ephPublKey.size());
    memcpy(&(finalCipher.front()), ephPublKey.data(), ephPublKey.size());
    finalCipher.insert(finalCipher.end(), vucCipherText.begin(), vucCipherText.end());
    return finalCipher;
}

// Blob asymDecrypt(Blob const& cipherBlob, SecretKey const& secret_key)
Blob asymDecrypt(Blob const& cipherBlob, Blob const& secret_key)
{
    Blob288 publickBlob;
    for ( int i = 0; i < 33; i++ )
    {
        publickBlob[i] = cipherBlob[i];
    }
    //truncate real cipher
    Blob realCipher(cipherBlob.data() + 33, cipherBlob.data() + cipherBlob.size());
    // PublicKey ephPublKey(Slice{ publickBlob.data(), publickBlob.size() });
    // auto const type = publicKeyType(ephPublKey);

    // Blob privateBlob(secret_key.data(), secret_key.data() + secret_key.size());
    // uint256 secretKey = uint256::fromVoid(privateBlob.data() + (privateBlob.size() - 32));
    // Blob secretKey(privateBlob.data() + (privateBlob.size() - 32));
    Blob256 secretKey;
    for ( int i = 0; i < secretKey.size(); i++ )
    {
        secretKey[i] = secret_key[i];
    }

    Blob vucPlainText;
    {
        try
        {
#ifdef USE_LOW_OPENSSL
            vucPlainText =
                decryptECIES_SSL102(secretKey, publickBlob, realCipher);
#else
            vucPlainText = decryptECIES(secretKey, publickBlob, realCipher);
#endif
        }
        catch (std::exception const&)
        {
            // TODO: log this or explain why this is unimportant!
            TRACE_ENCLAVE("Exception in asymDecrypt!");
        }
    }
    return vucPlainText;
}

} // ripple
