// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/aes.h>
#include <mbedtls/config.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>

#include "common/encryptor.h"
#include "common/trace.h"

#define ENCRYPT_OPERATION true
#define DECRYPT_OPERATION false

// Compute the sha256 hash of given data.
int ecall_dispatcher::Sha256(
    const uint8_t* data,
    size_t data_size,
    uint8_t sha256[HASH_VALUE_SIZE_IN_BYTES])
{
    int ret = 0;
    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);

    ret = mbedtls_sha256_starts_ret(&ctx, 0);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_update_ret(&ctx, data, data_size);
    if (ret)
        goto exit;

    ret = mbedtls_sha256_finish_ret(&ctx, sha256);
    if (ret)
        goto exit;

exit:
    mbedtls_sha256_free(&ctx);
    return ret;
}

// This routine uses the mbed_tls library to derive an AES key from the input
// password and produces a password-based key.
int ecall_dispatcher::generate_password_key(
    const char* password,
    unsigned char* salt,
    unsigned char* key,
    unsigned int key_size)
{
    mbedtls_md_context_t sha_ctx;
    const mbedtls_md_info_t* info_sha;
    int ret = 0;
    mbedtls_md_init(&sha_ctx);

    TRACE_ENCLAVE("generate_password_key");

    memset(key, 0, key_size);
    info_sha = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (info_sha == nullptr)
    {
        ret = 1;
        goto exit;
    }

    // setting up hash algorithm context
    ret = mbedtls_md_setup(&sha_ctx, info_sha, 1);
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_md_setup() failed with -0x%04x", -ret);
        goto exit;
    }

    // Derive a key from a password using PBKDF2.
    // PBKDF2 (Password-Based Key Derivation Function 2) are key derivation
    // functions with a sliding computational cost, aimed to reduce the
    // vulnerability of encrypted keys to brute force attacks. See
    // (https://en.wikipedia.org/wiki/PBKDF2) for more details.
    ret = mbedtls_pkcs5_pbkdf2_hmac(
        &sha_ctx,                       // Generic HMAC context
        (const unsigned char*)password, // Password to use when generating key
        strlen((const char*)password),  // Length of password
        salt,                           // salt to use when generating key
        SALT_SIZE_IN_BYTES,             // size of salt
        100000,                         // iteration count
        key_size,                       // length of generated key in bytes
        key);                           // generated key
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_pkcs5_pbkdf2_hmac failed with -0x%04x", -ret);
        goto exit;
    }
    TRACE_ENCLAVE("Key based on password successfully generated");
exit:
    mbedtls_md_free(&sha_ctx);
    return ret;
}

// Generate an encryption key: this is the key used to encrypt data
int ecall_dispatcher::generate_encryption_key(
    unsigned char* key,
    unsigned int key_size)
{
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    const char pers[] = "EncryptionKey";
    int ret = 0;

    TRACE_ENCLAVE("generate_encryption_key:");

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    memset(key, 0, key_size);

    // mbedtls_ctr_drbg_seed seeds and sets up the CTR_DRBG entropy source for
    // future reseeds.
    ret = mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        (unsigned char*)pers,
        sizeof(pers));
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_ctr_drbg_init failed with -0x%04x\n", -ret);
        goto exit;
    }

    // mbedtls_ctr_drbg_random uses CTR_DRBG to generate random data
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, key, key_size);
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_ctr_drbg_random failed with -0x%04x\n", -ret);
        goto exit;
    }
    TRACE_ENCLAVE(
        "Encryption key successfully generated: a %d byte key (hex):  ",
        key_size);

exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

// The encryption key is encrypted before it was written back to the encryption
// header as part of the encryption metadata.
int ecall_dispatcher::cipher_encryption_key(
    bool encrypt,
    unsigned char* input_data,
    unsigned int input_data_size,
    unsigned char* encrypt_key,
    unsigned char* iv,
    unsigned char* output_data,
    unsigned int output_data_size)
{
    int ret = 0;
    (void)output_data_size;
    mbedtls_aes_context aescontext;

    TRACE_ENCLAVE(
        "cipher_encryption_key: %s", encrypt ? "encrypting" : "decrypting");

    // init context
    mbedtls_aes_init(&aescontext);

    // set aes key
    if (encrypt)
    {
        ret = mbedtls_aes_setkey_enc(
            &aescontext, encrypt_key, ENCRYPTION_KEY_SIZE);
    }
    else
    {
        ret = mbedtls_aes_setkey_dec(
            &aescontext, encrypt_key, ENCRYPTION_KEY_SIZE);
    }
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_setkey_enc/dec failed with %d", ret);
        goto exit;
    }

    ret = mbedtls_aes_crypt_cbc(
        &aescontext,
        encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
        input_data_size, // input data length in bytes,
        iv,              // Initialization vector (updated after use)
        input_data,
        output_data);
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_crypt_cbc failed with %d", ret);
    }
exit:
    // free aes context
    mbedtls_aes_free(&aescontext);
    TRACE_ENCLAVE("ecall_dispatcher::cipher_encryption_key");
    return ret;
}

// For an encryption operation, the encryptor creates encryption metadata for
// writing back to the encryption header, which includes the following fields:
// digest: a hash value of the password
// key: encrypted version of the encryption key
//
// Operations involves the following operations:
//  1)derive a key from the password
//  2)produce a encryption key
//  3)generate a digest for the password
//  4)encrypt the encryption key with a password key
//
int ecall_dispatcher::prepare_encryption_header(
    encryption_header_t* header,
    string password)
{
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    int ret = 0;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES]; // sha256 digest of password
    unsigned char
        password_key[ENCRYPTION_KEY_SIZE_IN_BYTES]; // password generated key,
                                                    // used to encrypt
                                                    // encryption_key using
                                                    // AES256-CBC
    unsigned char
        encrypted_key[ENCRYPTION_KEY_SIZE_IN_BYTES]; // encrypted encryption_key
                                                     // using AES256-CBC
    unsigned char salt[SALT_SIZE_IN_BYTES];
    const char seed[] = "file_encryptor_sample";

    if (header == nullptr)
    {
        TRACE_ENCLAVE("prepare_encryption_header() failed with null argument"
                      " for encryption_header_t*");
        goto exit;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Initialize CTR-DRBG seed
    ret = mbedtls_ctr_drbg_seed(
        &ctr_drbg,
        mbedtls_entropy_func,
        &entropy,
        (const unsigned char*)seed,
        strlen(seed));
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_ctr_drbg_seed() failed with -0x%04x", -ret);
        goto exit;
    }

    // Generate random salt
    ret = mbedtls_ctr_drbg_random(&ctr_drbg, salt, sizeof(salt));
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_ctr_drbg_random() failed with -0x%04x", -ret);
        goto exit;
    }
    memcpy(header->salt, salt, sizeof(salt));

    TRACE_ENCLAVE("prepare_encryption_header");
    // derive a key from the password using PBDKF2
    ret = generate_password_key(
        password.c_str(), salt, password_key, sizeof(password_key));
    if (ret != 0)
    {
        TRACE_ENCLAVE("password_key");
        for (unsigned int i = 0; i < sizeof(password_key); i++)
            TRACE_ENCLAVE(
                "password_key[%d] =0x%02x", i, (unsigned int)(password_key[i]));
        goto exit;
    }

    // produce a encryption key
    TRACE_ENCLAVE("produce a encryption key");
    ret = generate_encryption_key(
        (unsigned char*)m_encryption_key, ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Enclave: m_encryption_key");
        for (unsigned int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
            TRACE_ENCLAVE(
                "m_encryption_key[%d] =0x%02x", i, m_encryption_key[i]);
        goto exit;
    }

    // generate a digest for the password
    TRACE_ENCLAVE("generate a digest for the password");
    ret = Sha256((const uint8_t*)password.c_str(), password.length(), digest);
    if (ret)
    {
        TRACE_ENCLAVE("Sha256 failed with %d", ret);
        goto exit;
    }

    memcpy(header->digest, digest, sizeof(digest));

    // encrypt the encryption key with a password key
    TRACE_ENCLAVE("encrypt the encryption key with a psswd key");
    ret = cipher_encryption_key(
        ENCRYPT_OPERATION,
        m_encryption_key,
        ENCRYPTION_KEY_SIZE_IN_BYTES,
        password_key,
        salt, // iv for encryption, decryption. In this sample we use
              // the salt in encryption header as iv.
        encrypted_key,
        sizeof(encrypted_key));
    if (ret != 0)
    {
        TRACE_ENCLAVE("EncryptEncryptionKey failed with [%d]", ret);
        goto exit;
    }
    memcpy(header->encrypted_key, encrypted_key, sizeof(encrypted_key));
    TRACE_ENCLAVE("Done with prepare_encryption_header successfully.");
exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

// Parse an input header for validating the password and getting the encryption
// key in preparation for decryption/encryption operations
//  1)Check password by comparing their digests
//  2)reproduce a password key from the password
//  3)decrypt the encryption key with a password key
int ecall_dispatcher::parse_encryption_header(
    encryption_header_t* header,
    string password)
{
    int ret = 0;
    if (header == nullptr)
    {
        TRACE_ENCLAVE("parse_encryption_header() failed with a null argument"
                      " for encryption_header_t*");
        goto exit;
    }

    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES];
    unsigned char password_key[ENCRYPTION_KEY_SIZE_IN_BYTES];
    unsigned char salt[SALT_SIZE_IN_BYTES];

    // check password by comparing their digests
    ret =
        Sha256((const uint8_t*)m_password.c_str(), m_password.length(), digest);
    if (ret)
    {
        TRACE_ENCLAVE("Sha256 failed with %d", ret);
        goto exit;
    }

    if (memcmp(header->digest, digest, sizeof(digest)) != 0)
    {
        TRACE_ENCLAVE("incorrect password");
        ret = 1;
        goto exit;
    }

    memcpy(salt, header->salt, sizeof(salt));

    // derive a key from the password using PBDKF2
    ret = generate_password_key(
        password.c_str(), salt, password_key, sizeof(password_key));
    if (ret != 0)
    {
        TRACE_ENCLAVE("generate_password_key failed with %d", ret);
        goto exit;
    }

    // decrypt the "encrypted encryption key" using the password key
    ret = cipher_encryption_key(
        DECRYPT_OPERATION,
        header->encrypted_key,
        ENCRYPTION_KEY_SIZE_IN_BYTES,
        password_key,
        salt, // iv for encryption, decryption. In this sample we use
              // the salt in encryption header as iv.
        (unsigned char*)m_encryption_key,
        ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Enclave: m_encryption_key");
        for (unsigned int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
            TRACE_ENCLAVE(
                "m_encryption_key[%d] =0x%02x", i, m_encryption_key[i]);
        goto exit;
    }

exit:
    return ret;
}

int ecall_dispatcher::process_encryption_header(encryption_header_t* header)
{
    int ret = 0;

    if (header == nullptr)
    {
        TRACE_ENCLAVE("process_encryption_header() failed with a null argument"
                      " for encryption_header_t*");
        goto exit;
    }

    if (m_encrypt)
    {
        // allocate host memory for the header and it will be returned back to
        // the host
        m_header =
            (encryption_header_t*)oe_host_malloc(sizeof(encryption_header_t));
        if (m_header == nullptr)
        {
            ret = 1;
            goto exit;
        }

        ret = prepare_encryption_header(m_header, m_password);
        if (ret != 0)
        {
            TRACE_ENCLAVE("prepare_encryption_header failed with %d", ret);
            goto exit;
        }
        memcpy(header, m_header, sizeof(encryption_header_t));
    }
    else
    {
        ret = parse_encryption_header(m_header, m_password);
        if (ret != 0)
        {
            TRACE_ENCLAVE("parse_encryption_header failed with %d", ret);
            goto exit;
        }
    }
exit:
    return ret;
}
