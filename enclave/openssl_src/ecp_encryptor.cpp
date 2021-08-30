#include "ecp/ECIES.h"
#include "ecp/ECDSAKey.h"
#include "ecp/Blob.h"
#include "common/encryptor.h"
#include "common/trace.h"

#include <string>

using namespace ripple;
using namespace std;

int ecall_dispatcher::test_ecp_secp256k1()
{
    Blob256 secret_key;
    Blob288 public_key;
    int ret = ec_generate_keypair(secret_key, public_key);
    string plain_text("Hello, world!");
    Blob plain_data;
    for ( char i : plain_text )
    {
        plain_data.push_back((unsigned char) i);
    }
    TRACE_ENCLAVE("Plain data:");
    for ( int i = 0; i < plain_data.size(); i++ )
    {
        TRACE_ENCLAVE("%02X%s", plain_data[i],
                ( i + 1 ) % 16 == 0 ? "\r\n" : " ");
    }
    Blob publicKey(public_key.data(), public_key.data() + public_key.size());
    Blob cipher_data = asymEncrypt(plain_data, publicKey);
    TRACE_ENCLAVE("Cipher data:");
    for ( int i = 0; i < cipher_data.size(); i++ )
    {
        TRACE_ENCLAVE("%02X%s", cipher_data[i],
                ( i + 1 ) % 16 == 0 ? "\r\n" : " ");
    }
    Blob secretKey(secret_key.data(), secret_key.data() + secret_key.size());
    Blob decrypted_data = asymDecrypt(cipher_data, secretKey);
    TRACE_ENCLAVE("Decrypted data:");
    for ( int i = 0; i < decrypted_data.size(); i++ )
    {
        TRACE_ENCLAVE("%02X%s", decrypted_data[i],
                ( i + 1 ) % 16 == 0 ? "\r\n" : " ");
    }

    return 0;
}
