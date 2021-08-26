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
    Blob cipher_data = encryptECIES(secret_key, public_key, plain_data);
    TRACE_ENCLAVE("Cipher data:");
    for ( int i = 0; i < cipher_data.size(); i++ )
    {
        TRACE_ENCLAVE("%02X%s", cipher_data[i],
                ( i + 1 ) % 16 == 0 ? "\r\n" : " ");
    }
    Blob decrypted_data = decryptECIES(secret_key, public_key, cipher_data);
    TRACE_ENCLAVE("Decrypted data:");
    for ( int i = 0; i < decrypted_data.size(); i++ )
    {
        TRACE_ENCLAVE("%02X%s", decrypted_data[i],
                ( i + 1 ) % 16 == 0 ? "\r\n" : " ");
    }

    return 0;
}
