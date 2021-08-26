/**
 * ECP encryptor. secp256k1.
 */

#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/rsa.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#include "common/encryptor.h"
#include "common/trace.h"

int ecall_dispatcher::test_ecp_secp256k1()
{
    mbedtls_pk_context pk;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init( &ctr_drbg );
    gen_key( &pk, &ctr_drbg );
    unsigned char plain_data[512] = "Hello world!";
    unsigned char cipher_data[4096] = "";
    size_t olen = 0;
    ecp_encrypt(&pk, plain_data,
        (size_t) strlen((const char *) plain_data), cipher_data, &olen, &ctr_drbg);
    return 0;
}


int ecall_dispatcher::gen_key(mbedtls_pk_context *key, mbedtls_ctr_drbg_context *ctr_drbg)
{
    int ret = 1;
    mbedtls_entropy_context entropy;
    // mbedtls_ctr_drbg_context ctr_drbg;
    // mbedtls_pk_context key;

    mbedtls_pk_init( key );
    // mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );

    const mbedtls_ecp_curve_info *curve_info;
    curve_info = mbedtls_ecp_curve_list();
    TRACE_ENCLAVE("available ec_curve values:");
    TRACE_ENCLAVE("    %s (default)", curve_info->name);
    while ( ( ++curve_info )->name != NULL )
    {
        TRACE_ENCLAVE("    %s", curve_info->name);
    }

    char curve_name[] = "secp256k1";
    curve_info = mbedtls_ecp_curve_info_from_name(curve_name);
    if (curve_info == NULL)
    {
        TRACE_ENCLAVE("mbedtls_ecp_curve_info_from_name return NULL");
        return -1;
    }
    // curve identifier for EC keys
    int ec_curve = curve_info->grp_id;

    if( ( ret = mbedtls_ctr_drbg_seed( ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) "gen_key",
                               strlen( "gen_key" ) ) ) != 0 )
    {
        TRACE_ENCLAVE( " failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", -ret );
        return -1;
    }
    TRACE_ENCLAVE("Selected curve name: %s", curve_name);

    /*
     * 1.1. Generate the key
     */
    TRACE_ENCLAVE("Generating the private key ...");
    if( ( ret = mbedtls_pk_setup( key,
            mbedtls_pk_info_from_type( (mbedtls_pk_type_t) MBEDTLS_PK_ECKEY ) ) ) != 0 )
    {
        TRACE_ENCLAVE( " failed\n  !  mbedtls_pk_setup returned -0x%04x", -ret );
        return -1;
    }
    ret = mbedtls_ecp_gen_key( (mbedtls_ecp_group_id) ec_curve,
                                   mbedtls_pk_ec( *key ),
                                   mbedtls_ctr_drbg_random, ctr_drbg );
    if( ret != 0 )
    {
        TRACE_ENCLAVE( " failed\n  !  mbedtls_ecp_gen_key returned -0x%04x", -ret );
        return -1;
    }
    mbedtls_ecp_keypair *ecp = mbedtls_pk_ec( *key );
    char buf[4096] = "";
    size_t olen = 0;
    TRACE_ENCLAVE("Key information:");
    mbedtls_printf( "curve: %s\n",
        mbedtls_ecp_curve_info_from_grp_id( ecp->grp.id )->name );
    mbedtls_mpi_write_string( &ecp->Q.X, 16, buf, (size_t) 4096, &olen );
    TRACE_ENCLAVE("X_Q: %s", buf);
    mbedtls_mpi_write_string( &ecp->Q.Y, 16, buf, (size_t) 4096, &olen );
    TRACE_ENCLAVE("Y_Q: %s", buf);
    mbedtls_mpi_write_string( &ecp->d  , 16, buf, (size_t) 4096, &olen );
    TRACE_ENCLAVE("D: %s", buf);

    return 0;
}

int ecall_dispatcher::ecp_encrypt(mbedtls_pk_context *pk, unsigned char *plain_text,
        size_t plain_size, unsigned char *buf, size_t *olen, mbedtls_ctr_drbg_context *ctr_drbg)
{
    int ret = 0;
    if ( plain_size > 1024 || strlen((const char *) plain_text) > 1024 )
    {
        // TODO (DCMMC)
        TRACE_ENCLAVE("input plain_text too long (> 1024)!");
        return -1;
    }
    if( ( ret = mbedtls_pk_encrypt( pk, plain_text, plain_size,
                            buf, olen, sizeof(buf),
                            mbedtls_ctr_drbg_random, ctr_drbg ) ) != 0 )
    {
        TRACE_ENCLAVE( " failed\n  ! mbedtls_pk_encrypt returned -0x%04x\n",
                        -ret );
        return -1;
    }

    TRACE_ENCLAVE("Cipher data:");
    for ( int i = 0; i < *olen; i++ )
    {
        TRACE_ENCLAVE("%02X%s", buf[i], ( i + 1 ) % 16 == 0 ? "\r\n" : " ");
    }
    return 0;
}
