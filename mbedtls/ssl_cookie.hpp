#pragma once

extern "C"
{
    #include "mbedtls/ssl_cookie.h"
}

#include "ctr_drbg.hpp"

namespace fact { namespace mbedtls {

class CookieContext
{
    mbedtls_ssl_cookie_ctx context;

public:
    CookieContext() { mbedtls_ssl_cookie_init(&context); }

    operator mbedtls_ssl_cookie_ctx&()
    {
        return context;
    }

    int setup(int (*f_rng)(void*, uint8_t*, size_t), void* p_rng)
    {
        //mbedtls_ctr_drbg_random; // this *is* available
        return mbedtls_ssl_cookie_setup(&context, f_rng, p_rng);
    }

    int setup(RandomGenerator& randomGenerator)
    {
        return mbedtls_ssl_cookie_setup(&context, mbedtls_ctr_drbg_random,
            &((mbedtls_ctr_drbg_context&) randomGenerator));
    }

    void free() { mbedtls_ssl_cookie_free(&context); }
};

} }
