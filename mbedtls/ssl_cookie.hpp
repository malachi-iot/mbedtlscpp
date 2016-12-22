#pragma once

extern "C"
{
    #include "mbedtls/ssl_cookie.h"
}

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
        return mbedtls_ssl_cookie_setup(&context, f_rng, p_rng);
    }
};

} }
