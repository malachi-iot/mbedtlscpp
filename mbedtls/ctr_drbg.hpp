#pragma once

extern "C"
{
  /* mbedtls/config.h MUST appear before all other mbedtls headers, or
     you'll get the default config.
     (Although mostly that isn't a big problem, you just might get
     errors at link time if functions don't exist.) */
  #include "mbedtls/config.h"

  #include "mbedtls/ssl.h"
}

namespace fact
{
namespace mbedtls
{
    class RandomGenerator
    {
        mbedtls_ctr_drbg_context ctr_drbg;

    public:
        RandomGenerator() { mbedtls_ctr_drbg_init(&ctr_drbg); }

        int seed(mbedtls_entropy_context& entropy, const char* pers)
        {
            return seed(entropy, (const uint8_t*)pers, strlen(pers));
        }

        int seed(mbedtls_entropy_context& entropy, const uint8_t* pers, size_t buflen)
        {
            return mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, buflen);
        }

        operator mbedtls_ctr_drbg_context&()
        {
            return ctr_drbg;
        }

        void free() { mbedtls_ctr_drbg_free(&ctr_drbg); }
    };
}
}
