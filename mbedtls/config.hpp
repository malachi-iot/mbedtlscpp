#pragma once

extern "C"
{
  /* mbedtls/config.h MUST appear before all other mbedtls headers, or
     you'll get the default config.
     (Although mostly that isn't a big problem, you just might get
     errors at link time if functions don't exist.) */
  #include "mbedtls/config.h"
}

namespace fact
{
namespace mbedtls
{
    

class SSLConfig
{
    mbedtls_ssl_config config;

    public:
    SSLConfig() { mbedtls_ssl_config_init(&config); }

    operator mbedtls_ssl_config&()
    {
      return config;
    }

    int defaults(int endpoint, int transport, int preset)
    {
      return mbedtls_ssl_config_defaults(&config, endpoint, transport, preset);
    }

    void readTimeout(uint32_t timeout)
    {
        mbedtls_ssl_conf_read_timeout(&config, timeout);
    }

    void handshakeTimeout(
        uint32_t ms_min = MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MIN, 
        uint32_t ms_max = MBEDTLS_SSL_DTLS_TIMEOUT_DFL_MAX)
    {
        mbedtls_ssl_conf_handshake_timeout(
            &config,
            ms_min,
            ms_max
        );
    }

    void renegotiation(bool enabled)
    {
        mbedtls_ssl_conf_renegotiation(&config, enabled ? 
            MBEDTLS_SSL_RENEGOTIATION_ENABLED :
            MBEDTLS_SSL_RENEGOTIATION_DISABLED);
    }

    void transport(int t)
    {
        mbedtls_ssl_conf_transport(&config, t);
    }


    void endpoint(int e)
    {
        mbedtls_ssl_conf_endpoint(&config, e);
    }


    void caChain(mbedtls_x509_crt& ca_chain)
    {
      mbedtls_ssl_conf_ca_chain(&config, &ca_chain, NULL);
    }

    void caChain(mbedtls_x509_crt& ca_chain, mbedtls_x509_crl& ca_crl)
    {
      mbedtls_ssl_conf_ca_chain(&config, &ca_chain, &ca_crl);
    }


    void setRng(mbedtls_ctr_drbg_context& ctr_drbg)
    {
      mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &ctr_drbg);
    }

    int ownCert(mbedtls_x509_crt& cert, mbedtls_pk_context& pk)
    {
        return mbedtls_ssl_conf_own_cert(&config, &cert, &pk);
    }


    void dtlsCookies(mbedtls_ssl_cookie_write_t* f_cookie_write,
        mbedtls_ssl_cookie_check_t* f_cookie_check, void* p_cookie)
    {
        mbedtls_ssl_conf_dtls_cookies(&config, f_cookie_write, f_cookie_check, p_cookie);
    }

    // TODO: clean up context, it's the one CookieContext uses for this
    // scenario
    void dtlsCookies(mbedtls_ssl_cookie_ctx* cookie_ctx)
    {
        mbedtls_ssl_conf_dtls_cookies(&config,
            mbedtls_ssl_cookie_write,
            mbedtls_ssl_cookie_check,
            cookie_ctx);
    }

#if defined(MBEDTLS_SSL_CACHE_C)
    // TODO:
    void sessionCache()
    {

    }
#endif

    void debug(void (*f_dbg)(void* ctx, int, const char*, int, const char*), void* p_dbg)
    {
        mbedtls_ssl_conf_dbg(&config, f_dbg, p_dbg);
    }

    void cookieSetup()
    {

    }

    void free() { mbedtls_ssl_config_free(&config); }
};


}
}
