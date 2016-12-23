#pragma once

extern "C"
{
  /* mbedtls/config.h MUST appear before all other mbedtls headers, or
     you'll get the default config.
     (Although mostly that isn't a big problem, you just might get
     errors at link time if functions don't exist.) */
  #include "mbedtls/config.h"

  #include "mbedtls/net.h"
  #include "mbedtls/debug.h"
  #include "mbedtls/entropy.h"
  #include "mbedtls/ctr_drbg.h"
  #include "mbedtls/error.h"
  #include "mbedtls/certs.h"
}

#include "mbedtls/ssl.hpp"
#include "mbedtls/ssl_cookie.hpp"

namespace fact
{
    namespace mbedtls
    {
        class PrivateKeyContext
        {
          mbedtls_pk_context pk;

        public:
            PrivateKeyContext() { mbedtls_pk_init(&pk); }

            operator mbedtls_pk_context&() { return pk; }

            int parseKey(const char* buf)
            {
                return mbedtls_pk_parse_key(&pk,
                    // always remember to grab 0 as part of the buffer, apparently
                    (const uint8_t*)buf, strlen(buf)+1, NULL, 0);
            }

            int parseKey(const uint8_t* buf, size_t buflen,
                const uint8_t* pwd = NULL, size_t pwdlen = 0)
            {
                return mbedtls_pk_parse_key(&pk, buf, buflen, pwd, pwdlen);
            }

            void free() { mbedtls_pk_free(&pk); }
        };



        class X509Certificate
        {
          mbedtls_x509_crt certificate;

        public:
          X509Certificate() { mbedtls_x509_crt_init(&certificate); }


          operator mbedtls_x509_crt&()
          {
              return certificate;
          }

            int parse(const char* buf)
            {
                // always remember to grab 0 as part of the buffer, apparently
                return parse((const uint8_t*)buf, strlen(buf)+1);
            }

            int parse(const uint8_t* buf, size_t buflen)
            {
                return mbedtls_x509_crt_parse(&certificate, buf, buflen);
            }

            void free() { mbedtls_x509_crt_free(&certificate); }
        };


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


        class EntropyContext
        {
          mbedtls_entropy_context  entropy;

        public:
          EntropyContext() { mbedtls_entropy_init(&entropy); }

          operator mbedtls_entropy_context&()
          {
            return entropy;
          }

          void free() { mbedtls_entropy_free(&entropy); }
        };


        class NetContext
        {
          mbedtls_net_context context;
        public:

          NetContext() { mbedtls_net_init(&context); }
          //~NetContext() { mbedtls_net_free(&context); }

          operator mbedtls_net_context&()
          {
              return context;
          }

          void free() {  mbedtls_net_free(&context); }

          int bind(const char* bind_ip, const char* port, int proto)
          {
              return mbedtls_net_bind(&context, bind_ip, port, proto);
          }

          int accept(mbedtls_net_context& client_ctx, void* client_ip, size_t buf_size, size_t* ip_len)
          {
              return mbedtls_net_accept(&context, &client_ctx, client_ip, buf_size, ip_len);
          }

          int accept(mbedtls_net_context& client_ctx)
          {
              return mbedtls_net_accept(&context, &client_ctx, NULL, 0, NULL);
          }
        };
    }
}
