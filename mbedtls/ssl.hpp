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
    typedef void mbedtls_ssl_set_timer_t(void* ctx, uint32_t int_ms, uint32_t fin_ms);
    typedef int mbedtls_ssl_get_timer_t(void* ctx);

class SSLContext
{
    mbedtls_ssl_context context;

public:
    SSLContext() { mbedtls_ssl_init(&context); }

    void free() { mbedtls_ssl_free(&context); }
    void reset() { mbedtls_ssl_session_reset(&context); }

    int handshake()
    {
        return mbedtls_ssl_handshake(&context);
    }

    int setup(mbedtls_ssl_config& conf)
    {
        return mbedtls_ssl_setup(&context, &conf);
    }

    void setBIO(void* p_bio,
        int (*f_send)(void *, const unsigned char *, size_t),
        int (*f_recv)(void *, unsigned char *, size_t),
        int (*f_recv_timeout)(void *, unsigned char *, size_t, uint32_t))
    {
        mbedtls_ssl_set_bio(&context, p_bio, f_send, f_recv, f_recv_timeout);
    }

    void setBIO(mbedtls_net_context& bio)
    {
        mbedtls_ssl_set_bio(&context, &bio,
          mbedtls_net_send,
          mbedtls_net_recv,
          NULL);
    }

    int closeNotify()
    {
        return mbedtls_ssl_close_notify(&context);
    }


    int read(uint8_t* buf, size_t len)
    {
        return mbedtls_ssl_read(&context, buf, len);
    }

    int write(const uint8_t* buf, size_t len)
    {
        return mbedtls_ssl_write(&context, buf, len);
    }

    // Set Timer Callbacks (mandatory for DTLS)
    // Please see https://tls.mbed.org/kb/how-to/dtls-tutorial
    void setTimerCb(void* p_timer,
        mbedtls_ssl_set_timer_t* f_set_timer,
        mbedtls_ssl_get_timer_t* f_get_timer)
    {
        //mbedtls_timing_set_delay(); // some platforms have these presets
        return mbedtls_ssl_set_timer_cb(&context, p_timer, f_set_timer, f_get_timer);
    }

    int setClientTransportId(uint8_t* info, size_t ilen)
    {
        return mbedtls_ssl_set_client_transport_id(&context, info, ilen);
    }
};

}
}
