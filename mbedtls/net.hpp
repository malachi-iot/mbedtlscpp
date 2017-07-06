#pragma once

extern "C"
{
#if MBEDTLS_VERSION_NUMBER > 0x02010000
#include "mbedtls/net_sockets.h"
#else
#include "mbedtls/net.h"
#endif
}

namespace fact
{
namespace mbedtls
{

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
    
    int setNonBlock()
    {
        return mbedtls_net_set_nonblock(&context);
    }
    
    int setBlock()
    {
        return mbedtls_net_set_block(&context);
    }
};

}
}
