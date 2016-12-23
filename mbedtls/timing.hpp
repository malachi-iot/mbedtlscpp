#pragma once

extern "C"
{
  /* mbedtls/config.h MUST appear before all other mbedtls headers, or
     you'll get the default config.
     (Although mostly that isn't a big problem, you just might get
     errors at link time if functions don't exist.) */
  #include "mbedtls/config.h"

  #include "mbedtls/timing.h"
}

namespace fact
{
namespace mbedtls
{

class TimingDelayContext
{
    mbedtls_timing_delay_context timer;

public:
    TimingDelayContext()
    {
        mbedtls_timing_delay_context_init(&timer);
    }

    operator mbedtls_timing_delay_context&()
    {
        return timer;
    }
};

}
}
