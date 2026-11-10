// Fuzzes SRT's public socket-option API: srt_setsockflag/srt_getsockflag on a fresh socket and
// srt_config_add on a connection-group option list (the surface where option values arrive from an
// application, including string options such as the packet-filter config, passphrase and stream id).
//
// Input: a sequence of records [option: 1 byte][length: 2 bytes LE][value bytes]; a length larger than the
// remaining input is cut to what is left. An empty input is rejected with -1.
#include <cstdint>
#include <cstring>
#include <vector>

#include "srt.h"

static void quiet_log_handler(void*, int, const char*, int, const char*, const char*) {}

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    srt_startup();
    srt_setloghandler(NULL, quiet_log_handler); // keep the harness quiet
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size == 0)
        return -1;

    SRTSOCKET s = srt_create_socket();
    if (s == SRT_INVALID_SOCK)
        return 0;
    SRT_SOCKOPT_CONFIG* cfg = srt_create_config();

    size_t pos = 0;
    while (size - pos >= 3)
    {
        const SRT_SOCKOPT opt = (SRT_SOCKOPT)(data[pos] % (SRTO_E_SIZE + 2));
        size_t len = data[pos + 1] | (size_t(data[pos + 2]) << 8);
        pos += 3;
        if (len > size - pos)
            len = size - pos;
        // The API takes the value as the application's own (aligned) object, so give it a non-null heap copy.
        std::vector<uint8_t> copy(len ? len : 16); // optlen 0 is accepted for any option and reads sizeof(T) bytes
        memcpy(copy.data(), data + pos, len);
        if (len == sizeof(bool))
            copy[0] &= 1; // a one-byte value is a C++ bool; an application can't pass another value
        if (opt == SRTO_TRANSTYPE && len >= sizeof(int))
        {
            // The value is a C enum (SRT_TRANSTYPE): an application can only pass one of its enumerators.
            int tt;
            memcpy(&tt, copy.data(), sizeof(tt));
            tt = tt & 1;
            memcpy(copy.data(), &tt, sizeof(tt));
        }
        const uint8_t* val = copy.data();
        pos += len;

        if (srt_setsockflag(s, opt, val, (int)len) == 0)
        {
            char out[1024];
            int outlen = sizeof(out);
            srt_getsockflag(s, opt, out, &outlen);
        }
        srt_config_add(cfg, opt, val, (int)len);
    }

    srt_delete_config(cfg);
    srt_close(s);
    return 0;
}
