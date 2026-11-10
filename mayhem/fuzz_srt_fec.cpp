// Fuzzes SRT's built-in forward error correction filter (FECFilterBuiltin, "fec,rows:R,cols:C"): the receive
// side that tracks row/column groups from data and FEC control packets arriving from a peer (and rebuilds
// lost packets), and the sender side that clips outgoing packets into FEC control packets.
//
// Input layout: [rows: 1][cols: 1][opts: 1][payload size: 1][isn: 4 LE], then records
//   [kind: 1][seq delta: 2 LE][length: 2 LE][length bytes of payload]
//   kind bit 0: packet is a FEC control packet (message number 0) instead of a data packet
//   kind bit 1: feed the packet to the sender side (in order) instead of the receive side
//   kind bits 4-7: left shift applied to the seq delta, to jump far ahead of the receive window
// Inputs shorter than the 8-byte preamble, or with a filter config SRT itself rejects, return -1.
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "srt.h"
#include "api.h"
#include "core.h"
#include "fec.h"
#include "packet.h"
#include "packetfilter_api.h"

using namespace srt;

static void quiet_log_handler(void*, int, const char*, int, const char*, const char*) {}

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    srt_startup();
    srt_setloghandler(NULL, quiet_log_handler); // keep the harness quiet
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 8)
        return -1;

    const int rows = (int)(int8_t)data[0] % 12;
    const int cols = data[1] % 24;
    const unsigned opts = data[2];
    const size_t plsize = 64 + (size_t(data[3]) * 1300) / 255;
    uint32_t isn;
    memcpy(&isn, data + 4, 4);
    isn &= 0x7FFFFFFF;

    static const char* const layouts[] = {"staircase", "even"};
    static const char* const arqs[] = {"never", "onreq", "always"};
    std::string conf = "fec,rows:" + std::to_string(rows) + ",cols:" + std::to_string(cols) +
                       ",layout:" + layouts[opts & 1] + ",arq:" + arqs[(opts >> 1) % 3];

    std::vector<SrtPacket> provided;
    SrtFilterInitializer init = {54321, (int32_t)((isn - 1) & 0x7FFFFFFF), (int32_t)((isn - 1) & 0x7FFFFFFF), plsize,
                                 CSrtConfig::DEF_BUFFER_SIZE};

    FECFilterBuiltin* fec = NULL;
    try
    {
        fec = new FECFilterBuiltin(init, provided, conf);
    }
    catch (const CUDTException&)
    {
        return -1;
    }

    int32_t snd_seq = (int32_t)isn;
    size_t pos = 8;
    while (size - pos >= 5)
    {
        const unsigned kind = data[pos];
        const uint32_t delta = (uint32_t(data[pos + 1]) | (uint32_t(data[pos + 2]) << 8)) << (kind >> 4);
        size_t len = data[pos + 3] | (size_t(data[pos + 4]) << 8);
        pos += 5;
        if (len > size - pos)
            len = size - pos;

        const bool control = kind & 1;
        const bool sender = kind & 2;
        if (control)
        {
            // A control packet must carry the FEC header (EXTRA_SIZE bytes) and fits in one packet.
            if (len < FECFilterBuiltin::EXTRA_SIZE)
                len = FECFilterBuiltin::EXTRA_SIZE;
            if (len > size_t(SRT_LIVE_MAX_PLSIZE))
                len = SRT_LIVE_MAX_PLSIZE;
        }
        else if (len > plsize)
        {
            len = plsize;
        }

        CPacket pkt;
        pkt.allocate(len);
        if (len)
        {
            const size_t avail = size - pos < len ? size - pos : len;
            memcpy(pkt.data(), data + pos, avail);
            if (avail < len)
                memset(pkt.data() + avail, 0, len - avail);
        }
        pos += len < size - pos ? len : size - pos;

        uint32_t* hdr = pkt.getHeader();
        hdr[SRT_PH_ID] = 54321;
        hdr[SRT_PH_TIMESTAMP] = 10;

        if (sender)
        {
            if (control)
                continue;
            hdr[SRT_PH_SEQNO] = snd_seq;
            hdr[SRT_PH_MSGNO] = 1 | MSGNO_PACKET_BOUNDARY::wrap(PB_SOLO);
            pkt.setLength(len);
            fec->feedSource(pkt);
            SrtPacket ctl(SRT_LIVE_MAX_PLSIZE);
            for (int i = 0; i < 4 && fec->packControlPacket(ctl, snd_seq); ++i)
            {
            }
            snd_seq = CSeqNo::incseq(snd_seq);
        }
        else
        {
            hdr[SRT_PH_SEQNO] = (isn + delta) & 0x7FFFFFFF;
            hdr[SRT_PH_MSGNO] = (control ? 0 : 1) | MSGNO_PACKET_BOUNDARY::wrap(PB_SOLO);
            pkt.setLength(len);
            FECFilterBuiltin::loss_seqs_t loss;
            fec->receive(pkt, loss);
            provided.clear();
        }
    }

    delete fec;
    return 0;
}
