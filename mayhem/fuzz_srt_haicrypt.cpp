// Fuzzes HaiCrypt, SRT's encryption layer, the way a receiving peer drives it: a Keying Material (KM)
// message arrives from the network and is processed (the same size checks as CCryptoControl::processSrtMsg_KMREQ
// apply), then encrypted data packets are decrypted, and the keyed receiver is cloned into a sender.
//
// Input layout: [flags: 1][km_len: 1][km_len bytes of KM message][16-byte SRT packet header][payload]
//   flags bit 0: AES-GCM instead of AES-CTR (when the crypto library supports it).
// Inputs too short for the layout, or with an invalid KM size, are rejected with -1.
#include <cstdint>
#include <cstring>
#include <vector>

#include "haicrypt.h"
#include "hcrypt_msg.h"

static const char kPassphrase[] = "mayhem-fuzz-passphrase";
static const size_t kHeaderLen = 16;

static void fill_cfg(HaiCrypt_Cfg& cfg, unsigned flags, size_t key_len, bool tx)
{
    memset(&cfg, 0, sizeof(cfg));
    cfg.flags = HAICRYPT_CFG_F_CRYPTO | (tx ? HAICRYPT_CFG_F_TX : 0);
    if ((flags & 1) && HaiCrypt_IsAESGCM_Supported())
        cfg.flags |= HAICRYPT_CFG_F_GCM;
    cfg.xport = HAICRYPT_XPT_SRT;
    cfg.cryspr = HaiCryptCryspr_Get_Instance();
    cfg.key_len = key_len;
    cfg.data_max_len = HAICRYPT_DEF_DATA_MAX_LENGTH;
    cfg.km_tx_period_ms = 0;
    cfg.km_refresh_rate_pkt = HAICRYPT_DEF_KM_REFRESH_RATE;
    cfg.km_pre_announce_pkt = HAICRYPT_DEF_KM_PRE_ANNOUNCE;
    cfg.secret.typ = HAICRYPT_SECTYP_PASSPHRASE;
    cfg.secret.len = sizeof(kPassphrase) - 1;
    memcpy(cfg.secret.str, kPassphrase, sizeof(kPassphrase) - 1);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < 2)
        return -1;
    const unsigned flags = data[0];
    const size_t km_len = data[1];
    if (size < 2 + km_len)
        return -1;
    if (km_len % 4 != 0 || km_len <= HCRYPT_MSG_KM_OFS_SALT || km_len > HCRYPT_MSG_KM_MAX_SZ)
        return -1;

    std::vector<unsigned char> km(data + 2, data + 2 + km_len);
    const size_t sek_len = hcryptMsg_KM_GetSekLen(km.data());
    if (sek_len == 0)
        return -1;

    HaiCrypt_Cfg cfg;
    fill_cfg(cfg, flags, sek_len, false);
    HaiCrypt_Handle rx = NULL;
    if (HaiCrypt_Create(&cfg, &rx) != HAICRYPT_OK)
        return -1;

    const int rc = HaiCrypt_Rx_Process(rx, km.data(), km.size(), NULL, NULL, 0);

    const uint8_t* pkt = data + 2 + km_len;
    const size_t pkt_len = size - 2 - km_len;

    // Like CCryptoControl::processSrtMsg_KMREQ, derive the sender from the receiver once the KM was accepted.
    HaiCrypt_Handle tx = NULL;
    if (rc >= 0 && HaiCrypt_Clone(rx, HAICRYPT_CRYPTO_DIR_TX, &tx) != HAICRYPT_OK)
        tx = NULL;

    // Like CCryptoControl::decrypt, only try data packets once a KM has been accepted.
    if (rc >= 0 && pkt_len >= kHeaderLen)
    {
        std::vector<unsigned char> buf(pkt, pkt + pkt_len);
        HaiCrypt_Rx_Data(rx, buf.data(), buf.data() + kHeaderLen, pkt_len - kHeaderLen);

        if (tx)
        {
            // Encryption in place may append an AEAD authentication tag after the payload.
            std::vector<unsigned char> out(pkt_len + HAICRYPT_AUTHTAG_MAX);
            memcpy(out.data(), pkt, pkt_len);
            HaiCrypt_Tx_Data(tx, out.data(), out.data() + kHeaderLen, pkt_len - kHeaderLen);
        }
    }

    if (tx)
        HaiCrypt_Close(tx);
    HaiCrypt_Close(rx);
    return 0;
}
