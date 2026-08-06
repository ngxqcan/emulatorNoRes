#pragma once

#include "config.h"

struct SspiHandle {
    CredHandle cred{}; CtxtHandle ctx{};
    bool cred_ok = false; bool ctx_ok = false;
    ~SspiHandle() {
        if (ctx_ok)  DeleteSecurityContext(&ctx);
        if (cred_ok) FreeCredentialsHandle(&cred);
    }
};

class TlsSocket {
public:
    SOCKET s = INVALID_SOCKET;
    SspiHandle* ss = nullptr;
    std::vector<uint8_t> enc_pending, plain_pending;

    bool Connect(const char* host, uint16_t port, bool skip_verify);
    bool Handshake(const char* host, bool skip_verify);
    void SendAll(const uint8_t* data, size_t len);
    void Drain();
    std::vector<uint8_t> RecvMsg();
    void Close();
};

bool RecvExact(SOCKET s, uint8_t* buf, int n);
bool SendExact(SOCKET s, const uint8_t* buf, int n);

struct ServerTlsConn {
    SOCKET       sock = INVALID_SOCKET;
    CredHandle   cred = {};
    CtxtHandle   ctx = {};
    bool         cred_ok = false, ctx_ok = false;
    std::vector<uint8_t> enc_buf, plain_buf;

    void close_handles();
    bool handshake(PCCERT_CONTEXT cert_ctx);
    void server_send(const std::vector<uint8_t>& data);
    void drain();
    std::vector<uint8_t> recv_msg();
};

std::vector<uint8_t> BcryptBlobToSpkiDer(const std::vector<uint8_t>& pubBlob);
std::vector<uint8_t> GenerateRsaSpkiPem();
const char* GatewayActionName(int vg_type);
bool PostToGateway(const std::vector<uint8_t>& envelope,
    const std::string& puuid,
    const std::string& region,
    std::vector<uint8_t>* out_response = nullptr,
    int vg_type = 3);
bool ExchangeVpsGatewayStep(
    TlsSocket& tls,
    uint32_t request_type,
    uint32_t expected_response_type,
    int gateway_action,
    const std::vector<uint8_t>& gateway_response,
    const std::string& puuid,
    const std::string& region,
    std::vector<uint8_t>& next_gateway_response,
    const char* tag);
void VpsServerHeartbeatLoop(
    std::unique_ptr<TlsSocket> tls,
    std::vector<uint8_t> latest_gateway_response,
    std::string puuid,
    std::string region);
PCCERT_CONTEXT LoadOrCreateCert();
void RunServer();

extern std::atomic_bool g_server_running;
extern std::atomic_bool g_vps_server_heartbeat_running;
