#include "tls_socket.h"
#include "logger.h"
#include "protocol_utils.h"
#include "hwid_spoof.h"
#include "vgk_manager.h"
#include "console_ui.h"

std::atomic_bool g_server_running(false);
std::atomic_bool g_vps_server_heartbeat_running(false);
static std::atomic_int g_active_clients(0);

bool TlsSocket::Connect(const char* host, uint16_t port, bool skip_verify) {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCKET) return false;
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(port);
    InetPtonA(AF_INET, host, &addr.sin_addr);
    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) { closesocket(s); s = INVALID_SOCKET; return false; }
    const DWORD t = 60000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char*)&t, sizeof(t));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char*)&t, sizeof(t));
    ss = new SspiHandle();
    if (!Handshake(host, skip_verify)) { delete ss; ss = nullptr; closesocket(s); s = INVALID_SOCKET; return false; }
    return true;
}

bool TlsSocket::Handshake(const char* host, bool skip_verify) {
    SCHANNEL_CRED sc{}; sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
    if (skip_verify) sc.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION;
    TimeStamp ts{};
    if (AcquireCredentialsHandleW(nullptr, (SEC_WCHAR*)UNISP_NAME_W,
        SECPKG_CRED_OUTBOUND, nullptr, &sc, nullptr, nullptr, &ss->cred, &ts) != SEC_E_OK) return false;
    ss->cred_ok = true;
    std::vector<uint8_t> inbuf(32 * 1024), outbuf(32 * 1024);
    SecBufferDesc in_desc{}; SecBuffer in_sec[2]{};
    DWORD ctx_attr = 0; bool first = true;
    const std::wstring whost(host, host + strlen(host));
    for (;;) {
        SecBuffer out_sec[1]{};
        out_sec[0].BufferType = SECBUFFER_TOKEN;
        out_sec[0].pvBuffer = outbuf.data();
        out_sec[0].cbBuffer = (ULONG)outbuf.size();
        SecBufferDesc out_desc;
        out_desc.ulVersion = SECBUFFER_VERSION;
        out_desc.cBuffers = 1;
        out_desc.pBuffers = out_sec;
        SECURITY_STATUS st = InitializeSecurityContextW(
            &ss->cred, first ? nullptr : &ss->ctx, const_cast<wchar_t*>(whost.c_str()),
            ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_STREAM |
            ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_USE_SUPPLIED_CREDS,
            0, SECURITY_NATIVE_DREP, first ? nullptr : &in_desc, 0,
            &ss->ctx, &out_desc, &ctx_attr, &ts);
        first = false;
        if (st != SEC_E_OK && st != SEC_I_CONTINUE_NEEDED) return false;
        ss->ctx_ok = true;
        if (out_sec[0].cbBuffer && out_sec[0].pvBuffer) {
            send(s, (const char*)out_sec[0].pvBuffer, out_sec[0].cbBuffer, 0);
            FreeContextBuffer(out_sec[0].pvBuffer);
        }
        if (st == SEC_E_OK) return true;
        int got = recv(s, (char*)inbuf.data(), (int)inbuf.size(), 0);
        if (got <= 0) return false;
        in_sec[0].cbBuffer = (ULONG)got;
        in_sec[0].BufferType = SECBUFFER_TOKEN;
        in_sec[0].pvBuffer = inbuf.data();
        in_sec[1].cbBuffer = 0;
        in_sec[1].BufferType = SECBUFFER_EMPTY;
        in_sec[1].pvBuffer = nullptr;
        in_desc.ulVersion = SECBUFFER_VERSION;
        in_desc.cBuffers = 2;
        in_desc.pBuffers = in_sec;
    }
}

void TlsSocket::SendAll(const uint8_t* data, size_t len) {
    SecPkgContext_StreamSizes sizes{};
    QueryContextAttributesW(&ss->ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
    size_t max_chunk = sizes.cbMaximumMessage > 0 ? sizes.cbMaximumMessage : len;
    size_t off = 0;
    while (off < len) {
        size_t chunk = (std::min)(len - off, max_chunk);
        std::vector<uint8_t> buf(sizes.cbHeader + chunk + sizes.cbTrailer);
        memcpy(buf.data() + sizes.cbHeader, data + off, chunk);
        SecBuffer sec[4]{};
        sec[0].cbBuffer = sizes.cbHeader;
        sec[0].BufferType = SECBUFFER_STREAM_HEADER;
        sec[0].pvBuffer = buf.data();
        sec[1].cbBuffer = (ULONG)chunk;
        sec[1].BufferType = SECBUFFER_DATA;
        sec[1].pvBuffer = buf.data() + sizes.cbHeader;
        sec[2].cbBuffer = sizes.cbTrailer;
        sec[2].BufferType = SECBUFFER_STREAM_TRAILER;
        sec[2].pvBuffer = buf.data() + sizes.cbHeader + chunk;
        sec[3].cbBuffer = 0;
        sec[3].BufferType = SECBUFFER_EMPTY;
        sec[3].pvBuffer = nullptr;
        SecBufferDesc desc;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = sec;
        EncryptMessage(&ss->ctx, 0, &desc, 0);
        ULONG total = sec[0].cbBuffer + sec[1].cbBuffer + sec[2].cbBuffer;
        send(s, (const char*)buf.data(), total, 0);
        off += chunk;
    }
}

void TlsSocket::Drain() {
    while (!enc_pending.empty()) {
        SecBuffer sec[4]{};
        sec[0].cbBuffer = (ULONG)enc_pending.size();
        sec[0].BufferType = SECBUFFER_DATA;
        sec[0].pvBuffer = enc_pending.data();
        for (int i = 1; i < 4; i++) {
            sec[i].cbBuffer = 0;
            sec[i].BufferType = SECBUFFER_EMPTY;
            sec[i].pvBuffer = nullptr;
        }
        SecBufferDesc desc;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = sec;
        SECURITY_STATUS st = DecryptMessage(&ss->ctx, &desc, 0, nullptr);
        if (st == SEC_E_INCOMPLETE_MESSAGE) break;
        if (st != SEC_E_OK) throw std::runtime_error("TLS decrypt failed");
        size_t extra_off = enc_pending.size(), extra_len = 0;
        for (int i = 0; i < 4; i++) {
            if (sec[i].BufferType == SECBUFFER_DATA && sec[i].cbBuffer)
                plain_pending.insert(plain_pending.end(),
                    (uint8_t*)sec[i].pvBuffer, (uint8_t*)sec[i].pvBuffer + sec[i].cbBuffer);
            if (sec[i].BufferType == SECBUFFER_EXTRA && sec[i].cbBuffer) {
                extra_off = (uint8_t*)sec[i].pvBuffer - enc_pending.data();
                extra_len = sec[i].cbBuffer;
            }
        }
        if (extra_len) enc_pending.assign(enc_pending.begin() + extra_off, enc_pending.begin() + extra_off + extra_len);
        else enc_pending.clear();
    }
}

std::vector<uint8_t> TlsSocket::RecvMsg() {
    for (;;) {
        Drain();
        if (plain_pending.size() >= 8) {
            uint32_t plen = ReadU32BE(plain_pending.data() + 4);
            size_t need = 8 + plen;
            if (plain_pending.size() >= need) {
                std::vector<uint8_t> msg(plain_pending.begin(), plain_pending.begin() + need);
                plain_pending.erase(plain_pending.begin(), plain_pending.begin() + need);
                return msg;
            }
        }
        uint8_t chunk[16 * 1024]; int got = recv(s, (char*)chunk, sizeof(chunk), 0);
        if (got <= 0) throw std::runtime_error("recv closed");
        enc_pending.insert(enc_pending.end(), chunk, chunk + got);
    }
}

void TlsSocket::Close() {
    if (ss) { delete ss; ss = nullptr; }
    if (s != INVALID_SOCKET) { closesocket(s); s = INVALID_SOCKET; }
}

bool RecvExact(SOCKET s, uint8_t* buf, int n) {
    int got = 0;
    while (got < n) {
        int r = recv(s, (char*)buf + got, n - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

bool SendExact(SOCKET s, const uint8_t* buf, int n) {
    int sent = 0;
    while (sent < n) {
        int r = send(s, (char*)buf + sent, n - sent, 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}

void ServerTlsConn::close_handles() {
    if (ctx_ok) { DeleteSecurityContext(&ctx); ctx_ok = false; }
    if (cred_ok) { FreeCredentialsHandle(&cred); cred_ok = false; }
}

bool ServerTlsConn::handshake(PCCERT_CONTEXT cert_ctx) {
    SCHANNEL_CRED sc{}; sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.cCreds = 1; sc.paCred = &cert_ctx;
    sc.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER | SP_PROT_TLS1_3_SERVER;
    sc.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER;
    TimeStamp ts{};
    if (AcquireCredentialsHandleW(nullptr, (SEC_WCHAR*)UNISP_NAME_W,
        SECPKG_CRED_INBOUND, nullptr, &sc, nullptr, nullptr, &cred, &ts) != SEC_E_OK) return false;
    cred_ok = true;

    bool first_call = true;
    std::vector<uint8_t> inbuf(32 * 1024);
    for (;;) {
        int got = recv(sock, (char*)inbuf.data(), (int)inbuf.size(), 0);
        if (got <= 0) return false;

        SecBuffer in_sec[2] = {
            {(ULONG)got,SECBUFFER_TOKEN,inbuf.data()},
            {0,SECBUFFER_EMPTY,nullptr} };
        SecBufferDesc in_desc = { SECBUFFER_VERSION,2,in_sec };

        SecBuffer out_sec[1] = { {0,SECBUFFER_TOKEN,nullptr} };
        SecBufferDesc out_desc = { SECBUFFER_VERSION,1,out_sec };

        DWORD ctx_attr = 0; TimeStamp ts2{};
        SECURITY_STATUS st = AcceptSecurityContext(
            &cred, first_call ? nullptr : &ctx,
            &in_desc, ASC_REQ_SEQUENCE_DETECT | ASC_REQ_CONFIDENTIALITY | ASC_REQ_STREAM | ASC_REQ_ALLOCATE_MEMORY,
            SECURITY_NATIVE_DREP, &ctx, &out_desc, &ctx_attr, &ts2);
        first_call = false; ctx_ok = true;

        if (out_sec[0].pvBuffer && out_sec[0].cbBuffer) {
            send(sock, (const char*)out_sec[0].pvBuffer, out_sec[0].cbBuffer, 0);
            FreeContextBuffer(out_sec[0].pvBuffer);
        }
        if (st == SEC_E_OK) return true;
        if (st != SEC_I_CONTINUE_NEEDED) return false;
    }
}

void ServerTlsConn::server_send(const std::vector<uint8_t>& data) {
    SecPkgContext_StreamSizes sizes{};
    QueryContextAttributesW(&ctx, SECPKG_ATTR_STREAM_SIZES, &sizes);
    size_t off = 0, len = data.size();
    size_t max_chunk = sizes.cbMaximumMessage > 0 ? sizes.cbMaximumMessage : len;
    while (off < len) {
        size_t chunk = (std::min)(len - off, max_chunk);
        std::vector<uint8_t> buf(sizes.cbHeader + chunk + sizes.cbTrailer);
        memcpy(buf.data() + sizes.cbHeader, data.data() + off, chunk);
        SecBuffer sec[4]{};
        sec[0].cbBuffer = sizes.cbHeader;
        sec[0].BufferType = SECBUFFER_STREAM_HEADER;
        sec[0].pvBuffer = buf.data();
        sec[1].cbBuffer = (ULONG)chunk;
        sec[1].BufferType = SECBUFFER_DATA;
        sec[1].pvBuffer = buf.data() + sizes.cbHeader;
        sec[2].cbBuffer = sizes.cbTrailer;
        sec[2].BufferType = SECBUFFER_STREAM_TRAILER;
        sec[2].pvBuffer = buf.data() + sizes.cbHeader + chunk;
        sec[3].cbBuffer = 0;
        sec[3].BufferType = SECBUFFER_EMPTY;
        sec[3].pvBuffer = nullptr;
        SecBufferDesc desc;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = sec;
        EncryptMessage(&ctx, 0, &desc, 0);
        ULONG total = sec[0].cbBuffer + sec[1].cbBuffer + sec[2].cbBuffer;
        send(sock, (const char*)buf.data(), total, 0);
        off += chunk;
    }
}

void ServerTlsConn::drain() {
    while (!enc_buf.empty()) {
        SecBuffer sec[4]{};
        sec[0] = { (ULONG)enc_buf.size(),SECBUFFER_DATA,enc_buf.data() };
        for (int i = 1; i < 4; i++) sec[i].BufferType = SECBUFFER_EMPTY;
        SecBufferDesc desc{ SECBUFFER_VERSION,4,sec };
        SECURITY_STATUS st = DecryptMessage(&ctx, &desc, 0, nullptr);
        if (st == SEC_E_INCOMPLETE_MESSAGE) break;
        if (st != SEC_E_OK) throw std::runtime_error("server TLS decrypt error");
        size_t extra_off = enc_buf.size(), extra_len = 0;
        for (int i = 0; i < 4; i++) {
            if (sec[i].BufferType == SECBUFFER_DATA && sec[i].cbBuffer)
                plain_buf.insert(plain_buf.end(), (uint8_t*)sec[i].pvBuffer, (uint8_t*)sec[i].pvBuffer + sec[i].cbBuffer);
            if (sec[i].BufferType == SECBUFFER_EXTRA && sec[i].cbBuffer) {
                extra_off = (uint8_t*)sec[i].pvBuffer - enc_buf.data();
                extra_len = sec[i].cbBuffer;
            }
        }
        if (extra_len) enc_buf.assign(enc_buf.begin() + extra_off, enc_buf.begin() + extra_off + extra_len);
        else enc_buf.clear();
    }
}

std::vector<uint8_t> ServerTlsConn::recv_msg() {
    for (;;) {
        drain();
        if (plain_buf.size() >= 8) {
            uint32_t plen = ReadU32BE(plain_buf.data() + 4);
            size_t need = 8 + plen;
            if (plain_buf.size() >= need) {
                std::vector<uint8_t> msg(plain_buf.begin(), plain_buf.begin() + need);
                plain_buf.erase(plain_buf.begin(), plain_buf.begin() + need);
                return msg;
            }
        }
        uint8_t chunk[16 * 1024]; int got = recv(sock, (char*)chunk, sizeof(chunk), 0);
        if (got <= 0) throw std::runtime_error("server recv closed");
        enc_buf.insert(enc_buf.end(), chunk, chunk + got);
    }
}

std::vector<uint8_t> BcryptBlobToSpkiDer(const std::vector<uint8_t>& pubBlob) {
    auto* blob = (BCRYPT_RSAKEY_BLOB*)pubBlob.data();
    DWORD expLen = blob->cbPublicExp, modLen = blob->cbModulus;
    const uint8_t* expBytes = pubBlob.data() + sizeof(BCRYPT_RSAKEY_BLOB);
    const uint8_t* modBytes = expBytes + expLen;
    auto der_len = [](size_t len, std::vector<uint8_t>& buf) {
        if (len < 0x80) { buf.push_back((uint8_t)len); }
        else if (len < 0x100) { buf.push_back(0x81); buf.push_back((uint8_t)len); }
        else { buf.push_back(0x82); buf.push_back((uint8_t)(len >> 8)); buf.push_back((uint8_t)len); }};
    auto der_int = [&der_len](const uint8_t* d, size_t sz)->std::vector<uint8_t> {
        std::vector<uint8_t> r; r.push_back(0x02);
        size_t skip = 0; while (skip + 1 < sz && d[skip] == 0) skip++;
        bool pad = (d[skip] & 0x80) != 0;
        der_len(sz - skip + (pad ? 1 : 0), r);
        if (pad) r.push_back(0x00);
        r.insert(r.end(), d + skip, d + sz); return r;};
    auto mod_int = der_int(modBytes, modLen), exp_int = der_int(expBytes, expLen);
    std::vector<uint8_t> rsa_pk; rsa_pk.push_back(0x30);
    std::vector<uint8_t> rsa_pk_body;
    rsa_pk_body.insert(rsa_pk_body.end(), mod_int.begin(), mod_int.end());
    rsa_pk_body.insert(rsa_pk_body.end(), exp_int.begin(), exp_int.end());
    der_len(rsa_pk_body.size(), rsa_pk);
    rsa_pk.insert(rsa_pk.end(), rsa_pk_body.begin(), rsa_pk_body.end());
    std::vector<uint8_t> bit_str; bit_str.push_back(0x03);
    der_len(rsa_pk.size() + 1, bit_str); bit_str.push_back(0x00);
    bit_str.insert(bit_str.end(), rsa_pk.begin(), rsa_pk.end());
    static const uint8_t alg_oid[] = { 0x30,0x0D,0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,0x05,0x00 };
    std::vector<uint8_t> spki_body;
    spki_body.insert(spki_body.end(), alg_oid, alg_oid + sizeof(alg_oid));
    spki_body.insert(spki_body.end(), bit_str.begin(), bit_str.end());
    std::vector<uint8_t> der_spki; der_spki.push_back(0x30);
    der_len(spki_body.size(), der_spki);
    der_spki.insert(der_spki.end(), spki_body.begin(), spki_body.end());
    return der_spki;
}

std::vector<uint8_t> GenerateRsaSpkiPem() {
    BCRYPT_ALG_HANDLE hAlg = nullptr; BCRYPT_KEY_HANDLE hKey = nullptr;
    std::vector<uint8_t> result;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, nullptr, 0) != 0) return result;
    if (BCryptGenerateKeyPair(hAlg, &hKey, 2048, 0) != 0) { BCryptCloseAlgorithmProvider(hAlg, 0); return result; }
    if (BCryptFinalizeKeyPair(hKey, 0) != 0) { BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0); return result; }
    DWORD pubSz = 0; BCryptExportKey(hKey, nullptr, BCRYPT_RSAPUBLIC_BLOB, nullptr, 0, &pubSz, 0);
    std::vector<uint8_t> pubBlob(pubSz);
    BCryptExportKey(hKey, nullptr, BCRYPT_RSAPUBLIC_BLOB, pubBlob.data(), pubSz, &pubSz, 0);
    BCryptDestroyKey(hKey); BCryptCloseAlgorithmProvider(hAlg, 0);
    auto der = BcryptBlobToSpkiDer(pubBlob); if (der.empty()) return result;
    std::string b64 = Base64Encode(der.data(), der.size());
    std::string pem = "-----BEGIN PUBLIC KEY-----\n";
    for (size_t i = 0; i < b64.size(); i += 64) pem += b64.substr(i, 64) + "\n";
    pem += "-----END PUBLIC KEY-----\n";
    result.assign(pem.begin(), pem.end());
    Log("[RSA] PEM SPKI generated " + std::to_string(result.size()) + "B");
    return result;
}

const char* GatewayActionName(int vg_type) {
    switch (vg_type) {
    case 3: return "AUTH";
    case 4: return "ACCESS";
    case 6: return "REPORT";
    case 7: return "HEARTBEAT";
    default: return "UNKNOWN";
    }
}

bool PostToGateway(const std::vector<uint8_t>& envelope,
    const std::string& puuid,
    const std::string& region,
    std::vector<uint8_t>* out_response,
    int vg_type) {   
    std::wstring gw_host = RegionToGwHost(region);
    std::string gw_host_s; for (wchar_t c : gw_host) gw_host_s += (char)(c & 0x7F);
    const std::string action_label = std::to_string(vg_type) + "(" + GatewayActionName(vg_type) + ")";
    Log("[GW] POST " + gw_host_s + " region=" + region + " action=" + action_label + " envelope=" + std::to_string(envelope.size()) + "B");

    HINTERNET hS = WinHttpOpen(VGC_UA, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) { Log("[GW] WinHttpOpen failed"); return false; }
    
    WinHttpSetTimeouts(hS, 10000, 10000, 15000, 15000);
    HINTERNET hC = WinHttpConnect(hS, gw_host.c_str(), GW_PORT, 0);
    if (!hC) { WinHttpCloseHandle(hS); Log("[GW] Connect failed"); return false; }
    HINTERNET hR = WinHttpOpenRequest(hC, L"POST", GW_PATH, L"HTTP/1.1",
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!hR) { WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return false; }

    DWORD ssl = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
        SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(hR, WINHTTP_OPTION_SECURITY_FLAGS, &ssl, sizeof(ssl));

    std::wstring headers;
    headers += L"User-Agent: vanguard/1.18.4-47+20260725.000000\r\n";
    headers += L"Content-Type: application/x-protobuf\r\n";
    if (!puuid.empty()) { std::wstring w(puuid.begin(), puuid.end()); headers += L"X-VG-2: " + w + L"\r\n"; }
    headers += L"X-VG-1: " + std::to_wstring(vg_type) + L"\r\nX-VG-3: 1\r\nAccept: */*";

    BOOL ok = WinHttpSendRequest(hR, headers.c_str(), (DWORD)-1L,
        (LPVOID)envelope.data(), (DWORD)envelope.size(), (DWORD)envelope.size(), 0);
    if (!ok || !WinHttpReceiveResponse(hR, nullptr)) {
        Log("[GW] Send/recv failed err=" + std::to_string(GetLastError()));
        WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        return false;
    }

    DWORD status = 0, sz = sizeof(DWORD);
    WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX, &status, &sz, WINHTTP_NO_HEADER_INDEX);

    std::vector<uint8_t> resp_body; DWORD avail = 0;
    while (WinHttpQueryDataAvailable(hR, &avail) && avail > 0) {
        std::vector<uint8_t> chunk(avail); DWORD rd = 0;
        WinHttpReadData(hR, chunk.data(), avail, &rd); chunk.resize(rd);
        resp_body.insert(resp_body.end(), chunk.begin(), chunk.end());
    }
    WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);

    Log("[GW] HTTP " + std::to_string(status) + " action=" + action_label + " body=" + std::to_string(resp_body.size()) + "B");
    if (status == 200) {
        Log("[GW] *** GATEWAY " + std::string(GatewayActionName(vg_type)) + " OK region=" + region + " action=" + action_label + " ***");
        
        if (out_response) *out_response = resp_body;
        {
            std::lock_guard<std::mutex> lk(g_gw_auth_response_mtx);
            g_gw_auth_response = resp_body;
        }
        {
            std::lock_guard<std::mutex> lk(g_gw_session_mtx);
            g_gw_session.last_auth_response = resp_body;
            g_gw_session.ready = true;
            g_gw_session.cached_at = (double)std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            
            if (vg_type == 3) {
                auto decrypted = VGW::DecryptGatewayResponse(resp_body);
                if (!decrypted.empty()) {
                    auto ar = VGW::DecodeAuthResponse(decrypted);
                    if (!ar.ephemeral_identifiers.empty())
                        g_gw_session.ephemeral_identifiers = ar.ephemeral_identifiers;
                }
            }
        }
        Log("[GW] gateway response cached for next VPS gateway step/action");
        Log("[GW] next gateway action will use latest response body");
        return true;
    }
    else if (!resp_body.empty()) {
        std::string s(resp_body.begin(), resp_body.end());
        Log("[GW] body: " + s.substr(0, 300));
    }
    else {
        Log("[GW] empty body -- check rso_jwt/entitlement/region");
    }
    return false;
}

bool ExchangeVpsGatewayStep(
    TlsSocket& tls,
    uint32_t request_type,
    uint32_t expected_response_type,
    int gateway_action,
    const std::vector<uint8_t>& gateway_response,
    const std::string& puuid,
    const std::string& region,
    std::vector<uint8_t>& next_gateway_response,
    const char* tag)
{
    auto req = PackMsg(request_type, gateway_response);
    tls.SendAll(req.data(), req.size());

    auto msg = tls.RecvMsg();
    if (msg.size() < 8) {
        Log(std::string("[VPS] ") + tag + " response too short");
        return false;
    }

    uint32_t mt = ReadU32BE(msg.data());
    if (mt == MSG_ERROR) {
        std::string err(msg.begin() + 8, msg.end());
        Log(std::string("[VPS] ") + tag + " server error: " + err);
        return false;
    }
    if (mt != expected_response_type) {
        Log(std::string("[VPS] ") + tag + " expected type " + std::to_string(expected_response_type) + ", got " + std::to_string(mt));
        return false;
    }

    std::vector<uint8_t> payload(msg.begin() + 8, msg.end());
    std::string sid;
    auto envelope = ParseSessionGatewayBody(payload, &sid);
    if (envelope.empty()) {
        Log(std::string("[VPS] ") + tag + " empty envelope");
        return false;
    }

    Log(std::string("[VPS] ") + tag + " envelope=" + std::to_string(envelope.size()) + "B action=" + std::to_string(gateway_action));
    return PostToGateway(envelope, puuid, region, &next_gateway_response, gateway_action);
}

void VpsServerHeartbeatLoop(
    std::unique_ptr<TlsSocket> tls,
    std::vector<uint8_t> latest_gateway_response,
    std::string puuid,
    std::string region)
{
    Log("[VPS-HB] server-driven heartbeat loop started");
    g_vps_server_heartbeat_running.store(true);

    try {
        while (g_vps_server_heartbeat_running.load()) {
            for (int i = 0; i < 30 && g_vps_server_heartbeat_running.load(); ++i) {
                Sleep(1000);
            }
            if (!g_vps_server_heartbeat_running.load()) break;
            if (latest_gateway_response.empty()) {
                Log("[VPS-HB] stopped: missing latest gateway response");
                break;
            }

            std::string server_pub_out;
            auto hb_envelope = VGW::BuildGatewayHeartbeatPayload(latest_gateway_response, server_pub_out);
            if (hb_envelope.empty()) {
                Log("[VPS-HB] BuildGatewayHeartbeatPayload failed -- retrying via server");
                
                std::vector<uint8_t> heartbeat_response;
                if (!ExchangeVpsGatewayStep(
                    *tls,
                    MSG_SESSION_HEARTBEAT,
                    MSG_SESSION_HEARTBEAT_OK,
                    7,
                    latest_gateway_response,
                    puuid,
                    region,
                    heartbeat_response,
                    "SESSION_HEARTBEAT")) {
                    Log("[VPS-HB] fallback heartbeat exchange failed");
                    break;
                }
                if (!heartbeat_response.empty()) latest_gateway_response = heartbeat_response;
                ResetGatewayReauthTimer();
                g_gateway_reauth_remaining_sec.store(30);
                UpdateConsoleTitle();
                Log("[VPS-HB] fallback heartbeat OK");
                continue;
            }

            std::vector<uint8_t> hb_resp;
            if (!PostToGateway(hb_envelope, puuid, region, &hb_resp, 7)) {
                Log("[VPS-HB] direct gateway heartbeat failed -- retrying via server");
                std::vector<uint8_t> heartbeat_response;
                if (!ExchangeVpsGatewayStep(
                    *tls,
                    MSG_SESSION_HEARTBEAT,
                    MSG_SESSION_HEARTBEAT_OK,
                    7,
                    latest_gateway_response,
                    puuid,
                    region,
                    heartbeat_response,
                    "SESSION_HEARTBEAT")) {
                    Log("[VPS-HB] fallback heartbeat exchange failed");
                    break;
                }
                if (!heartbeat_response.empty()) latest_gateway_response = heartbeat_response;
            } else {
                if (!hb_resp.empty()) latest_gateway_response = hb_resp;
                Log("[VPS-HB] direct gateway heartbeat OK resp=" + std::to_string(hb_resp.size()) + "B");
            }

            ResetGatewayReauthTimer();
            g_gateway_reauth_remaining_sec.store(30);
            UpdateConsoleTitle();
            Log("[VPS-HB] heartbeat OK");
        }
    }
    catch (const std::exception& e) {
        Log("[VPS-HB] exception: " + std::string(e.what()));
    }

    g_vps_server_heartbeat_running.store(false);
    g_keepalive_running.store(false);
    tls->Close();
    Log("[VPS-HB] server-driven heartbeat loop stopped");
}

PCCERT_CONTEXT LoadOrCreateCert() {
    {
        std::vector<BYTE> pfx_data;
        std::ifstream f("server.pfx", std::ios::binary);
        if (f) {
            pfx_data = std::vector<BYTE>((std::istreambuf_iterator<char>(f)), {});
            CRYPT_DATA_BLOB blob{ (DWORD)pfx_data.size(),pfx_data.data() };
            HCERTSTORE store = PFXImportCertStore(&blob, L"", CRYPT_EXPORTABLE | CRYPT_USER_KEYSET);
            if (store) {
                PCCERT_CONTEXT ctx = CertFindCertificateInStore(store, X509_ASN_ENCODING, 0, CERT_FIND_ANY, nullptr, nullptr);
                if (ctx) { Log("[SRV] Loaded server.pfx"); CertCloseStore(store, 0); return ctx; }
                CertCloseStore(store, 0);
            }
        }
    }
    
    Log("[SRV] server.pfx not found â€” generating self-signed cert");
    HCERTSTORE myStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, nullptr);
    if (!myStore) { Log("[SRV] CertOpenStore failed"); return nullptr; }

    CERT_NAME_BLOB nameBlob{};
    const char* subj = "CN=DndVanguardServer";
    DWORD nameLen = 0;
    CertStrToNameA(X509_ASN_ENCODING, subj, CERT_X500_NAME_STR, nullptr, nullptr, &nameLen, nullptr);
    std::vector<BYTE> nameBuf(nameLen);
    CertStrToNameA(X509_ASN_ENCODING, subj, CERT_X500_NAME_STR, nullptr, nameBuf.data(), &nameLen, nullptr);
    nameBlob.cbData = nameLen; nameBlob.pbData = nameBuf.data();

    CRYPT_KEY_PROV_INFO kpi{};
    kpi.pwszContainerName = const_cast<wchar_t*>(L"DndVanguardSrv");
    kpi.pwszProvName = nullptr;
    kpi.dwProvType = PROV_RSA_FULL;
    kpi.dwFlags = CRYPT_MACHINE_KEYSET;
    kpi.dwKeySpec = AT_KEYEXCHANGE;

    SYSTEMTIME st_start{}, st_end{};
    GetSystemTime(&st_start);
    st_end = st_start; st_end.wYear += 10;

    PCCERT_CONTEXT ctx = CertCreateSelfSignCertificate(0, &nameBlob, 0, &kpi, nullptr, &st_start, &st_end, nullptr);
    if (!ctx) { Log("[SRV] CertCreateSelfSignCertificate failed err=" + std::to_string(GetLastError())); return nullptr; }

    CRYPT_DATA_BLOB pfx{};
    if (PFXExportCertStore(myStore, &pfx, L"", EXPORT_PRIVATE_KEYS)) {
        std::vector<BYTE> buf(pfx.cbData);
        pfx.pbData = buf.data();
        if (PFXExportCertStore(myStore, &pfx, L"", EXPORT_PRIVATE_KEYS)) {
            std::ofstream out("server.pfx", std::ios::binary);
            out.write((char*)buf.data(), buf.size());
            Log("[SRV] Saved server.pfx for reuse");
        }
    }
    CertCloseStore(myStore, 0);
    Log("[SRV] Self-signed cert created");
    return ctx;
}

static void HandleTunnelClient(SOCKET raw, PCCERT_CONTEXT cert_ctx) {
    if (g_active_clients.load() >= MAX_CLIENTS) { closesocket(raw); return; }
    g_active_clients++;

    ServerTlsConn conn;
    conn.sock = raw;
    std::string session_id;
    const DWORD rcvtimeo = 120000;
    setsockopt(raw, SOL_SOCKET, SO_RCVTIMEO, (char*)&rcvtimeo, sizeof(rcvtimeo));

    auto send_pkt = [&](uint32_t type, const std::vector<uint8_t>& payload = {}) {
        auto pkt = PackMsg(type, payload);
        conn.server_send(pkt);
        };
    auto send_err = [&](const char* msg) {
        std::vector<uint8_t> e(msg, msg + strlen(msg));
        send_pkt(MSG_ERROR, e);
        };

    try {
        if (!conn.handshake(cert_ctx)) throw std::runtime_error("TLS handshake failed");
        Log("[SRV] client connected");

        for (;;) {
            auto msg = conn.recv_msg();
            uint32_t mt = ReadU32BE(msg.data());
            uint32_t plen = ReadU32BE(msg.data() + 4);
            std::vector<uint8_t> payload(msg.begin() + 8, msg.end());

            if (mt == MSG_SESSION_AUTH) {
                size_t off = 0;
                std::string auth_key = ParseLPStr(payload, off);
                auto gw_machine_id = ParseLPBytes(payload, off);
                std::string jwt = ParseLPStr(payload, off);
                std::string puuid = ParseLPStr(payload, off);
                uint32_t val_pid = (off + 4 <= payload.size()) ? ReadU32BE(payload.data() + off) : 0; off += 4;
                int64_t  client_ts_ms = (off + 8 <= payload.size()) ? (int64_t)ReadU64BE(payload.data() + off) : 0; off += 8;
                std::string region = ParseLPStr(payload, off);
                auto hwid_fp = ParseLPBytes(payload, off);
                std::string riot_acct = ParseLPStr(payload, off);
                std::string hostname = ParseLPStr(payload, off);

                if (auth_key != AUTH_KEY) {
                    Log("[SRV] SESSION_AUTH auth_failed");
                    send_err("auth_failed"); break;
                }
                if (jwt.empty()) { send_err("jwt_empty"); continue; }

                if (region.empty()) region = ShardFromJwtRobust(jwt);
                if (region.empty()) {
                    std::lock_guard<std::mutex> lk2(g_jwt_cache_mtx);
                    region = g_cached_region.empty() ? "na" : g_cached_region;
                }
                region = ApplyConfiguredRegion(region, "[SRV] SESSION_AUTH");
                
                {
                    std::lock_guard<std::mutex> lk2(g_jwt_cache_mtx);
                    if (!region.empty()) g_cached_region = region;
                }
                if (riot_acct.empty()) riot_acct = AccountFromJwt(jwt);
                if (puuid.empty()) puuid = PuuidFromJwt(jwt);

                std::string client_ip = "127.0.0.1";
                session_id = g_session_mgr.create_session(
                    jwt, puuid, region, riot_acct, hostname, client_ip,
                    gw_machine_id, hwid_fp, val_pid, client_ts_ms);

                const auto& _hwp1 = GetRandomizedHardwareProfile();
                auto gw_envelope = VGW::BuildGatewayAuthPayload(jwt, puuid, GetConfiguredGatewayMachineId(), GetStableHt(), "",
                    _hwp1.cpu_brand, _hwp1.cpu_model, _hwp1.gpu_model, "Windows 10 Pro", _hwp1.os_version);
                
                if (gw_envelope.empty()) {
                    gw_envelope = g_session_mgr.send_heartbeat(session_id, true, IOCTL_VGK_HB, {});
                    Log("[SRV] SESSION_AUTH_OK using vgk fallback envelope for session=" + session_id.substr(0, 8));
                }

                std::vector<uint8_t> ok_payload;
                PushLenStr(ok_payload, session_id);
                PushU32BE(ok_payload, (uint32_t)gw_envelope.size());
                ok_payload.insert(ok_payload.end(), gw_envelope.begin(), gw_envelope.end());
                send_pkt(MSG_SESSION_AUTH_OK, ok_payload);
                Log("[SRV] SESSION_AUTH_OK session=" + session_id.substr(0, 8) + " gw_envelope=" + std::to_string(gw_envelope.size()) + "B");
            }
            else if (mt == MSG_HELLO) {
                send_err("use_session_auth");
            }
            else if (mt == MSG_SYNC) {
                if (session_id.empty()) { send_err("not_authenticated"); continue; }
                size_t off = 0;
                std::string sync_sid = ParseLPStr(payload, off);
                uint64_t last_seq = (off + 8 <= payload.size()) ? ReadU64BE(payload.data() + off) : 0;
                session_id = sync_sid;
                if (!g_session_mgr.is_active(session_id)) continue;
                g_session_mgr.touch(session_id);
                auto buffered = g_session_mgr.get_buffered(session_id, last_seq + 1);
                Log("[SRV] SYNC session=" + session_id.substr(0, 8) + " buffered=" + std::to_string(buffered.size()));
                for (auto& [seq, data] : buffered) {
                    std::vector<uint8_t> hb_pkt;
                    PushU64BE(hb_pkt, seq);
                    PushU32BE(hb_pkt, (uint32_t)data.size());
                    hb_pkt.insert(hb_pkt.end(), data.begin(), data.end());
                    send_pkt(MSG_HB_BUFFER, hb_pkt);
                }
            }
            else if (mt == MSG_IOCTL) {
                if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
                    send_err("not_authenticated"); continue;
                }
                size_t off = 0;
                uint32_t ioctl_code = (off + 4 <= payload.size()) ? ReadU32BE(payload.data() + off) : 0; off += 4;
                uint32_t dlen = (off + 4 <= payload.size()) ? ReadU32BE(payload.data() + off) : 0; off += 4;
                std::vector<uint8_t> idata(payload.begin() + off, payload.begin() + off + dlen);
                g_session_mgr.touch(session_id);
                std::vector<uint8_t> resp;
                
                if ((ioctl_code >> 16) == 0x22 || ioctl_code == IOCTL_VGK_HB)
                    resp = g_session_mgr.send_heartbeat(session_id, true, ioctl_code, idata);
                else
                    resp = g_session_mgr.send_heartbeat(session_id, false, ioctl_code, idata);
                g_session_mgr.note_ioctl(session_id, ioctl_code, (int)idata.size(), (int)resp.size());
                std::vector<uint8_t> resp_pkt;
                PushU32BE(resp_pkt, (uint32_t)resp.size());
                resp_pkt.insert(resp_pkt.end(), resp.begin(), resp.end());
                send_pkt(MSG_IOCTL_RESP, resp_pkt);
            }
            else if (mt == MSG_PING) {
                if (!session_id.empty() && g_session_mgr.is_active(session_id))
                    g_session_mgr.note_ping(session_id);
                send_pkt(MSG_PONG);
            }
            else if (mt == MSG_JWT_UPDATE) {
                if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
                    send_err("not_authenticated"); continue;
                }
                size_t off = 0;
                std::string new_jwt = ParseLPStr(payload, off);
                std::string new_puuid = ParseLPStr(payload, off);
                if (new_jwt.empty()) { send_err("jwt_empty"); continue; }
                if (g_session_mgr.update_jwt(session_id, new_jwt, new_puuid))
                    send_pkt(MSG_JWT_OK);
                else send_err("session_missing");
            }
            else if (mt == MSG_PIPE_AUTH) {
                if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
                    send_err("not_authenticated"); continue;
                }
                uint32_t val_pid = (payload.size() >= 4) ? ReadU32BE(payload.data()) : 0;
                g_session_mgr.note_pipe_auth(session_id, val_pid);
                send_pkt(MSG_PIPE_AUTH_OK);
            }
            else if (mt == MSG_SESSION_ACCESS) {
                if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
                    send_err("not_authenticated"); continue;
                }
                auto s = g_session_mgr.get(session_id);
                if (!s) { send_err("session_missing"); continue; }

                std::string sid_out;
                auto envelope = ParseSessionGatewayBody(payload, &sid_out);
                if (envelope.empty()) { send_err("empty_envelope"); continue; }

                Log("[SRV] SESSION_ACCESS envelope=" + std::to_string(envelope.size()) + "B session=" + session_id.substr(0, 8));

                std::string server_pub_out, token_out;
                auto access_envelope = VGW::BuildGatewayAccessPayload(envelope, server_pub_out, token_out);
                if (access_envelope.empty()) { send_err("access_payload_failed"); continue; }

                std::vector<uint8_t> access_resp;
                bool ok = PostToGateway(access_envelope, s->puuid, s->region, &access_resp, 4);
                if (!ok || access_resp.empty()) { send_err("gateway_access_failed"); continue; }

                std::vector<uint8_t> ok_payload;
                PushLenStr(ok_payload, session_id);
                PushU32BE(ok_payload, (uint32_t)access_resp.size());
                ok_payload.insert(ok_payload.end(), access_resp.begin(), access_resp.end());
                send_pkt(MSG_SESSION_ACCESS_OK, ok_payload);
                Log("[SRV] SESSION_ACCESS_OK session=" + session_id.substr(0, 8) + " resp=" + std::to_string(access_resp.size()) + "B");
            }
            else if (mt == MSG_SESSION_HEARTBEAT) {
                if (session_id.empty() || !g_session_mgr.is_active(session_id)) {
                    send_err("not_authenticated"); continue;
                }
                auto s = g_session_mgr.get(session_id);
                if (!s) { send_err("session_missing"); continue; }

                std::string sid_out;
                auto prev_resp = ParseSessionGatewayBody(payload, &sid_out);
                if (prev_resp.empty()) { send_err("empty_envelope"); continue; }

                Log("[SRV] SESSION_HEARTBEAT session=" + session_id.substr(0, 8) + " prev_resp=" + std::to_string(prev_resp.size()) + "B");

                std::string server_pub_out;
                auto hb_envelope = VGW::BuildGatewayHeartbeatPayload(prev_resp, server_pub_out);
                if (hb_envelope.empty()) { send_err("hb_payload_failed"); continue; }

                std::vector<uint8_t> hb_resp;
                bool ok = PostToGateway(hb_envelope, s->puuid, s->region, &hb_resp, 7);
                if (!ok || hb_resp.empty()) {
                    hb_resp = g_fallback.get(session_id);
                    if (hb_resp.empty()) { send_err("gateway_hb_failed"); continue; }
                    Log("[SRV] SESSION_HEARTBEAT using fallback cache session=" + session_id.substr(0, 8));
                }

                g_fallback.update(session_id, hb_resp);
                g_session_mgr.send_heartbeat(session_id, true); 

                std::vector<uint8_t> ok_payload;
                PushLenStr(ok_payload, session_id);
                PushU32BE(ok_payload, (uint32_t)hb_resp.size());
                ok_payload.insert(ok_payload.end(), hb_resp.begin(), hb_resp.end());
                send_pkt(MSG_SESSION_HEARTBEAT_OK, ok_payload);
                Log("[SRV] SESSION_HEARTBEAT_OK session=" + session_id.substr(0, 8) + " resp=" + std::to_string(hb_resp.size()) + "B");
            }
            else {
                Log("[SRV] unknown msg type=" + std::to_string(mt));
            }
        }
    }
    catch (const std::exception& e) {
        Log("[SRV] client exception: " + std::string(e.what()));
    }

    if (!session_id.empty())
        Log("[SRV] connection closed session=" + session_id.substr(0, 8) + " (session stays)");
    conn.close_handles();
    closesocket(raw);
    g_active_clients--;
}

void RunServer() {
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);

    PCCERT_CONTEXT cert = LoadOrCreateCert();
    if (!cert) { Log("[SRV] Cannot load cert â€” server abort"); return; }

    SOCKET listen_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    const int one = 1; setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, (char*)&one, sizeof(one));
    sockaddr_in addr{}; addr.sin_family = AF_INET; addr.sin_port = htons(SERVER_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); 

    if (bind(listen_sock, (sockaddr*)&addr, sizeof(addr)) != 0) {
        Log("[SRV] bind failed err=" + std::to_string(WSAGetLastError())); return;
    }
    listen(listen_sock, 64);
    Log("[SRV] TLS listening 127.0.0.1:" + std::to_string(SERVER_PORT));

    g_hb_running = true;   g_van84_running = true;
    std::thread(HeartbeatLoop).detach();
    std::thread(Van84Loop).detach();

    while (g_server_running.load()) {
        sockaddr_in cli_addr{}; int cli_len = sizeof(cli_addr);
        SOCKET cli = accept(listen_sock, (sockaddr*)&cli_addr, &cli_len);
        if (cli == INVALID_SOCKET) continue;
        std::thread(HandleTunnelClient, cli, cert).detach();
    }

    g_hb_running = false; g_van84_running = false;
    closesocket(listen_sock);
    CertFreeCertificateContext(cert);
    Log("[SRV] Server stopped");
}
