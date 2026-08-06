#include "vgk_manager.h"
#include "logger.h"
#include "protocol_utils.h"
#include "hwid_spoof.h"
#include "tls_socket.h"
#include "console_ui.h"

FallbackCache g_fallback;
EventLog g_elog;

std::vector<uint8_t> g_vgk_payload;
std::mutex           g_vgk_payload_mtx;

static const uint8_t FALLBACK_TOKEN[] = {
    0x08,0x01,0x12,0xA0,0x02,0x52,0x47,0x01,0x00,0x05,0xFA,0xA7,
    0x74,0xC9,0x93,0x69,0x50,0x77,0xF4,0xB0,0xD9,0xC8,0x0D,0x6F,
    0x67,0x57,0x08,0xCB,0xFC,0x03,0x06,0x60,0x70,0x2C,0x73,0x9E,
    0x2C,0xA5,0xF7,0x25,0xF0,0x4E,0x2A,0x8F,0x9F,0xB5,0xC7,0x06,
    0xA9,0x4E,0x78,0x15,0x7B,0x20,0x7D,0xD3,0x0F,0xC5,0xB8,0x24,
    0xEE,0xD2,0xBC,0xA1,0x9E,0x83,0x0F,0x34,0x98,0x2F,0x3D,0xED,
    0xF1,0x3A,0xD2,0x63,0xDC,0xA0,0xA6,0x16,0x9F,0xAA,0x21,0xD5,
    0xA4,0xE9,0x1C,0xFE,0xB6,0x7A,0xC2,0x4B,0x0C,0x6F,0x90,0x7B,
    0x6F,0x80,0x77,0x70,0x67,0x3B,0x0A,0xB5,0x2A,0x4A,0x71,0xBF,
    0xBE,0xE9,0xBE,0x4C,0xBE,0xF3,0xC2,0xBE,0xCD,0x2F,0xB2,0xDA,
    0xE8,0x82,0xDB,0xDD,0x3F,0xF0,0x5A,0x98,0x0D,0xA0,0x2D,0x7F,
    0xAD,0xDA,0xE7,0xD6,0xF5,0x9D,0x32,0x1D,0x0B,0x38,0x48,0x9F,
    0x03,0xBD,0x23,0xF0,0x39,0x76,0x52,0x67,0x8F,0x02,0x32,0x3B,
    0xBC,0x82,0xCA,0x10,0xDE,0x6A,0xC7,0x3C,0x51,0x14,0xFF,0x58,
    0x8B,0xFE,0x7B,0x63,0xA6,0xE2,0x9D,0xDB,0x5B,0xC0,0xCD,0x7F,
    0x92,0xCE,0xA6,0x5D,0x0C,0x19,0x25,0x00,0x6E,0xDC,0x7B,0x3B,
    0x0F,0x68,0x2B,0xE1,0xDD,0xE8,0x66,0x03,0x70,0x58,0x3E,0x5F,
    0xEA,0xB1,0x65,0x68,0x4C,0xB1,0x2D,0xF9,0x7E,0xD9,0x45,0xBF,
    0x06,0xAD,0xDF,0x74,0xFC,0x1A,0x5F,0x09,0x41,0x33,0xA6,0x30,
    0xF2,0xD6,0x02,0xE6,0xCB,0x46,0x37,0xF3,0x2B,0x7A,0xB9,0x7A,
    0xC6,0x06,0x13,0x7C,0x0A,0xF5,0x78,0xB4,0x36,0x43,0xDD,0x6E,
    0xBF,0x68,0xBF,0x90,0xC7,0x0E,0x7D,0x19,0x72,0xBB,0xDA,0x9F,
    0xF5,0x44,0x82,0x96,0x2F,0xD0,0x2F,0xEB,0x49,0xBE,0x8B,0x17,
    0x05,0x5D,0xE3,0x8C,0x10,0xBA,0xB3,0x42,0x7C,0x01,0xDD,0xA9,
    0x00,0xE5,0xC2,0x6D,0xD0,
};
static const size_t FALLBACK_TOKEN_LEN = sizeof(FALLBACK_TOKEN);

SessionManager g_session_mgr;

std::string g_cached_jwt;
std::string g_cached_sid;
std::string g_cached_ext_sid;
std::string g_cached_puuid;
std::string g_cached_region; 
std::string g_region_override; 
std::mutex  g_jwt_cache_mtx;

RoundTracker g_round_tracker;
TasksModulesHandler g_tasks_handler;

std::atomic_bool g_hb_running(false);
std::atomic_bool g_van84_running(false);
std::atomic_bool g_keepalive_running(false);
std::atomic_int  g_keepalive_fail_count(0);
static constexpr bool GATEWAY_AUTO_SEND_ON_CAPTURE = false;
std::atomic_int  g_gateway_reauth_remaining_sec(GATEWAY_REAUTH_INTERVAL_SEC);
std::atomic_bool g_gateway_reauth_restart_countdown(false);
std::atomic_bool g_gateway_auto_send(GATEWAY_AUTO_SEND_ON_CAPTURE);
std::atomic_bool g_gateway_send_inflight(false);
std::atomic_bool g_gateway_manual_reauth_inflight(false);
std::atomic<ULONGLONG> g_gateway_manual_last_trigger_ms(0);
std::atomic_bool g_backend_started(false);

std::mutex            g_pending_gateway_mtx;
PendingGatewayRequest g_pending_gateway;
uint32_t         g_valorant_pid_fwd = 0; 
std::atomic_bool g_gw_reauth_needed(false); 

VGW::GatewaySession g_gw_session;
std::mutex           g_gw_session_mtx;
std::atomic_bool     g_gw_auto_posted(false);  
std::atomic_int      g_val_loading_pct(0);
std::vector<uint8_t> g_gw_auth_response;
std::mutex            g_gw_auth_response_mtx;

std::atomic_bool g_shutdown(false);
std::atomic_bool g_api_called(false);
std::atomic<void*> g_current_pipe(nullptr);
uint32_t g_valorant_pid = 0;

static std::atomic_int  g_reauth_fail_count(0);
static double           g_last_reauth_time = 0;

void FallbackCache::update(const std::string& sid, const std::vector<uint8_t>& resp) {
    std::lock_guard<std::mutex> lk(mtx_);
    store_[sid] = resp;
}

std::vector<uint8_t> FallbackCache::get(const std::string& sid) const {
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = store_.find(sid);
    return it != store_.end() ? it->second : std::vector<uint8_t>{};
}

void CryptoSession::mount(const std::string& j, const std::string& p) {
    jwt = j; puuid = p; mounted = true; hb_count = 0; token_variant = 0;
}

void CryptoSession::update_jwt(const std::string& j, const std::string& p) {
    jwt = j; puuid = p; token_variant = 0;
}

std::vector<uint8_t> CryptoSession::heartbeat_payload() {
    hb_count++;
    {
        std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
        if (!g_vgk_payload.empty()) {
            Log("[CRYPTO] using real vgk payload hb#" + std::to_string(hb_count) + " size=" + std::to_string(g_vgk_payload.size()));
            return g_vgk_payload;
        }
    }
    Log("[CRYPTO] WARNING: using FALLBACK_TOKEN hb#" + std::to_string(hb_count) + " (real vgk payload not yet received)");
    return std::vector<uint8_t>(FALLBACK_TOKEN, FALLBACK_TOKEN + FALLBACK_TOKEN_LEN);
}

std::vector<uint8_t> CryptoSession::ioctl_response(uint32_t code, const std::vector<uint8_t>& data) {
    if (!mounted) return {};
    if (code == IOCTL_VGK_HB) return heartbeat_payload();
    if (code == IOCTL_VGK_ACC) {
        if (!data.empty()) return heartbeat_payload();
        return { 0x43,0x4C,0x45,0x41,0x4E,0x00 }; 
    }
    if ((code >> 16) == 0x22) {
        if (!data.empty()) return heartbeat_payload();
        return { 0x43,0x4C,0x45,0x41,0x4E,0x00 };
    }
    if (!data.empty()) return data;
    return heartbeat_payload();
}

bool ProgramWorker::alive() const {
    if (proc == INVALID_HANDLE_VALUE) return false;
    DWORD code = 0;
    return GetExitCodeProcess(proc, &code) && code == STILL_ACTIVE;
}

bool ProgramWorker::start() {
    if (program_path.empty() || GetFileAttributesA(program_path.c_str()) == INVALID_FILE_ATTRIBUTES)
        return false;
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET tmp = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(tmp, (sockaddr*)&sa, sizeof(sa));
    int salen = sizeof(sa); getsockname(tmp, (sockaddr*)&sa, &salen);
    port = (uint16_t)ntohs(sa.sin_port);
    closesocket(tmp);

    std::string cmd = program_path
        + " --container " + container_id
        + " --ipc-port " + std::to_string(port);
    STARTUPINFOA si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(nullptr, (LPSTR)cmd.c_str(), nullptr, nullptr, FALSE,
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return false;
    CloseHandle(pi.hThread);
    proc = pi.hProcess;

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (std::chrono::steady_clock::now() < deadline) {
        if (!alive()) return false;
        if (_ping()) { ready_ = true; return true; }
        Sleep(150);
    }
    stop(); return false;
}

void ProgramWorker::stop() {
    if (alive()) TerminateProcess(proc, 0);
    if (proc != INVALID_HANDLE_VALUE) { CloseHandle(proc); proc = INVALID_HANDLE_VALUE; }
    ready_ = false;
}

std::vector<uint8_t> ProgramWorker::ioctl(uint32_t code, const std::vector<uint8_t>& data, int timeout_ms) {
    std::vector<uint8_t> req(10 + data.size());
    req[0] = 1; req[1] = 2;
    req[2] = req[3] = 0;
    req[4] = (code >> 24) & 0xFF; req[5] = (code >> 16) & 0xFF;
    req[6] = (code >> 8) & 0xFF;  req[7] = code & 0xFF;
    uint32_t dlen = (uint32_t)data.size();
    req[8] = (dlen >> 8) & 0xFF; req[9] = dlen & 0xFF;  
    memcpy(req.data() + 10, data.data(), data.size());
    auto resp = _request(req, timeout_ms);
    if (resp.size() < 4) return {};
    uint32_t status = (resp[0] << 8) | resp[1];
    if (status != 0) return {};
    uint32_t rlen = (resp[2] << 8) | resp[3];
    if (resp.size() < 4 + rlen) return {};
    return std::vector<uint8_t>(resp.begin() + 4, resp.begin() + 4 + rlen);
}

bool ProgramWorker::_ping() {
    std::vector<uint8_t> req = { 1,4,0,0,0,0,0,0,0,0 };
    try { auto r = _request(req, 500); return r.size() >= 2 && r[0] == 0 && r[1] == 0; }
    catch (...) { return false; }
}

std::vector<uint8_t> ProgramWorker::_request(const std::vector<uint8_t>& req, int timeout_ms) {
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (char*)&to, sizeof(to));
    sockaddr_in addr{}; addr.sin_family = AF_INET;
    addr.sin_port = htons(port); addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(s, (sockaddr*)&addr, sizeof(addr)) != 0) { closesocket(s); return {}; }
    send(s, (char*)req.data(), (int)req.size(), 0);
    std::vector<uint8_t> buf(16384); int got = recv(s, (char*)buf.data(), (int)buf.size(), 0);
    closesocket(s);
    if (got <= 0) return {};
    buf.resize(got); return buf;
}

double NowSec() {
    return std::chrono::duration<double>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

std::vector<uint8_t> RealVgkIoctl(uint32_t ioctl_code, const std::vector<uint8_t>& in_data) {
    HANDLE hDev = CreateFileA("\\\\.\\vgk",
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

    if (hDev == INVALID_HANDLE_VALUE) {
        hDev = CreateFileA("\\\\.\\vgk0",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    }
    if (hDev == INVALID_HANDLE_VALUE) return {};

    std::vector<uint8_t> out_buf(8192, 0);
    DWORD bytes_returned = 0;

    BOOL ok = DeviceIoControl(
        hDev,
        ioctl_code,
        in_data.empty() ? nullptr : (LPVOID)in_data.data(),
        (DWORD)in_data.size(),
        out_buf.data(),
        (DWORD)out_buf.size(),
        &bytes_returned,
        nullptr);

    CloseHandle(hDev);

    if (!ok || bytes_returned == 0) return {};
    out_buf.resize(bytes_returned);
    return out_buf;
}

std::shared_ptr<Session> SessionManager::get(const std::string& sid) const {
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid); return it != sessions.end() ? it->second : nullptr;
}

bool SessionManager::is_active(const std::string& sid) const {
    std::lock_guard<std::mutex> lk(mtx); return sessions.count(sid) > 0;
}

void SessionManager::touch(const std::string& sid) {
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid); if (it != sessions.end()) it->second->last_activity = NowSec();
}

void SessionManager::note_ping(const std::string& sid) {
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid);
    if (it != sessions.end()) { it->second->ping_count++; it->second->last_activity = NowSec(); }
}

void SessionManager::note_ioctl(const std::string& sid, uint32_t code, int in_len, int out_len) {
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid);
    if (it != sessions.end()) { it->second->ioctl_count++; it->second->last_activity = NowSec(); }
    Log("IOCTL session=" + sid.substr(0, 8) + " code=0x" + [&] {
        std::ostringstream o; o << std::hex << code; return o.str();}() +
            " in=" + std::to_string(in_len) + " out=" + std::to_string(out_len));
}

std::string SessionManager::create_session(
    const std::string& jwt, const std::string& puuid,
    const std::string& region, const std::string& riot_account,
    const std::string& hostname, const std::string& client_ip,
    const std::vector<uint8_t>& gw_machine_id,
    const std::vector<uint8_t>& hwid_fp,
    uint32_t valorant_pid, int64_t client_ts_ms)
{
    BYTE rnd[16]; BCryptGenRandom(nullptr, (PUCHAR)rnd, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    rnd[6] = (rnd[6] & 0x0F) | 0x40; rnd[8] = (rnd[8] & 0x3F) | 0x80;
    std::ostringstream ss;
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) ss << '-';
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)rnd[i];
    }
    std::string sid = ss.str();

    auto s = std::make_shared<Session>();
    s->session_id = sid; s->riot_token = jwt; s->puuid = puuid;
    s->region = region; s->riot_account = riot_account;
    s->hostname = hostname; s->client_ip = client_ip;
    s->gateway_machine_id = gw_machine_id; s->hwid_fingerprint = hwid_fp;
    s->valorant_pid = valorant_pid; s->client_ts_ms = client_ts_ms;
    s->created_at = NowSec(); s->last_activity = NowSec();
    s->hb_last_sent = NowSec(); s->hb_last_success = NowSec();
    s->last_keepalive_boost = NowSec(); 
    s->session_hardened = true; 
    s->crypto.mount(jwt, puuid);
    s->pipe_auth_count = 1; s->jwt_push_count = jwt.empty() ? 0 : 1;
    {
        std::lock_guard<std::mutex> lk(mtx);
        sessions[sid] = s;
    }
    g_elog.log(sid, "session_auth", "created", "ip=" + client_ip + " region=" + region);
    Log("session " + sid.substr(0, 8) + " CREATED ip=" + client_ip + " region=" + region +
        " account=" + riot_account.substr(0, 24) + " pid=" + std::to_string(valorant_pid) + " [INFINITE SESSION]");
    
    if (on_session_created) on_session_created(sid, puuid, region, riot_account);
    return sid;
}

bool SessionManager::update_jwt(const std::string& sid, const std::string& jwt, const std::string& puuid) {
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid); if (it == sessions.end()) return false;
    auto& s = *it->second;
    s.riot_token = jwt; s.puuid = puuid; s.jwt_push_count++;
    s.last_activity = NowSec();
    s.last_keepalive_boost = NowSec(); 
    s.hb_missed = 0;                   
    s.emergency_mode = false;          
    s.burst_counter = 0;               
    s.hb_success_count = 0;            
    s.crypto.update_jwt(jwt, puuid);
    g_elog.log(sid, "jwt_update", "ok");
    Log("JWT UPDATE session=" + sid.substr(0, 8) + " - ALL COUNTERS RESET");
    return true;
}

bool SessionManager::note_pipe_auth(const std::string& sid, uint32_t pid) {
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid); if (it == sessions.end()) return false;
    it->second->valorant_pid = pid; it->second->pipe_auth_count++;
    it->second->last_activity = NowSec();
    return true;
}

void SessionManager::destroy_session(const std::string& sid) {
    std::shared_ptr<Session> s;
    {
        std::lock_guard<std::mutex> lk(mtx); auto it = sessions.find(sid);
        if (it != sessions.end()) { s = it->second; sessions.erase(it); }
    }
    if (s && s->worker) s->worker->stop();
    g_elog.log(sid, "session", "destroyed");
    Log("session " + sid.substr(0, 8) + " destroyed");
    
    if (on_session_destroyed) on_session_destroyed(sid);
}

void SessionManager::expire_idle() {
    if (IDLE_TIMEOUT_SEC <= 0) return;
    double now = NowSec();
    std::vector<std::string> expired;
    {
        std::lock_guard<std::mutex> lk(mtx);
        for (auto& kv : sessions) {
            double effective_timeout = IDLE_TIMEOUT_SEC;
            if (kv.second->session_hardened) {
                double boost_age = now - kv.second->last_keepalive_boost;
                if (boost_age < SESSION_KEEPALIVE_BOOST) {
                    effective_timeout += SESSION_KEEPALIVE_BOOST; 
                }
            }
            if (now - kv.second->last_activity > effective_timeout) 
                expired.push_back(kv.first);
        }
    }
    for (auto& sid : expired) { Log("session " + sid.substr(0, 8) + " idle timeout"); destroy_session(sid); }
}

std::vector<uint8_t> SessionManager::send_heartbeat(const std::string& sid, bool force,
    uint32_t code, const std::vector<uint8_t>& data) {
    auto s = get(sid); if (!s) return {};
    std::vector<uint8_t> resp;

    resp = RealVgkIoctl(code, data);
    if (!resp.empty()) {
        Log("HB real_vgk code=0x" + [&] {std::ostringstream o; o << std::hex << code; return o.str(); }() + " resp=" + std::to_string(resp.size()) + "B");
    }

    if (resp.empty() && s->worker && s->worker->alive()) {
        resp = s->worker->ioctl(code, data, 5000);
    }
    
    if (resp.empty()) resp = s->crypto.ioctl_response(code, data);
    
    if (resp.empty()) resp = g_fallback.get(sid);
    g_fallback.update(sid, resp);
    {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = sessions.find(sid); if (it != sessions.end()) {
            auto& ss = *it->second;
            ss.hb_sequence++;
            ss.hb_last_sent = NowSec();
            if (!resp.empty()) { 
                ss.hb_missed = 0; 
                ss.hb_last_success = NowSec(); 
                ss.hb_success_count++; 
                ss.emergency_mode = false; 
                ss.burst_counter = 0; 
                
                if (ss.hb_success_count % 20 == 0) {
                    ss.last_activity = NowSec();
                    ss.last_keepalive_boost = NowSec();
                }
            }
            else {
                ss.hb_missed++;
                if (ss.hb_missed >= 5) {
                    Log("WARN session " + sid.substr(0, 8) + " missed=" + std::to_string(ss.hb_missed) + " risk -102");
                }
                if (ss.hb_missed > 15) Log("CRITICAL session " + sid.substr(0, 8) + " missed HB risk Error 102");
            }
            ss.hb_buffer.push_back({ ss.hb_sequence,resp });
            if (ss.hb_buffer.size() > 1024) ss.hb_buffer.pop_front(); 
        }
    }
    g_elog.log(sid, "heartbeat", resp.empty() ? "empty" : "ok");
    return resp;
}

std::vector<std::pair<uint64_t, std::vector<uint8_t>>>
SessionManager::get_buffered(const std::string& sid, uint64_t from_seq) {
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>> out;
    std::lock_guard<std::mutex> lk(mtx);
    auto it = sessions.find(sid); if (it == sessions.end()) return out;
    for (auto& e : it->second->hb_buffer)
        if (e.seq >= from_seq) out.push_back({ e.seq,e.data });
    return out;
}

std::string ApplyConfiguredRegion(const std::string& detected_region, const char* tag) {
    std::string forced_region;
    {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        forced_region = g_region_override;
    }

    if (!forced_region.empty()) {
        Log(std::string(tag) + " region override -> " + forced_region +
            (detected_region.empty() ? " (detected=<empty>)" : " (detected=" + detected_region + ")"));
        return forced_region;
    }
    return detected_region;
}

void RoundTracker::on_match_start() {
    std::lock_guard<std::mutex> lk(mtx);
    in_match.store(true);
    lobby_pending.store(false);
    round_number.store(0);
    match_start_time = NowSec();
    last_round_time  = NowSec();
    Log("[ROUND] Match started");
}

void RoundTracker::on_round_end() {
    std::lock_guard<std::mutex> lk(mtx);
    round_number.fetch_add(1);
    last_round_time = NowSec();
    Log("[ROUND] Round " + std::to_string(round_number.load()) + " ended");
}

void RoundTracker::on_lobby_return(std::function<void()> refresh_fn) {
    {
        std::lock_guard<std::mutex> lk(mtx);
        if (!in_match.load() && !lobby_pending.load()) return;
        in_match.store(false);
        lobby_pending.store(true);
        Log("[ROUND] Lobby return after " + std::to_string(round_number.load()) + " rounds â€” refreshing session");
    }
    if (refresh_fn) refresh_fn();
    lobby_pending.store(false);
}

std::vector<uint8_t> TasksModulesHandler::handle_packet(const std::vector<uint8_t>& pkt) {
    std::lock_guard<std::mutex> lk(mtx);
    ack_count++;
    std::ostringstream hdrHex;
    int hdrLen = (int)pkt.size() < 8 ? (int)pkt.size() : 8;
    for (int i = 0; i < hdrLen; i++)
        hdrHex << std::hex << std::setw(2) << std::setfill('0') << (int)pkt[i] << " ";
    Log("[TASKS] packet size=" + std::to_string(pkt.size()) + " ack#" + std::to_string(ack_count) + " header=" + hdrHex.str());
    tasks_received.store(true);

    std::vector<uint8_t> ack;
    if (pkt.size() >= 8) {
        ack.push_back(pkt[0] + 1); 
        ack.push_back(0x00);
        ack.push_back(0x00);
        ack.push_back(0x00);
        ack.push_back(pkt[4]);
        ack.push_back(pkt[5]);
        ack.push_back(pkt[6]);
        ack.push_back(pkt[7]);
    } else {
        ack = { 0x66, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    }
    std::ostringstream ackHex;
    for (auto b : ack) ackHex << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
    Log("[TASKS] ACK sent: " + ackHex.str());
    return ack;
}

std::vector<uint8_t> TasksModulesHandler::handle_auth_request(
    const std::string& jwt, const std::string& puuid,
    const std::string& sid, const std::string& region)
{
    std::lock_guard<std::mutex> lk(mtx);
    Log("[AUTH_REQ] 0x64 new session request â€” puuid=" + (puuid.size()>8?puuid.substr(0,8)+"...":puuid));
    std::vector<uint8_t> resp;
    if (!jwt.empty() && !puuid.empty()) {
        resp.push_back(0x00); 
        uint32_t plen = (uint32_t)puuid.size();
        resp.push_back((plen>>24)&0xFF); resp.push_back((plen>>16)&0xFF);
        resp.push_back((plen>>8)&0xFF);  resp.push_back(plen&0xFF);
        resp.insert(resp.end(), puuid.begin(), puuid.end());
        
        if (!sid.empty()) {
            uint32_t slen = (uint32_t)sid.size();
            resp.push_back((slen>>24)&0xFF); resp.push_back((slen>>16)&0xFF);
            resp.push_back((slen>>8)&0xFF);  resp.push_back(slen&0xFF);
            resp.insert(resp.end(), sid.begin(), sid.end());
        }
    } else {
        resp.push_back(0x01); 
    }
    return resp;
}

void Van84Loop() {
    while (g_van84_running.load()) {
        Sleep(5000); 

        std::vector<std::string> sids;
        {
            std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
            for (auto& kv : g_session_mgr.sessions) sids.push_back(kv.first);
        }
        for (auto& sid : sids) {
            auto s = g_session_mgr.get(sid); if (!s) continue;
            double elapsed = NowSec() - s->hb_last_success;

            if (elapsed > 45.0 && elapsed < 120.0) {
                Log("VAN84 preventive HB session=" + sid.substr(0, 8) + " elapsed=" + std::to_string((int)elapsed) + "s");
                g_session_mgr.send_heartbeat(sid, true);
            }

            if (elapsed > 120.0) {
                Log("VAN84 session stale, resetting hb_missed");
                std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
                s->hb_missed = 0;
                s->emergency_mode = false;
                s->burst_counter  = 0;
            }

            if (s->session_hardened) {
                std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
                s->last_keepalive_boost = NowSec();
                s->last_activity = NowSec();
            }
        }
    }
}

void HeartbeatLoop() {
    while (g_hb_running.load()) {
        Sleep(1000);
        std::vector<std::string> sids;
        {
            std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
            for (auto& kv : g_session_mgr.sessions) sids.push_back(kv.first);
        }

        for (auto& sid : sids) {
            auto s = g_session_mgr.get(sid); if (!s) continue;
            double elapsed_ms = (NowSec() - s->hb_last_sent) * 1000.0;

            if (elapsed_ms >= (double)(HB_INTERVAL_MS - 500)) {
                g_session_mgr.send_heartbeat(sid);
            }
        }
        g_session_mgr.expire_idle();
    }
}

bool GatewayDoReauth() {
    std::string jwt, puuid, region, sid;
    {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        jwt    = g_cached_jwt;
        puuid  = g_cached_puuid;
        sid    = g_cached_sid;
        region = g_cached_region;
    }
    if (jwt.empty() || puuid.empty()) {
        Log("[GW-KA] re-auth skipped: no jwt/puuid");
        return false;
    }
    if (region.empty()) region = ShardFromJwtRobust(jwt);
    if (region.empty()) region = "na";
    region = ApplyConfiguredRegion(region, "[GW-KA]");

    double now = NowSec();
    bool forced = g_gw_reauth_needed.load();
    if (!forced && (now - g_last_reauth_time) < 60.0) {
        Log("[GW-KA] re-auth throttled â€” last was " + std::to_string((int)(now - g_last_reauth_time)) + "s ago");
        return false;
    }
    if (forced) Log("[GW-KA] re-auth forced (lobby return / new match)");

    const std::string resolved_sid = ResolveNonEmptySid(jwt, sid, puuid, "[GW-KA]");
    std::string last_ephemeral;
    {
        std::lock_guard<std::mutex> lk(g_gw_session_mtx);
        last_ephemeral = g_gw_session.ephemeral_identifiers;
    }
    const auto& _hwp2 = GetRandomizedHardwareProfile();
    auto envelope = VGW::BuildGatewayAuthPayload(jwt, resolved_sid, GetConfiguredGatewayMachineId(), GetStableHt(), last_ephemeral,
        _hwp2.cpu_brand, _hwp2.cpu_model, _hwp2.gpu_model, "Windows 10 Pro", _hwp2.os_version);
    if (envelope.empty()) {
        Log("[GW-KA] re-auth skipped: envelope empty");
        return false;
    }

    g_last_reauth_time = NowSec();
    Log("[GW-KA] sending re-auth -> " + region);
    std::vector<uint8_t> new_resp;
    bool ok = PostToGateway(envelope, puuid, region, &new_resp, 3);
    if (ok) {
        g_reauth_fail_count.store(0);
        ResetGatewayReauthTimer();
        Log("[GW-KA] re-auth OK -> " + region);
    } else {
        int fails = g_reauth_fail_count.fetch_add(1) + 1;
        Log("[GW-KA] re-auth FAILED fails=" + std::to_string(fails));
        g_last_reauth_time = NowSec() + 120.0; 
        g_gateway_reauth_remaining_sec.store(120);
        UpdateConsoleTitle();
    }
    g_gw_reauth_needed.store(false);
    return ok;
}

void GatewayKeepaliveLoop() {
    Log("[GW-KA] keepalive loop started â€” re-auth every 5.5 minutes");
    while (g_keepalive_running.load()) {
        for (int i = 0; i < 330 && g_keepalive_running.load(); i++) {
            Sleep(1000);
            if (g_gw_reauth_needed.load()) break;
        }
        if (!g_keepalive_running.load()) break;
        GatewayDoReauth();
    }
    Log("[GW-KA] keepalive loop stopped");
}

void GatewayKeepaliveLoop45Min() {
    Log("[GW-KA] keepalive loop started - re-auth every 45 minutes");
    while (g_keepalive_running.load()) {
        g_gateway_reauth_restart_countdown.store(false);
        g_gateway_reauth_remaining_sec.store(GATEWAY_REAUTH_INTERVAL_SEC);
        UpdateConsoleTitle();

        for (int i = 0; i < GATEWAY_REAUTH_INTERVAL_SEC && g_keepalive_running.load(); i++) {
            Sleep(1000);
            if (g_gw_reauth_needed.load()) break;
            if (g_gateway_reauth_restart_countdown.exchange(false)) {
                i = -1;
                g_gateway_reauth_remaining_sec.store(GATEWAY_REAUTH_INTERVAL_SEC);
                UpdateConsoleTitle();
                continue;
            }
            g_gateway_reauth_remaining_sec.store(GATEWAY_REAUTH_INTERVAL_SEC - (i + 1));
            UpdateConsoleTitle();
        }

        if (!g_keepalive_running.load()) break;

        g_gateway_reauth_remaining_sec.store(0);
        UpdateConsoleTitle();
        if (GatewayDoReauth()) {
            Beep(880, 120);
        }
    }

    g_gateway_reauth_remaining_sec.store(GATEWAY_REAUTH_INTERVAL_SEC);
    UpdateConsoleTitle();
    Log("[GW-KA] keepalive loop stopped");
}

bool SmartGatewayMint(const std::string& jwt, const std::string& sid,
    const std::string& puuid, uint32_t pid) {
        const std::string resolved_sid = ResolveNonEmptySid(jwt, sid, puuid, "[GW]");

        {
            std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
            if (!g_cached_jwt.empty() && g_cached_jwt == jwt && g_cached_sid == resolved_sid) {
                std::lock_guard<std::mutex> lk2(g_gw_session_mtx);
                if (g_gw_session.ready) {
                    return true; 
                }
            }
        }

        {
            std::lock_guard<std::mutex> lk(g_gw_session_mtx);
            if (g_gw_session.ready) {
                Log("[GW] token or sid changed! -- allowing new JWT mint");
                g_gw_session.Reset();
            }
        }

        g_keepalive_running.store(false);

        Log("[GW] forwarding token to gateway (auto-mint)");

        {
            std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
            g_cached_jwt = jwt;
            g_cached_sid = resolved_sid;
            g_cached_puuid = puuid;
        }

        std::string region = ShardFromJwtRobust(jwt);
        if (region.empty()) {
            std::lock_guard<std::mutex> lk3(g_jwt_cache_mtx);
            LogJwtRegionHints(jwt, "[JWT-REGION][GW]");
            region = g_cached_region.empty() ? "na" : g_cached_region;
            Log("[GW] region fallback -> " + region);
        }
        region = ApplyConfiguredRegion(region, "[GW]");
        
        {
            std::lock_guard<std::mutex> lk3(g_jwt_cache_mtx);
            if (!region.empty()) g_cached_region = region;
        }

        Log("[GW] building auth payload (standalone protobuf+crypto)");
        const auto& _hwp3 = GetRandomizedHardwareProfile();
        auto envelope = VGW::BuildGatewayAuthPayload(jwt, resolved_sid, GetConfiguredGatewayMachineId(), GetStableHt(), "",
            _hwp3.cpu_brand, _hwp3.cpu_model, _hwp3.gpu_model, "Windows 10 Pro", _hwp3.os_version);
        if (envelope.empty()) {
            Log("[GW] BuildGatewayAuthPayload failed -- falling back to vgk payload");
            std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
            envelope = g_vgk_payload;
        }
        if (envelope.empty()) {
            Log("[GW] no envelope available, mint aborted");
            return false;
        }

        std::vector<uint8_t> auth_resp;
        bool ok = PostToGateway(envelope, puuid, region, &auth_resp);
        if (ok) {
            Log("[GW] gateway mint success (auto)");
            ResetGatewayReauthTimer();
            g_last_reauth_time = NowSec();
            StopVgk();

            if (!g_keepalive_running.exchange(true)) {
                ResetGatewayReauthTimer();
                std::thread(GatewayKeepaliveLoop45Min).detach();
            }
            return true;
        }
        else {
            Log("[GW] gateway mint failed -- will retry on next JWT");
            g_keepalive_running.store(false);
            g_gw_auto_posted.store(false);
        }
        return false;
}

std::vector<uint8_t> BuildSessionAuth(
    const std::string& jwt, const std::string& puuid,
    const std::string& external_sid, const std::string& region,
    uint32_t pid, const std::vector<uint8_t>& hwid,
    const std::vector<uint8_t>& rsa_spki_pem,
    const std::string& cpu_brand, const std::string& cpu_model,
    const std::string& gpu_brand, const std::string& gpu_model,
    uint32_t cpu_logical_count)
{
    std::vector<uint8_t> body;
    PushLenStr(body, AUTH_KEY);
    PushLenBytes(body, hwid);                
    PushLenStr(body, jwt);
    PushLenStr(body, puuid);
    PushU32BE(body, pid);
    uint64_t now_ms = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    PushU64BE(body, now_ms);
    PushLenStr(body, region);
    PushLenBytes(body, hwid);                
    PushLenStr(body, puuid);                 

    PushLenStr(body, RandomizedVersion ? GetFakeHostname() : "WIN-PC");

    PushLenBytes(body, rsa_spki_pem);
    PushLenStr(body, "release-13.00-shipping-30-4955671");
    PushU32BE(body, 4955671); PushU32BE(body, 13);
    PushU32BE(body, 0); PushU32BE(body, 30); PushU32BE(body, 0);
    PushLenStr(body, external_sid);
    PushLenStr(body, cpu_brand); PushLenStr(body, cpu_model);
    PushLenStr(body, gpu_brand); PushLenStr(body, gpu_model);
    PushU32BE(body, cpu_logical_count);
    return body;
}

typedef NTSTATUS(NTAPI* pfnNtUnloadDriver)(PUNICODE_STRING DriverServiceName);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION;

#define SystemHandleInformation 16
typedef NTSTATUS(NTAPI* pfnNtQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);

void KillVgkHandles() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return;
    auto NtQSI = (pfnNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQSI) return;

    ULONG size = 1 << 20; 
    std::vector<BYTE> buf(size);
    NTSTATUS st;
    while ((st = NtQSI(SystemHandleInformation, buf.data(), (ULONG)buf.size(), &size)) == 0x80000005L) {
        buf.resize(buf.size() * 2);
    }
    if (st != 0) return;

    auto* info = (SYSTEM_HANDLE_INFORMATION*)buf.data();

    DWORD val_pid = 0;
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    std::string n; for (wchar_t c : pe.szExeFile) if (c) n += (char)(c & 0x7F);
                    if (_stricmp(n.c_str(), "VALORANT-Win64-Shipping.exe") == 0) {
                        val_pid = pe.th32ProcessID; break;
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
    }
    if (!val_pid) { Log("[VGK] Valorant not found"); return; }

    HANDLE hVgk = CreateFileA("\\\\.\\vgk",
        GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);

    PVOID vgk_obj = nullptr;
    if (hVgk != INVALID_HANDLE_VALUE) {
        DWORD my_pid = GetCurrentProcessId();
        for (ULONG i = 0; i < info->NumberOfHandles; i++) {
            auto& e = info->Handles[i];
            if (e.UniqueProcessId == my_pid && (HANDLE)(uintptr_t)e.HandleValue == hVgk) {
                vgk_obj = e.Object; break;
            }
        }
        CloseHandle(hVgk);
    }

    HANDLE hVal = OpenProcess(PROCESS_DUP_HANDLE, FALSE, val_pid);
    if (!hVal) { Log("[VGK] Cannot open Valorant process"); return; }

    int killed = 0;
    for (ULONG i = 0; i < info->NumberOfHandles; i++) {
        auto& e = info->Handles[i];
        if (e.UniqueProcessId != (USHORT)val_pid) continue;
        if (vgk_obj && e.Object != vgk_obj) continue;
        if (!vgk_obj) continue; 

        HANDLE dup = nullptr;
        if (DuplicateHandle(hVal, (HANDLE)(uintptr_t)e.HandleValue,
            GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_CLOSE_SOURCE)) {
            CloseHandle(dup);
            killed++;
        }
    }
    CloseHandle(hVal);
    Log("[VGK] Closed " + std::to_string(killed) + " vgk handle(s) from Valorant");
}

bool ForceUnloadVgk() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return false;
    auto NtUnloadDriver = (pfnNtUnloadDriver)GetProcAddress(ntdll, "NtUnloadDriver");
    if (!NtUnloadDriver) return false;

    WCHAR reg_path[] = L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\vgk";
    UNICODE_STRING us;
    us.Buffer = reg_path;
    us.Length = (USHORT)(wcslen(reg_path) * sizeof(WCHAR));
    us.MaximumLength = us.Length + sizeof(WCHAR);

    NTSTATUS st = NtUnloadDriver(&us);
    Log("[VGK] NtUnloadDriver status=0x" + [&] {std::ostringstream o; o << std::hex << (uint32_t)st; return o.str(); }() +
        (st == 0 ? " (OK)" : st == 0xC0000024L ? " (refs exist)" : st == 0xC000010EL ? " (not loaded)" : ""));
    return st == 0;
}

void StopVgk() {
    Log("[VGK] StopVgk called â€” skipping service stop (Valorant still running)");
}

bool SendViaLocalServer(const std::string& rso_jwt,
    const std::string& sid, const std::string& puuid, uint32_t pid)
{
    const std::string resolved_sid = ResolveNonEmptySid(rso_jwt, sid, puuid, "[CLI]");

    {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(3);
        while (std::chrono::steady_clock::now() < deadline) {
            {
                std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
                if (!g_vgk_payload.empty()) break;
            }
            Sleep(50);
        }
    }
    auto tls = std::make_unique<TlsSocket>();
    if (!tls->Connect(SERVER_HOST, SERVER_PORT, TLS_SKIP_VERIFY)) { Log(("[CLI] TLS connect failed")); return false; }
    Log(("[CLI] TLS connected"));

    auto hwid = GetConfiguredHwid();
    std::string cpu_brand, cpu_model, gpu_brand, gpu_model; uint32_t cpu_cores = 0;
    GetCpuInfo(cpu_brand, cpu_model, cpu_cores);
    GetGpuInfo(gpu_brand, gpu_model);

    auto rsa_pem = GenerateRsaSpkiPem();
    if (rsa_pem.empty()) { Log(("[CLI] RSA keygen failed")); tls->Close(); return false; }

    std::string region = ShardFromJwtRobust(rso_jwt);
    if (region.empty()) {
        LogJwtRegionHints(rso_jwt, "[JWT-REGION][CLI]");
        std::lock_guard<std::mutex> lk2(g_jwt_cache_mtx);
        region = g_cached_region.empty() ? "na" : g_cached_region;
    }
    region = ApplyConfiguredRegion(region, "[CLI]");

    auto sa_payload = BuildSessionAuth(
        rso_jwt, puuid, resolved_sid, region, pid, hwid, rsa_pem,
        cpu_brand, cpu_model, gpu_brand, gpu_model, cpu_cores);

    auto sa_pkt = PackMsg(MSG_SESSION_AUTH, sa_payload);
    Log("[CLI] Sending SESSION_AUTH puuid=" + puuid.substr(0, 8) + " region=" + region);

    try {
        tls->SendAll(sa_pkt.data(), sa_pkt.size());
        auto msg = tls->RecvMsg();
        uint32_t mt = ReadU32BE(msg.data());
        uint32_t plen = ReadU32BE(msg.data() + 4);

        if (mt == MSG_ERROR) {
            std::string err(msg.begin() + 8, msg.end());
            Log("[CLI] Server error: " + err); tls->Close(); return false;
        }
        if (mt != MSG_SESSION_AUTH_OK) {
            Log("[CLI] Expected SESSION_AUTH_OK, got " + std::to_string(mt)); tls->Close(); return false;
        }

        std::vector<uint8_t> payload(msg.begin() + 8, msg.end());
        std::string server_sid;
        std::vector<uint8_t> envelope = ParseSessionGatewayBody(payload, &server_sid);

        Log("[CLI] SESSION_AUTH_OK server_sid=" + server_sid.substr(0, 8) + " envelope=" + std::to_string(envelope.size()) + "B");

        UpdateDisplaySessionState(puuid, region, puuid);

        bool vps_gateway_ok = false;
        std::vector<uint8_t> access_resp;
        std::vector<uint8_t> heartbeat_resp;
        if (!envelope.empty()) {
            std::vector<uint8_t> auth_resp;
            Log("[VPS] Posting server auth envelope to Riot Gateway (action=3)");
            if (PostToGateway(envelope, puuid, region, &auth_resp, 3) && !auth_resp.empty()) {
                if (ExchangeVpsGatewayStep(
                    *tls,
                    MSG_SESSION_ACCESS,
                    MSG_SESSION_ACCESS_OK,
                    4,
                    auth_resp,
                    puuid,
                    region,
                    access_resp,
                    "SESSION_ACCESS")) {
                    vps_gateway_ok = true;

                    if (ExchangeVpsGatewayStep(
                        *tls,
                        MSG_SESSION_HEARTBEAT,
                        MSG_SESSION_HEARTBEAT_OK,
                        7,
                        access_resp,
                        puuid,
                        region,
                        heartbeat_resp,
                        "SESSION_HEARTBEAT")) {
                        Log("[VPS] Initial server-driven heartbeat completed");
                    }
                }
            }
        }

        if (vps_gateway_ok) {
            Log("[VPS] Server-driven gateway flow completed");
            StopVgk();
            g_vps_server_heartbeat_running.store(false);
            g_keepalive_running.store(true);
            ResetGatewayReauthTimer();
            std::thread(
                VpsServerHeartbeatLoop,
                std::move(tls),
                heartbeat_resp.empty() ? access_resp : heartbeat_resp,
                puuid,
                region).detach();
            return true;
        }

        tls->Close();
        Log("[CLI] Server gateway flow unavailable; falling back to local SmartGatewayMint");
        return SmartGatewayMint(rso_jwt, resolved_sid, puuid, pid);
    }
    catch (const std::exception& e) {
        Log("[CLI] Exception: " + std::string(e.what())); tls->Close();
    }
    return false;
}

void QueuePendingGatewayRequest(const std::string& jwt,
    const std::string& sid, const std::string& puuid, uint32_t pid)
{
    std::lock_guard<std::mutex> lk(g_pending_gateway_mtx);
    g_pending_gateway.jwt = jwt;
    g_pending_gateway.sid = sid;
    g_pending_gateway.puuid = puuid;
    g_pending_gateway.pid = pid;
    g_pending_gateway.queued_at = std::chrono::steady_clock::now();
    g_pending_gateway.valid = true;
}

bool TriggerPendingGatewaySend() {
    if (g_gateway_send_inflight.exchange(true)) {
        return false;
    }

    PendingGatewayRequest request;
    {
        std::lock_guard<std::mutex> lk(g_pending_gateway_mtx);
        if (!g_pending_gateway.valid) {
            g_gateway_send_inflight.store(false);
            return false;
        }
        request = g_pending_gateway;
    }

    std::thread([request]() {
        Log("[GUI] Manual gateway send requested");
        bool ok = SendViaLocalServer(request.jwt, request.sid, request.puuid, request.pid);
        if (ok) {
            Beep(880, 120);
            std::lock_guard<std::mutex> lk(g_pending_gateway_mtx);
            if (g_pending_gateway.valid &&
                g_pending_gateway.jwt == request.jwt &&
                g_pending_gateway.sid == request.sid) {
                g_pending_gateway.valid = false;
            }
        } else {
            Log("[GUI] Manual gateway send failed; request kept pending");
        }
        g_gateway_send_inflight.store(false);
    }).detach();

    return true;
}

bool TriggerGatewayManualAction() {
    if (g_gateway_auto_send.load()) {
        return false;
    }

    constexpr ULONGLONG MANUAL_GATEWAY_COOLDOWN_MS = 10000;
    ULONGLONG now_ms = GetTickCount64();
    ULONGLONG last_trigger_ms = g_gateway_manual_last_trigger_ms.load();
    if (last_trigger_ms != 0 && (now_ms - last_trigger_ms) < MANUAL_GATEWAY_COOLDOWN_MS) {
        ULONGLONG remaining_ms = MANUAL_GATEWAY_COOLDOWN_MS - (now_ms - last_trigger_ms);
        Log("[GUI] F1 ignored: manual gateway cooldown " + std::to_string((remaining_ms + 999) / 1000) + "s");
        return false;
    }

    bool has_pending_request = false;
    {
        std::lock_guard<std::mutex> lk(g_pending_gateway_mtx);
        has_pending_request = g_pending_gateway.valid;
    }
    if (has_pending_request) {
        bool triggered = TriggerPendingGatewaySend();
        if (triggered) {
            g_gateway_manual_last_trigger_ms.store(now_ms);
        }
        return triggered;
    }

    std::string jwt;
    std::string puuid;
    {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        jwt = g_cached_jwt;
        puuid = g_cached_puuid;
    }

    if (jwt.empty() || puuid.empty()) {
        Log("[GUI] F1 ignored: no cached gateway session");
        return false;
    }

    if (g_gateway_manual_reauth_inflight.exchange(true)) {
        Log("[GUI] F1 ignored: manual re-auth already in flight");
        return false;
    }

    g_gateway_manual_last_trigger_ms.store(now_ms);

    std::thread([]() {
        Log("[GUI] F1 manual gateway re-auth requested");
        g_gw_reauth_needed.store(true);
        if (GatewayDoReauth()) {
            Beep(880, 120);
        }
        g_gateway_manual_reauth_inflight.store(false);
    }).detach();

    return true;
}

bool TriggerGatewayAutoRefreshAction() {
    if (!g_gateway_auto_send.load()) {
        return false;
    }

    constexpr ULONGLONG MANUAL_GATEWAY_COOLDOWN_MS = 10000;
    ULONGLONG now_ms = GetTickCount64();
    ULONGLONG last_trigger_ms = g_gateway_manual_last_trigger_ms.load();
    if (last_trigger_ms != 0 && (now_ms - last_trigger_ms) < MANUAL_GATEWAY_COOLDOWN_MS) {
        ULONGLONG remaining_ms = MANUAL_GATEWAY_COOLDOWN_MS - (now_ms - last_trigger_ms);
        Log("[GUI] F2 ignored: manual gateway cooldown " + std::to_string((remaining_ms + 999) / 1000) + "s");
        return false;
    }

    std::string jwt;
    std::string puuid;
    {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        jwt = g_cached_jwt;
        puuid = g_cached_puuid;
    }

    if (jwt.empty() || puuid.empty()) {
        Log("[GUI] F2 ignored: no cached gateway session");
        return false;
    }

    if (g_gateway_manual_reauth_inflight.exchange(true)) {
        Log("[GUI] F2 ignored: manual re-auth already in flight");
        return false;
    }

    g_gateway_manual_last_trigger_ms.store(now_ms);

    std::thread([]() {
        Log("[GUI] F2 automated-mode gateway refresh requested");
        g_gw_reauth_needed.store(true);
        if (GatewayDoReauth()) {
            Beep(880, 120);
        }
        g_gateway_manual_reauth_inflight.store(false);
    }).detach();

    return true;
}
