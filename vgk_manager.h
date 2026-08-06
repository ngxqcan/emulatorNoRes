#pragma once

#include "config.h"

class FallbackCache {
public:
    void update(const std::string& sid, const std::vector<uint8_t>& resp);
    std::vector<uint8_t> get(const std::string& sid) const;
private:
    mutable std::mutex mtx_;
    std::map<std::string, std::vector<uint8_t>> store_;
};
extern FallbackCache g_fallback;

class EventLog {
public:
    EventLog() {}
    void log(const std::string&, const std::string&, const std::string&,
             const std::string& = "", int = 0, int = -1) {}
private:
    std::mutex mtx_;
};
extern EventLog g_elog;

extern std::vector<uint8_t> g_vgk_payload;
extern std::mutex           g_vgk_payload_mtx;

struct CryptoSession {
    std::string jwt;
    std::string puuid;
    bool mounted = false;
    int  hb_count = 0;
    int  token_variant = 0;

    void mount(const std::string& j, const std::string& p);
    void update_jwt(const std::string& j, const std::string& p);
    std::vector<uint8_t> heartbeat_payload();
    std::vector<uint8_t> ioctl_response(uint32_t code, const std::vector<uint8_t>& data);
};

struct ProgramWorker {
    std::string  container_id;
    std::string  program_path;
    HANDLE       proc = INVALID_HANDLE_VALUE;
    uint16_t     port = 0;
    bool         ready_ = false;

    bool alive() const;
    bool start();
    void stop();
    std::vector<uint8_t> ioctl(uint32_t code, const std::vector<uint8_t>& data, int timeout_ms = 5000);
    bool _ping();
    std::vector<uint8_t> _request(const std::vector<uint8_t>& req, int timeout_ms);
};

struct Session {
    std::string  session_id;
    std::string  riot_token;
    std::string  puuid;
    std::string  region;
    std::string  riot_account;
    std::string  hostname;
    std::string  client_ip;
    std::string  container_id;
    std::vector<uint8_t> gateway_machine_id;
    std::vector<uint8_t> hwid_fingerprint;
    uint32_t     valorant_pid = 0;
    int64_t      client_ts_ms = 0;
    int          jwt_push_count = 0;
    int          pipe_auth_count = 0;
    int          ping_count = 0;
    int          ioctl_count = 0;
    double       created_at = 0;
    double       last_activity = 0;
    CryptoSession crypto;
    std::shared_ptr<ProgramWorker> worker;

    uint64_t hb_sequence = 0;
    double   hb_last_sent = 0;
    double   hb_last_success = 0;
    int      hb_missed = 0;
    int      hb_success_count = 0;      
    double   last_keepalive_boost = 0;   
    bool     session_hardened = false;   
    bool     emergency_mode = false;     
    int      burst_counter = 0;          
    double   last_burst_time = 0;        

    struct HbEntry { uint64_t seq; std::vector<uint8_t> data; };
    std::deque<HbEntry> hb_buffer; 
};

double NowSec();

std::vector<uint8_t> RealVgkIoctl(uint32_t ioctl_code, const std::vector<uint8_t>& in_data);

class SessionManager {
public:
    std::map<std::string, std::shared_ptr<Session>> sessions;
    mutable std::mutex mtx;
    std::string program_path;

    std::function<void(const std::string&, const std::string&, const std::string&, const std::string&)> on_session_created;
    std::function<void(const std::string&)> on_session_destroyed; 

    std::shared_ptr<Session> get(const std::string& sid) const;
    bool is_active(const std::string& sid) const;
    void touch(const std::string& sid);
    void note_ping(const std::string& sid);
    void note_ioctl(const std::string& sid, uint32_t code, int in_len, int out_len);
    std::string create_session(
        const std::string& jwt, const std::string& puuid,
        const std::string& region, const std::string& riot_account,
        const std::string& hostname, const std::string& client_ip,
        const std::vector<uint8_t>& gw_machine_id,
        const std::vector<uint8_t>& hwid_fp,
        uint32_t valorant_pid, int64_t client_ts_ms);
    bool update_jwt(const std::string& sid, const std::string& jwt, const std::string& puuid);
    bool note_pipe_auth(const std::string& sid, uint32_t pid);
    void destroy_session(const std::string& sid);
    void expire_idle();
    std::vector<uint8_t> send_heartbeat(const std::string& sid, bool force = false,
        uint32_t code = IOCTL_VGK_HB,
        const std::vector<uint8_t>& data = {});
    std::vector<std::pair<uint64_t, std::vector<uint8_t>>>
        get_buffered(const std::string& sid, uint64_t from_seq);
};
extern SessionManager g_session_mgr;

extern std::string g_cached_jwt;
extern std::string g_cached_sid;
extern std::string g_cached_ext_sid;
extern std::string g_cached_puuid;
extern std::string g_cached_region; 
extern std::string g_region_override; 
extern std::mutex  g_jwt_cache_mtx;

std::string ApplyConfiguredRegion(const std::string& detected_region, const char* tag);

struct RoundTracker {
    std::atomic_int  round_number{0};
    std::atomic_bool in_match{false};
    std::atomic_bool lobby_pending{false};
    double           match_start_time = 0;
    double           last_round_time  = 0;
    std::mutex       mtx;

    void on_match_start();
    void on_round_end();
    void on_lobby_return(std::function<void()> refresh_fn);
    bool is_in_match()   const { return in_match.load(); }
    int  current_round() const { return round_number.load(); }
};
extern RoundTracker g_round_tracker;

struct TasksModulesHandler {
    std::atomic_bool tasks_received{false};
    int  ack_count = 0;
    std::mutex mtx;

    std::vector<uint8_t> handle_packet(const std::vector<uint8_t>& pkt);
    std::vector<uint8_t> handle_auth_request(
        const std::string& jwt, const std::string& puuid,
        const std::string& sid, const std::string& region);
};
extern TasksModulesHandler g_tasks_handler;

extern std::atomic_bool g_hb_running;
extern std::atomic_bool g_van84_running;
extern std::atomic_bool g_keepalive_running;
extern std::atomic_int  g_keepalive_fail_count;
extern std::atomic_int  g_gateway_reauth_remaining_sec;
extern std::atomic_bool g_gateway_reauth_restart_countdown;
extern std::atomic_bool g_gateway_auto_send;
extern std::atomic_bool g_gateway_send_inflight;
extern std::atomic_bool g_gateway_manual_reauth_inflight;
extern std::atomic<ULONGLONG> g_gateway_manual_last_trigger_ms;
extern std::atomic_bool g_backend_started;

struct PendingGatewayRequest {
    std::string jwt;
    std::string sid;
    std::string puuid;
    uint32_t pid = 0;
    std::chrono::steady_clock::time_point queued_at{};
    bool valid = false;
};

extern std::mutex            g_pending_gateway_mtx;
extern PendingGatewayRequest g_pending_gateway;
extern uint32_t         g_valorant_pid_fwd;
extern std::atomic_bool g_gw_reauth_needed;

extern VGW::GatewaySession g_gw_session;
extern std::mutex           g_gw_session_mtx;
extern std::atomic_bool     g_gw_auto_posted;
extern std::atomic_int      g_val_loading_pct;
extern std::vector<uint8_t> g_gw_auth_response;
extern std::mutex            g_gw_auth_response_mtx;

extern std::atomic_bool g_shutdown;
extern std::atomic_bool g_api_called;
extern std::atomic<void*> g_current_pipe;
extern uint32_t g_valorant_pid;

void StopVgk();
void KillVgkHandles();
bool ForceUnloadVgk();
void Van84Loop();
void HeartbeatLoop();
bool GatewayDoReauth();
void GatewayKeepaliveLoop();
void GatewayKeepaliveLoop45Min();
bool SmartGatewayMint(const std::string& jwt, const std::string& sid,
                     const std::string& puuid, uint32_t pid);
std::vector<uint8_t> BuildSessionAuth(
    const std::string& jwt, const std::string& puuid,
    const std::string& external_sid, const std::string& region,
    uint32_t pid, const std::vector<uint8_t>& hwid,
    const std::vector<uint8_t>& rsa_spki_pem,
    const std::string& cpu_brand, const std::string& cpu_model,
    const std::string& gpu_brand, const std::string& gpu_model,
    uint32_t cpu_logical_count);

bool SendViaLocalServer(const std::string& rso_jwt,
    const std::string& sid, const std::string& puuid, uint32_t pid);
void QueuePendingGatewayRequest(const std::string& jwt,
    const std::string& sid, const std::string& puuid, uint32_t pid);
bool TriggerPendingGatewaySend();
bool TriggerGatewayManualAction();
bool TriggerGatewayAutoRefreshAction();
