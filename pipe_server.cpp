#include "pipe_server.h"
#include "logger.h"
#include "protocol_utils.h"
#include "vgk_manager.h"
#include "console_ui.h"

void TryExtractAndSend(const uint8_t* buf, DWORD len) {
    std::string ascii(len, ' ');
    for (DWORD i = 0; i < len; i++) if (buf[i] >= 0x20 && buf[i] < 0x7F) ascii[i] = (char)buf[i];
    static const std::regex jwt_re(R"((eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}))");
    static const std::regex uuid_re(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");

    std::vector<std::string> all_jwts;
    std::sregex_iterator jit(ascii.begin(), ascii.end(), jwt_re), jend;
    for (; jit != jend; ++jit) all_jwts.push_back((*jit)[1].str());

    if (all_jwts.empty()) {
        Log("[PIPE] No JWT found in this scan.");
        return;
    }

    std::string jwt = all_jwts[0];
    Log("[PIPE] JWT candidates found=" + std::to_string(all_jwts.size()));

    std::string first_uuid, last_uuid;
    std::sregex_iterator it(ascii.begin(), ascii.end(), uuid_re), end;
    for (; it != end; ++it) { if (first_uuid.empty()) first_uuid = it->str(); last_uuid = it->str(); }

    std::string puuid = first_uuid;
    if (puuid.empty()) puuid = PuuidFromJwt(jwt);
    std::string ext_sid = ResolveNonEmptySid(jwt, last_uuid, puuid, "[PIPE]");
    uint32_t vpid = g_valorant_pid;
    Log("[PIPE] puuid=" + puuid.substr(0, 8) + " sid=" + ext_sid.substr(0, 8) + " pid=" + std::to_string(vpid));

    {
        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
        if (jwt == g_cached_jwt && ext_sid == g_cached_ext_sid) {
            return;
        }
        g_cached_jwt     = jwt;
        g_cached_ext_sid = ext_sid;
        g_cached_sid     = ext_sid;
        g_cached_puuid   = puuid;
    }

    Log("[PIPE] NEW AUTH_TOKEN captured (length: " + std::to_string(jwt.size()) + ")");
    QueuePendingGatewayRequest(jwt, ext_sid, puuid, vpid);
    if (g_gateway_auto_send.load()) {
        Log("[PIPE] token saved -- auto gateway send enabled");
        std::thread([jwt, ext_sid, puuid, vpid]() {
            SendViaLocalServer(jwt, ext_sid, puuid, vpid);
        }).detach();
    } else {
        Log("[PIPE] token captured -- press F1 for gateway send");
    }
}

uint32_t PipeReadU32(const uint8_t* p) {
    uint32_t v = 0;
    memcpy(&v, p, sizeof(v));
    return v;
}

void PipeWriteU32(std::vector<uint8_t>& v, size_t off, uint32_t value) {
    if (v.size() >= off + sizeof(value)) memcpy(v.data() + off, &value, sizeof(value));
}

void PipeWriteU64(std::vector<uint8_t>& v, size_t off, uint64_t value) {
    if (v.size() >= off + sizeof(value)) memcpy(v.data() + off, &value, sizeof(value));
}

bool PipeWriteAndFlush(HANDLE pipe, const std::vector<uint8_t>& data, const std::string& tag) {
    if (data.empty()) {
        Log(tag + " skipped empty write");
        return false;
    }
    DWORD bw = 0;
    BOOL ok = WriteFile(pipe, data.data(), (DWORD)data.size(), &bw, nullptr);
    if (ok) FlushFileBuffers(pipe);
    Log(tag + " written=" + std::to_string(bw) + "/" + std::to_string(data.size()) +
        (ok ? "" : " err=" + std::to_string(GetLastError())));
    return ok && bw == data.size();
}

int PipeCompatNextMagic(int magic) {
    static std::mutex magic_mtx;
    static int step = -1;
    std::lock_guard<std::mutex> lk(magic_mtx);
    step = (step + 1) % 5;
    if (step == 0) return magic + 1;
    if (step == 1) return magic + 3;
    if (step == 2) return magic - 1;
    if (step == 3) return magic + 2;
    return magic + 5;
}

std::string PipeExtractFirstUuid(const uint8_t* data, size_t n) {
    std::string ascii((const char*)data, (const char*)data + n);
    static const std::regex uuid_re(R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
    std::smatch m;
    if (std::regex_search(ascii, m, uuid_re)) return m[0].str();
    return "";
}

bool PipeParseUuidBytes(const std::string& uuid, uint8_t out[16]) {
    if (uuid.size() != 36) return false;
    auto hexval = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    uint8_t raw[16]{};
    int ri = 0;
    for (size_t i = 0; i < uuid.size();) {
        if (uuid[i] == '-') {
            ++i;
            continue;
        }
        if (i + 1 >= uuid.size() || ri >= 16) return false;
        int hi = hexval(uuid[i]);
        int lo = hexval(uuid[i + 1]);
        if (hi < 0 || lo < 0) return false;
        raw[ri++] = (uint8_t)((hi << 4) | lo);
        i += 2;
    }
    if (ri != 16) return false;

    out[0] = raw[3]; out[1] = raw[2]; out[2] = raw[1]; out[3] = raw[0];
    out[4] = raw[5]; out[5] = raw[4];
    out[6] = raw[7]; out[7] = raw[6];
    memcpy(out + 8, raw + 8, 8);
    return true;
}

std::vector<uint8_t> PipeBuildCompatAuthAck(int magic, const std::string& uuid) {
    std::vector<uint8_t> ack(0x3c, 0);
    PipeWriteU32(ack, 0, (uint32_t)(magic + 1));
    PipeWriteU32(ack, 4, 0x40);
    PipeWriteU32(ack, 8, 1);
    PipeWriteU32(ack, 0x18, 0x18);

    uint8_t guid[16]{};
    if (PipeParseUuidBytes(uuid, guid)) {
        memcpy(ack.data() + 0x24, guid, sizeof(guid));
    }
    else {
        Log("[PIPE][COMPAT] auth ack uuid parse failed, GUID left zero uuid=" + uuid);
    }

    uint64_t timestamp = (uint64_t)std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    PipeWriteU64(ack, 0x34, timestamp);
    return ack;
}

bool SendPipeDisconnectMessage(HANDLE pipe, const std::string& reason) {
    if (!pipe || pipe == INVALID_HANDLE_VALUE) {
        Log("[PIPE][DISCONNECT] skipped: invalid pipe reason=" + reason);
        return false;
    }

    std::vector<uint8_t> payload(36, 0);
    payload[0] = 0x02;
    payload[4] = 0x24;
    payload[8] = 0x01;
    PipeWriteU32(payload, 24, 0x539);

    Log("[PIPE][DISCONNECT] sending 36-byte payload reason=" + reason);
    return PipeWriteAndFlush(pipe, payload, "[PIPE][DISCONNECT] payload");
}

bool SendDisconnectMessageToCurrentPipe(const std::string& reason) {
    HANDLE pipe = (HANDLE)g_current_pipe.load();
    return SendPipeDisconnectMessage(pipe, reason);
}

void HandlePipeClient(HANDLE pipe) {
    std::vector<uint8_t> buf(16384); DWORD bytesRead; int hb_count = 0; int packet_count = 0;
    g_current_pipe.store((void*)pipe);
    Log("[PIPE] current pipe handle registered");

    {
        std::vector<uint8_t> challenge(36, 0);
        PipeWriteU64(challenge, 0, 0x24000003e9ULL); 
        PipeWriteU64(challenge, 8, 1);
        PipeWriteU32(challenge, 24, 4);
        PipeWriteAndFlush(pipe, challenge, "[PIPE] initial 36-byte challenge handshake");
    }

    while (!g_shutdown.load()) {
        if (!ReadFile(pipe, buf.data(), (DWORD)buf.size(), &bytesRead, nullptr) || bytesRead == 0) break;
        packet_count++;
        Log("[PIPE] packet#" + std::to_string(packet_count) + " " + std::to_string(bytesRead) + " bytes (0x" + [&] {std::ostringstream o; o << std::hex << (int)buf[0]; return o.str(); }() + ")");

        if (bytesRead == 40 && buf[0] == 0x03) {
            std::vector<uint8_t> resp(buf.data(), buf.data() + 40); resp[0] = 0x04;
            PipeWriteAndFlush(pipe, resp, "[PIPE][HB] vgk ping ack #" + std::to_string(++hb_count));
            {
                std::lock_guard<std::mutex> lk(g_session_mgr.mtx);
                for (auto& kv : g_session_mgr.sessions) kv.second->last_activity = NowSec();
            }
            continue;
        }

        if (buf[0] == 0x64) {
            std::ostringstream rawHex;
            DWORD logLen = bytesRead < 16 ? bytesRead : 16;
            for (DWORD i = 0; i < logLen; i++)
                rawHex << std::hex << std::setw(2) << std::setfill('0') << (int)buf[i] << " ";
            Log("[PIPE][0x64] AUTH_REQUEST bytes=" + std::to_string(bytesRead) + " raw=" + rawHex.str());

            if (bytesRead > 40) {
                Log("[PIPE][0x64] scanning for JWT inside auth request...");
                TryExtractAndSend(buf.data(), bytesRead);
            }

            std::string jwt, puuid, sid, region;
            {
                std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
                jwt    = g_cached_jwt;
                puuid  = g_cached_puuid;
                sid    = g_cached_sid;
                region = g_cached_region;
            }

            if (jwt.empty()) {
                Log("[PIPE][0x64] JWT not yet available, waiting 2s...");
                Sleep(2000);
                std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
                jwt    = g_cached_jwt;
                puuid  = g_cached_puuid;
                sid    = g_cached_sid;
                region = g_cached_region;
            }

            region = ApplyConfiguredRegion(region, "[PIPE][0x64]");
            Log("[PIPE][0x64] jwt=" + (jwt.empty() ? "EMPTY" : jwt.substr(0,20)+"...") + " puuid=" + (puuid.empty() ? "EMPTY" : puuid.substr(0,8)+"..."));

            auto pkt  = std::vector<uint8_t>(buf.data(), buf.data() + bytesRead);
            auto resp = g_tasks_handler.handle_auth_request(jwt, puuid, sid, region);
            
            if (!jwt.empty()) {
                std::thread([]() { g_round_tracker.on_round_end(); }).detach();
            }
            PipeWriteAndFlush(pipe, resp, "[PIPE][0x64] AUTH_REQUEST response");
            Log("[PIPE] AUTH_REQUEST (0x64) handled, response sent");
            continue;
        }

        if (bytesRead >= 36) {
            const int compat_type = (int)PipeReadU32(buf.data() + 8);
            if (compat_type == 1 || compat_type == 2 || compat_type == 4 || compat_type == 5 || compat_type == 6) {
                const int magic = (int)PipeReadU32(buf.data());
                std::vector<uint8_t> reply;
                bool inject_type_9 = false;

                Log("[PIPE][COMPAT] struct type=" + std::to_string(compat_type) +
                    " magic=0x" + [&] { std::ostringstream o; o << std::hex << magic; return o.str(); }() +
                    " bytes=" + std::to_string(bytesRead));

                if (compat_type == 6) {
                    reply = { 8, 9, 18, 0 };
                    Log("[PIPE][COMPAT] type 6 task ACK shape selected");
                }
                else if (compat_type == 5) {
                    reply.assign(56, 0);
                    const int reply_magic = PipeCompatNextMagic(magic);
                    PipeWriteU32(reply, 0, (uint32_t)reply_magic);
                    PipeWriteU32(reply, 4, 56);
                    PipeWriteU32(reply, 8, 1);
                    PipeWriteU32(reply, 24, 16);
                    Log("[PIPE][COMPAT] type 5 modules ACK magic=0x" +
                        [&] { std::ostringstream o; o << std::hex << reply_magic; return o.str(); }());
                }
                else if (compat_type == 4) {
                    if (bytesRead > 100) {
                        Log("[PIPE][COMPAT] type 4 scanning for JWT/SID");
                        TryExtractAndSend(buf.data(), bytesRead);
                    }

                    std::string active_uuid = PipeExtractFirstUuid(buf.data(), bytesRead);
                    if (active_uuid.empty()) {
                        std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
                        active_uuid = !g_cached_sid.empty() ? g_cached_sid : g_cached_puuid;
                    }
                    if (active_uuid.empty()) active_uuid = "00000000-0000-0000-0000-000000000000";

                    reply = PipeBuildCompatAuthAck(magic, active_uuid);
                    inject_type_9 = true;
                    Log("[PIPE][COMPAT] type 4 auth ACK uuid=" + active_uuid +
                        " reply_magic=0x" + [&] { std::ostringstream o; o << std::hex << (magic + 1); return o.str(); }());
                }
                else if (compat_type == 1) {
                    reply.assign(buf.data(), buf.data() + bytesRead);
                    const int reply_magic = PipeCompatNextMagic(magic);
                    PipeWriteU32(reply, 0, (uint32_t)reply_magic);
                    Log("[PIPE][COMPAT] type 1 echo ACK magic=0x" +
                        [&] { std::ostringstream o; o << std::hex << reply_magic; return o.str(); }());
                }
                else if (compat_type == 2) {
                    reply.assign(48, 0);
                    const int reply_magic = PipeCompatNextMagic(magic);
                    PipeWriteU32(reply, 0, (uint32_t)reply_magic);
                    PipeWriteU32(reply, 4, 48);
                    PipeWriteU32(reply, 8, 1);
                    PipeWriteU32(reply, 24, 8);
                    Log("[PIPE][COMPAT] type 2 ACK magic=0x" +
                        [&] { std::ostringstream o; o << std::hex << reply_magic; return o.str(); }());
                }

                PipeWriteAndFlush(pipe, reply, "[PIPE][COMPAT] type " + std::to_string(compat_type) + " reply");

                if (inject_type_9) {
                    Sleep(200);
                    std::vector<uint8_t> injected(40, 0);
                    const int injected_magic = PipeCompatNextMagic(magic);
                    PipeWriteU32(injected, 0, (uint32_t)injected_magic);
                    PipeWriteU32(injected, 4, 40);
                    PipeWriteU32(injected, 8, 9);
                    PipeWriteAndFlush(pipe, injected, "[PIPE][COMPAT] injected type 9 session-auth");
                }
                continue;
            }
        }

        if (buf[0] == 0x65 && bytesRead >= 4) {
            auto pkt  = std::vector<uint8_t>(buf.data(), buf.data() + bytesRead);
            auto ack  = g_tasks_handler.handle_packet(pkt);
            PipeWriteAndFlush(pipe, ack, "[PIPE][0x65] TASKS ACK");
            Log("[PIPE] TASKS packet (0x65) acked");
            
            if (bytesRead > 100) {
                Log("[PIPE][0x65] scanning for JWT inside tasks packet...");
                std::string old_jwt;
                {
                    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
                    old_jwt = g_cached_jwt;
                }
                TryExtractAndSend(buf.data(), bytesRead);
                
                std::string new_jwt;
                {
                    std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
                    new_jwt = g_cached_jwt;
                }
                if (!new_jwt.empty() && new_jwt != old_jwt && !old_jwt.empty()) {
                    Log("[LOBBY] JWT changed â€” previous match ended, new match starting");
                    Log("[LOBBY] Triggering gateway re-auth for new match");
                    g_gw_reauth_needed.store(true);
                    g_gateway_reauth_remaining_sec.store(0);
                    UpdateConsoleTitle();
                }
            }
            continue;
        }

        if (buf[0] == 0x66 && bytesRead >= 4) {
            auto pkt = std::vector<uint8_t>(buf.data(), buf.data() + bytesRead);
            auto ack = g_tasks_handler.handle_packet(pkt);
            PipeWriteAndFlush(pipe, ack, "[PIPE][0x66] MODULES ACK");
            Log("[PIPE] MODULES packet (0x66) acked");
            continue;
        }

        if (buf[0] == 0x67 && bytesRead >= 8) {
            std::vector<uint8_t> payload(buf.data(), buf.data() + bytesRead);
            {
                std::lock_guard<std::mutex> lk(g_vgk_payload_mtx);
                g_vgk_payload = payload;
            }
            Log("[PIPE] vgk payload captured " + std::to_string(bytesRead) + "B");
            if (bytesRead >= 4) {
                uint32_t magic; memcpy(&magic, buf.data(), 4); uint32_t nm = magic + 1;
                std::vector<uint8_t> echo(buf.data(), buf.data() + bytesRead);
                memcpy(echo.data(), &nm, 4);
                PipeWriteAndFlush(pipe, echo, "[PIPE][0x67] echo");
            }
            continue;
        }

        if (buf[0] == 0x68 && bytesRead == 68) {
            std::vector<uint8_t> echo(buf.data(), buf.data() + bytesRead);
            PipeWriteAndFlush(pipe, echo, "[PIPE][0x68] 68-byte raw echo");
            continue;
        }

        if (bytesRead > 100) { Log("[PIPE] Scanning..."); TryExtractAndSend(buf.data(), bytesRead); }
        if (bytesRead >= 4) {
            uint32_t magic; memcpy(&magic, buf.data(), 4); uint32_t nm = magic + 1;
            std::vector<uint8_t> echo(buf.data(), buf.data() + bytesRead);
            memcpy(echo.data(), &nm, 4);
            PipeWriteAndFlush(pipe, echo, "[PIPE] default echo");
        }
    }
    SendPipeDisconnectMessage(pipe, "pipe thread ending");
    void* expected_pipe = (void*)pipe;
    g_current_pipe.compare_exchange_strong(expected_pipe, nullptr);
    CloseHandle(pipe); Log("[PIPE] Client disconnected");
    
    g_round_tracker.on_lobby_return([&]() {
        std::string jwt, puuid, sid, region;
        {
            std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
            jwt = g_cached_jwt; puuid = g_cached_puuid;
            sid = g_cached_sid; region = g_cached_region;
        }
        if (!jwt.empty()) {
            Log("[ROUND] Lobby return detected â€” triggering gateway re-auth immediately");
            g_gw_reauth_needed.store(true);
            g_gateway_reauth_remaining_sec.store(0);
            UpdateConsoleTitle();
        }
    });
}

void PipeServerLoop() {
    while (!g_shutdown.load()) {
        HANDLE pipe = CreateNamedPipeW(PIPE_NAME, PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES, 1048576, 1048576, 500, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) { Sleep(1000); continue; }
        Log(("[PIPE] Waiting for client..."));
        if (ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) {
            Log("[PIPE] Client connected");
            std::thread(HandlePipeClient, pipe).detach();
        }
        else { CloseHandle(pipe); }
    }
}

uint32_t GetValorantPID() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe); uint32_t pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do { if (_wcsicmp(pe.szExeFile, L"VALORANT-Win64-Shipping.exe") == 0) { pid = pe.th32ProcessID; break; } } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap); return pid;
}

BOOL WINAPI CtrlHandler(DWORD t) {
    if (t == CTRL_CLOSE_EVENT || t == CTRL_C_EVENT || t == CTRL_BREAK_EVENT || t == CTRL_SHUTDOWN_EVENT) {
        SendDisconnectMessageToCurrentPipe("console control event " + std::to_string((int)t));
    }
    return TRUE;
}
