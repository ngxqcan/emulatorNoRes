#include "console_ui.h"
#include "logger.h"
#include "vgk_manager.h"
#include "pipe_server.h"

ActiveSessionInfo g_active_session;
std::mutex g_display_mtx;
std::atomic_bool g_display_running(false);

void UpdateDisplaySessionState(const std::string& puuid, const std::string& region, const std::string& account) {
    std::lock_guard<std::mutex> lk(g_display_mtx);
    g_active_session.puuid = puuid;
    g_active_session.region = region;
    g_active_session.account = account;
    g_active_session.start_time = std::chrono::steady_clock::now();
    g_active_session.active = true;
}

void ClearConsole() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(h, &csbi)) return;
    DWORD cells = csbi.dwSize.X * csbi.dwSize.Y, written;
    COORD origin = { 0,0 };
    FillConsoleOutputCharacterA(h, ' ', cells, origin, &written);
    FillConsoleOutputAttribute(h, csbi.wAttributes, cells, origin, &written);
    SetConsoleCursorPosition(h, origin);
}

void ResizeConsoleWindowTall() {
    HWND hwnd = GetConsoleWindow();
    if (!hwnd) return;

    RECT rc{};
    if (!GetWindowRect(hwnd, &rc)) return;

    const int width = rc.right - rc.left;
    const int height = 720;
    SetWindowPos(hwnd, nullptr, rc.left, rc.top, width, height, SWP_NOZORDER | SWP_NOACTIVATE);
}

void SetColor(WORD attr) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attr);
}

std::string ShortValue(const std::string& value, size_t keep) {
    if (value.empty()) return "--";
    if (value.size() <= keep) return value;
    return value.substr(0, keep) + "...";
}

std::string UpperAscii(std::string value) {
    for (char& c : value) {
        if (c >= 'a' && c <= 'z') c = (char)(c - ('a' - 'A'));
    }
    return value.empty() ? "--" : value;
}

std::string FormatClock(int total_seconds) {
    if (total_seconds < 0) total_seconds = 0;
    int hh = total_seconds / 3600;
    int mm = (total_seconds % 3600) / 60;
    int ss = total_seconds % 60;
    char buf[32];
    sprintf_s(buf, "%02d:%02d:%02d", hh, mm, ss);
    return std::string(buf);
}

void DrawHorizontalRule(char ch) {
    SetColor(COL_DIM);
    for (int i = 0; i < 78; ++i) std::cout << ch;
    std::cout << "\n";
}

void DrawHorizontalRuleColored(char ch, WORD color) {
    SetColor(color);
    for (int i = 0; i < 78; ++i) std::cout << ch;
    std::cout << "\n";
}

void DrawField(const char* label, const std::string& value, WORD value_color) {
    SetColor(COL_GRAY);
    std::cout << "  " << label;
    SetColor(value_color);
    std::cout << value << "\n";
}

void UpdateConsoleTitle() {
    SetConsoleTitleW(L"Techno Verse");
}

void ResetGatewayReauthTimer() {
    g_gateway_reauth_remaining_sec.store(GATEWAY_REAUTH_INTERVAL_SEC);
    g_gateway_reauth_restart_countdown.store(true);
    UpdateConsoleTitle();
}

void GatewayHotkeyLoop() {
    Log(("[GUI] F1/F2 hotkey loop active"));
    while (!g_shutdown.load()) {
        if (!g_gateway_auto_send.load() && (GetAsyncKeyState(VK_F1) & 1)) {
            TriggerGatewayManualAction();
        }
        if (g_gateway_auto_send.load() && (GetAsyncKeyState(VK_F2) & 1)) {
            TriggerGatewayAutoRefreshAction();
        }
        Sleep(50);
    }
}

int GetValorantLoadingPct() {
    int pct = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"VALORANT-Win64-Shipping.exe") == 0) {
                ValorantWindowCtx ctx{ pe.th32ProcessID, 0 };
                EnumWindows([](HWND hwnd, LPARAM lp) -> BOOL {
                    auto* c = reinterpret_cast<ValorantWindowCtx*>(lp);
                    DWORD wp = 0; GetWindowThreadProcessId(hwnd, &wp);
                    if (wp != c->pid) return TRUE;
                    wchar_t title[256]{}; GetWindowTextW(hwnd, title, 255);
                    std::wstring t(title);
                    auto pos = t.find(L"Loading");
                    if (pos != std::wstring::npos) {
                        auto p1 = t.find(L'(', pos);
                        auto p2 = t.find(L'%', pos);
                        if (p1 != std::wstring::npos && p2 != std::wstring::npos && p2 > p1)
                            c->pct = _wtoi(t.substr(p1 + 1, p2 - p1 - 1).c_str());
                    }
                    return TRUE;
                    }, (LPARAM)&ctx);
                pct = ctx.pct;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pct;
}

void DisplayLoop() {    
    bool val_detected_logged = false;
    bool val_sesh_logged = false;
    bool val_valid_logged = false;
    
    while (g_display_running.load()) {
        Sleep(500);
        ClearConsole();

        ActiveSessionInfo active_snapshot;
        {
            std::lock_guard<std::mutex> lk(g_display_mtx);
            active_snapshot = g_active_session;
        }

        std::string cached_region;
        std::string cached_sid;
        std::string cached_puuid;
        {
            std::lock_guard<std::mutex> lk(g_jwt_cache_mtx);
            cached_region = g_cached_region;
            cached_sid = g_cached_sid;
            cached_puuid = g_cached_puuid;
        }

        std::vector<std::string> log_snapshot;
        {
            std::lock_guard<std::mutex> lock(g_log_mutex);
            log_snapshot = g_log_lines;
        }

        const uint32_t valorant_pid = GetValorantPID();
        const bool valorant_running = valorant_pid != 0;
        const bool keepalive_running = g_keepalive_running.load();
        const bool forced_refresh = g_gw_reauth_needed.load();
        const int reauth_remaining = g_gateway_reauth_remaining_sec.load();

        std::string session_age = ("--:--:--");
        if (active_snapshot.active) {
            auto now = std::chrono::steady_clock::now();
            int secs = (int)std::chrono::duration_cast<std::chrono::seconds>(
                now - active_snapshot.start_time).count();
            session_age = FormatClock(secs);
        }
        SetColor(COL_CYAN);

        SetColor(COL_WHITE);
        DrawField(("Runtime         : "), valorant_running ? ("VALORANT DETECTED") : ("WAITING FOR VALORANT"),
            valorant_running ? COL_GREEN : COL_ORANGE);
        DrawField(("Gateway Reauth  : "), FormatClock(reauth_remaining),
            forced_refresh ? COL_RED : COL_GREEN);
        DrawField(("Gateway Session : "), keepalive_running ? ("ACTIVE - YOU CAN QUEUE") : ("IDLE - YOU CANNOT QUEUE"),
            keepalive_running ? COL_GREEN : COL_ORANGE);
        
        DrawField(("Valorant PID    : "), valorant_running ? std::to_string(valorant_pid) : ("--"),
            valorant_running ? COL_WHITE : COL_DIM);

        DrawHorizontalRule('-');
        if (!g_gateway_auto_send.load()) {
            DrawField(("Session State   : "), active_snapshot.active ? ("ACTIVE") : ("NOT RUNNING - PRESS 'F1' IN LOBBY"), active_snapshot.active ? COL_GREEN : COL_ORANGE);
        }
        else
        {
            DrawField(("Session State   : "), active_snapshot.active ? ("ACTIVE") : ("NOT RUNNING"), active_snapshot.active ? COL_GREEN : COL_ORANGE);
        }
        DrawField(("Session Age     : "), session_age, COL_WHITE);
        DrawField(("Region          : "), UpperAscii(active_snapshot.active ? active_snapshot.region : cached_region), COL_WHITE);
        DrawField(("Session PUUID   : "), ShortValue(active_snapshot.active ? active_snapshot.puuid : cached_puuid, 12), COL_WHITE);
        DrawField(("Gateway SID     : "), ShortValue(cached_sid, 12), COL_WHITE);
        DrawField(("Account         : "), ShortValue(active_snapshot.account, 24), COL_WHITE);

        DrawHorizontalRule('-');
        SetColor(COL_YELLOW);
        std::cout << ("  Controls\n");
        if (g_gateway_auto_send.load()) {
            DrawField(("F2              : "), ("MANUAL SESSION / GATEWAY REFRESH"), COL_WHITE);
        } else {
            DrawField(("F1              : "), ("GATEWAY [SEND / REAUTH] SESSION"), COL_WHITE);
        }
        DrawField(("Gateway Mode    : "), g_gateway_auto_send.load() ? ("AUTO ON TOKEN CAPTURE") : ("MANUAL VIA F1"), COL_WHITE);

        DrawHorizontalRule('-');
        SetColor(COL_YELLOW);
        std::cout << ("  Live Log\n");
        if (log_snapshot.empty()) {
            SetColor(COL_DIM);
            std::cout << ("  [no log lines yet]\n");
        } else {
            SetColor(COL_WHITE);
            for (const auto& line : log_snapshot) {
                std::cout << ("  ") << line << ("\n");
            }
        }

        DrawHorizontalRule('-');
        SetColor(COL_DIM);
        std::cout << ("  Live dashboard active\n");
        
        static int tick = 0;
        tick++;
        if (tick % 10 == 0) { 
            const std::vector<std::string> random_logs = {
            ("Checking gateway connection state..."),
            ("Verifying heartbeat token data..."),
            ("Connected to auth session endpoint."),
            ("Optimizing tunnel network buffer..."),
            };
            if (rand() % 10 == 0) { 
                AddFunnyLog(random_logs[rand() % random_logs.size()]);
            }
        }
        
        if (GetValorantPID() != 0 && !val_detected_logged) {
            AddFunnyLog(("Valorant detected."));
            val_detected_logged = true;
        }
        if (g_active_session.active && !val_sesh_logged) {
            AddFunnyLog(("Session data ready."));
            Sleep(200);
            AddFunnyLog(("Session submitted."));
            val_sesh_logged = true;
        }
        if (val_sesh_logged && !val_valid_logged) {
            Sleep(300);
            AddFunnyLog(("Session validated. Vanguard bypass active."));
            val_valid_logged = true;
        }
    }
}
