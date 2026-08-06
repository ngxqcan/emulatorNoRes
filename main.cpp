#include "config.h"
#include "logger.h"
#include "protocol_utils.h"
#include "hwid_spoof.h"
#include "tls_socket.h"
#include "vgk_manager.h"
#include "pipe_server.h"
#include "console_ui.h"
#include "gui_app.h"

void CreateVanguardMutex() {
    if (g_vanguard_mutex == nullptr) {
        g_vanguard_mutex = CreateMutexA(NULL, FALSE, "Global\\587203BC-5798-47BA-8BDA-C63D7DE25FCD");
        if (g_vanguard_mutex != nullptr) {
            Log("Created simulated Vanguard mutex.");
        }
    }
}

void CreateVanguardSharedMemory() {
    if (g_vanguard_shared_memory == nullptr) {
        g_vanguard_shared_memory = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 0x1000, "Global\\294E088E-E3EF-42A9-AE0C-1EF642412F95");
        if (g_vanguard_shared_memory == nullptr) {
            Log("Failed to create simulated Vanguard shared memory.");
        }
        else {
            Log("Created simulated Vanguard shared memory (FileMapping).");
        }
    }
}

int MainCMDUI(int argc, char* argv[]) {
    HWND hConsole = GetConsoleWindow();
    if (hConsole) ShowWindow(hConsole, SW_HIDE);

    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    {
        char exePath[MAX_PATH] = {};
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string logPath(exePath);
        auto slash = logPath.find_last_of("\\/");
        if (slash != std::string::npos) logPath = logPath.substr(0, slash + 1);
        logPath += "gay.log";
        std::lock_guard<std::mutex> lk(g_log_mtx);
        g_log_file.open(logPath, std::ios::out | std::ios::trunc);
    }
    Log("=== TECHNO VERSE START ===");
    Log("Build: " __DATE__ " " __TIME__);

    g_gateway_auto_send.store(true);
    Log("[CFG] Gateway mode selected: automated refresh");

    g_session_mgr.on_session_created = [](const std::string& sid, const std::string& puuid,
        const std::string& region, const std::string& account) {
            std::lock_guard<std::mutex> lk(g_display_mtx);
            g_active_session.puuid = puuid;
            g_active_session.region = region;
            g_active_session.account = account;
            g_active_session.start_time = std::chrono::steady_clock::now();
            g_active_session.active = true;
        };
    g_session_mgr.on_session_destroyed = [](const std::string&) {
        std::lock_guard<std::mutex> lk(g_display_mtx);
        g_active_session.active = false;
        g_active_session.puuid = "";
        g_active_session.region = "";
        };

    g_server_running = true;
    std::thread([]() { RunServer(); }).detach();
    Sleep(300);

    system("sc stop vgc >nul 2>&1");
    Sleep(300);
    system("sc start vgc >nul 2>&1");
    Sleep(500);

    HANDLE h = CreateFileW(PIPE_NAME, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); }

    std::thread(PipeServerLoop).detach();
    std::thread(GatewayHotkeyLoop).detach();

    CreateVanguardMutex();
    CreateVanguardSharedMemory();

    // Launch background thread to monitor Valorant process
    std::thread([]() {
        while (!g_shutdown.load()) {
            g_valorant_pid = GetValorantPID();
            if (g_valorant_pid) { 
                g_valorant_pid_fwd = g_valorant_pid; 
                break; 
            }
            Sleep(500);
        }

        bool disconnect_sent_after_valorant_exit = false;
        while (!g_shutdown.load()) {
            Sleep(500);
            uint32_t current_val_pid = GetValorantPID();
            if (current_val_pid == 0 && g_valorant_pid != 0 && !disconnect_sent_after_valorant_exit) {
                Log("[PIPE][DISCONNECT] Valorant process ended, notifying pipe");
                SendDisconnectMessageToCurrentPipe("valorant process ended");
                disconnect_sent_after_valorant_exit = true;
            }
            if (current_val_pid != 0 && current_val_pid != g_valorant_pid) {
                g_valorant_pid = current_val_pid;
                g_valorant_pid_fwd = current_val_pid;
                disconnect_sent_after_valorant_exit = false;
            }
        }
    }).detach();

    // Launch ImGui Win32 DX11 GUI Application
    return RunGuiApp(GetModuleHandle(nullptr), SW_SHOWDEFAULT);
}

int main(int argc, char* argv[]) {
    return MainCMDUI(argc, argv);
}

int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    return MainCMDUI(0, nullptr);
}
