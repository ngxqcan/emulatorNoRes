#pragma once

#include "config.h"

#define COL_CYAN   (FOREGROUND_BLUE|FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define COL_WHITE  (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE|FOREGROUND_INTENSITY)
#define COL_YELLOW (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define COL_GREEN  (FOREGROUND_GREEN|FOREGROUND_INTENSITY)
#define COL_RED    (FOREGROUND_RED|FOREGROUND_INTENSITY)
#define COL_GRAY   (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_BLUE)
#define COL_ORANGE (FOREGROUND_RED|FOREGROUND_GREEN|FOREGROUND_INTENSITY)  
#define COL_DIM    (FOREGROUND_BLUE|FOREGROUND_INTENSITY)

struct ActiveSessionInfo {
    std::string puuid;
    std::string region;
    std::string account;
    std::chrono::steady_clock::time_point start_time;
    bool active = false;
};

struct ValorantWindowCtx { DWORD pid; int pct; };

extern ActiveSessionInfo g_active_session;
extern std::mutex g_display_mtx;
extern std::atomic_bool g_display_running;

void UpdateDisplaySessionState(const std::string& puuid, const std::string& region, const std::string& account);
void ClearConsole();
void ResizeConsoleWindowTall();
void SetColor(WORD attr);
std::string ShortValue(const std::string& value, size_t keep = 8);
std::string UpperAscii(std::string value);
std::string FormatClock(int total_seconds);
void DrawHorizontalRule(char ch = '=');
void DrawHorizontalRuleColored(char ch, WORD color);
void DrawField(const char* label, const std::string& value, WORD value_color = COL_WHITE);
void DisplayLoop();
void UpdateConsoleTitle();
void ResetGatewayReauthTimer();
void GatewayHotkeyLoop();
int GetValorantLoadingPct();
