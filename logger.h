#pragma once

#include "config.h"

extern std::mutex    g_log_mtx;
extern std::ofstream g_log_file;
extern std::mutex    g_ui_log_mtx;
extern std::deque<std::string> g_ui_log_lines;

extern std::vector<std::string> g_log_lines;
extern std::mutex g_log_mutex;

void PushUiLogLine(const std::string& line);
void Log(const std::string& msg);
std::string GetTimestamp();
void AddFunnyLog(const std::string& msg);
