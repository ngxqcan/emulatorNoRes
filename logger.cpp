#include "logger.h"

std::mutex    g_log_mtx;
std::ofstream g_log_file;
std::mutex    g_ui_log_mtx;
std::deque<std::string> g_ui_log_lines;

std::vector<std::string> g_log_lines;
std::mutex g_log_mutex;

void PushUiLogLine(const std::string& line) {
    std::lock_guard<std::mutex> lk(g_ui_log_mtx);
    g_ui_log_lines.push_back(line);
    while (g_ui_log_lines.size() > 300) {
        g_ui_log_lines.pop_front();
    }
    
    {
        std::lock_guard<std::mutex> lk2(g_log_mutex);
        g_log_lines.push_back(line);
        while (g_log_lines.size() > 20)
            g_log_lines.erase(g_log_lines.begin());
    }
}

void Log(const std::string& msg) {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::tm bt{}; localtime_s(&bt, &t);
    std::ostringstream ss;
    ss << "[" << std::put_time(&bt, "%H:%M:%S")
        << "." << std::setfill('0') << std::setw(3) << ms.count()
        << "] " << msg;
    PushUiLogLine(ss.str());
    std::lock_guard<std::mutex> lk(g_log_mtx);
    if (g_log_file.is_open()) { g_log_file << ss.str() << "\n"; g_log_file.flush(); }
}

std::string GetTimestamp() {
    auto now = std::chrono::system_clock::now();
    auto time_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::tm bt{}; localtime_s(&bt, &time_now);
    char buf[64];
    sprintf_s(buf, "%02d:%02d:%02d.%03d", bt.tm_hour, bt.tm_min, bt.tm_sec, (int)ms.count());
    return std::string(buf);
}

void AddFunnyLog(const std::string& msg) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    g_log_lines.push_back(("[") + GetTimestamp() + ("] ") + msg);
    
    if (g_log_lines.size() > 20) {
        g_log_lines.erase(g_log_lines.begin());
    }
}
