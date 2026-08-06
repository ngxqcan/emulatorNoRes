#pragma once

#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <Shlwapi.h>
#include <bcrypt.h>
#include <sspi.h>
#include <schannel.h>
#include "vanguard_gateaway.h"  
#include <winsock2.h>
#include <ws2tcpip.h>
#include <winhttp.h>
#include <wincrypt.h>
#include <TlHelp32.h>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "Advapi32.lib")

#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <deque>
#include <functional>
#include <condition_variable>
#include <optional>

// Global variables
extern bool authenticatedsession;
extern HANDLE g_vanguard_mutex;
extern HANDLE g_vanguard_shared_memory;

// Constants
constexpr bool          RandomizedVersion = true;
constexpr uint16_t      SERVER_PORT = 51820;
constexpr bool          TLS_SKIP_VERIFY = true;
constexpr int           IDLE_TIMEOUT_SEC = 0;      
constexpr int           HB_INTERVAL_MS = 25000;    
constexpr int           VAN84_THRESH_SEC = 1800;   
constexpr int           MAX_CLIENTS = 32;
constexpr int           SESSION_KEEPALIVE_BOOST = 600;
constexpr int           EMERGENCY_HB_MS = 12000;   
constexpr int           MAX_HB_BURST = 3;
constexpr int           GATEWAY_REAUTH_INTERVAL_SEC = 45 * 60;

constexpr const char* SERVER_HOST = "";
constexpr const char* AUTH_KEY = "";
constexpr const wchar_t* GW_PATH = L"/vanguard/v1/gateway";
constexpr INTERNET_PORT  GW_PORT = 8443;
constexpr const wchar_t* VGC_UA = L"vanguard/1.18.4-29+20260714.000000";
constexpr const wchar_t* PIPE_NAME = L"\\\\.\\pipe\\933823D3-C77B-4BAE-89D7-A92B567236BC";

enum MsgType : uint32_t {
    MSG_HELLO = 1,
    MSG_HELLO_OK = 2,
    MSG_SYNC = 3,
    MSG_IOCTL = 4,
    MSG_IOCTL_RESP = 5,
    MSG_HB_BUFFER = 6,
    MSG_PING = 7,
    MSG_PONG = 8,
    MSG_ERROR = 9,
    MSG_JWT_UPDATE = 10,
    MSG_JWT_OK = 11,
    MSG_PIPE_AUTH = 12,
    MSG_PIPE_AUTH_OK = 13,
    MSG_SESSION_AUTH = 14,
    MSG_SESSION_AUTH_OK = 15,
    MSG_SESSION_ACCESS = 16,
    MSG_SESSION_ACCESS_OK = 17,
    MSG_SESSION_HEARTBEAT = 18,
    MSG_SESSION_HEARTBEAT_OK = 19,
    MSG_SESSION_REPORT = 20,
    MSG_SESSION_REPORT_OK = 21,
    MSG_SESSION_DISCONNECT = 22,
    MSG_SESSION_DISCONNECT_OK = 23,
    MSG_AUTH_REQUEST = 100,   
    MSG_AUTH_RESPONSE = 101,  
    MSG_TASKS_DATA = 102,     
    MSG_TASKS_ACK = 103,      
    MSG_ROUND_START = 110,    
    MSG_ROUND_END = 111,      
};

constexpr uint32_t IOCTL_VGK_HB = 0x222000;
constexpr uint32_t IOCTL_VGK_ACC = 0x22C03C;
constexpr size_t   MAX_PAYLOAD = 128 * 1024 * 1024;
