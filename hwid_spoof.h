#pragma once

#include "config.h"

struct RandomizedHardwareProfile {
    char cpu_brand[32];
    char cpu_model[128];
    uint32_t cpu_cores;
    char gpu_brand[32];
    char gpu_model[128];
    char bios_vendor[64];
    char bios_version[32];
    char mobo_model[64];
    char volume_serial[12];
    char machine_guid[40];
    char hostname[32];
    char os_version[20];
};

struct VgcMachineEntry {
    std::string machine_id;
    std::string ht;
};

std::string RegReadStr(HKEY root, const wchar_t* sub, const wchar_t* val);
std::vector<uint8_t> GetRealHwid();
std::wstring GetHwidProfilePath();
bool SaveHwidProfile(const RandomizedHardwareProfile& p);
bool LoadHwidProfile(RandomizedHardwareProfile& p);
const RandomizedHardwareProfile& GetRandomizedHardwareProfile();
std::vector<uint8_t> GetRandomHwid();
std::string BytesToHexString(const std::vector<uint8_t>& bytes);
std::vector<uint8_t> GetConfiguredHwid();
std::string GetCachedHwPart6();
std::wstring GetOutputTxtPath();
bool LoadMachinePool();
std::wstring GetExeDirFile(const wchar_t* filename);
std::wstring MakeLockFilePath(size_t idx);
void WriteLockFile(size_t idx);
size_t FindExistingLockFile(size_t pool_size);
void EnsureMachineSelected();
std::string GetConfiguredGatewayMachineId();
std::string GetStableHt();
std::string GetFakeHostname();
void GetCpuInfo(std::string& brand, std::string& model, uint32_t& cores);
void GetGpuInfo(std::string& brand, std::string& model);
