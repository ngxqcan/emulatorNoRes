#include "hwid_spoof.h"
#include "logger.h"

static std::vector<VgcMachineEntry> g_machine_pool;
static size_t g_selected_machine_idx = (size_t)-1;
static std::mutex g_machine_pool_mtx;

std::string RegReadStr(HKEY root, const wchar_t* sub, const wchar_t* val) {
    HKEY hk = nullptr;
    if (RegOpenKeyExW(root, sub, 0, KEY_READ, &hk) != ERROR_SUCCESS) return {};
    wchar_t buf[512]{}; DWORD sz = sizeof(buf);
    RegQueryValueExW(hk, val, nullptr, nullptr, (LPBYTE)buf, &sz);
    RegCloseKey(hk);
    std::string out;
    for (int i = 0; buf[i] && i < 256; i++) out += (char)(buf[i] & 0xFF);
    return out;
}

std::vector<uint8_t> GetRealHwid() {
    std::string bios_vendor = RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVendor");
    std::string bios_ver   = RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"BIOSVersion");
    std::string bios = bios_vendor.empty() ? bios_ver : (bios_vendor + " " + bios_ver);
    if (bios.empty()) bios = RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\BIOS", L"SystemProductName");
    std::string cpu = RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"ProcessorNameString");
    if (cpu.empty()) cpu = RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"Identifier");
    wchar_t sysRoot[MAX_PATH]{}; GetSystemDirectoryW(sysRoot, MAX_PATH); sysRoot[3] = L'\0';
    DWORD volSerial = 0; GetVolumeInformationW(sysRoot, nullptr, 0, &volSerial, nullptr, nullptr, nullptr, 0);
    char volBuf[16]; sprintf_s(volBuf, "%08X", volSerial);
    std::string guid = RegReadStr(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", L"MachineGuid");
    std::string composite = "BIOS:" + bios + "|CPU:" + cpu + "|VOL:" + std::string(volBuf) + "|MGUID:" + guid;
    Log("[HWID] composite: " + composite.substr(0, 80) + "...");
    std::vector<uint8_t> hash(32, 0);
    HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0; DWORD hashLen = 32;
    CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)composite.data(), (DWORD)composite.size(), 0);
    CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
    std::ostringstream hex; for (auto b : hash) hex << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    Log("[HWID] sha256=" + hex.str());
    return hash;
}

std::wstring GetHwidProfilePath() {
    wchar_t path[MAX_PATH] = {};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    wchar_t* last = wcsrchr(path, L'\\');
    if (last) *(last + 1) = L'\0';
    wcscat_s(path, L"hwid_profile.bin");
    return path;
}

bool SaveHwidProfile(const RandomizedHardwareProfile& p) {
    static const uint32_t MAGIC = 0x44495748;
    static const uint32_t VER   = 5;
    auto path = GetHwidProfilePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    WriteFile(h, &MAGIC, 4, &written, nullptr);
    WriteFile(h, &VER,   4, &written, nullptr);
    uint32_t sz = sizeof(p);
    WriteFile(h, &sz, 4, &written, nullptr);
    WriteFile(h, &p, sz, &written, nullptr);
    CloseHandle(h);
    return written == sz;
}

bool LoadHwidProfile(RandomizedHardwareProfile& p) {
    static const uint32_t MAGIC = 0x44495748;
    static const uint32_t VER   = 5;
    auto path = GetHwidProfilePath();
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    uint32_t magic = 0, ver = 0, sz = 0; DWORD read = 0;
    ReadFile(h, &magic, 4, &read, nullptr);
    ReadFile(h, &ver,   4, &read, nullptr);
    ReadFile(h, &sz,    4, &read, nullptr);
    if (magic != MAGIC || ver != VER || sz != sizeof(p)) { CloseHandle(h); return false; }
    ReadFile(h, &p, sz, &read, nullptr);
    CloseHandle(h);
    return read == sz;
}

const RandomizedHardwareProfile& GetRandomizedHardwareProfile() {
    static RandomizedHardwareProfile profile{};
    static bool initialized = false;
    if (initialized) return profile;

    struct CpuEntry { const char* brand; const char* cpuid; const char* model; uint32_t cores; int intel; };
    static const CpuEntry cpus[] = {
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i5-9400F CPU @ 2.90GHz",  6,  1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz", 12, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i7-9700K CPU @ 3.60GHz",  8,  1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz", 16, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i5-11400F CPU @ 2.60GHz", 12, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i7-11700K CPU @ 3.60GHz", 16, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i5-12400F CPU @ 2.50GHz", 12, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i7-12700K CPU @ 3.60GHz", 20, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i9-12900K CPU @ 3.20GHz", 24, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i5-13400F CPU @ 2.50GHz", 16, 1 },
        { "GenuineIntel", "Intel", "Intel(R) Core(TM) i7-13700K CPU @ 3.40GHz", 24, 1 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 5 3600 6-Core Processor",          12, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 7 3700X 8-Core Processor",         16, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 5 5600X 6-Core Processor",         12, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 7 5700X 8-Core Processor",         16, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 7 5800X 8-Core Processor",         16, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 9 5900X 12-Core Processor",        24, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 5 7600X 6-Core Processor",         12, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 7 7700X 8-Core Processor",         16, 0 },
        { "AuthenticAMD", "AMD",   "AMD Ryzen 9 7900X 12-Core Processor",        24, 0 },
    };

    struct GpuEntry { const char* brand; const char* model; };
    static const GpuEntry gpus[] = {
        { "NVIDIA", "NVIDIA GeForce GTX 1660 SUPER"   },
        { "NVIDIA", "NVIDIA GeForce GTX 1660 Ti"      },
        { "NVIDIA", "NVIDIA GeForce RTX 2060"         },
        { "NVIDIA", "NVIDIA GeForce RTX 2070 SUPER"   },
        { "NVIDIA", "NVIDIA GeForce RTX 3060"         },
        { "NVIDIA", "NVIDIA GeForce RTX 3060 Ti"      },
        { "NVIDIA", "NVIDIA GeForce RTX 3070"         },
        { "NVIDIA", "NVIDIA GeForce RTX 3080"         },
        { "NVIDIA", "NVIDIA GeForce RTX 4060"         },
        { "NVIDIA", "NVIDIA GeForce RTX 4060 Ti"      },
        { "NVIDIA", "NVIDIA GeForce RTX 4070"         },
        { "AMD",    "AMD Radeon RX 6600"              },
        { "AMD",    "AMD Radeon RX 6600 XT"           },
        { "AMD",    "AMD Radeon RX 6700 XT"           },
        { "AMD",    "AMD Radeon RX 6800 XT"           },
        { "AMD",    "AMD Radeon RX 7600"              },
        { "AMD",    "AMD Radeon RX 7700 XT"           },
    };

    struct MoboEntry { int intel; const char* vendor; const char* model; const char* bios_ver; };
    static const MoboEntry mobos[] = {
        { 1, "American Megatrends Inc.", "ASUS PRIME Z490-P",     "0501" },
        { 1, "American Megatrends Inc.", "ASUS ROG STRIX Z490-F", "0603" },
        { 1, "American Megatrends Inc.", "ASUS PRIME Z590-P",     "0606" },
        { 1, "American Megatrends Inc.", "ASUS TUF GAMING Z590",  "1401" },
        { 1, "American Megatrends Inc.", "ASUS PRIME Z690-P",     "1201" },
        { 1, "American Megatrends Inc.", "ASUS ROG STRIX Z690-F", "1403" },
        { 1, "American Megatrends Inc.", "MSI MAG Z490 TOMAHAWK", "A.40" },
        { 1, "American Megatrends Inc.", "MSI MPG Z590 GAMING",   "A.60" },
        { 1, "American Megatrends Inc.", "MSI MAG Z690 TOMAHAWK", "A.80" },
        { 1, "American Megatrends Inc.", "Gigabyte Z490 AORUS",   "F60"  },
        { 1, "American Megatrends Inc.", "Gigabyte Z590 AORUS",   "F65"  },
        { 1, "American Megatrends Inc.", "Gigabyte Z690 AORUS",   "F10"  },
        { 0, "American Megatrends Inc.", "ASUS ROG STRIX X570-E", "2606" },
        { 0, "American Megatrends Inc.", "ASUS TUF GAMING X570",  "2803" },
        { 0, "American Megatrends Inc.", "ASUS PRIME B550-PLUS",  "2402" },
        { 0, "American Megatrends Inc.", "MSI MAG X570 TOMAHAWK", "A.60" },
        { 0, "American Megatrends Inc.", "MSI MPG B550 GAMING",   "A.40" },
        { 0, "American Megatrends Inc.", "Gigabyte X570 AORUS",   "F34"  },
        { 0, "American Megatrends Inc.", "Gigabyte B550 AORUS",   "F17"  },
        { 0, "American Megatrends Inc.", "ASRock X570 Phantom",   "P4.10"},
    };

    std::vector<uint8_t> seed(64, 0);
    BCryptGenRandom(nullptr, seed.data(), (ULONG)seed.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);

    const auto& cpu = cpus[seed[0] % (sizeof(cpus) / sizeof(cpus[0]))];
    const auto& gpu = gpus[seed[1] % (sizeof(gpus) / sizeof(gpus[0]))];

    const MoboEntry* matched[20]; int mc = 0;
    for (auto& m : mobos) if (m.intel == cpu.intel && mc < 20) matched[mc++] = &m;
    const auto& mobo = *matched[seed[2] % mc];

    strcpy_s(profile.cpu_brand,   cpu.cpuid);
    strcpy_s(profile.cpu_model,   cpu.model);
    profile.cpu_cores = cpu.cores;
    strcpy_s(profile.gpu_brand,   gpu.brand);
    strcpy_s(profile.gpu_model,   gpu.model);
    strcpy_s(profile.bios_vendor, mobo.vendor);
    strcpy_s(profile.bios_version,mobo.bios_ver);
    strcpy_s(profile.mobo_model,  mobo.model);

    sprintf_s(profile.volume_serial, "%08X",
        (uint32_t)((seed[4] << 24) | (seed[5] << 16) | (seed[6] << 8) | seed[7]));

    sprintf_s(profile.machine_guid, "%02x%02x%02x%02x-%02x%02x-4%01x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        seed[8],  seed[9],  seed[10], seed[11],
        seed[12], seed[13],
        seed[14] & 0x0F, seed[15],
        (seed[16] & 0x3F) | 0x80, seed[17],
        seed[18], seed[19], seed[20], seed[21], seed[22], seed[23]);

    static const char* prefixes[] = { "DESKTOP-", "WIN-" };
    static const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const char* pfx = prefixes[seed[24] % 2];
    strcpy_s(profile.hostname, pfx);
    size_t pfx_len = strlen(pfx);
    for (int i = 0; i < 7; i++)
        profile.hostname[pfx_len + i] = charset[seed[25 + i] % (sizeof(charset) - 1)];
    profile.hostname[pfx_len + 7] = '\0';

    static const char* os_builds[] = {
        "10.0.19044", "10.0.19045", "10.0.22000",
        "10.0.22621", "10.0.22631", "10.0.26100",
    };
    strcpy_s(profile.os_version, os_builds[seed[32 % 32] % (sizeof(os_builds)/sizeof(os_builds[0]))]);

    Log(std::string("[HWID] generated new profile cpu=") + profile.cpu_model + " os=" + profile.os_version);

    initialized = true;
    return profile;
}

std::vector<uint8_t> GetRandomHwid() {
    const auto& profile = GetRandomizedHardwareProfile();
    
    std::string composite = std::string("BIOS:") + profile.bios_vendor + " " + profile.bios_version
        + "|CPU:" + profile.cpu_model
        + "|VOL:" + profile.volume_serial
        + "|MGUID:" + profile.machine_guid;
    Log("[HWID] randomized composite: " + composite.substr(0, 80) + "...");

    std::vector<uint8_t> hash(32, 0);
    HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0; DWORD hashLen = 32;
    CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)composite.data(), (DWORD)composite.size(), 0);
    CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);

    std::ostringstream hex; for (auto b : hash) hex << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    Log("[HWID] randomized sha256=" + hex.str());
    return hash;
}

std::string BytesToHexString(const std::vector<uint8_t>& bytes) {
    std::ostringstream hex;
    for (auto b : bytes) hex << std::hex << std::setfill('0') << std::setw(2) << (int)b;
    return hex.str();
}

std::vector<uint8_t> GetConfiguredHwid() {
    auto hash = GetRandomHwid(); 
    Log("[HWID] SESSION_AUTH hwid=" + BytesToHexString(hash).substr(0, 16) + "...");
    return hash;
}

std::string GetCachedHwPart6() {
    static std::string cached_s6;
    if (!cached_s6.empty()) return cached_s6;

    auto makeSlot = [](const std::string& entry) -> std::string {
        std::vector<uint8_t> buf(96, 0);
        size_t len = entry.size() < 96 ? entry.size() : 96;
        memcpy(buf.data(), entry.data(), len);
        return VGW::Base64Encode(buf.data(), buf.size());
    };

    auto r_pci = VGW::RandomBytes(16);
    std::ostringstream pci_ss;
    for (int i = 0; i < 16; i++) {
        if (i > 0 && i % 2 == 0) pci_ss << "_";
        pci_ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)r_pci[i];
    }
    static const char* disk_models[] = {
        "SAMSUNG MZVL21T0HCLR-00B00",
        "SAMSUNG MZVLB512HAJQ-000H1",
        "WDC WDS500G2B0C-00PXH0",
        "KINGSTON SKC3000S1024G",
        "CT1000P3SSD8",
    };
    uint8_t dm_seed = 0;
    BCryptGenRandom(nullptr, &dm_seed, 1, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    std::string slot0 = pci_ss.str() + "." + disk_models[dm_seed % 5];

    std::string empty_slot = makeSlot("");
    cached_s6 = makeSlot(slot0) + ";" + empty_slot + ";" +
                empty_slot + ";" + empty_slot + ";" + empty_slot;
    return cached_s6;
}

std::wstring GetOutputTxtPath() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    wchar_t* last = wcsrchr(path, L'\\');
    if (last) *(last + 1) = L'\0';
    wcscat_s(path, L"output.txt");
    return path;
}

bool LoadMachinePool() {
    std::lock_guard<std::mutex> lk(g_machine_pool_mtx);
    if (!g_machine_pool.empty()) return true;

    auto path = GetOutputTxtPath();
    std::ifstream f(path);
    if (!f.is_open()) {
        Log("[GW] output.txt not found at " + [&]{ std::string s; for (wchar_t c : path) if (c) s += (char)(c & 0xFF); return s; }());
        return false;
    }

    VgcMachineEntry cur;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();

        if (line.empty() || line[0] == '#') {
            if (!cur.machine_id.empty() && !cur.ht.empty()) {
                g_machine_pool.push_back(cur);
                cur = {};
            }
            continue;
        }
        if (line.rfind("machine_id=", 0) == 0)
            cur.machine_id = line.substr(11);
        else if (line.rfind("ht=", 0) == 0)
            cur.ht = line.substr(3);
    }
    
    if (!cur.machine_id.empty() && !cur.ht.empty())
        g_machine_pool.push_back(cur);

    Log("[GW] output.txt loaded: " + std::to_string(g_machine_pool.size()) + " machine entries");
    return !g_machine_pool.empty();
}

std::wstring GetExeDirFile(const wchar_t* filename) {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    wchar_t* last = wcsrchr(path, L'\\');
    if (last) *(last + 1) = L'\0';
    wcscat_s(path, filename);
    return path;
}

std::wstring MakeLockFilePath(size_t idx) {
    wchar_t name[64]{};
    swprintf_s(name, L"hesap%zu.txt", idx + 1);
    return GetExeDirFile(name);
}

void WriteLockFile(size_t idx) {
    auto path = MakeLockFilePath(idx);
    HANDLE hf = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return;
    std::string content = "machine_index=" + std::to_string(idx) + "\n";
    DWORD written = 0;
    WriteFile(hf, content.data(), (DWORD)content.size(), &written, nullptr);
    CloseHandle(hf);
}

size_t FindExistingLockFile(size_t pool_size) {
    wchar_t dir[MAX_PATH]{};
    GetModuleFileNameW(nullptr, dir, MAX_PATH);
    wchar_t* last = wcsrchr(dir, L'\\');
    if (last) *(last + 1) = L'\0';

    wchar_t pattern[MAX_PATH]{};
    wcscpy_s(pattern, dir);
    wcscat_s(pattern, L"hesap*.txt");

    WIN32_FIND_DATAW fd{};
    HANDLE hFind = FindFirstFileW(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return (size_t)-1;

    size_t found_idx = (size_t)-1;
    do {
        wchar_t full[MAX_PATH]{};
        wcscpy_s(full, dir);
        wcscat_s(full, fd.cFileName);

        HANDLE hf = CreateFileW(full, GENERIC_READ, FILE_SHARE_READ, nullptr,
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hf == INVALID_HANDLE_VALUE) continue;
        char buf[64]{}; DWORD rd = 0;
        ReadFile(hf, buf, sizeof(buf) - 1, &rd, nullptr);
        CloseHandle(hf);

        std::string content(buf, rd);
        auto pos = content.find("machine_index=");
        if (pos != std::string::npos) {
            size_t idx = (size_t)std::stoul(content.substr(pos + 14));
            if (idx < pool_size) { found_idx = idx; break; }
        }
    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);
    return found_idx;
}

void EnsureMachineSelected() {
    if (g_selected_machine_idx != (size_t)-1) return;
    if (!LoadMachinePool() || g_machine_pool.empty()) {
        Log("[GW] ERROR: machine pool empty, check output.txt");
        g_selected_machine_idx = 0;
        return;
    }

    size_t pool_size = g_machine_pool.size();

    size_t existing = FindExistingLockFile(pool_size);
    if (existing != (size_t)-1) {
        g_selected_machine_idx = existing;
        Log("[GW] reusing machine idx=" + std::to_string(existing) + " (hesap" + std::to_string(existing + 1) + ".txt found)");
        return;
    }

    uint32_t rnd = 0;
    BCryptGenRandom(nullptr, (PUCHAR)&rnd, sizeof(rnd), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    g_selected_machine_idx = rnd % pool_size;
    WriteLockFile(g_selected_machine_idx);
    Log("[GW] new machine idx=" + std::to_string(g_selected_machine_idx) +
        " -> hesap" + std::to_string(g_selected_machine_idx + 1) + ".txt created (" +
        std::to_string(pool_size) + " entries)");
}

std::string GetConfiguredGatewayMachineId() {
    EnsureMachineSelected();
    std::lock_guard<std::mutex> lk(g_machine_pool_mtx);
    if (g_machine_pool.empty()) return "";
    return g_machine_pool[g_selected_machine_idx].machine_id;
}

std::string GetStableHt() {
    EnsureMachineSelected();
    std::lock_guard<std::mutex> lk(g_machine_pool_mtx);
    if (g_machine_pool.empty()) return "";
    return g_machine_pool[g_selected_machine_idx].ht;
}

std::string GetFakeHostname() {
    return GetRandomizedHardwareProfile().hostname;
}

void GetCpuInfo(std::string& brand, std::string& model, uint32_t& cores) {
    if (RandomizedVersion) {
        const auto& p = GetRandomizedHardwareProfile();
        brand = p.cpu_brand;
        model = p.cpu_model;
        cores = p.cpu_cores;
        Log("[HWINFO] CPU rand brand=" + brand + " model=" + model);
        return;
    }

    model = RegReadStr(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"ProcessorNameString");
    while (!model.empty() && (model.back() == ' ' || model.back() == '\t')) model.pop_back();
    brand = (model.find("Intel") != std::string::npos) ? "GenuineIntel" : (model.find("AMD") != std::string::npos) ? "AuthenticAMD" : "Unknown";
    SYSTEM_INFO si{}; GetSystemInfo(&si); cores = si.dwNumberOfProcessors ? si.dwNumberOfProcessors : 1;
    Log("[HWINFO] CPU real brand=" + brand + " model=" + model + " logical_count=" + std::to_string(cores));
}

void GetGpuInfo(std::string& brand, std::string& model) {
    if (RandomizedVersion) {
        const auto& p = GetRandomizedHardwareProfile();
        brand = p.gpu_brand;
        model = p.gpu_model;
        Log("[HWINFO] GPU rand brand=" + brand + " model=" + model);
        return;
    }

    model = RegReadStr(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", L"DriverDesc");
    if (model.empty()) { brand = "Unknown"; model = "Unknown"; Log("[HWINFO] GPU real brand=" + brand + " model=" + model); return; }
    brand = (model.find("NVIDIA") != std::string::npos) ? "NVIDIA" :
        (model.find("AMD") != std::string::npos || model.find("Radeon") != std::string::npos) ? "AMD" :
        (model.find("Intel") != std::string::npos) ? "Intel" : "Unknown";
    Log("[HWINFO] GPU real brand=" + brand + " model=" + model);
}
