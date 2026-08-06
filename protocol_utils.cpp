#include "protocol_utils.h"
#include "logger.h"

std::wstring RegionToGwHost(const std::string& region) {
    if (region == "la" || region == "la1" || region == "la2") return L"latam.vg.ac.pvp.net";
    if (region == "br" || region == "br1")                return L"br.vg.ac.pvp.net";
    if (region == "na" || region == "na1")                return L"na.vg.ac.pvp.net";
    if (region == "eu" || region == "eu1" || region == "eu2" || region == "eu3") return L"eu.vg.ac.pvp.net";
    if (region == "ap" || region == "ap1" || region == "ap2") return L"ap.vg.ac.pvp.net";
    if (region == "kr")                               return L"kr.vg.ac.pvp.net";
    return L"na.vg.ac.pvp.net";
}

void PushU32BE(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back((x >> 24) & 0xFF); v.push_back((x >> 16) & 0xFF);
    v.push_back((x >> 8) & 0xFF);  v.push_back(x & 0xFF);
}

void PushU64BE(std::vector<uint8_t>& v, uint64_t x) {
    for (int i = 7; i >= 0; i--) v.push_back((uint8_t)(x >> (i * 8)));
}

void PushLenStr(std::vector<uint8_t>& v, const std::string& s) {
    PushU32BE(v, (uint32_t)s.size());
    v.insert(v.end(), s.begin(), s.end());
}

void PushLenBytes(std::vector<uint8_t>& v, const std::vector<uint8_t>& b) {
    PushU32BE(v, (uint32_t)b.size());
    v.insert(v.end(), b.begin(), b.end());
}

uint32_t ReadU32BE(const uint8_t* p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

uint64_t ReadU64BE(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

std::vector<uint8_t> PackMsg(uint32_t type, const std::vector<uint8_t>& payload) {
    if (payload.size() > MAX_PAYLOAD) throw std::runtime_error("payload too large");
    std::vector<uint8_t> pkt;
    PushU32BE(pkt, type);
    PushU32BE(pkt, (uint32_t)payload.size());
    pkt.insert(pkt.end(), payload.begin(), payload.end());
    return pkt;
}

std::vector<uint8_t> PackMsg(uint32_t type) {
    std::vector<uint8_t> pkt;
    PushU32BE(pkt, type); PushU32BE(pkt, 0);
    return pkt;
}

std::string ParseLPStr(const std::vector<uint8_t>& buf, size_t& off) {
    if (off + 4 > buf.size()) return "";
    uint32_t len = ReadU32BE(buf.data() + off); off += 4;
    if (off + len > buf.size()) return "";
    std::string s((char*)buf.data() + off, len); off += len;
    return s;
}

std::vector<uint8_t> ParseLPBytes(const std::vector<uint8_t>& buf, size_t& off) {
    if (off + 4 > buf.size()) return {};
    uint32_t len = ReadU32BE(buf.data() + off); off += 4;
    if (off + len > buf.size()) return {};
    std::vector<uint8_t> b(buf.data() + off, buf.data() + off + len); off += len;
    return b;
}

std::vector<uint8_t> ParseSessionGatewayBody(const std::vector<uint8_t>& payload, std::string* session_id) {
    size_t off = 0;
    std::string sid = ParseLPStr(payload, off);
    if (session_id) *session_id = sid;
    if (off + 4 > payload.size()) return {};
    uint32_t gw_len = ReadU32BE(payload.data() + off);
    off += 4;
    if (off + gw_len > payload.size()) return {};
    return std::vector<uint8_t>(payload.begin() + off, payload.begin() + off + gw_len);
}

std::string Base64UrlDecode(const std::string& in) {
    std::string s = in;
    for (auto& c : s) { if (c == '-')c = '+'; if (c == '_')c = '/'; }
    while (s.size() % 4) s += '=';
    DWORD outLen = 0;
    CryptStringToBinaryA(s.c_str(), (DWORD)s.size(), CRYPT_STRING_BASE64,
        nullptr, &outLen, nullptr, nullptr);
    std::string out(outLen, '\0');
    CryptStringToBinaryA(s.c_str(), (DWORD)s.size(), CRYPT_STRING_BASE64,
        (BYTE*)out.data(), &outLen, nullptr, nullptr);
    out.resize(outLen);
    return out;
}

std::string Base64Encode(const uint8_t* data, size_t len) {
    static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out; int val = 0, valb = -6;
    for (size_t i = 0; i < len; i++) { val = (val << 8) + data[i]; valb += 8; while (valb >= 0) { out += tbl[(val >> valb) & 0x3F]; valb -= 6; } }
    if (valb > -6) out += tbl[((val << 8) >> (valb + 8)) & 0x3F];
    while (out.size() % 4) out += '=';
    return out;
}

std::string JsonGetStr(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";
    pos = json.find(':', pos + search.size());
    if (pos == std::string::npos) return "";
    while (pos < json.size() && (json[pos] == ' ' || json[pos] == ':' || json[pos] == '\t')) pos++;
    if (pos >= json.size()) return "";
    if (json[pos] == '"') {
        pos++;
        auto end = json.find('"', pos);
        if (end == std::string::npos) return "";
        return json.substr(pos, end - pos);
    }
    
    auto end = json.find_first_of(",}", pos);
    return json.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
}

std::string DecodeJwtPayload(const std::string& jwt) {
    auto dot1 = jwt.find('.');
    if (dot1 == std::string::npos) return "";
    auto dot2 = jwt.find('.', dot1 + 1);
    if (dot2 == std::string::npos) return "";
    return Base64UrlDecode(jwt.substr(dot1 + 1, dot2 - dot1 - 1));
}

std::string ShardFromJwt(const std::string& jwt) {
    auto payload = DecodeJwtPayload(jwt);

    {
        auto dat_pos = payload.find("\"dat\"");
        if (dat_pos != std::string::npos) {
            auto brace = payload.find('{', dat_pos);
            auto close = payload.find('}', brace);
            if (brace != std::string::npos && close != std::string::npos) {
                std::string dat_obj = payload.substr(brace, close - brace + 1);
                std::string dr = JsonGetStr(dat_obj, "r");
                for (auto& c : dr) c = tolower(c);
                if (!dr.empty()) {
                    if (dr == "la2" || dr == "la1" || dr == "la") return "la";
                    if (dr == "br1" || dr == "br")             return "br";
                    if (dr == "na1" || dr == "na")             return "na";
                    if (dr == "eu1" || dr == "eu2" || dr == "eu3" || dr == "eu") return "eu";
                    if (dr == "ap1" || dr == "ap2" || dr == "ap")  return "ap";
                    if (dr == "kr")                        return "kr";
                }
            }
        }
    }

    std::string r = JsonGetStr(payload, "r");
    for (auto& c : r) c = tolower(c);
    if (r == "br" || r == "br1")                               return "br";
    if (r == "la" || r == "la1" || r == "la2")                 return "la";
    if (r == "na" || r == "na1")                               return "na";
    if (r == "eu" || r == "eu1" || r == "eu2" || r == "eu3")   return "eu";
    if (r == "ap" || r == "ap1" || r == "ap2")                 return "ap";
    if (r == "kr")                                             return "kr";

    std::string aff = JsonGetStr(payload, "affinity");
    if (aff.empty()) aff = JsonGetStr(payload, "region");
    for (auto& c : aff) c = tolower(c);
    if (!aff.empty()) {
        if (aff.find("la") != std::string::npos) return "la";
        if (aff.find("br") != std::string::npos) return "br";
        if (aff.find("na") != std::string::npos) return "na";
        if (aff.find("eu") != std::string::npos) return "eu";
        if (aff.find("ap") != std::string::npos) return "ap";
        if (aff.find("kr") != std::string::npos) return "kr";
    }

    std::string cty = JsonGetStr(payload, "cty");
    if (cty.empty()) cty = JsonGetStr(payload, "lcty");
    for (auto& c : cty) c = tolower(c);
    
    if (cty == "usa" || cty == "can" || cty == "mex") return "na";
    if (cty == "kor" || cty == "kr") return "kr";
    if (cty == "bra" || cty == "arg" || cty == "chl" || cty == "col" ||
        cty == "per" || cty == "ven" || cty == "ecu" || cty == "bol" ||
        cty == "pry" || cty == "ury") return "br";
    if (cty == "gtm" || cty == "cri" || cty == "pan" || cty == "hnd" ||
        cty == "slv" || cty == "nic" || cty == "dom") return "la";
    if (cty == "deu" || cty == "fra" || cty == "gbr" || cty == "esp" ||
        cty == "ita" || cty == "pol" || cty == "tur" || cty == "nld" ||
        cty == "bel" || cty == "che" || cty == "aut" || cty == "swe" ||
        cty == "nor" || cty == "dnk" || cty == "fin" || cty == "prt" ||
        cty == "grc" || cty == "cze" || cty == "hun" || cty == "rou" ||
        cty == "rus" || cty == "ukr" || cty == "mda") return "eu";
    if (cty == "jpn" || cty == "aus" || cty == "sgp" || cty == "nzl" ||
        cty == "phl" || cty == "tha" || cty == "idn" || cty == "mys" ||
        cty == "vnm" || cty == "twn" || cty == "hkg" || cty == "mmr") return "ap";

    std::string iss = JsonGetStr(payload, "iss");
    for (auto& c : iss) c = tolower(c);
    if (iss.find(".la.") != std::string::npos || iss.find("latam") != std::string::npos) return "la";
    if (iss.find(".br.") != std::string::npos) return "br";
    if (iss.find(".na.") != std::string::npos || iss.find("na1") != std::string::npos) return "na";
    if (iss.find(".eu.") != std::string::npos || iss.find("eu1") != std::string::npos) return "eu";
    if (iss.find(".ap.") != std::string::npos || iss.find("ap1") != std::string::npos) return "ap";
    if (iss.find(".kr.") != std::string::npos) return "kr";

    return ""; 
}

std::string NormalizeShardHintRobust(std::string value) {
    for (auto& c : value) c = (char)tolower((unsigned char)c);
    while (!value.empty() && (value.back() == '"' || value.back() == ' ' || value.back() == '\r' || value.back() == '\n' || value.back() == '\t')) value.pop_back();
    while (!value.empty() && (value.front() == '"' || value.front() == ' ' || value.front() == '\r' || value.front() == '\n' || value.front() == '\t')) value.erase(value.begin());
    if (value.empty()) return "";

    if (value == "la" || value == "la1" || value == "la2" || value == "latam") return "la";
    if (value == "br" || value == "br1" || value == "brazil") return "br";
    if (value == "na" || value == "na1" || value == "na2" || value == "northamerica" || value == "north_america") return "na";
    if (value == "eu" || value == "eu1" || value == "eu2" || value == "eu3" || value == "emea" || value == "europe" || value == "euw" || value == "eune") return "eu";
    if (value == "ap" || value == "ap1" || value == "ap2" || value == "apac" || value == "asia" || value == "oce") return "ap";
    if (value == "kr" || value == "korea") return "kr";

    if (value.find("latam") != std::string::npos || value.rfind("la", 0) == 0) return "la";
    if (value.find("brazil") != std::string::npos || value.rfind("br", 0) == 0) return "br";
    if (value.find("emea") != std::string::npos || value.find("europe") != std::string::npos || value.rfind("eu", 0) == 0) return "eu";
    if (value.find("north") != std::string::npos || value.rfind("na", 0) == 0) return "na";
    if (value.find("apac") != std::string::npos || value.find("asia") != std::string::npos || value.find("oce") != std::string::npos || value.rfind("ap", 0) == 0) return "ap";
    if (value.find("korea") != std::string::npos || value.rfind("kr", 0) == 0) return "kr";
    return "";
}

std::string ShardFromJwtRobust(const std::string& jwt) {
    auto payload = DecodeJwtPayload(jwt);
    if (payload.empty()) return "";

    {
        auto dat_pos = payload.find("\"dat\"");
        if (dat_pos != std::string::npos) {
            auto brace = payload.find('{', dat_pos);
            auto close = payload.find('}', brace);
            if (brace != std::string::npos && close != std::string::npos) {
                std::string dat_obj = payload.substr(brace, close - brace + 1);
                if (auto v = NormalizeShardHintRobust(JsonGetStr(dat_obj, "r")); !v.empty()) return v;
                if (auto v = NormalizeShardHintRobust(JsonGetStr(dat_obj, "region")); !v.empty()) return v;
                if (auto v = NormalizeShardHintRobust(JsonGetStr(dat_obj, "affinity")); !v.empty()) return v;
            }
        }
    }

    for (const auto& key : { "r", "affinity", "region", "shard", "player_region", "geo_region", "geo", "loc" }) {
        if (auto v = NormalizeShardHintRobust(JsonGetStr(payload, key)); !v.empty()) return v;
    }

    for (const auto& pattern : {
        std::regex("\"r\"\\s*:\\s*\"([^\"]+)\""),
        std::regex("\"affinity\"\\s*:\\s*\"([^\"]+)\""),
        std::regex("\"region\"\\s*:\\s*\"([^\"]+)\""),
        std::regex("\"shard\"\\s*:\\s*\"([^\"]+)\""),
        std::regex("\"player_region\"\\s*:\\s*\"([^\"]+)\""),
        std::regex("\"geo_region\"\\s*:\\s*\"([^\"]+)\"")
        }) {
        std::smatch m;
        if (std::regex_search(payload, m, pattern) && m.size() > 1) {
            if (auto v = NormalizeShardHintRobust(m[1].str()); !v.empty()) return v;
        }
    }

    auto region_from_country = [](std::string cty) -> std::string {
        for (auto& c : cty) c = (char)tolower((unsigned char)c);
        if (cty == "usa" || cty == "us" || cty == "can" || cty == "ca" || cty == "mex" || cty == "mx") return "na";
        if (cty == "kor" || cty == "kr") return "kr";
        if (cty == "bra" || cty == "br" || cty == "arg" || cty == "ar" || cty == "chl" || cty == "cl" || cty == "col" || cty == "co" ||
            cty == "per" || cty == "pe" || cty == "ven" || cty == "ve" || cty == "ecu" || cty == "ec" || cty == "bol" || cty == "bo" ||
            cty == "pry" || cty == "py" || cty == "ury" || cty == "uy") return "br";
        if (cty == "gtm" || cty == "gt" || cty == "cri" || cty == "cr" || cty == "pan" || cty == "pa" || cty == "hnd" || cty == "hn" ||
            cty == "slv" || cty == "sv" || cty == "nic" || cty == "ni" || cty == "dom" || cty == "do") return "la";
        if (cty == "deu" || cty == "de" || cty == "fra" || cty == "fr" || cty == "gbr" || cty == "gb" || cty == "uk" || cty == "esp" || cty == "es" ||
            cty == "ita" || cty == "it" || cty == "pol" || cty == "pl" || cty == "tur" || cty == "tr" || cty == "nld" || cty == "nl" ||
            cty == "bel" || cty == "be" || cty == "che" || cty == "ch" || cty == "aut" || cty == "at" || cty == "swe" || cty == "se" ||
            cty == "nor" || cty == "no" || cty == "dnk" || cty == "dk" || cty == "fin" || cty == "fi" || cty == "prt" || cty == "pt" ||
            cty == "grc" || cty == "gr" || cty == "cze" || cty == "cz" || cty == "hun" || cty == "hu" || cty == "rou" || cty == "ro" ||
            cty == "rus" || cty == "ru" || cty == "ukr" || cty == "ua" || cty == "mda" || cty == "md") return "eu";
        if (cty == "jpn" || cty == "jp" || cty == "aus" || cty == "au" || cty == "sgp" || cty == "sg" || cty == "nzl" || cty == "nz" ||
            cty == "phl" || cty == "ph" || cty == "tha" || cty == "th" || cty == "idn" || cty == "id" || cty == "mys" || cty == "my" ||
            cty == "vnm" || cty == "vn" || cty == "twn" || cty == "tw" || cty == "hkg" || cty == "hk" || cty == "mmr" || cty == "mm" ||
            cty == "pak" || cty == "pk") return "ap";
        return "";
    };

    std::string cty = JsonGetStr(payload, "cty");
    std::string lcty = JsonGetStr(payload, "lcty");
    if (auto v = region_from_country(lcty); !v.empty()) return v;
    if (auto v = region_from_country(cty); !v.empty()) return v;

    std::string iss = JsonGetStr(payload, "iss");
    for (auto& c : iss) c = (char)tolower((unsigned char)c);
    if (iss.find(".la.") != std::string::npos || iss.find("latam") != std::string::npos) return "la";
    if (iss.find(".br.") != std::string::npos) return "br";
    if (iss.find(".na.") != std::string::npos || iss.find("na1") != std::string::npos) return "na";
    if (iss.find(".eu.") != std::string::npos || iss.find("eu1") != std::string::npos || iss.find("emea") != std::string::npos || iss.find("europe") != std::string::npos) return "eu";
    if (iss.find(".ap.") != std::string::npos || iss.find("ap1") != std::string::npos) return "ap";
    if (iss.find(".kr.") != std::string::npos) return "kr";

    return ShardFromJwt(jwt);
}

void LogJwtRegionHints(const std::string& jwt, const std::string& prefix) {
    auto payload = DecodeJwtPayload(jwt);
    if (payload.empty()) {
        Log(prefix + " jwt_payload=EMPTY");
        return;
    }

    std::string dat_r;
    auto dat_pos = payload.find("\"dat\"");
    if (dat_pos != std::string::npos) {
        auto brace = payload.find('{', dat_pos);
        auto close = payload.find('}', brace);
        if (brace != std::string::npos && close != std::string::npos) {
            dat_r = JsonGetStr(payload.substr(brace, close - brace + 1), "r");
        }
    }

    std::string iss = JsonGetStr(payload, "iss");
    if (iss.size() > 64) iss = iss.substr(0, 64) + "...";

    Log(prefix +
        " dat.r=" + (dat_r.empty() ? "<empty>" : dat_r) +
        " r=" + (JsonGetStr(payload, "r").empty() ? "<empty>" : JsonGetStr(payload, "r")) +
        " affinity=" + (JsonGetStr(payload, "affinity").empty() ? "<empty>" : JsonGetStr(payload, "affinity")) +
        " region=" + (JsonGetStr(payload, "region").empty() ? "<empty>" : JsonGetStr(payload, "region")) +
        " shard=" + (JsonGetStr(payload, "shard").empty() ? "<empty>" : JsonGetStr(payload, "shard")) +
        " player_region=" + (JsonGetStr(payload, "player_region").empty() ? "<empty>" : JsonGetStr(payload, "player_region")) +
        " geo_region=" + (JsonGetStr(payload, "geo_region").empty() ? "<empty>" : JsonGetStr(payload, "geo_region")) +
        " cty=" + (JsonGetStr(payload, "cty").empty() ? "<empty>" : JsonGetStr(payload, "cty")) +
        " lcty=" + (JsonGetStr(payload, "lcty").empty() ? "<empty>" : JsonGetStr(payload, "lcty")) +
        " iss=" + (iss.empty() ? "<empty>" : iss));
}

std::string AccountFromJwt(const std::string& jwt) {
    auto payload = DecodeJwtPayload(jwt);
    for (auto& k : { "sub","acct","name" }) {
        auto v = JsonGetStr(payload, k);
        if (!v.empty()) return v;
    }
    return "";
}

std::string PuuidFromJwt(const std::string& jwt) {
    auto payload = DecodeJwtPayload(jwt);
    static const std::regex uuid_re(
        R"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})");
    for (auto& k : { "sub","puuid" }) {
        auto v = JsonGetStr(payload, k);
        if (std::regex_match(v, uuid_re)) return v;
    }
    std::smatch m;
    if (std::regex_search(payload, m, uuid_re)) return m[0].str();
    return "";
}

std::string ResolveNonEmptySid(const std::string& jwt, const std::string& sid, const std::string& puuid, const char* tag) {
    if (!sid.empty() && sid != puuid) return sid;

    std::string jwt_puuid = PuuidFromJwt(jwt);
    if (!sid.empty() && sid != jwt_puuid) return sid;

    Log(std::string(tag) + " no distinct session UUID in pipe — f13 will be empty");
    if (false) { 
        return jwt_puuid;
    }

    Log(std::string(tag) + " WARNING: sid fallback unavailable");
    return "";
}

std::string Md5HexUpper(const std::vector<uint8_t>& data) {
    HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0;
    CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
    CryptHashData(hHash, data.data(), (DWORD)data.size(), 0);
    BYTE md5[16] = {}; DWORD len = 16;
    CryptGetHashParam(hHash, HP_HASHVAL, md5, &len, 0);
    CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
    std::ostringstream ss;
    for (int i = 0; i < 16; i++) ss << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << (int)md5[i];
    return ss.str();
}
