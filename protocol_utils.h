#pragma once

#include "config.h"

// Binary helpers
void PushU32BE(std::vector<uint8_t>& v, uint32_t x);
void PushU64BE(std::vector<uint8_t>& v, uint64_t x);
void PushLenStr(std::vector<uint8_t>& v, const std::string& s);
void PushLenBytes(std::vector<uint8_t>& v, const std::vector<uint8_t>& b);
uint32_t ReadU32BE(const uint8_t* p);
uint64_t ReadU64BE(const uint8_t* p);

std::vector<uint8_t> PackMsg(uint32_t type, const std::vector<uint8_t>& payload);
std::vector<uint8_t> PackMsg(uint32_t type);

std::string ParseLPStr(const std::vector<uint8_t>& buf, size_t& off);
std::vector<uint8_t> ParseLPBytes(const std::vector<uint8_t>& buf, size_t& off);
std::vector<uint8_t> ParseSessionGatewayBody(const std::vector<uint8_t>& payload, std::string* session_id = nullptr);

// String & JWT & Region helpers
std::wstring RegionToGwHost(const std::string& region);
std::string Base64UrlDecode(const std::string& in);
std::string Base64Encode(const uint8_t* data, size_t len);
std::string JsonGetStr(const std::string& json, const std::string& key);
std::string DecodeJwtPayload(const std::string& jwt);
std::string ShardFromJwt(const std::string& jwt);
std::string NormalizeShardHintRobust(std::string value);
std::string ShardFromJwtRobust(const std::string& jwt);
void LogJwtRegionHints(const std::string& jwt, const std::string& prefix);
std::string AccountFromJwt(const std::string& jwt);
std::string PuuidFromJwt(const std::string& jwt);
std::string ResolveNonEmptySid(const std::string& jwt, const std::string& sid, const std::string& puuid, const char* tag);
std::string Md5HexUpper(const std::vector<uint8_t>& data);
