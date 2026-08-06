#pragma once

#include "config.h"

void TryExtractAndSend(const uint8_t* buf, DWORD len);
uint32_t PipeReadU32(const uint8_t* p);
void PipeWriteU32(std::vector<uint8_t>& v, size_t off, uint32_t value);
void PipeWriteU64(std::vector<uint8_t>& v, size_t off, uint64_t value);
bool PipeWriteAndFlush(HANDLE pipe, const std::vector<uint8_t>& data, const std::string& tag);
int PipeCompatNextMagic(int magic);
std::string PipeExtractFirstUuid(const uint8_t* data, size_t n);
bool PipeParseUuidBytes(const std::string& uuid, uint8_t out[16]);
std::vector<uint8_t> PipeBuildCompatAuthAck(int magic, const std::string& uuid);
bool SendPipeDisconnectMessage(HANDLE pipe, const std::string& reason);
bool SendDisconnectMessageToCurrentPipe(const std::string& reason);
void HandlePipeClient(HANDLE pipe);
void PipeServerLoop();
uint32_t GetValorantPID();
BOOL WINAPI CtrlHandler(DWORD t);
