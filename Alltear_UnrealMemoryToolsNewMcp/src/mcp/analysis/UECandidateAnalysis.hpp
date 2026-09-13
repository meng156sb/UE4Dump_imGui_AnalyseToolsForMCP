#pragma once

#include <atomic>
#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

#include <KittyMemoryMgr.hpp>

namespace UmtMcp::Analysis
{
using json = nlohmann::json;

json ScanGNamesCandidates(const json &args, const KittyMemoryMgr &mgr, const std::atomic<bool> *cancelFlag = nullptr);
json SampleGNamesCandidate(const json &args, const KittyMemoryMgr &mgr);
json ScanObjectCandidates(const json &args, const KittyMemoryMgr &mgr, const std::atomic<bool> *cancelFlag = nullptr);
json SampleObjectCandidate(const json &args, const KittyMemoryMgr &mgr);

// 只按 pid + processStartTime 认进程：整份 maps 的 FNV 会因为无关 VMA 抖动而变，
// 候选地址本身是否仍然可读由调用方另行判断。
bool ValidateCandidateBinding(const std::string &kind, const std::string &sessionId,
                              int candidateId, pid_t pid, uint64_t processStartTime,
                              uintptr_t address, std::string &reason);
void InvalidateCandidateSessions();
}
