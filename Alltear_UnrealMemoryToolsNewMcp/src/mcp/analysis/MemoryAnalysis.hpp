#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include <KittyMemoryMgr.hpp>

namespace UmtMcp::Analysis
{
using json = nlohmann::json;

struct MapSnapshot
{
    pid_t pid = 0;
    uint64_t processStartTime = 0;
    std::string revision;
    std::vector<KittyMemoryEx::ProcMap> maps;
};

MapSnapshot CaptureMaps(const KittyMemoryMgr &mgr);
std::string CurrentMapRevision(const KittyMemoryMgr &mgr);
bool IsReadableAddress(const MapSnapshot &snapshot, uintptr_t address, size_t size = 1);
bool IsWritableAddress(const MapSnapshot &snapshot, uintptr_t address, size_t size = 1);
// 「工具读得到」≠「内核 perms 有 r」。KittyMemSys 对 EFAULT 有 /proc/pid/mem pread 回退，
// 国服 FNamePool / GUObjectArray 所在的 [anon:.bss] 窗口 perms 无 r（-w-p），readable=false
// 却完全读得到。候选扫描的准入判断必须用这个；用 IsReadableAddress 会把真池整个排除，
// 只在可读 BSS 里剩下假阳性。
bool IsAccessibleAddress(const MapSnapshot &snapshot, uintptr_t address, size_t size = 1);
ElfScanner FindUnrealElf(const KittyMemoryMgr &mgr, const std::string &moduleHint = {});

json ListModules(const json &args, const KittyMemoryMgr &mgr);
json ScanPattern(const json &args, const KittyMemoryMgr &mgr, const std::atomic<bool> *cancelFlag = nullptr);
json SearchMemory(const json &args, const KittyMemoryMgr &mgr, const std::atomic<bool> *cancelFlag = nullptr);
json FindReferences(const json &args, const KittyMemoryMgr &mgr, const std::atomic<bool> *cancelFlag = nullptr);

void InvalidateSessions();
}
