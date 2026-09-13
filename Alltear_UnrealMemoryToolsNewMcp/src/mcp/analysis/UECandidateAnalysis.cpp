#include "UECandidateAnalysis.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "MemoryAnalysis.hpp"
#include "../MemoryHelpers.hpp"
#include "../Protocol.hpp"
#include "../../Utils/NameCipher.hpp"

namespace UmtMcp::Analysis
{
namespace
{
constexpr size_t kChunk = 1024 * 1024;
constexpr size_t kDefaultScanBudget = 64 * 1024 * 1024;
constexpr size_t kMaxCandidateSessions = 32;
constexpr int kCandidatePageSize = 20;

struct NameLayout
{
    uint32_t stride = 2;
    uint32_t blocksBit = 16;
    uint32_t blocksOff = 0x40;
    uint32_t headerOff = 0;
    uint32_t lengthShift = 6;
};

struct NameCandidate
{
    int id = 0;
    uintptr_t poolAddress = 0;
    uintptr_t slotAddress = 0;
    uintptr_t block0 = 0;
    NameLayout layout;
    int score = 0;
    // 命中的锚点名个数。分数不足以区分真池和「指针密集段」的垃圾（见扫描处的说明），
    // 这个字段才是判据：真池必然在某个偏移解出 None/ByteProperty 等锚点名。
    int anchorHits = 0;
    json evidence = json::array();
    json failedChecks = json::array();
};

struct NameSession
{
    pid_t pid = 0;
    uint64_t processStartTime = 0;
    std::string revision;
    std::string id;
    std::vector<NameCandidate> candidates;
    uint64_t scannedBytes = 0;
    uint64_t skippedBytes = 0;
    bool truncated = false;
};

struct ObjectLayout
{
    uint32_t objObjectsOff = 0x10;
    uint32_t objectsOff = 0;
    uint32_t numElementsOff = 0x14;
    bool chunked = true;
    uint32_t numElementsPerChunk = 65536;
    uint32_t itemObjectOff = 0;
    uint32_t itemSize = 0x18;
    uint32_t classPrivateOff = 0x10;
    uint32_t namePrivateOff = 0x18;
    uint32_t outerPrivateOff = 0x20;
};

struct ObjectCandidate
{
    int id = 0;
    uintptr_t arrayAddress = 0;
    uintptr_t objectsAddress = 0;
    int32_t numElements = 0;
    ObjectLayout layout;
    int score = 0;
    json evidence = json::array();
    json failedChecks = json::array();
    std::string namesSessionId;
    int namesCandidateId = -1;
};

struct ObjectSession
{
    pid_t pid = 0;
    uint64_t processStartTime = 0;
    std::string revision;
    std::string id;
    std::vector<ObjectCandidate> candidates;
    uint64_t scannedBytes = 0;
    uint64_t skippedBytes = 0;
    bool truncated = false;
};

std::mutex gCandidateMutex;
std::unordered_map<std::string, NameSession> gNameSessions;
std::unordered_map<std::string, ObjectSession> gObjectSessions;
std::atomic<uint64_t> gCandidateSeq{0};

std::string NewId(const char *prefix)
{
    return std::string(prefix) + "-" + std::to_string(++gCandidateSeq);
}

std::string Confidence(int score)
{
    if (score >= 70) return "HIGH";
    if (score >= 40) return "MEDIUM";
    return "LOW";
}

template <typename T>
bool ReadValue(const KittyMemoryMgr &mgr, uintptr_t address, T &value)
{
    return mgr.readMem(address, &value, sizeof(value)) == sizeof(value);
}

bool IsPrintableName(const std::string &name)
{
    // 127 是 header 里的字符数上限；UTF-8 CJK 每字 3 字节，所以按字节放宽到 127*3。
    if (name.empty() || name.size() > 127 * 3) return false;
    for (unsigned char c : name)
        if (c < 0x20 || c == 0x7F) return false;
    return true;
}

// 比 IsPrintableName 严：要求整串都落在 ASCII 可见区 [0x20,0x7E]。
// 用途是区分「明文名字」和「异或过的名字」——密文里出现 >=0x80 的字节很正常（实测
// None 的密文是 b1 90 91 9a），所以只要限制在 <0x80 就能把两者分开。只给 ANSI 路径的
// Auto 启发式用；宽字符走 IsPlausibleFName。
bool IsPlainAsciiName(const std::string &name)
{
    if (name.empty() || name.size() > 127) return false;
    for (unsigned char c : name)
        if (c < 0x20 || c > 0x7E) return false;
    return true;
}

// 宽字符 Auto 启发式：解出的每个码点都得落在 FName 实际会用的区间。错密钥解宽字符
// 不会出非法字节，会出合法 UTF-8 乱码（西里尔/IPA/生僻汉字），IsPrintableName 放它过。
bool IsPlausibleFName(const std::string &name)
{
    if (name.empty() || name.size() > 127 * 3) return false;
    const unsigned char *p = reinterpret_cast<const unsigned char *>(name.data());
    const unsigned char *end = p + name.size();
    while (p < end)
    {
        uint32_t cp = 0;
        if (*p < 0x80)
        {
            cp = *p++;
        }
        else if ((*p & 0xE0) == 0xC0 && p + 1 < end)
        {
            cp = (uint32_t(*p & 0x1F) << 6) | uint32_t(p[1] & 0x3F);
            p += 2;
        }
        else if ((*p & 0xF0) == 0xE0 && p + 2 < end)
        {
            cp = (uint32_t(*p & 0x0F) << 12) | (uint32_t(p[1] & 0x3F) << 6) | uint32_t(p[2] & 0x3F);
            p += 3;
        }
        else if ((*p & 0xF8) == 0xF0 && p + 3 < end)
        {
            cp = (uint32_t(*p & 0x07) << 18) | (uint32_t(p[1] & 0x3F) << 12) |
                 (uint32_t(p[2] & 0x3F) << 6) | uint32_t(p[3] & 0x3F);
            p += 4;
        }
        else
        {
            return false;
        }
        const bool ok = (cp >= 0x20 && cp < 0x7F) ||
                        (cp >= 0x4E00 && cp <= 0x9FFF) ||
                        cp == 0x3001 || cp == 0x3002 || cp == 0xFF0C ||
                        cp == 0x00B7 || cp == 0x2014;
        if (!ok) return false;
    }
    return true;
}

NameLayout ParseNameLayout(const json &value)
{
    NameLayout layout;
    if (!value.is_object()) return layout;
    layout.stride = std::clamp(value.value("stride", 2), 1, 16);
    layout.blocksBit = std::clamp(value.value("blocksBit", 16), 8, 24);
    layout.blocksOff = std::clamp(value.value("blocksOff", 0x40), 0, 0x1000);
    layout.headerOff = std::clamp(value.value("headerOff", 0), 0, 32);
    layout.lengthShift = std::clamp(value.value("lengthShift", 6), 1, 15);
    return layout;
}

json NameLayoutJson(const NameLayout &layout)
{
    return {{"kind", "FNamePool"}, {"stride", layout.stride},
            {"blocksBit", layout.blocksBit}, {"blocksOff", layout.blocksOff},
            {"headerOff", layout.headerOff}, {"lengthShift", layout.lengthShift}};
}

ObjectLayout ParseObjectLayout(const json &value)
{
    ObjectLayout layout;
    if (!value.is_object()) return layout;
    layout.objObjectsOff = std::clamp(value.value("objObjectsOff", 0x10), 0, 0x400);
    layout.objectsOff = std::clamp(value.value("objectsOff", 0), 0, 0x100);
    layout.numElementsOff = std::clamp(value.value("numElementsOff", 0x14), 0, 0x100);
    layout.chunked = value.value("chunked", true);
    layout.numElementsPerChunk = std::clamp(value.value("numElementsPerChunk", 65536), 1, 1048576);
    layout.itemObjectOff = std::clamp(value.value("itemObjectOff", 0), 0, 0x100);
    layout.itemSize = std::clamp(value.value("itemSize", 0x18), 8, 0x100);
    layout.classPrivateOff = std::clamp(value.value("classPrivateOff", 0x10), 0, 0x100);
    if (value.contains("namePrivateOffsets") && value["namePrivateOffsets"].is_array() &&
        !value["namePrivateOffsets"].empty())
        layout.namePrivateOff = std::clamp(value["namePrivateOffsets"][0].get<int>(), 0, 0x100);
    else
        layout.namePrivateOff = std::clamp(value.value("namePrivateOff", 0x18), 0, 0x100);
    layout.outerPrivateOff = std::clamp(value.value("outerPrivateOff", 0x20), 0, 0x100);
    return layout;
}

json ObjectLayoutJson(const ObjectLayout &layout)
{
    return {{"objObjectsOff", layout.objObjectsOff}, {"objectsOff", layout.objectsOff},
            {"numElementsOff", layout.numElementsOff}, {"chunked", layout.chunked},
            {"numElementsPerChunk", layout.numElementsPerChunk},
            {"itemObjectOff", layout.itemObjectOff}, {"itemSize", layout.itemSize},
            {"classPrivateOff", layout.classPrivateOff},
            {"namePrivateOffsets", json::array({layout.namePrivateOff})},
            {"outerPrivateOff", layout.outerPrivateOff}};
}

size_t ParseCandidateCursor(const json &args)
{
    const std::string raw = args.value("cursor", "");
    if (raw.empty()) return 0;
    try
    {
        size_t used = 0;
        const auto value = std::stoull(raw, &used, 10);
        if (used != raw.size()) throw std::invalid_argument("trailing");
        return static_cast<size_t>(value);
    }
    catch (...)
    {
        throw HandlerError(Err::kBadArgs, "cursor 必须是十进制候选偏移");
    }
}

json NameCandidateJson(const NameCandidate &candidate)
{
    return {{"candidateId", candidate.id},
            {"poolAddress", FormatAddress(candidate.poolAddress)},
            {"slotAddress", FormatAddress(candidate.slotAddress)},
            {"valueAddress", FormatAddress(candidate.poolAddress)},
            {"indirection", 0}, {"layout", NameLayoutJson(candidate.layout)},
            {"score", candidate.score}, {"confidence", Confidence(candidate.score)},
            {"evidence", candidate.evidence}, {"failedChecks", candidate.failedChecks},
            {"source", "STRUCTURAL_SCAN"}};
}

json ObjectCandidateJson(const ObjectCandidate &candidate)
{
    return {{"candidateId", candidate.id},
            {"arrayAddress", FormatAddress(candidate.arrayAddress)},
            {"slotAddress", FormatAddress(candidate.arrayAddress)},
            {"valueAddress", FormatAddress(candidate.arrayAddress)},
            {"indirection", 0}, {"objectsAddress", FormatAddress(candidate.objectsAddress)},
            {"numElements", candidate.numElements}, {"layout", ObjectLayoutJson(candidate.layout)},
            {"score", candidate.score}, {"confidence", Confidence(candidate.score)},
            {"evidence", candidate.evidence}, {"failedChecks", candidate.failedChecks},
            {"source", "STRUCTURAL_SCAN"}};
}

template <typename Session, typename Formatter>
json PageCandidates(const Session &session, const json &args, Formatter formatter)
{
    const size_t cursor = ParseCandidateCursor(args);
    if (cursor > session.candidates.size())
        throw HandlerError(Err::kBadArgs, "cursor 超出候选结果范围");
    const size_t limit = static_cast<size_t>(
        std::clamp(args.value("limit", kCandidatePageSize), 1, kCandidatePageSize));
    const size_t end = std::min(session.candidates.size(), cursor + limit);
    json candidates = json::array();
    for (size_t i = cursor; i < end; ++i) candidates.push_back(formatter(session.candidates[i]));
    return {{"sessionId", session.id}, {"pid", session.pid},
            {"processStartTime", std::to_string(session.processStartTime)},
            {"mapRevision", session.revision}, {"candidates", candidates},
            {"returned", candidates.size()}, {"totalCandidates", session.candidates.size()},
            {"scannedBytes", session.scannedBytes}, {"skippedBytes", session.skippedBytes},
            {"truncated", session.truncated},
            {"nextCursor", end < session.candidates.size() ? json(std::to_string(end)) : json(nullptr)}};
}

std::unordered_set<std::string> RequestedMapIds(const json &args)
{
    std::unordered_set<std::string> ids;
    for (const auto &id : args.value("mapIds", json::array()))
        if (id.is_string()) ids.insert(id.get<std::string>());
    return ids;
}

std::string MapId(const KittyMemoryEx::ProcMap &map)
{
    return "map:" + FormatAddress(map.startAddress).substr(2);
}

std::vector<KittyMemoryEx::ProcMap> CandidateMaps(const json &args, const MapSnapshot &snapshot,
                                                   bool names)
{
    const std::string region = args.value("region", names ? "ELF_SEGMENTS" : "MODULE_RW");
    const auto mapIds = RequestedMapIds(args);
    std::vector<KittyMemoryEx::ProcMap> maps;
    for (const auto &map : snapshot.maps)
    {
        // 国服 FNamePool / GUObjectArray 落在 [anon:.bss]，perms 无 r（readable=false）但
        // pread 回退读得到。只放行 readable 会让 region=BSS 跳过真池所在的那个 VMA——
        // 实测 scanGnames 因此只报了一个 score 30 的结构假阳性，真池从不进榜。
        if (!map.readable && !map.writeable) continue;
        if (!mapIds.empty() && !mapIds.count(MapId(map))) continue;
        const bool ueModule = map.pathname.find("libUE4.so") != std::string::npos ||
                              map.pathname.find("libUnreal.so") != std::string::npos;
        const bool anonymous = map.pathname.empty() || map.pathname.front() == '[';
        bool use = false;
        if (!mapIds.empty()) use = true;
        else if (region == "ALL_READABLE") use = true;
        else if (region == "ELF_SEGMENTS") use = ueModule;
        else if (region == "BSS") use = map.writeable && (anonymous || ueModule);
        else if (region == "MODULE_RW") use = map.writeable && ueModule;
        else throw HandlerError(Err::kBadArgs, "未知 region: " + region);
        if (use) maps.push_back(map);
    }
    if (maps.empty()) throw HandlerError(Err::kNotFound, "候选扫描范围内没有可读映射");
    // FNamePool / GUObjectArray 落在 [anon:.bss]——Android 给已加载 ELF 的 .bss 的命名。
    // 光按大小降序排是错的：进程里同时有 GB 级的 dalvik-LinearAlloc / jit-cache / GPU
    // 映射，DFM 可写映射共 4167MB/1800 个、最大的两个各 1GB，64MB 预算会被它们整段吃掉，
    // 真池所在的 14.7MB [anon:.bss] 永远轮不到（实测 scannedBytes=64MB、candidates=0）。
    // 所以先按「像不像 UE 的 BSS」分级，同级内再按大小降序。
    // 指定了 mapIds 时调用方已经圈定范围，保持原顺序。
    if (mapIds.empty())
    {
        const auto regionRank = [](const KittyMemoryEx::ProcMap &m) -> int
        {
            const std::string &p = m.pathname;
            // .bss 必须排在 .so 自己的段之前：FNamePool/GUObjectArray 在 [anon:.bss] 里，
            // 而 .so 的 rw 数据段全是 vtable/指针数组，会瞬间把 maxCandidates 刷满。
            if (p.find(".bss") != std::string::npos) return 0;
            if (p.find("libUE4.so") != std::string::npos ||
                p.find("libUnreal.so") != std::string::npos)
                return 1;
            const bool noise = p.find("dalvik") != std::string::npos ||
                               p.find("jit") != std::string::npos ||
                               p.find("mali") != std::string::npos ||
                               p.find("gralloc") != std::string::npos ||
                               p.find("ashmem") != std::string::npos ||
                               p.rfind("/dev/", 0) == 0;
            if (noise) return 3;
            return (p.empty() || p.front() == '[') ? 2 : 3;
        };
        std::sort(maps.begin(), maps.end(),
                  [&regionRank](const KittyMemoryEx::ProcMap &a, const KittyMemoryEx::ProcMap &b)
                  {
                      const int ra = regionRank(a), rb = regionRank(b);
                      if (ra != rb) return ra < rb;
                      const size_t sa = a.endAddress > a.startAddress
                          ? static_cast<size_t>(a.endAddress - a.startAddress) : 0;
                      const size_t sb = b.endAddress > b.startAddress
                          ? static_cast<size_t>(b.endAddress - b.startAddress) : 0;
                      return sa > sb;
                  });
        if (names && region == "BSS")
        {
            constexpr size_t kMinBssBytes = 256 * 1024;
            maps.erase(std::remove_if(maps.begin(), maps.end(),
                       [](const KittyMemoryEx::ProcMap &m)
                       {
                           const size_t n = m.endAddress > m.startAddress
                               ? static_cast<size_t>(m.endAddress - m.startAddress) : 0;
                           return n < kMinBssBytes;
                       }),
                       maps.end());
            if (maps.empty())
                throw HandlerError(Err::kNotFound, "候选扫描范围内没有可读映射");
        }
    }
    return maps;
}

// FName 正文的字节处理方式。见 Utils/NameCipher.hpp。
enum class NameDecode
{
    Raw,     // 当明文用，不做任何变换
    Cipher,  // 强制按该变换解一遍
    Auto,    // 解一遍，只有解出来明显比原文更像名字时才采用（对不加密的游戏等价于 Raw）
};

const char *NameDecodeName(NameDecode mode)
{
    switch (mode)
    {
    case NameDecode::Cipher: return "dfm";
    case NameDecode::Auto:   return "auto";
    default:                 return "none";
    }
}

NameDecode ParseNameDecode(const std::string &value)
{
    if (value == "dfm" || value == "cipher") return NameDecode::Cipher;
    if (value == "none" || value == "raw") return NameDecode::Raw;
    if (value == "auto") return NameDecode::Auto;
    throw HandlerError(Err::kBadArgs, "decode 须为 auto / dfm / none");
}

bool ReadNameHeader(const KittyMemoryMgr &mgr, uintptr_t entry, const NameLayout &layout,
                    size_t &length, bool &wide)
{
    uint16_t header = 0;
    if (!ReadValue(mgr, entry + layout.headerOff, header))
        return false;
    length = header >> layout.lengthShift;
    wide = (header & 1) != 0;
    return true;
}

// 条目字节数 → 走到下一个真实 id 的步长。FNamePool 的 id 就是「字节偏移 / stride」，
// 条目首尾相接，所以相邻两个真实 id 的间隔 = 条目占位 / stride，而不是 1。
// 按 id 自增枚举会落进条目正文中间，把后续若干条目拼成一个长串（夹在被当正文的 2 字节
// header），看起来就是一串 "??"。要顺序枚举就必须用这个步长走。
//
// 占位要把字节数向上对齐到 stride：分配器 FNameEntryAllocator::Allocate 就是这么切的，
// 用裸的 2 + 正文会漏掉对齐填充。奇数长的名字会因此错位（"Color" len 5 真实占 8 字节、
// 下一个 id 是 +4，按 2+5=7 算成 +3 就踩进下一条目的正文），之后整条链全歪。
int32_t NameEntryStep(size_t length, bool wide, uintptr_t stride)
{
    if (!stride) stride = 2;
    const size_t bytes = sizeof(uint16_t) + (wide ? length * 2 : length);
    const size_t padded = (bytes + stride - 1) / stride * stride;
    return static_cast<int32_t>(padded / stride);
}

bool DecodeNameAt(const KittyMemoryMgr &mgr, uintptr_t block, uint32_t offsetUnits,
                  const NameLayout &layout, std::string &name, std::string &failure,
                  NameDecode mode = NameDecode::Raw, bool *outDecoded = nullptr)
{
    if (outDecoded) *outDecoded = false;
    const uintptr_t entry = block + static_cast<uintptr_t>(offsetUnits) * layout.stride;
    size_t length = 0;
    bool wide = false;
    if (!ReadNameHeader(mgr, entry, layout, length, wide))
    {
        failure = "entry header unreadable";
        return false;
    }
    if (length < 1 || length > 127)
    {
        failure = "entry length out of range";
        return false;
    }
    const uintptr_t text = entry + layout.headerOff + sizeof(uint16_t);
    if (!wide)
    {
        std::vector<char> bytes(length);
        if (mgr.readMem(text, bytes.data(), length) != length)
        {
            failure = "entry bytes unreadable";
            return false;
        }
        name.assign(bytes.begin(), bytes.end());
        if (mode != NameDecode::Raw)
        {
            std::string dec = name;
            UmtNameCipher::DecodeAnsi(dec);
            // Auto 的判据：解出来是纯 ASCII 可见字符、而原文不是。密文里出现 >=0x80 很常见
            // （None 的密文是 b1 90 91 9a），所以这条能把「解对了」和「本来就不用解」分开；
            // 对不加密的游戏原文本来就是纯 ASCII，Auto 会保持原样，不会误伤。
            const bool take = (mode == NameDecode::Cipher) ||
                              (IsPlainAsciiName(dec) && !IsPlainAsciiName(name));
            if (take)
            {
                name.swap(dec);
                if (outDecoded) *outDecoded = true;
            }
        }
    }
    else
    {
        // 宽字符正文是 UTF-16LE，长度是字符数。旧实现按 ASCII 截断并在 ch>0x7F 直接失败，
        // 所以 CJK 名在候选扫描里永远看不见。解码走 NameCipher 那条已经在 dump 路径验证过
        // 的 DecodeWideToUtf8；Raw 只做 UTF-16→UTF-8，不异或。
        std::vector<char> body(length * 2);
        if (mgr.readMem(text, body.data(), body.size()) != body.size())
        {
            failure = "wide entry bytes unreadable";
            return false;
        }
        const auto chars = static_cast<uint32_t>(length);
        if (mode == NameDecode::Raw)
        {
            name = UmtNameCipher::Utf16LeToUtf8(body.data(), chars);
        }
        else
        {
            std::string dec = UmtNameCipher::DecodeWideToUtf8(body.data(), chars);
            if (mode == NameDecode::Cipher)
            {
                name.swap(dec);
                if (outDecoded) *outDecoded = true;
            }
            else
            {
                std::string rawUtf8 = UmtNameCipher::Utf16LeToUtf8(body.data(), chars);
                // 跟 ANSI Auto 同一结构：解出来像名字、原文不像，才采用。未加密的宽字符
                // 游戏原文已经 plausible，Auto 保持原样。
                // 变换是对合，所以「两边都像名字」时 Auto 无法判断该不该解——DFM 的 L=2
                // 「地图」密文本身也是 CJK（啯图），Auto 会留下密文。要解这种名字用 decode=dfm。
                const bool take = IsPlausibleFName(dec) && !IsPlausibleFName(rawUtf8);
                if (take)
                {
                    name.swap(dec);
                    if (outDecoded) *outDecoded = true;
                }
                else
                {
                    name.swap(rawUtf8);
                }
            }
        }
    }
    if (!IsPrintableName(name))
    {
        failure = "entry text is not printable";
        return false;
    }
    return true;
}

bool DecodeNameId(const KittyMemoryMgr &mgr, const NameCandidate &candidate, int32_t id,
                  std::string &name, std::string &failure,
                  NameDecode mode = NameDecode::Raw, bool *outDecoded = nullptr)
{
    if (id < 0) { failure = "negative name id"; return false; }
    const uint32_t blockIndex = static_cast<uint32_t>(id) >> candidate.layout.blocksBit;
    const uint32_t offset = static_cast<uint32_t>(id) & ((1U << candidate.layout.blocksBit) - 1U);
    uintptr_t block = 0;
    if (!ReadValue(mgr, candidate.poolAddress + candidate.layout.blocksOff +
                         static_cast<uintptr_t>(blockIndex) * sizeof(uintptr_t), block) || !block)
    {
        failure = "block pointer unreadable";
        return false;
    }
    return DecodeNameAt(mgr, block, offset, candidate.layout, name, failure, mode, outDecoded);
}

NameCandidate ValidateNameCandidate(const KittyMemoryMgr &mgr, const MapSnapshot &snapshot,
                                    uintptr_t pool, uintptr_t slot, uintptr_t blockValue,
                                    const NameLayout &layout,
                                    const std::vector<uint32_t> &anchorOffsets,
                                    const std::unordered_set<std::string> &anchorNames,
                                    NameDecode mode)
{
    NameCandidate candidate;
    candidate.poolAddress = pool;
    candidate.slotAddress = slot;
    candidate.layout = layout;
    if (IsAccessibleAddress(snapshot, pool, layout.blocksOff + sizeof(uintptr_t)))
    {
        candidate.score += 5;
        candidate.evidence.push_back("pool address is readable");
    }
    else
    {
        candidate.failedChecks.push_back("pool address is not readable");
        return candidate;
    }
    // blockValue 由调用方传入：它就是调用方在缓冲里已经读到的 *(uintptr_t*)slot，而
    // 调用方是拿 pool = slot - blocksOff 反推的，所以 pool + blocksOff == slot，
    // 这里再 ReadValue 一次读的是同一个地址 —— 纯冗余的 pread 系统调用。
    // 扫描热循环里每个候选省一次，是实测耗时的大头之一。
    if (!IsAccessibleAddress(snapshot, blockValue, 4))
    {
        candidate.failedChecks.push_back("Blocks[0] is unreadable");
        return candidate;
    }
    candidate.block0 = blockValue;
    candidate.score += 10;
    candidate.evidence.push_back({{"check", "Blocks[0] readable"},
                                  {"address", FormatAddress(candidate.block0)}});

    // 廉价前置门禁：真池的 Blocks[0] 指向一个名称块，其首个条目（偏移 0）必然是合法条目
    // —— UE 的 FNamePool 块从第一个被分配的条目开始，索引 0 就是 "None"。所以「偏移 0 的
    // header 不可读或长度越界」的候选可以直接判死，不必再走完 8 个锚点偏移。
    // 每个被挡掉的候选省下 7 次 pread；扫描热循环里有上百万个候选，这是主要开销。
    // 仅在调用方确实会试 offset 0 时启用（默认 anchorOffsets 以 0 开头）；调用方传了
    // 不含 0 的自定义偏移时跳过此门禁，保持原有语义、避免误杀。
    if (!anchorOffsets.empty() && anchorOffsets.front() == 0)
    {
        size_t len0 = 0;
        bool wide0 = false;
        if (!ReadNameHeader(mgr, candidate.block0, layout, len0, wide0) || len0 < 1 || len0 > 127)
        {
            candidate.failedChecks.push_back("Blocks[0] first entry header invalid");
            return candidate;
        }
    }

    int valid = 0, anchors = 0;
    for (uint32_t offset : anchorOffsets)
    {
        std::string name, failure;
        bool decoded = false;
        // 必须按 mode 解一遍再比：DFM 这类游戏的正文是异或过的，拿密文跟 "None"/anchor
        // 比永远不相等，于是锚点分（+15/+8/+20）在这类游戏上恒为 0，候选自校验形同虚设。
        if (!DecodeNameAt(mgr, candidate.block0, offset, layout, name, failure, mode, &decoded)) continue;
        ++valid;
        if (candidate.evidence.size() < 5)
            candidate.evidence.push_back({{"offset", offset}, {"name", name}, {"decoded", decoded}});
        if (name == "None") candidate.score += 15;
        if (anchorNames.count(name)) { ++anchors; candidate.score += 8; }
    }
    if (valid >= 3) candidate.score += 15;
    else candidate.failedChecks.push_back("fewer than three anchor offsets decoded");
    if (anchors >= 3) candidate.score += 20;
    else if (anchors == 0) candidate.failedChecks.push_back("no requested anchor name matched");
    candidate.anchorHits = anchors;
    return candidate;
}

// 进程身份只看 pid + starttime。整份 /proc/pid/maps 的 FNV 会因无关 VMA
// （堆、GPU、ashmem、JIT）抖动而变，DFM 上扫描刚结束 sample 就会 E_MAP_STALE。
// sample / override 真正依赖的是候选地址还在；可读性由调用方用 snapshot 验。
const NameCandidate &GetNameCandidate(const std::string &sessionId, int candidateId,
                                      pid_t pid, uint64_t processStartTime)
{
    auto it = gNameSessions.find(sessionId);
    if (it == gNameSessions.end() || it->second.pid != pid ||
        it->second.processStartTime != processStartTime)
        throw HandlerError(Err::kSessionStale, "names candidate session 不存在或进程已切换");
    for (const auto &candidate : it->second.candidates)
        if (candidate.id == candidateId) return candidate;
    throw HandlerError(Err::kSessionStale, "names candidateId 不存在");
}

const ObjectCandidate &GetObjectCandidate(const std::string &sessionId, int candidateId,
                                          pid_t pid, uint64_t processStartTime)
{
    auto it = gObjectSessions.find(sessionId);
    if (it == gObjectSessions.end() || it->second.pid != pid ||
        it->second.processStartTime != processStartTime)
        throw HandlerError(Err::kSessionStale, "objects candidate session 不存在或进程已切换");
    for (const auto &candidate : it->second.candidates)
        if (candidate.id == candidateId) return candidate;
    throw HandlerError(Err::kSessionStale, "objects candidateId 不存在");
}

bool ReadObjectAt(const KittyMemoryMgr &mgr, const ObjectCandidate &candidate, int32_t index,
                  uintptr_t &object)
{
    object = 0;
    if (index < 0 || index >= candidate.numElements || candidate.layout.itemSize == 0)
        return false;
    const ObjectLayout &layout = candidate.layout;
    uintptr_t itemBase = candidate.objectsAddress;
    if (layout.chunked)
    {
        if (layout.numElementsPerChunk == 0)
            return false;
        const uint32_t chunkIndex = static_cast<uint32_t>(index) / layout.numElementsPerChunk;
        const uint32_t within = static_cast<uint32_t>(index) % layout.numElementsPerChunk;
        uintptr_t chunk = 0;
        if (!ReadValue(mgr, candidate.objectsAddress + chunkIndex * sizeof(uintptr_t), chunk) || !chunk)
            return false;
        itemBase = chunk + static_cast<uintptr_t>(within) * layout.itemSize;
    }
    else
        itemBase += static_cast<uintptr_t>(index) * layout.itemSize;
    return ReadValue(mgr, itemBase + layout.itemObjectOff, object) && object >= 0x10000;
}

ObjectCandidate ValidateObjectCandidate(const KittyMemoryMgr &mgr, const MapSnapshot &snapshot,
                                        uintptr_t array, const ObjectLayout &layout)
{
    ObjectCandidate candidate;
    candidate.arrayAddress = array;
    candidate.layout = layout;
    const uintptr_t objObjects = array + layout.objObjectsOff;
    if (!ReadValue(mgr, objObjects + layout.objectsOff, candidate.objectsAddress) ||
        !IsWritableAddress(snapshot, candidate.objectsAddress, sizeof(uintptr_t)))
    {
        candidate.failedChecks.push_back("Objects/Chunks pointer is not writable storage");
        return candidate;
    }
    candidate.score += 15;
    candidate.evidence.push_back({{"check", "Objects/Chunks pointer readable"},
                                  {"address", FormatAddress(candidate.objectsAddress)}});
    if (layout.chunked)
    {
        uintptr_t firstChunk = 0;
        if (!ReadValue(mgr, candidate.objectsAddress, firstChunk) ||
            !IsWritableAddress(snapshot, firstChunk, layout.itemSize))
        {
            candidate.failedChecks.push_back("first chunk is not writable storage");
            return candidate;
        }
        candidate.evidence.push_back({{"check", "first chunk writable"},
                                      {"address", FormatAddress(firstChunk)}});
    }
    if (!ReadValue(mgr, objObjects + layout.numElementsOff, candidate.numElements) ||
        candidate.numElements < 1024 || candidate.numElements > 5000000)
    {
        candidate.failedChecks.push_back("NumElements outside 1024..5000000");
        return candidate;
    }
    candidate.score += 10;
    candidate.evidence.push_back({{"check", "NumElements plausible"},
                                  {"value", candidate.numElements}});

    int readableObjects = 0, readableClasses = 0;
    for (int32_t i = 0; i < std::min<int32_t>(candidate.numElements, 32); ++i)
    {
        uintptr_t object = 0;
        if (!ReadObjectAt(mgr, candidate, i, object) || !IsAccessibleAddress(snapshot, object, 8)) continue;
        ++readableObjects;
        uintptr_t klass = 0;
        if (ReadValue(mgr, object + layout.classPrivateOff, klass) && IsAccessibleAddress(snapshot, klass, 8))
            ++readableClasses;
    }
    if (readableObjects >= 3)
    {
        candidate.score += 15;
        candidate.evidence.push_back({{"check", "readable UObject samples"}, {"count", readableObjects}});
    }
    else candidate.failedChecks.push_back("fewer than three readable UObject samples");
    if (readableClasses >= 2)
    {
        candidate.score += 10;
        candidate.evidence.push_back({{"check", "readable ClassPrivate samples"}, {"count", readableClasses}});
    }
    else candidate.failedChecks.push_back("fewer than two readable ClassPrivate samples");
    return candidate;
}

void EnhanceObjectCandidateWithNames(const KittyMemoryMgr &mgr, ObjectCandidate &candidate,
                                     const NameCandidate &names, NameDecode mode)
{
    int decoded = 0;
    int anchors = 0;
    for (int32_t i = 0; i < std::min<int32_t>(candidate.numElements, 32); ++i)
    {
        uintptr_t object = 0;
        if (!ReadObjectAt(mgr, candidate, i, object)) continue;
        int32_t nameId = -1;
        if (!ReadValue(mgr, object + candidate.layout.namePrivateOff, nameId)) continue;
        std::string name, failure;
        if (!DecodeNameId(mgr, names, nameId, name, failure, mode)) continue;
        ++decoded;
        if (name == "Object" || name == "Package" || name == "Class" ||
            name.find("CoreUObject") != std::string::npos)
            ++anchors;
        if (candidate.evidence.size() < 5)
            candidate.evidence.push_back({{"check", "name decoded"}, {"index", i}, {"name", name}});
    }
    if (decoded >= 3) candidate.score += 10;
    else candidate.failedChecks.push_back("fewer than three UObject names decoded");
    if (anchors > 0)
    {
        candidate.score += 20;
        if (candidate.evidence.size() < 5)
            candidate.evidence.push_back({{"check", "CoreUObject anchor names"}, {"count", anchors}});
    }
    else candidate.failedChecks.push_back("no Object/Package/Class/CoreUObject anchor name");
}
}

json ScanGNamesCandidates(const json &args, const KittyMemoryMgr &mgr, const std::atomic<bool> *cancelFlag)
{
    if (!mgr.isMemValid()) throw HandlerError(Err::kNotAttached, "未 attach 到目标进程");
    const MapSnapshot snapshot = CaptureMaps(mgr);
    const std::string existingId = args.value("sessionId", "");
    if (!existingId.empty())
    {
        std::lock_guard<std::mutex> lock(gCandidateMutex);
        auto it = gNameSessions.find(existingId);
        if (it == gNameSessions.end() || it->second.pid != snapshot.pid ||
            it->second.processStartTime != snapshot.processStartTime)
            throw HandlerError(Err::kSessionStale, "names candidate session 不存在或进程已切换");
        return PageCandidates(it->second, args, NameCandidateJson);
    }
    const auto maps = CandidateMaps(args, snapshot, true);
    std::vector<NameLayout> layouts;
    for (const auto &item : args.value("layouts", json::array())) layouts.push_back(ParseNameLayout(item));
    if (layouts.empty())
    {
        // 调用方没给布局时不能只试标准 UE 那一套（BlocksOff 0x40 / BlocksBit 16）：
        // 国服的块表比标准版前移一个指针、块位宽也是 18（DeltaForce.hpp 里
        // BlocksBit=18、BlocksOff -= sizeof(void*)），只试标准布局时真池永远进不了候选。
        // 多一套布局的代价只是内层多跑一遍自校验——外层槽位过滤与布局无关。
        layouts.push_back({});
        NameLayout cn{};
        cn.blocksOff -= static_cast<uint32_t>(sizeof(void *));
        cn.blocksBit = 18;
        layouts.push_back(cn);
    }
    std::vector<uint32_t> anchorOffsets = {0, 2, 4, 6, 8, 10, 12, 16};
    if (args.contains("anchorOffsets") && args["anchorOffsets"].is_array())
    {
        anchorOffsets.clear();
        for (const auto &off : args["anchorOffsets"])
            if (off.is_number_unsigned() || off.is_number_integer()) anchorOffsets.push_back(off.get<uint32_t>());
    }
    // Convert byte offsets to unit offsets (÷ stride) since DecodeNameAt multiplies by stride.
    for (auto &o : anchorOffsets)
        o = o / layouts[0].stride;
    std::unordered_set<std::string> anchorNames = {"None", "ByteProperty", "IntProperty", "Object"};
    for (const auto &name : args.value("anchorNames", json::array()))
        if (name.is_string()) anchorNames.insert(name.get<std::string>());
    // decode: "auto"（默认，解一遍、只有更像名字才采用）/ "dfm"（强制解）/ "none"（当明文）。
    // 不加密的游戏用 auto 等价于 none，所以默认值对两边都安全。
    const NameDecode mode = ParseNameDecode(args.value("decode", "auto"));
    const int maxCandidates = std::clamp(args.value("maxCandidates", 50), 1, 200);
    const size_t budget = static_cast<size_t>(std::clamp<int64_t>(
        args.value("maxScanBytes", static_cast<int64_t>(kDefaultScanBudget)), 4096, 256LL * 1024 * 1024));
    uintptr_t minPtr = 0;
    uintptr_t maxPtr = std::numeric_limits<uintptr_t>::max();
    if (args.contains("minPtr") && !ParseAddress(args.value("minPtr", ""), minPtr))
        throw HandlerError(Err::kBadArgs, "minPtr 地址格式无效");
    if (args.contains("maxPtr") && !ParseAddress(args.value("maxPtr", ""), maxPtr))
        throw HandlerError(Err::kBadArgs, "maxPtr 地址格式无效");
    if (maxPtr <= minPtr) throw HandlerError(Err::kBadArgs, "maxPtr 须大于 minPtr");

    NameSession session;
    session.pid = snapshot.pid;
    session.processStartTime = snapshot.processStartTime;
    session.revision = snapshot.revision;
    session.id = NewId("names");
    size_t scanned = 0, skipped = 0;
    bool truncated = false;
    std::vector<uint8_t> buffer(kChunk);
    uint32_t minBlocksOff = layouts[0].blocksOff;
    uint32_t maxBlocksOff = layouts[0].blocksOff;
    for (const auto &layout : layouts)
    {
        minBlocksOff = std::min(minBlocksOff, layout.blocksOff);
        maxBlocksOff = std::max(maxBlocksOff, layout.blocksOff);
    }
    for (const auto &map : maps)
    {
        // minPtr/maxPtr 过滤的是 pool 地址，slot = pool + blocksOff。
        // 不跳过窗口外的 chunk 就会从 BSS 头读十几 MB 才碰到真池（job_11 扫了 15MB
        // 才命中 192 字节窗口里的 0x7408a96ec0）。
        uintptr_t rangeStart = map.startAddress;
        uintptr_t rangeEnd = map.endAddress;
        if (minPtr != 0 || maxPtr != std::numeric_limits<uintptr_t>::max())
        {
            const uintptr_t slotLo = minPtr > std::numeric_limits<uintptr_t>::max() - minBlocksOff
                ? std::numeric_limits<uintptr_t>::max() : minPtr + minBlocksOff;
            const uintptr_t slotHi = maxPtr > std::numeric_limits<uintptr_t>::max() - maxBlocksOff
                ? std::numeric_limits<uintptr_t>::max() : maxPtr + maxBlocksOff;
            if (slotLo > rangeStart) rangeStart = slotLo & ~static_cast<uintptr_t>(7);
            if (slotHi < rangeEnd) rangeEnd = slotHi;
            if (rangeEnd <= rangeStart) continue;
        }
        for (uintptr_t cursor = rangeStart; cursor < rangeEnd && scanned < budget; cursor += kChunk)
        {
            if (cancelFlag && cancelFlag->load()) throw HandlerError(Err::kCancelled, "FNamePool 候选扫描已取消");
            const size_t size = std::min<size_t>(kChunk, rangeEnd - cursor);
            const size_t got = mgr.readMem(cursor, buffer.data(), size);
            if (got < sizeof(uintptr_t)) { skipped += size; continue; }
            scanned += size;
            for (size_t off = 0; off + sizeof(uintptr_t) <= got; off += sizeof(uintptr_t))
            {
                uintptr_t value = 0;
                std::memcpy(&value, buffer.data() + off, sizeof(value));
                if (!IsAccessibleAddress(snapshot, value, 4)) continue;
                const uintptr_t slot = cursor + off;
                for (const auto &layout : layouts)
                {
                    uintptr_t pool = slot >= layout.blocksOff ? slot - layout.blocksOff : 0;
                    if (!pool || pool < minPtr || pool >= maxPtr) continue;
                    // 这里曾经有一个 seen 去重集（键是 pool+layout 拼成的十六进制字符串）。
                    // 它是多余的：slot = cursor + off 在一趟线性扫描里全局唯一（块内不重叠、
                    // maps 之间不重叠），所以 (pool, layout) 本来就不会重复。而它每个槽位都要
                    // 构造一次 ostringstream + std::string（堆分配 + locale 格式化），
                    // 8.4M 槽 × 2 布局 = 上千万次，是扫描耗时最大的单项。
                    NameCandidate candidate = ValidateNameCandidate(mgr, snapshot, pool, slot, value,
                                                                    layout, anchorOffsets, anchorNames,
                                                                    mode);
                    // 光靠分数筛不住：5(池可访问) + 10(Blocks[0] 可访问) + 15(解出 ≥3 个偏移)
                    // = 30 分是「指针密集段」的垃圾地板。实测扫 libUE4 自己的 rw 数据段，
                    // 1MB 内就刷满 20 个 30 分假货（anchors 全为 0），真池永远进不了榜。
                    // 真池必然在某个偏移解出锚点名（None 在 offset 0），所以判据用锚点命中数，
                    // 不用分数阈值。
                    if (candidate.anchorHits == 0) continue;
                    candidate.id = static_cast<int>(session.candidates.size());
                    session.candidates.push_back(std::move(candidate));
                    if (static_cast<int>(session.candidates.size()) >= maxCandidates)
                    {
                        truncated = true;
                        break;
                    }
                }
                if (truncated) break;
            }
            if (truncated) break;
        }
        if (truncated || scanned >= budget) break;
    }
    std::sort(session.candidates.begin(), session.candidates.end(),
              [](const NameCandidate &a, const NameCandidate &b) { return a.score > b.score; });
    // 扫描期间 maps 抖动不再丢结果：候选地址的可读性由 sample 再验。
    for (size_t i = 0; i < session.candidates.size(); ++i) session.candidates[i].id = static_cast<int>(i);
    session.scannedBytes = scanned;
    session.skippedBytes = skipped;
    session.truncated = truncated || scanned >= budget;

    {
        std::lock_guard<std::mutex> lock(gCandidateMutex);
        if (gNameSessions.size() >= kMaxCandidateSessions) gNameSessions.erase(gNameSessions.begin());
        gNameSessions[session.id] = session;
    }
    return PageCandidates(session, args, NameCandidateJson);
}

json SampleGNamesCandidate(const json &args, const KittyMemoryMgr &mgr)
{
    if (!mgr.isMemValid()) throw HandlerError(Err::kNotAttached, "未 attach 到目标进程");
    const MapSnapshot snapshot = CaptureMaps(mgr);
    const std::string sessionId = args.value("sessionId", "");
    const int candidateId = args.value("candidateId", -1);
    const int32_t start = args.value("startIndex", 0);
    const int32_t count = std::clamp(args.value("count", 32), 1, 200);
    if (start < 0) throw HandlerError(Err::kBadArgs, "startIndex 须 >= 0");
    std::lock_guard<std::mutex> lock(gCandidateMutex);
    const NameCandidate &candidate = GetNameCandidate(sessionId, candidateId, snapshot.pid,
                                                       snapshot.processStartTime);
    if (!IsReadableAddress(snapshot, candidate.poolAddress,
                           candidate.layout.blocksOff + sizeof(uintptr_t)))
        throw HandlerError(Err::kMapStale, "names candidate 的 FNamePool 已不可读");
    const NameDecode mode = ParseNameDecode(args.value("decode", "auto"));
    // walk 默认 true：沿条目链走（见 NameEntryStep 的说明）。传 false 退回按 id 自增，
    // 用来对照「某个 id 是不是刚好踩在条目边界上」——稠密模式下大量 valid=false 就说明
    // 这个池子的 id 不稠密。
    const bool walk = args.value("walk", true);
    json samples = json::array(), errors = json::array();
    int32_t id = start;
    for (int32_t n = 0; n < count; ++n)
    {
        std::string name, failure;
        bool decoded = false;
        const bool valid = DecodeNameId(mgr, candidate, id, name, failure, mode, &decoded);
        samples.push_back({{"index", id}, {"name", name}, {"valid", valid}, {"decoded", decoded}});
        if (!valid && errors.size() < 16) errors.push_back({{"index", id}, {"reason", failure}});
        if (!walk) { ++id; continue; }
        // 步长从 header 现算：len 就在条目里，不依赖调用方传 stride/blockBit 之外的东西
        uintptr_t block = 0;
        const uint32_t blockIndex = static_cast<uint32_t>(id) >> candidate.layout.blocksBit;
        const uint32_t off = static_cast<uint32_t>(id) & ((1U << candidate.layout.blocksBit) - 1U);
        size_t len = 0;
        bool wide = false;
        if (id < 0 ||
            !ReadValue(mgr, candidate.poolAddress + candidate.layout.blocksOff +
                                static_cast<uintptr_t>(blockIndex) * sizeof(uintptr_t), block) ||
            !block || !ReadNameHeader(mgr, block + static_cast<uintptr_t>(off) * candidate.layout.stride,
                                      candidate.layout, len, wide))
            break;
        const int32_t step = NameEntryStep(len, wide, candidate.layout.stride);
        if (step <= 0) break;
        id += step;
    }
    return {{"sessionId", sessionId}, {"candidateId", candidateId},
            {"poolAddress", FormatAddress(candidate.poolAddress)}, {"layout", NameLayoutJson(candidate.layout)},
            {"startIndex", start}, {"count", count}, {"walk", walk}, {"decode", NameDecodeName(mode)},
            {"samples", samples}, {"readErrors", errors}};
}

json ScanObjectCandidates(const json &args, const KittyMemoryMgr &mgr, const std::atomic<bool> *cancelFlag)
{
    if (!mgr.isMemValid()) throw HandlerError(Err::kNotAttached, "未 attach 到目标进程");
    const MapSnapshot snapshot = CaptureMaps(mgr);
    const std::string existingId = args.value("sessionId", "");
    if (!existingId.empty())
    {
        std::lock_guard<std::mutex> lock(gCandidateMutex);
        auto it = gObjectSessions.find(existingId);
        if (it == gObjectSessions.end() || it->second.pid != snapshot.pid ||
            it->second.processStartTime != snapshot.processStartTime)
            throw HandlerError(Err::kSessionStale, "objects candidate session 不存在或进程已切换");
        return PageCandidates(it->second, args, ObjectCandidateJson);
    }
    const auto maps = CandidateMaps(args, snapshot, false);
    std::vector<ObjectLayout> layouts;
    for (const auto &item : args.value("layouts", json::array())) layouts.push_back(ParseObjectLayout(item));
    if (layouts.empty())
    {
        layouts.push_back({});
        ObjectLayout flat;
        flat.chunked = false;
        layouts.push_back(flat);
    }
    const int maxCandidates = std::clamp(args.value("maxCandidates", 50), 1, 200);
    // 名字池正文的处理方式；配合 namesCandidate 做锚点匹配时，拿密文比 "Object" 永远不中
    const NameDecode mode = ParseNameDecode(args.value("decode", "auto"));
    const size_t budget = static_cast<size_t>(std::clamp<int64_t>(
        args.value("maxDistanceBytes", static_cast<int64_t>(kDefaultScanBudget)), 4096, 256LL * 1024 * 1024));

    const std::string direction = args.value("direction", "REGION");
    uintptr_t directionalStart = 0;
    uintptr_t directionalEnd = std::numeric_limits<uintptr_t>::max();
    if (direction != "REGION")
    {
        if (direction != "UP" && direction != "DOWN" && direction != "BOTH")
            throw HandlerError(Err::kBadArgs, "direction 必须是 UP/DOWN/BOTH/REGION");
        uintptr_t origin = 0;
        if (!ParseAddress(args.value("origin", ""), origin))
            throw HandlerError(Err::kBadArgs, "UP/DOWN/BOTH 必须提供有效 origin");
        if (direction == "UP" || direction == "BOTH")
            directionalStart = origin > budget ? origin - budget : 0;
        else directionalStart = origin;
        if (direction == "DOWN" || direction == "BOTH")
            directionalEnd = origin > std::numeric_limits<uintptr_t>::max() - budget
                ? std::numeric_limits<uintptr_t>::max() : origin + budget;
        else directionalEnd = origin;
    }

    ObjectSession session;
    session.pid = snapshot.pid;
    session.processStartTime = snapshot.processStartTime;
    session.revision = snapshot.revision;
    session.id = NewId("objects");
    const std::string namesSessionId = args.value("namesSessionId", "");
    const int namesCandidateId = args.value("namesCandidateId", -1);
    std::optional<NameCandidate> namesCandidate;
    if (!namesSessionId.empty() || namesCandidateId >= 0)
    {
        if (namesSessionId.empty() || namesCandidateId < 0)
            throw HandlerError(Err::kBadArgs, "namesSessionId 与 namesCandidateId 必须同时提供");
        std::lock_guard<std::mutex> lock(gCandidateMutex);
        namesCandidate = GetNameCandidate(namesSessionId, namesCandidateId,
                                          snapshot.pid, snapshot.processStartTime);
    }
    size_t scanned = 0, skipped = 0;
    bool truncated = false;
    std::unordered_set<std::string> seen;
    std::vector<uint8_t> buffer(kChunk + 0x500);
    for (const auto &map : maps)
    {
        const uintptr_t mapStart = std::max(static_cast<uintptr_t>(map.startAddress), directionalStart);
        const uintptr_t mapEnd = std::min(static_cast<uintptr_t>(map.endAddress), directionalEnd);
        if (mapEnd <= mapStart) continue;
        for (uintptr_t cursor = mapStart; cursor < mapEnd && scanned < budget; cursor += kChunk)
        {
            if (cancelFlag && cancelFlag->load())
                throw HandlerError(Err::kCancelled, "GUObjectArray 候选扫描已取消");
            const size_t primary = std::min<size_t>(kChunk, mapEnd - cursor);
            const size_t overlap = std::min<size_t>(0x500, mapEnd - cursor - primary);
            const size_t got = mgr.readMem(cursor, buffer.data(), primary + overlap);
            if (got < 0x20) { skipped += primary; continue; }
            scanned += primary;
            for (size_t local = 0; local + 0x20 <= primary; local += sizeof(uintptr_t))
            {
                const uintptr_t address = cursor + local;
                for (const auto &layout : layouts)
                {
                    const size_t objectsPos = local + layout.objObjectsOff + layout.objectsOff;
                    const size_t countPos = local + layout.objObjectsOff + layout.numElementsOff;
                    if (objectsPos + sizeof(uintptr_t) > got || countPos + sizeof(int32_t) > got) continue;
                    uintptr_t objects = 0;
                    int32_t count = 0;
                    std::memcpy(&objects, buffer.data() + objectsPos, sizeof(objects));
                    std::memcpy(&count, buffer.data() + countPos, sizeof(count));
                    if (count < 1024 || count > 5000000 ||
                        !IsReadableAddress(snapshot, objects, sizeof(uintptr_t)))
                        continue;
                    std::ostringstream key;
                    key << std::hex << address << ':' << layout.objObjectsOff << ':' << layout.objectsOff
                        << ':' << layout.numElementsOff << ':' << layout.chunked << ':'
                        << layout.numElementsPerChunk << ':' << layout.itemObjectOff << ':' << layout.itemSize
                        << ':' << layout.classPrivateOff << ':' << layout.namePrivateOff << ':' << layout.outerPrivateOff;
                    if (!seen.insert(key.str()).second) continue;
                    ObjectCandidate candidate = ValidateObjectCandidate(mgr, snapshot, address, layout);
                    if (candidate.score < 25) continue;
                    if (namesCandidate) EnhanceObjectCandidateWithNames(mgr, candidate, *namesCandidate, mode);
                    candidate.id = static_cast<int>(session.candidates.size());
                    candidate.namesSessionId = namesSessionId;
                    candidate.namesCandidateId = namesCandidateId;
                    session.candidates.push_back(std::move(candidate));
                    if (static_cast<int>(session.candidates.size()) >= maxCandidates)
                    {
                        truncated = true;
                        break;
                    }
                }
                if (truncated) break;
            }
            if (truncated) break;
        }
        if (truncated || scanned >= budget) break;
    }
    std::sort(session.candidates.begin(), session.candidates.end(),
              [](const ObjectCandidate &a, const ObjectCandidate &b) { return a.score > b.score; });
    // 同 ScanGNamesCandidates：扫描期间 maps 抖动不该丢结果，候选地址可读性由 sample 再验。
    for (size_t i = 0; i < session.candidates.size(); ++i) session.candidates[i].id = static_cast<int>(i);
    session.scannedBytes = scanned;
    session.skippedBytes = skipped;
    session.truncated = truncated || scanned >= budget;
    {
        std::lock_guard<std::mutex> lock(gCandidateMutex);
        if (gObjectSessions.size() >= kMaxCandidateSessions) gObjectSessions.erase(gObjectSessions.begin());
        gObjectSessions[session.id] = session;
    }
    return PageCandidates(session, args, ObjectCandidateJson);
}

json SampleObjectCandidate(const json &args, const KittyMemoryMgr &mgr)
{
    if (!mgr.isMemValid()) throw HandlerError(Err::kNotAttached, "未 attach 到目标进程");
    const MapSnapshot snapshot = CaptureMaps(mgr);
    const std::string sessionId = args.value("sessionId", "");
    const int candidateId = args.value("candidateId", -1);
    const int32_t start = args.value("startIndex", 0);
    const int32_t count = std::clamp(args.value("count", 32), 1, 200);
    const NameDecode mode = ParseNameDecode(args.value("decode", "auto"));
    std::lock_guard<std::mutex> lock(gCandidateMutex);
    const ObjectCandidate &candidate = GetObjectCandidate(sessionId, candidateId, snapshot.pid,
                                                          snapshot.processStartTime);
    if (start < 0 || start >= candidate.numElements)
        throw HandlerError(Err::kBadArgs, "startIndex 越界");

    const NameCandidate *names = nullptr;
    if (!candidate.namesSessionId.empty() && candidate.namesCandidateId >= 0)
    {
        try { names = &GetNameCandidate(candidate.namesSessionId, candidate.namesCandidateId,
                                        snapshot.pid, snapshot.processStartTime); }
        catch (const HandlerError &) { names = nullptr; }
    }
    json samples = json::array(), errors = json::array();
    for (int32_t index = start; index < std::min(candidate.numElements, start + count); ++index)
    {
        uintptr_t object = 0, klass = 0, outer = 0;
        int32_t nameId = -1;
        const bool gotObject = ReadObjectAt(mgr, candidate, index, object);
        bool valid = gotObject && IsReadableAddress(snapshot, object, 8);
        if (valid)
        {
            ReadValue(mgr, object + candidate.layout.classPrivateOff, klass);
            ReadValue(mgr, object + candidate.layout.outerPrivateOff, outer);
            ReadValue(mgr, object + candidate.layout.namePrivateOff, nameId);
        }
        std::string name, failure;
        bool decoded = false;
        if (valid && names) DecodeNameId(mgr, *names, nameId, name, failure, mode, &decoded);
        samples.push_back({{"index", index},
                           {"objectAddress", gotObject ? json(FormatAddress(object)) : json(nullptr)},
                           {"nameId", nameId}, {"name", name}, {"decoded", decoded},
                           {"classAddress", klass ? json(FormatAddress(klass)) : json(nullptr)},
                           {"outerAddress", outer ? json(FormatAddress(outer)) : json(nullptr)},
                           {"valid", valid}});
        if (!valid && errors.size() < 16) errors.push_back({{"index", index}, {"reason", "object unreadable"}});
    }
    return {{"sessionId", sessionId}, {"candidateId", candidateId},
            {"arrayAddress", FormatAddress(candidate.arrayAddress)}, {"numElements", candidate.numElements},
            {"layout", ObjectLayoutJson(candidate.layout)}, {"decode", NameDecodeName(mode)},
            {"samples", samples}, {"readErrors", errors}};
}

bool ValidateCandidateBinding(const std::string &kind, const std::string &sessionId,
                              int candidateId, pid_t pid, uint64_t processStartTime,
                              uintptr_t address, std::string &reason)
{
    std::lock_guard<std::mutex> lock(gCandidateMutex);
    try
    {
        if (kind == "names")
        {
            const NameCandidate &candidate = GetNameCandidate(sessionId, candidateId, pid,
                                                              processStartTime);
            if (candidate.poolAddress != address) { reason = "candidate address mismatch"; return false; }
            return true;
        }
        if (kind == "objects")
        {
            const ObjectCandidate &candidate = GetObjectCandidate(sessionId, candidateId, pid,
                                                                  processStartTime);
            if (candidate.arrayAddress != address) { reason = "candidate address mismatch"; return false; }
            return true;
        }
        reason = "unknown candidate kind";
        return false;
    }
    catch (const HandlerError &error)
    {
        reason = error.what();
        return false;
    }
}

void InvalidateCandidateSessions()
{
    std::lock_guard<std::mutex> lock(gCandidateMutex);
    gNameSessions.clear();
    gObjectSessions.clear();
}
}
