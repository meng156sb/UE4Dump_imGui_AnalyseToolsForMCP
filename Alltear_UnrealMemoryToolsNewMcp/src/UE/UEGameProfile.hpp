#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

#include "../Utils/Logger.hpp"

#include "UEMemory.hpp"
#include "UEOffsets.hpp"

enum class PATTERN_MAP_TYPE : int8_t
{
    ANY_R,  // Search in any private readable map

    ANY_X,  // Search in any private readable & executable map

    ANY_W,  // Search in any private readable & writeable map

    BSS,  // Search in .bss maps
};

struct UEAddressOverrides
{
    uintptr_t namesPtr = 0;
    uintptr_t guObjectArrayPtr = 0;
    bool hasNamesPtr = false;
    bool hasGUObjectArrayPtr = false;
    bool hasNameLayout = false;
    bool hasObjectLayout = false;

    uintptr_t nameStride = 0;
    uintptr_t nameBlocksBit = 0;
    uintptr_t nameBlocksOff = 0;
    uintptr_t nameHeaderOff = 0;
    uintptr_t nameLengthShift = 0;
    uintptr_t objObjectsOff = 0;
    uintptr_t objectsOff = 0;
    uintptr_t numElementsOff = 0;
    uintptr_t numElementsPerChunk = 0;
    uintptr_t itemObjectOff = 0;
    uintptr_t itemSize = 0;
    uintptr_t classPrivateOff = 0;
    uintptr_t namePrivateOff = 0;
    uintptr_t outerPrivateOff = 0;
};

class IGameProfile
{
public:
protected:
    UEVars _UEVars;
    UEAddressOverrides _addressOverrides;
    UE_Offsets _baseOffsetsBackup;
    bool _hasOffsetsBackup = false;

public:
    virtual ~IGameProfile() = default;

    UEVarsInitStatus InitUEVars();
    const UEVars *GetUEVars() const { return &_UEVars; }
    void SetAddressOverrides(const UEAddressOverrides &overrides);

    virtual ElfScanner GetUnrealELF() const;

    // arch support check
    virtual bool ArchSupprted() const = 0;

    virtual std::string GetAppName() const = 0;

    virtual std::vector<std::string> GetAppIDs() const = 0;

    virtual bool isUsingCasePreservingName() const = 0;

    virtual bool IsUsingFNamePool() const = 0;

    virtual bool isUsingOutlineNumberName() const = 0;

    virtual UE_Offsets *GetOffsets() const = 0;

    // Address of the `UWorld*` / `UEngine*` global *pointer variable* (the slot),
    // or 0 when this build cannot name it. A profile that has a verified
    // module-relative offset for the slot should return `base + rva`; that is
    // strictly more reliable than guessing which object instance is the global,
    // because a class like UWorld has many live instances and the reference scan
    // cannot tell the global apart from a transient one. Public because the
    // dumper consumes these directly, unlike the other Get* helpers which feed
    // UEVars.
    virtual uintptr_t GetGWorldSlot() const { return 0; }
    virtual uintptr_t GetGEngineSlot() const { return 0; }

    // 名字池的 id 不是稠密的：FNamePool 里条目首尾相接（2 字节 header + len 字节正文，
    // 不同版本还可能带 NUL/对齐填充），所以相邻两个真实 id 的间隔 = 条目字节数 / Stride。
    // 按 id 自增枚举会落进条目中间，读出一个由后续若干条目拼起来的长串（中间夹着被
    // 当成正文的 2 字节 header）。要枚举就必须按条目链走，这个接口给出走一步所需的信息。
    // 返回 false 表示该 id 处无法解析条目（含扁平 FNameEntryArray 之外的异常情况）。
    virtual bool GetNameEntryMeta(int32_t id, size_t &outLength, int32_t &outNextId, bool &outWide) const;

protected:
    virtual uintptr_t GetGUObjectArrayPtr() const;
    virtual uintptr_t GetMatrix()  const = 0;
    virtual uintptr_t GetPhysx() const = 0;
    virtual uintptr_t GetFrameCount() const = 0;
    virtual uintptr_t GetStaticFindObject() const;
    virtual uintptr_t GetNativeAndroidApp() const;
    virtual uintptr_t GetProcessEvent() const;
    // NativeAndroidApp 的基类实现是「结构搜索」而非声明式模块偏移：它在可读段里找
    // 「指针 → +0x20 → +0x8 == "zhCN"」的槽位，依赖运行时 locale 状态，因此可能为 0，
    // 也可能命中同形的别的槽位。目前没有任何 profile 声明过它的 RVA，所以默认就是
    // 「未校验」；将来若某个游戏把 RVA 写进 profile，覆盖本函数返回 true 即可让产物
    // 不再带告警注释。
    virtual bool HasVerifiedNativeAndroidApp() const { return false; }
    // GNames / NamePoolData
    virtual uintptr_t GetNamesPtr() const;

    virtual uint8_t *GetNameEntry(int32_t id) const;
    // can override if decryption is needed
    virtual std::string GetNameEntryString(uint8_t *entry) const;
    virtual std::string GetNameByID(int32_t id) const;

    virtual bool isEmulator() const;

    virtual uintptr_t findIdaPattern(PATTERN_MAP_TYPE map_type,
                                     const std::string &pattern, const int step,
                                     uint32_t skip_result = 0) const;


};
