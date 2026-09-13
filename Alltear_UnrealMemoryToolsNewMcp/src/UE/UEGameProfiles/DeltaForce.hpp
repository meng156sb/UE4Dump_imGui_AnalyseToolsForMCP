#pragma once

#include "../UEGameProfile.hpp"
#include "../../Utils/NameCipher.hpp"
using namespace UEMemory;

class DeltaForceProfile : public IGameProfile
{
public:
    DeltaForceProfile() = default;

    bool ArchSupprted() const override
    {
        auto e_machine = GetUnrealELF().header().e_machine;
        return e_machine == EM_AARCH64;
    }

    std::string GetAppName() const override
    {
        return "Delta Force(CN)";
    }

    std::vector<std::string> GetAppIDs() const override
    {
        return {"com.tencent.tmgp.dfm"};
    }

    bool isUsingCasePreservingName() const override
    {
        return false;
    }

    bool IsUsingFNamePool() const override
    {
        return true;
    }

    bool isUsingOutlineNumberName() const override
    {
        return false;
    }
    // --- CN build module-relative globals ------------------------------------
    // Verified on com.tencent.tmgp.dfm across several ASLR bases. All four live in
    // the same "-w-p" [anon:.bss] window, which is why locating them also needed
    // KittyPtrValidator::isPtrReadable to accept writable (not just 'r') regions.
    static constexpr uintptr_t kCnFNamePoolRva = 0x20291EC0;
    static constexpr uintptr_t kCnGUObjectArrayRva = 0x202B8CF8;
    static constexpr uintptr_t kCnGWorldRva = 0x1FE10148;
    static constexpr uintptr_t kCnGEngineRva = 0x205F1640;

    // Resolve a CN module-relative *slot* address, refusing it unless the slot is
    // actually mapped and readable -- so a build that moves it degrades to the
    // generic search instead of returning a plausible-looking wrong address.
    uintptr_t ResolveCnSlot(uintptr_t rva) const
    {
        const uintptr_t base = GetUnrealELF().base();
        if (!base) return 0;
        const uintptr_t slot = base + rva;
        if (!kPtrValidator.isPtrReadable(slot, sizeof(uintptr_t)))
            return 0;
        return slot;
    }

    // Same, but for the two globals that hold a *pointer* to a live UObject
    // (GWorld / GEngine). Being mapped is not enough for those: a moved or
    // half-initialised slot would still be readable and would then be reported
    // as a valid offset. Require the pointee to be a readable object whose class
    // -- or one of whose superclasses -- is named `expectClass`, which is the
    // same relationship the generic scan proves by matching IsA() against the
    // real UClass. The chain walk matters: DFM's GEngine holds a `GPGameEngine`,
    // a UEngine subclass, so an exact-name compare would reject it.
    uintptr_t ResolveCnObjectSlot(uintptr_t rva, const char *expectClass) const
    {
        const uintptr_t slot = ResolveCnSlot(rva);
        if (!slot) return 0;

        const size_t probe = GetOffsets()->UObject.NamePrivate + sizeof(int32_t);
        const uintptr_t object = vm_rpm_ptr<uintptr_t>((void *)slot);
        if (!kPtrValidator.isPtrReadable(object, probe))
            return 0;

        uintptr_t uclass = vm_rpm_ptr<uintptr_t>((void *)(object + GetOffsets()->UObject.ClassPrivate));
        for (int depth = 0; uclass && depth < 32; ++depth)
        {
            if (!kPtrValidator.isPtrReadable(uclass, probe))
                break;

            const int32_t nameId = vm_rpm_ptr<int32_t>((void *)(uclass + GetOffsets()->UObject.NamePrivate));
            if (GetNameByID(nameId) == expectClass)
                return slot;

            uclass = vm_rpm_ptr<uintptr_t>((void *)(uclass + GetOffsets()->UStruct.SuperStruct));
        }

        LOGW("DeltaForce: slot [<Base> + 0x%lX] does not dereference to a %s -- ignoring it",
             (unsigned long)rva, expectClass);
        return 0;
    }

    uintptr_t GetGUObjectArrayPtr() const override
    {
        return IGameProfile::GetGUObjectArrayPtr();
    }
    uintptr_t GetFrameCount() const override
    {
        PATTERN_MAP_TYPE map_type = isEmulator() ? PATTERN_MAP_TYPE::ANY_R : PATTERN_MAP_TYPE::ANY_X;

        std::string ida_pattern = "? ? ? F0 ? ? ? F9 ? ? ? F9 C0 03 5F D6 ? ? ? A9 FD 03 00 91 ? ? ? D0";
        const int step = 0;
        auto FrameOff = Arm64::Decode_ADRP_LDR(findIdaPattern(map_type, ida_pattern, step));
        if (FrameOff !=0)
            return vm_rpm_ptr<uintptr_t>((void*)FrameOff);
        return  0;
    }
    uintptr_t GetMatrix() const override
    {
        std::vector<std::pair<std::string, int>> idaPatterns = {
            {"08 3D 40 F9 00 01 3F D6 E8 03 13 AA ? ? ? F9", 0x18},
            {"FD ? ? A9 28 ? ? F9 F3 ? ? F8 C0 03 5F D6", -0x1c},
            {"00 01 3F D6 E8 03 13 AA 60 ? 00 F9 ? ? ? A9", 14},
        };

        PATTERN_MAP_TYPE map_type = isEmulator() ? PATTERN_MAP_TYPE::ANY_R : PATTERN_MAP_TYPE::ANY_X;

        for (const auto &it : idaPatterns)
        {
            std::string ida_pattern = it.first;
            const int step = it.second;

            uintptr_t adrl = Arm64::Decode_ADRP_LDR(findIdaPattern(map_type, ida_pattern, step));
            if (adrl != 0) return adrl;
        }
        return 0;
    }
    uintptr_t GetPhysx() const override
    {
        std::vector<std::pair<std::string, int>> idaPatterns = {
            {"E1 ? ? ? 40 00 40 BD F4 03 02 AA",0x28},
            {"48 ? ? ? F3 03 04 AA F5 03 03 2A", -0xc},
        };

        PATTERN_MAP_TYPE map_type = isEmulator() ? PATTERN_MAP_TYPE::ANY_R : PATTERN_MAP_TYPE::ANY_X;

        for (const auto &it : idaPatterns)
        {
            std::string ida_pattern = it.first;
            const int step = it.second;

            uintptr_t adrl = Arm64::Decode_ADRP_LDR(findIdaPattern(map_type, ida_pattern, step),8);
            //printf("%lx\n", vm_rpm_ptr<uintptr_t>((void*)adrl));
            if (adrl != 0) return vm_rpm_ptr<uintptr_t>((void*)adrl);
        }
        return 0;
    }
    uintptr_t GetNamesPtr() const override
    {
        // This profile matches the CN build (com.tencent.tmgp.dfm) only, and on that
        // build the international IDA pattern below finds nothing at all -- the
        // resulting 0 was then rejected by the pointer validator, so InitUEVars()
        // always failed with ERROR_INIT_NAMEPOOL and the dedicated profile was
        // abandoned. Prefer the verified module-relative address instead, but only
        // when the pool's own Blocks[0] pointer also checks out.
        if (uintptr_t pool = ResolveCnSlot(kCnFNamePoolRva))
        {
            const uintptr_t blocks0 = vm_rpm_ptr<uintptr_t>((void *)(pool + GetOffsets()->FNamePool.BlocksOff));
            if (blocks0 >= 0x10000 && kPtrValidator.isPtrReadable(blocks0, 2))
                return pool;
        }

        PATTERN_MAP_TYPE map_type = isEmulator() ? PATTERN_MAP_TYPE::ANY_R : PATTERN_MAP_TYPE::ANY_X;

        std::string ida_pattern = "91 ? 10 81 52 ? ? 21 8b";
        const int step = -7;

        return Arm64::Decode_ADRP_ADD(findIdaPattern(map_type, ida_pattern, step));
    }

    uintptr_t GetGWorldSlot() const override { return ResolveCnObjectSlot(kCnGWorldRva, "World"); }
    uintptr_t GetGEngineSlot() const override { return ResolveCnObjectSlot(kCnGEngineRva, "Engine"); }
    UE_Offsets *GetOffsets() const override
    {
        static UE_Offsets offsets = UE_DefaultOffsets::UE4_25_27(isUsingCasePreservingName());

        static bool once = false;
        if (!once)
        {
            once = true;

            offsets.FNamePool.BlocksBit = 18;
            offsets.FNamePool.BlocksOff -= sizeof(void *);

            offsets.TUObjectArray.NumElements = sizeof(int32_t);
            offsets.TUObjectArray.Objects = offsets.TUObjectArray.NumElements + (sizeof(int32_t) * 3);

            offsets.UObject.ClassPrivate = sizeof(void *);
            offsets.UObject.OuterPrivate = offsets.UObject.ClassPrivate + sizeof(void *);
            offsets.UObject.ObjectFlags = offsets.UObject.OuterPrivate + sizeof(void *);
            offsets.UObject.NamePrivate = offsets.UObject.ObjectFlags + sizeof(int32_t);
            offsets.UObject.InternalIndex = offsets.UObject.NamePrivate + offsets.FName.Size;

            offsets.UStruct.PropertiesSize = offsets.UField.Next + (sizeof(void *) * 2) + sizeof(int32_t);
            offsets.UStruct.SuperStruct = offsets.UStruct.PropertiesSize + sizeof(int32_t);
            offsets.UStruct.Children = offsets.UStruct.SuperStruct + (sizeof(void *) * 2);
            offsets.UStruct.ChildProperties = offsets.UStruct.Children + (sizeof(void *) * 3);

            offsets.UFunction.NumParams = offsets.UStruct.ChildProperties + ((sizeof(void *) + sizeof(int32_t) * 2) * 2) + (sizeof(void *) * 5);
            offsets.UFunction.ParamSize = offsets.UFunction.NumParams + sizeof(int16_t);
            offsets.UFunction.EFunctionFlags = offsets.UFunction.ParamSize + sizeof(int16_t) + sizeof(int32_t);
            offsets.UFunction.Func = offsets.UFunction.EFunctionFlags + (sizeof(int32_t) * 2) + (sizeof(void *) * 3);

            offsets.FField.FlagsPrivate = sizeof(void *);
            offsets.FField.Next = offsets.FField.FlagsPrivate + (sizeof(void *) * 2);
            offsets.FField.ClassPrivate = offsets.FField.Next + sizeof(void *);
            offsets.FField.NamePrivate = offsets.FField.ClassPrivate + sizeof(void *);

            offsets.FProperty.ArrayDim = offsets.FField.NamePrivate + GetPtrAlignedOf(offsets.FName.Size) + sizeof(void *);
            offsets.FProperty.ElementSize = offsets.FProperty.ArrayDim + sizeof(int32_t);
            offsets.FProperty.PropertyFlags = offsets.FProperty.ElementSize + sizeof(int32_t);
            offsets.FProperty.Offset_Internal = offsets.FProperty.PropertyFlags + sizeof(int64_t) + sizeof(int32_t);
            offsets.FProperty.Size = offsets.FProperty.Offset_Internal + (sizeof(int32_t) * 3) + (sizeof(void *) * 4);
        }

        return &offsets;
    }


    std::string GetNameEntryString(uint8_t *entry) const override
    {
        // 宽字符条目（header bit0 == 1）必须先在这里拦下来。基类的实现按 ANSI 处理：
        // 只读 len 个字节（应该是 2*len，len 是字符数），而且不做 UTF-16 解码；出来再被下面
        // 的 DecodeAnsi 按 8 位密钥逐字节异或一遍。真机上这就是所有 `?` 名字的来源——
        // 实测 BP_InteractorContainer_BoxBase_C 的成员：wide=0 的（SmallAreaConfig/
        // BigArea/MapNameToEnum/Price/SaveID/SaveRot/SavePos…）全部完好，wide=1 的 15 个
        // 全部碎掉，一一对应。按这里的规则解出来是 `地图` `地图大区域` `地图小区域自定义名称`
        // `Loot容器分类` `是否参与随机` `MapName2地图` 这类完整名字。
        // ANSI 那条路（下面）是验证过的，保持原样不动。
        if (entry && IsUsingFNamePool())
        {
            UE_Offsets *off = GetOffsets();
            uint16_t header = 0;
            if (vm_rpm_ptr(entry + off->FNamePoolEntry.Header, &header, sizeof(int16_t)) &&
                (header & 1) != 0)
            {
                const size_t chars = off->FNamePoolEntry.GetLength(header);
                // len 为 0 是 outline number 条目（正文不在本条目内），过大说明 id 不在
                // 条目边界上——都交回基类，让它按原逻辑走。
                if (chars > 0 && chars <= kMAX_UENAME_BUFFER)
                {
                    // 必须按字节数整读：宽字符正文里的 ASCII 字符低字节是 0x00，
                    // vm_rpm_str 会在那里截断（`MapName2地图` 只能读出 1 个字节）。
                    std::string body(chars * 2, '\0');
                    if (vm_rpm_ptr(entry + off->FNamePoolEntry.Header + sizeof(int16_t),
                                   body.data(), body.size()))
                        return UmtNameCipher::DecodeWideToUtf8(
                            body.data(), static_cast<uint32_t>(chars));
                }
            }
        }

        std::string name = IGameProfile::GetNameEntryString(entry);

        // 正文是异或过的，密钥只跟名长有关。算法收敛到 Utils/NameCipher.hpp 一份：
        // 原先这里的内联副本写 `(key & 0x80) ^ ~b`，UEGameProfile.cpp 的候选校验副本写
        // `... | 0x7F` 再直接异或，两者写法不同但等价（已对 len 1..1024 × 全部 256 个字节
        // 取值穷举比对，并对真机 block0 实测字节验证过 None/N0ne/Nome/30949b77fd7e7042/SHVector）。
        // 收敛成一份，免得以后只改一边。
        UmtNameCipher::DecodeAnsi(name);

        return name;
    }
};