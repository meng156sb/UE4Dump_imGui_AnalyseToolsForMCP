#pragma once

// FName 正文的字节变换（DFM 国服在用，别的游戏多半不用）。
//
// 背景：DFM 的 FNameEntry 正文不是明文，读出 `None` 会变成一串不可读字节。变换本身很弱，
// 密钥只跟 header 里的名字长度 len 有关，但**按条目是 ANSI 还是宽字符分两条路**，两条路的
// 密钥位宽不同——这一点是踩过的坑，见下。
//
// --- ANSI 条目（header bit0 == 0）--------------------------------------------
// 逐字节异或一个 8 位密钥，密钥只有两种取值：
//
//   ~b            （key & 0x80 == 0）
//   0x80 ^ ~b     （key & 0x80 != 0，等价于 b ^ 0x7F）
//
// 因为 `0x80 ^ ~b` 就是 `b ^ 0x7F`、`~b` 就是 `b ^ 0xFF`，所以整体就是一个逐字节异或，
// 密钥只取决于 len。工程上曾经有两个副本（profile 里一份、候选分析里没有），两边写法
// 不同，结果一样——一份用 `(33*len) | 0x7F` 再直接异或，一份用 `(33*len)` 取 bit7 再取反。
// 这里统一成前者：算出 key 后直接 `b ^ key`，key 的低 7 位恒为 1（即 key ∈ {0x7F, 0xFF}）。
//
// --- 宽字符条目（header bit0 == 1）-------------------------------------------
// 正文是 UTF-16LE，每个字符 2 字节，而且**只有偶数下标的那个 u16 被异或**（奇数下标原样保留）。
// 密钥用同一个九分支公式算，取完整 16 位：
//
//   key16(len) = ((KeyBase(len) + 0x80) & ~0x7F) | 0x7F
//
// 即"把低 7 位填成 1，其余高位原样保留"。ANSI 那条路就是同一个值**取低字节**——两条路是
// 一个式子的两种截断，不是两个式子。
//
// 这里踩过一个坑：宽字符的密钥早先写成 `& 0x180`（只保留到 bit8），把 bit9 及以上全丢了。
// (L=12 真密钥 0x27F 被压成 0x07F、L=39 真密钥 0x5FF 被压成 0x1FF。) 受害的名字不会碎成
// 非法字节，而是解出**合法 UTF-8 的乱码**（西里尔/国际音标/生僻汉字），所以"数 '?' 个数"
// 这种验收完全看不见它们——见上面那条"不能拿可打印性自校验"。真机实测三个数据点定死了
// 这条公式：L=2 → 0x17F、L=12 → 0x27F、L=39 → 0x5FF，只有"低 7 位置 1、其余全留"同时满足，
// `& 0x180` 在 L=12/39 上都不满足。
//
// 所以宽字符的异或掩码在字节上周期是 4：两个密钥字节后面跟两个 0x00。任何"单个字节密钥 +
// 逐字节异或"都不可能表达它，拿 8 位密钥去解宽字符条目必然出垃圾——真机上这些名字碎成非
// UTF-8 字节，最后被 UmtText::SanitizeUtf8 逐个换成 '?'，SDK 里就出现 `?~e?I`、`0)`、
// `?׊V?` 这种东西。
//
// 实测（DeltaForce CN，pid 4591，BP_InteractorContainer_BoxBase_C 的 15 个宽字符成员）：
// wide=1 的全部是 CJK 名字且全部碎掉，wide=0 的全部完好，一一对应；按上面这条规则解出来
// 是 `地图` `地图大区域` `地图小区域自定义名称` `Loot容器分类` `是否参与随机` `MapName2地图`
// 这类完整名字（含 ASCII+CJK 混排的 `MapName2地图`，它的 ASCII 半边也一并还原）。
//
// 上面这条 & 0x180 的坑修掉后，同一份 dump 里最后三个残留乱码名也归位了（都是"合法 UTF-8
// 的乱码"，'?' 计数为 0，只能靠"解出的字符是否都落在可打印/CJK 区间"扫出来）：
//
//   L=12  ɏpɥnɂrɯk稴损崀启                       → OpenBrok破损开启
//   L=39  啳卡倍_в5џFд1х2д4х4г8с9е2х4й7тDаBв9в6з0дCй → 关卡名_25_F41E244E438A952E497BD0B2926704C9
//   L=39  儯一搧_б1џCсAгAхEв4и9ц6фAц3гCд4тAаFйCвEх8ж → 唯一性_11_CAA3AEE2489F6DAF33C44BA0F9C2EE86
//
// 后两个 L 相同、结构也相同（`<中文名>_<序号>_<32 位大写 hex>`），互相印证。
//
// 注意：这个变换不能拿"解出来是不是可打印"来自校验——密文本身也基本落在可打印区间，
// 几种形态都能通过可打印检查。判断是否解对，要看解出的字符数与 header 声明的 len 是否
// 一致，以及是否能对上已知名字（`None`/`Object` 这类）。

#include <cstdint>
#include <string>

namespace UmtNameCipher
{

// len 是 header 里的名字长度，单位是**字符数**（宽字符条目的字节数是 len * 2）。
// 九分支是密钥的公共部分；两条路都从它经 KeyRaw 取密钥，只是截断宽度不同。
inline uint32_t KeyBase(uint32_t len)
{
    switch (len % 9)
    {
    case 0u:
        return ((len & 0x1F) + len);
    case 1u:
        return ((len ^ 0xDF) + len);
    case 2u:
        return ((len | 0xCF) + len);
    case 3u:
        return (33 * len);
    case 4u:
        return (len + (len >> 2));
    case 5u:
        return (3 * len + 5);
    case 6u:
        return (((4 * len) | 5) + len);
    case 7u:
        return (((len >> 4) | 7) + len);
    case 8u:
        return ((len ^ 0xC) + len);
    default:
        return ((len ^ 0x40) + len);
    }
}

// 唯一的密钥公式：把 (KeyBase(len) + 0x80) 的低 7 位填成 1，高位原样保留。
// ANSI 取低字节、宽字符取完整 16 位，两条路共用这一个式子。
inline uint32_t KeyRaw(uint32_t len)
{
    return ((KeyBase(len) + 0x80) & ~static_cast<uint32_t>(0x7F)) | 0x7F;
}

// ANSI 条目：8 位密钥，取 KeyRaw 的低字节。展开后就是原来写的
// `((KeyBase(len) + 0x80) & 0x80) | 0x7F`——两个旧副本里一个写 `formula + 0x80 ... | 0x7F`，
// 另一个写 `(formula & 0x80) ^ ~b`。把后者展开 `~b = 0xFF ^ b` 就是
// `b ^ (0xFF ^ (formula & 0x80))`，于是 formula 的 bit7 为 0 时密钥是 0xFF、为 1 时是 0x7F
// ——正好是「先 +0x80 把 bit7 取反，再把低 7 位填成 1」。两边等价，已对 L=1..1024 穷举比对。
inline uint8_t KeyForLength(uint32_t len)
{
    return static_cast<uint8_t>(KeyRaw(len));
}

// 宽字符条目：同一个式子的完整 16 位。别再写 `& 0x180`——那会把 bit9 及以上丢掉，
// 解出来是"合法 UTF-8 的乱码"，比碎字节更难发现。
inline uint16_t KeyForLengthWide(uint32_t len)
{
    return static_cast<uint16_t>(KeyRaw(len));
}

// 原地解密 len 个字节。变换对合（自己就是自己的逆），所以加密解密同一个函数。
inline void DecodeAnsi(char *str, uint32_t len)
{
    if (!str || len == 0)
        return;
    const uint8_t key = KeyForLength(len);
    for (uint32_t i = 0; i < len; ++i)
        str[i] = static_cast<char>(static_cast<uint8_t>(str[i]) ^ key);
}

inline void DecodeAnsi(std::string &str)
{
    DecodeAnsi(str.data(), static_cast<uint32_t>(str.length()));
}

// 原地解密宽字符正文（UTF-16LE 字节串，charCount 是字符数）：只异或偶数下标的 u16。
inline void DecodeWide(char *body, uint32_t charCount)
{
    if (!body || charCount == 0)
        return;
    const uint16_t key = KeyForLengthWide(charCount);
    uint8_t *p = reinterpret_cast<uint8_t *>(body);
    for (uint32_t i = 0; i < charCount; i += 2)
    {
        uint8_t *unit = p + (i * 2);
        const uint16_t v = static_cast<uint16_t>(
            static_cast<uint16_t>(unit[0] | (static_cast<uint16_t>(unit[1]) << 8)) ^ key);
        unit[0] = static_cast<uint8_t>(v & 0xFF);
        unit[1] = static_cast<uint8_t>(v >> 8);
    }
}

namespace Detail
{

inline void AppendUtf8(std::string &out, uint32_t cp)
{
    if (cp < 0x80u)
    {
        out += static_cast<char>(cp);
    }
    else if (cp < 0x800u)
    {
        out += static_cast<char>(0xC0u | (cp >> 6));
        out += static_cast<char>(0x80u | (cp & 0x3Fu));
    }
    else if (cp < 0x10000u)
    {
        out += static_cast<char>(0xE0u | (cp >> 12));
        out += static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu));
        out += static_cast<char>(0x80u | (cp & 0x3Fu));
    }
    else
    {
        out += static_cast<char>(0xF0u | (cp >> 18));
        out += static_cast<char>(0x80u | ((cp >> 12) & 0x3Fu));
        out += static_cast<char>(0x80u | ((cp >> 6) & 0x3Fu));
        out += static_cast<char>(0x80u | (cp & 0x3Fu));
    }
}

}  // namespace Detail

// UTF-16LE → UTF-8，不解密。落单的代理替换成 '?'。
inline std::string Utf16LeToUtf8(const char *raw, uint32_t charCount)
{
    std::string out;
    if (!raw || charCount == 0)
        return out;

    out.reserve(static_cast<size_t>(charCount) * 3);
    const uint8_t *p = reinterpret_cast<const uint8_t *>(raw);
    for (uint32_t i = 0; i < charCount; ++i)
    {
        uint32_t cp = static_cast<uint32_t>(
            static_cast<uint16_t>(p[i * 2] | (static_cast<uint16_t>(p[i * 2 + 1]) << 8)));

        if (cp >= 0xD800u && cp <= 0xDBFFu)
        {
            uint32_t lo = 0;
            if (i + 1 < charCount)
                lo = static_cast<uint32_t>(static_cast<uint16_t>(
                    p[(i + 1) * 2] | (static_cast<uint16_t>(p[(i + 1) * 2 + 1]) << 8)));

            if (lo >= 0xDC00u && lo <= 0xDFFFu)
            {
                cp = 0x10000u + ((cp - 0xD800u) << 10) + (lo - 0xDC00u);
                ++i;
            }
            else
            {
                cp = '?';
            }
        }
        else if (cp >= 0xDC00u && cp <= 0xDFFFu)
        {
            cp = '?';
        }

        Detail::AppendUtf8(out, cp);
    }
    return out;
}

// 宽字符条目一条龙：raw 是 UTF-16LE 正文，charCount 是字符数（字节数 = charCount * 2）。
// 解密 + 转 UTF-8。落单的代理（半截名字或长度读错）替换成 '?'，免得把非法序列喂给下游。
inline std::string DecodeWideToUtf8(const char *raw, uint32_t charCount)
{
    if (!raw || charCount == 0)
        return {};
    std::string body(raw, static_cast<size_t>(charCount) * 2);
    DecodeWide(body.data(), charCount);
    return Utf16LeToUtf8(body.data(), charCount);
}

}  // namespace UmtNameCipher
