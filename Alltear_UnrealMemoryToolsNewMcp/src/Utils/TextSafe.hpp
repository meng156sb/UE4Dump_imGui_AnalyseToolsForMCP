#pragma once

#include <cstdint>
#include <string>

#include <nlohmann/json.hpp>

// 本工具处理的每一段文本都来自游戏内存：FName 解密结果、readString、searchMemory 的
// 命中片段。这些字节不受我们控制，而 nlohmann::json 的 dump() 默认是 strict 模式——
// 串里只要有一个字节不是合法 UTF-8 就抛 type_error.316。
//
// 实测（Delta Force CN，pid 4591）：SAMPLE_GNAMES 取 id=0，国服 dec_ansi 解出的是非
// UTF-8 垃圾字节，紧随其后的 response.dump() 抛出未捕获异常，libc++abi 直接 terminate，
// 整个设备端进程连同已经跑完的探针结果一起消失。一个坏名字换一条命，代价完全不成比例。
//
// 两道防线：
//   1. SanitizeUtf8 —— 在名字出口把坏字节换成 '?'，让产物本身（SDK .hpp/.md、JSON、GUI）
//      就是干净文本；
//   2. SafeDump —— 序列化的唯一收口。坏字节退化成 U+FFFD 而不是把进程带走；即使 (1)
//      漏了某条路径（比如 readString 直接回原始内存），(2) 仍然兜得住。
namespace UmtText
{
// 严格按 Unicode 良构性校验：拒绝孤立续字节、截断序列、overlong 编码和 UTF-16 代理
// 区间。比 nlohmann 宽松的 lead/continuation 检查更严，因此通过校验的串 SafeDump 一定
// 不会抛异常。
inline bool IsValidUtf8(const std::string &s)
{
    const size_t n = s.size();
    size_t i = 0;
    while (i < n)
    {
        const uint8_t c = uint8_t(s[i]);
        size_t len = 0;
        if (c < 0x80)
            len = 1;
        else if (c >= 0xC2 && c <= 0xDF)
            len = 2;
        else if (c >= 0xE0 && c <= 0xEF)
            len = 3;
        else if (c >= 0xF0 && c <= 0xF4)
            len = 4;
        else
            return false;  // 孤立续字节 (0x80-0xBF)、0xC0/0xC1 overlong、>0xF4

        if (i + len > n)
            return false;  // 截断

        for (size_t k = 1; k < len; k++)
        {
            if ((uint8_t(s[i + k]) & 0xC0) != 0x80)
                return false;
        }

        if (len == 3)
        {
            const uint8_t b1 = uint8_t(s[i + 1]);
            if (c == 0xE0 && b1 < 0xA0)
                return false;  // overlong
            if (c == 0xED && b1 > 0x9F)
                return false;  // UTF-16 代理区 U+D800-DFFF
        }
        else if (len == 4)
        {
            const uint8_t b1 = uint8_t(s[i + 1]);
            if (c == 0xF0 && b1 < 0x90)
                return false;  // overlong
            if (c == 0xF4 && b1 > 0x8F)
                return false;  // > U+10FFFF
        }

        i += len;
    }
    return true;
}

// 把非法字节逐个替换成 '?'，合法序列原样保留。选 '?' 而不是 U+FFFD 是因为名字会被写进
// 生成的 SDK 头文件（标识符/注释）和日志，单字节 ASCII 占位符在任何下游都不会再引入
// 编码问题。中文名字本身是合法 UTF-8，不受影响。
inline std::string SanitizeUtf8(const std::string &s)
{
    if (IsValidUtf8(s))
        return s;

    std::string out;
    out.reserve(s.size());

    const size_t n = s.size();
    size_t i = 0;
    while (i < n)
    {
        const uint8_t c = uint8_t(s[i]);
        size_t len = 0;
        if (c < 0x80)
            len = 1;
        else if (c >= 0xC2 && c <= 0xDF)
            len = 2;
        else if (c >= 0xE0 && c <= 0xEF)
            len = 3;
        else if (c >= 0xF0 && c <= 0xF4)
            len = 4;

        bool ok = len != 0 && i + len <= n;
        if (ok)
        {
            for (size_t k = 1; k < len; k++)
            {
                if ((uint8_t(s[i + k]) & 0xC0) != 0x80)
                {
                    ok = false;
                    break;
                }
            }
        }
        if (ok && len == 3)
        {
            const uint8_t b1 = uint8_t(s[i + 1]);
            if ((c == 0xE0 && b1 < 0xA0) || (c == 0xED && b1 > 0x9F))
                ok = false;
        }
        if (ok && len == 4)
        {
            const uint8_t b1 = uint8_t(s[i + 1]);
            if ((c == 0xF0 && b1 < 0x90) || (c == 0xF4 && b1 > 0x8F))
                ok = false;
        }

        if (ok)
        {
            out.append(s, i, len);
            i += len;
        }
        else
        {
            out.push_back('?');
            i += 1;  // 逐字节前进，避免吞掉紧跟其后的合法序列
        }
    }

    return out;
}

// 序列化收口。任何可能承载「游戏内存文本」的响应都必须走这里。
inline std::string SafeDump(const nlohmann::json &j, int indent = -1)
{
    return j.dump(indent, ' ', false, nlohmann::json::error_handler_t::replace);
}

}  // namespace UmtText
