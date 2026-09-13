#pragma once

#include <memory>

#include "KittyUtils.hpp"
#include "KittyIOFile.hpp"

enum EKittyMemOP
{
    EK_MEM_OP_NONE = 0,
    EK_MEM_OP_SYSCALL,
    EK_MEM_OP_IO
};

class IKittyMemOp
{
protected:
    pid_t _pid;

public:
    IKittyMemOp() : _pid(0) {}
    virtual ~IKittyMemOp() = default;

    virtual bool init(pid_t pid) = 0;

    inline pid_t processID() const { return _pid; }

    virtual size_t Read(uintptr_t address, void *buffer, size_t len) const = 0;
    virtual size_t Write(uintptr_t address, void *buffer, size_t len) const = 0;

    std::string ReadStr(uintptr_t address, size_t maxLen);
    bool WriteStr(uintptr_t address, std::string str);
};

class KittyMemSys : public IKittyMemOp
{
private:
    // Lazily opened /proc/<pid>/mem, used only for the chunks process_vm_readv
    // refuses. See the EFAULT branch in Read() for why that is necessary.
    mutable std::unique_ptr<KittyIOFile> _pFallbackMem;
    mutable bool _fallbackUnavailable = false;

    size_t readViaFallback(uintptr_t address, void *buffer, size_t len) const;

public:
    bool init(pid_t pid);

    size_t Read(uintptr_t address, void *buffer, size_t len) const;
    size_t Write(uintptr_t address, void *buffer, size_t len) const;
};

class KittyMemIO : public IKittyMemOp
{
private:
    std::unique_ptr<KittyIOFile> _pMem;

public:
    bool init(pid_t pid);

    size_t Read(uintptr_t address, void *buffer, size_t len) const;
    size_t Write(uintptr_t address, void *buffer, size_t len) const;
};