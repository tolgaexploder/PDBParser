#pragma once
#include <combaseapi.h>
#include <atlcomcli.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <optional>
#include <functional>
#include "dia2.h"

#define INVALID_OFFSET static_cast<DWORD64>(-1)

struct SymbolInfo {
    std::string name;
    DWORD64 rva;
    DWORD64 size;
    DWORD typeId;
};

struct StructMember {
    std::string name;
    DWORD64 offset;
    DWORD64 size;
    DWORD typeId;
};

struct StructInfo {
    std::string name;
    DWORD64 size;
    std::vector<StructMember> members;
};

enum class MachineType : DWORD {
    x86 = IMAGE_FILE_MACHINE_I386,
    x64 = IMAGE_FILE_MACHINE_AMD64,
    IA64 = IMAGE_FILE_MACHINE_IA64,
    ARM = IMAGE_FILE_MACHINE_ARM,
    ARM64 = IMAGE_FILE_MACHINE_ARM64
};

class PdbParser {
private:
    CComPtr<IDiaDataSource> m_pDataSource;
    CComPtr<IDiaSession> m_pSession;
    CComPtr<IDiaSymbol> m_pGlobalScope;
    MachineType m_machineType;
    std::wstring m_pdbPath;

    mutable std::unordered_map<std::wstring, DWORD64> m_symbolCache;
    mutable std::unordered_map<std::wstring, StructInfo> m_structCache;

    bool InitializeDia() noexcept;
    void CleanupCom() noexcept;
    std::optional<StructInfo> ParseStructInternal(const std::wstring& structName) const;

    template<typename Func>
    bool EnumerateSymbols(enum SymTagEnum symTag, const Func& callback) const;

public:
    explicit PdbParser(const std::wstring& pdbPath);
    ~PdbParser() = default;

    PdbParser(const PdbParser&) = delete;
    PdbParser& operator=(const PdbParser&) = delete;
    PdbParser(PdbParser&&) = default;
    PdbParser& operator=(PdbParser&&) = default;

    bool IsInitialized() const noexcept { return m_pGlobalScope != nullptr; }
    MachineType GetMachineType() const noexcept { return m_machineType; }
    const std::wstring& GetPdbPath() const noexcept { return m_pdbPath; }

    std::vector<SymbolInfo> GetAllPublicSymbols() const;
    std::optional<DWORD64> GetSymbolRva(const std::wstring& symbolName) const;

    std::optional<StructInfo> GetStructInfo(const std::wstring& structName) const;
    std::optional<DWORD64> GetStructMemberOffset(const std::wstring& structName,
        const std::wstring& memberName) const;
    std::vector<std::wstring> GetAllStructNames() const;

    std::vector<SymbolInfo> FindSymbolsByPattern(const std::wstring& pattern) const;
    bool DumpToJson(const std::wstring& outputPath) const;

    void PreloadSymbols();
    void PreloadStructures();
    void ClearCaches() noexcept;
};

class PdbDownloader {
private:
    static std::string ExtractPdbInfo(const std::wstring& exePath);
    static bool DownloadFile(const std::string& url, const std::wstring& outputPath);

public:
    static std::optional<std::wstring> DownloadPdbForExecutable(const std::wstring& exePath);
};

struct SymbolDiff {
    std::string name;
    DWORD64 oldRva = 0;
    DWORD64 newRva = 0;
    bool added = false;
    bool removed = false;
    bool changed = false;
};

class PdbComparer {
public:
    static std::vector<SymbolDiff> ComparePdbs(const PdbParser& oldPdb, const PdbParser& newPdb);
    static void PrintDifferences(const std::vector<SymbolDiff>& diffs);
    static bool ExportDifferencesToJson(const std::vector<SymbolDiff>& diffs, const std::wstring& outputPath);
};

class BatchProcessor {
public:
    static void ProcessDirectory(const std::wstring& directory, const std::wstring& outputDir);
    static void ProcessMultiplePdbs(const std::vector<std::wstring>& pdbFiles, const std::wstring& outputDir);
    static void GenerateSummaryReport(const std::vector<std::wstring>& pdbFiles, const std::wstring& outputPath);
};