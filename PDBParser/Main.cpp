#include "PdbAnalyzer.h"
#include <iostream>
#include <filesystem>
#include <vector>

void ShowUsage(const char* programName) {
    std::cout << "Advanced PDB Parser - Professional Reverse Engineering Tool\n";
    std::cout << "Usage: " << programName << " <pdb_file> [options]\n";
    std::cout << "       " << programName << " -auto <exe_file> [options]\n";
    std::cout << "       " << programName << " -diff <old_pdb> <new_pdb> [options]\n";
    std::cout << "       " << programName << " -batch <directory> [output_dir]\n\n";

    std::cout << "Basic Options:\n";
    std::cout << "  -s <symbol>         Find specific symbol by name\n";
    std::cout << "  -t <struct>         Analyze structure layout\n";
    std::cout << "  -m <struct> <member> Find structure member offset\n";
    std::cout << "  -p <pattern>        Search symbols by regex pattern\n";
    std::cout << "  -l                  List all available structures\n";
    std::cout << "  -perf               Run performance benchmarks\n";
    std::cout << "  -export <file>      Export results to JSON\n";
    std::cout << "  -kernel             Resolve critical kernel symbols\n";
    std::cout << "  -full               Complete analysis (default)\n\n";

    std::cout << "Advanced Options:\n";
    std::cout << "  -auto <exe>         Download PDB for executable from Microsoft\n";
    std::cout << "  -diff <old> <new>   Compare two PDB files\n";
    std::cout << "  -batch <dir> [out]  Process all PDBs in directory\n\n";

    std::cout << "Examples:\n";
    std::cout << "  " << programName << " YourApp.pdb\n";
    std::cout << "  " << programName << " -auto C:\\Windows\\System32\\ntoskrnl.exe -kernel\n";
    std::cout << "  " << programName << " app.pdb -s \"CreateFileW\" -export results.json\n";
    std::cout << "  " << programName << " -diff old_version.pdb new_version.pdb\n";
    std::cout << "  " << programName << " -batch C:\\Symbols\\ C:\\Analysis\\\n";
    std::cout << "  " << programName << " ntdll.pdb -p \".*Heap.*\" -t \"_HEAP\"\n\n";
}

int wmain(int argc, wchar_t* argv[]) {
    if (argc < 2) {
        ShowUsage("PDBParser.exe");
        return 1;
    }

    std::wstring firstArg = argv[1];

    if (firstArg == L"-auto" && argc >= 3) {
        std::wstring exePath = argv[2];

        if (!std::filesystem::exists(exePath)) {
            std::wcerr << L"Error: Executable not found: " << exePath << L"\n";
            return 1;
        }

        std::cout << "Attempting to download PDB for executable...\n";
        auto downloadedPdb = PdbDownloader::DownloadPdbForExecutable(exePath);

        if (!downloadedPdb) {
            std::cout << "Failed to download PDB for executable\n";
            return 1;
        }

        std::wcout << L"Successfully downloaded PDB: " << *downloadedPdb << L"\n";

        try {
            PdbAnalyzer analyzer(*downloadedPdb);
            bool hasAdditionalOptions = false;

            for (int i = 3; i < argc; i++) {
                std::wstring arg = argv[i];
                hasAdditionalOptions = true;

                if (arg == L"-kernel") {
                    std::cout << "\n" << std::string(60, '=') << "\n";
                    std::cout << "  Kernel Symbol Resolution\n";
                    std::cout << std::string(60, '=') << "\n";

                    PdbParser parser(*downloadedPdb);
                    if (!parser.IsInitialized()) {
                        std::cout << "Failed to initialize PDB parser\n";
                        return 1;
                    }

                    auto WmipSMBiosTableLength = parser.GetSymbolRva(L"WmipSMBiosTableLength");
                    auto PsEnumProcesses = parser.GetSymbolRva(L"PsEnumProcesses");
                    auto PspInsertProcess = parser.GetSymbolRva(L"PspInsertProcess");
                    auto PspTerminateProcess = parser.GetSymbolRva(L"PspTerminateProcess");
                    auto MmQueryVirtualMemory = parser.GetSymbolRva(L"MmQueryVirtualMemory");
                    auto NtResumeThread = parser.GetSymbolRva(L"NtResumeThread");
                    auto BgpFwQueryBootGraphicsInformation = parser.GetSymbolRva(L"BgpFwQueryBootGraphicsInformation");
                    auto PsEnumProcessThreads = parser.GetSymbolRva(L"PsEnumProcessThreads");
                    auto KeResumeThread = parser.GetSymbolRva(L"KeResumeThread");
                    auto PspCreateThread = parser.GetSymbolRva(L"PspCreateThread");
                    auto PspSetQuotaLimits = parser.GetSymbolRva(L"PspSetQuotaLimits");
                    auto MmQueryWorkingSetInformation = parser.GetSymbolRva(L"MmQueryWorkingSetInformation");
                    auto MmAdjustWorkingSetSizeEx = parser.GetSymbolRva(L"MmAdjustWorkingSetSizeEx");
                    auto MiAllocateVirtualMemoryPrepare = parser.GetSymbolRva(L"MiAllocateVirtualMemoryPrepare");
                    auto ExpBootEnvironmentInformation = parser.GetSymbolRva(L"ExpBootEnvironmentInformation");
                    auto PspRundownSingleProcess = parser.GetSymbolRva(L"PspRundownSingleProcess");
                    auto PspGetContextThreadInternal = parser.GetSymbolRva(L"PspGetContextThreadInternal");
                    auto WmipSMBiosTablePhysicalAddress = parser.GetSymbolRva(L"WmipSMBiosTablePhysicalAddress");
                    auto WmipQueryAllData = parser.GetSymbolRva(L"WmipQueryAllData");
                    auto PiDDBLock = parser.GetSymbolRva(L"PiDDBLock");
                    auto PiDDBCacheTable = parser.GetSymbolRva(L"PiDDBCacheTable");
                    auto PspInsertThread = parser.GetSymbolRva(L"PspInsertThread");
                    auto ZwSetInformationProcess = parser.GetSymbolRva(L"ZwSetInformationProcess");
                    auto PsQueryFullProcessImageName = parser.GetSymbolRva(L"PsQueryFullProcessImageName");
                    auto KiNmiInterruptStart = parser.GetSymbolRva(L"KiNmiInterruptStart");
                    auto WmipSMBiosVersionInfo = parser.GetSymbolRva(L"WmipSMBiosVersionInfo");

                    if (!WmipSMBiosTableLength || !PsEnumProcesses || !PspInsertProcess ||
                        !PspTerminateProcess || !MmQueryVirtualMemory || !NtResumeThread ||
                        !BgpFwQueryBootGraphicsInformation || !PsEnumProcessThreads ||
                        !KeResumeThread || !PspCreateThread || !PspSetQuotaLimits ||
                        !MmQueryWorkingSetInformation || !MmAdjustWorkingSetSizeEx ||
                        !MiAllocateVirtualMemoryPrepare || !ExpBootEnvironmentInformation ||
                        !PspRundownSingleProcess || !PspGetContextThreadInternal ||
                        !WmipSMBiosTablePhysicalAddress || !WmipQueryAllData ||
                        !PiDDBLock || !PiDDBCacheTable || !PspInsertThread ||
                        !ZwSetInformationProcess || !PsQueryFullProcessImageName ||
                        !KiNmiInterruptStart || !WmipSMBiosVersionInfo) {

                        printf("[-] Some kernel symbols not found!\n");
                    }
                    else {
                        printf("[+] All kernel symbols resolved!\n");
                    }

                    printf("\nKernel Symbol Offsets:\n");
                    printf("WmipSMBiosTableLength = 0x%llx\n", WmipSMBiosTableLength.value_or(0));
                    printf("PsEnumProcesses = 0x%llx\n", PsEnumProcesses.value_or(0));
                    printf("PspInsertProcess = 0x%llx\n", PspInsertProcess.value_or(0));
                    printf("PspTerminateProcess = 0x%llx\n", PspTerminateProcess.value_or(0));
                    printf("MmQueryVirtualMemory = 0x%llx\n", MmQueryVirtualMemory.value_or(0));
                    printf("NtResumeThread = 0x%llx\n", NtResumeThread.value_or(0));
                    printf("BgpFwQueryBootGraphicsInformation = 0x%llx\n", BgpFwQueryBootGraphicsInformation.value_or(0));
                    printf("PsEnumProcessThreads = 0x%llx\n", PsEnumProcessThreads.value_or(0));
                    printf("KeResumeThread = 0x%llx\n", KeResumeThread.value_or(0));
                    printf("PspCreateThread = 0x%llx\n", PspCreateThread.value_or(0));
                    printf("PspSetQuotaLimits = 0x%llx\n", PspSetQuotaLimits.value_or(0));
                    printf("MmQueryWorkingSetInformation = 0x%llx\n", MmQueryWorkingSetInformation.value_or(0));
                    printf("MmAdjustWorkingSetSizeEx = 0x%llx\n", MmAdjustWorkingSetSizeEx.value_or(0));
                    printf("MiAllocateVirtualMemoryPrepare = 0x%llx\n", MiAllocateVirtualMemoryPrepare.value_or(0));
                    printf("ExpBootEnvironmentInformation = 0x%llx\n", ExpBootEnvironmentInformation.value_or(0));
                    printf("PspRundownSingleProcess = 0x%llx\n", PspRundownSingleProcess.value_or(0));
                    printf("PspGetContextThreadInternal = 0x%llx\n", PspGetContextThreadInternal.value_or(0));
                    printf("WmipSMBiosTablePhysicalAddress = 0x%llx\n", WmipSMBiosTablePhysicalAddress.value_or(0));
                    printf("WmipQueryAllData = 0x%llx\n", WmipQueryAllData.value_or(0));
                    printf("PiDDBLock = 0x%llx\n", PiDDBLock.value_or(0));
                    printf("PiDDBCacheTable = 0x%llx\n", PiDDBCacheTable.value_or(0));
                    printf("PspInsertThread = 0x%llx\n", PspInsertThread.value_or(0));
                    printf("ZwSetInformationProcess = 0x%llx\n", ZwSetInformationProcess.value_or(0));
                    printf("PsQueryFullProcessImageName = 0x%llx\n", PsQueryFullProcessImageName.value_or(0));
                    printf("KiNmiInterruptStart = 0x%llx\n", KiNmiInterruptStart.value_or(0));
                    printf("WmipSMBiosVersionInfo = 0x%llx\n", WmipSMBiosVersionInfo.value_or(0));
                }
                else if (arg == L"-s" && i + 1 < argc) {
                    analyzer.FindSpecificSymbol(argv[++i]);
                }
                else if (arg == L"-t" && i + 1 < argc) {
                    analyzer.AnalyzeStructure(argv[++i]);
                }
                else if (arg == L"-m" && i + 2 < argc) {
                    analyzer.FindStructMember(argv[i + 1], argv[i + 2]);
                    i += 2;
                }
                else if (arg == L"-p" && i + 1 < argc) {
                    analyzer.SearchByPattern(argv[++i]);
                }
                else if (arg == L"-l") {
                    analyzer.ListStructures();
                }
                else if (arg == L"-perf") {
                    analyzer.PerformanceTest();
                }
                else if (arg == L"-export" && i + 1 < argc) {
                    analyzer.ExportResults(argv[++i]);
                }
                else if (arg == L"-full") {
                    hasAdditionalOptions = false;
                    break;
                }
            }

            if (!hasAdditionalOptions) {
                analyzer.ShowBasicInfo();
                analyzer.AnalyzeSymbols();
                analyzer.ListStructures();
                analyzer.PerformanceTest();
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << std::endl;
            return 1;
        }

        return 0;
    }

    if (firstArg == L"-diff" && argc >= 4) {
        std::wstring oldPdb = argv[2];
        std::wstring newPdb = argv[3];

        if (!std::filesystem::exists(oldPdb) || !std::filesystem::exists(newPdb)) {
            std::wcout << L"Error: One or both PDB files not found\n";
            return 1;
        }

        try {
            PdbParser parser1(oldPdb);
            PdbParser parser2(newPdb);

            if (!parser1.IsInitialized() || !parser2.IsInitialized()) {
                std::cout << "Failed to initialize PDB parsers\n";
                return 1;
            }

            auto diffs = PdbComparer::ComparePdbs(parser1, parser2);
            PdbComparer::PrintDifferences(diffs);

            for (int i = 4; i < argc - 1; i++) {
                if (std::wstring(argv[i]) == L"-export") {
                    PdbComparer::ExportDifferencesToJson(diffs, argv[i + 1]);
                    std::wcout << L"Differences exported to: " << argv[i + 1] << L"\n";
                    break;
                }
            }

        }
        catch (const std::exception& e) {
            std::cerr << "Error comparing PDBs: " << e.what() << std::endl;
            return 1;
        }

        return 0;
    }

    if (firstArg == L"-batch" && argc >= 3) {
        std::wstring directory = argv[2];
        std::wstring outputDir = (argc >= 4) ? argv[3] : L"batch_output";

        if (!std::filesystem::exists(directory)) {
            std::wcout << L"Error: Directory not found: " << directory << L"\n";
            return 1;
        }

        try {
            BatchProcessor::ProcessDirectory(directory, outputDir);
            std::wcout << L"Batch processing complete. Results in: " << outputDir << L"\n";
        }
        catch (const std::exception& e) {
            std::cerr << "Error in batch processing: " << e.what() << std::endl;
            return 1;
        }

        return 0;
    }

    std::wstring pdbPath = firstArg;

    if (!std::filesystem::exists(pdbPath)) {
        std::wcerr << L"Error: PDB file not found: " << pdbPath << L"\n";
        return 1;
    }

    try {
        PdbAnalyzer analyzer(pdbPath);
        bool hasOptions = false;

        for (int i = 2; i < argc; i++) {
            std::wstring arg = argv[i];
            hasOptions = true;

            if (arg == L"-s" && i + 1 < argc) {
                analyzer.FindSpecificSymbol(argv[++i]);
            }
            else if (arg == L"-t" && i + 1 < argc) {
                analyzer.AnalyzeStructure(argv[++i]);
            }
            else if (arg == L"-m" && i + 2 < argc) {
                analyzer.FindStructMember(argv[i + 1], argv[i + 2]);
                i += 2;
            }
            else if (arg == L"-p" && i + 1 < argc) {
                analyzer.SearchByPattern(argv[++i]);
            }
            else if (arg == L"-l") {
                analyzer.ListStructures();
            }
            else if (arg == L"-perf") {
                analyzer.PerformanceTest();
            }
            else if (arg == L"-export" && i + 1 < argc) {
                analyzer.ExportResults(argv[++i]);
            }
            else if (arg == L"-kernel") {
                std::cout << "\n" << std::string(60, '=') << "\n";
                std::cout << "  Kernel Symbol Resolution\n";
                std::cout << std::string(60, '=') << "\n";

                PdbParser parser(pdbPath);
                if (!parser.IsInitialized()) {
                    std::cout << "Failed to initialize PDB parser\n";
                    continue;
                }

                auto WmipSMBiosTableLength = parser.GetSymbolRva(L"WmipSMBiosTableLength");
                auto PsEnumProcesses = parser.GetSymbolRva(L"PsEnumProcesses");
                auto PspInsertProcess = parser.GetSymbolRva(L"PspInsertProcess");
                auto PspTerminateProcess = parser.GetSymbolRva(L"PspTerminateProcess");
                auto MmQueryVirtualMemory = parser.GetSymbolRva(L"MmQueryVirtualMemory");
                auto NtResumeThread = parser.GetSymbolRva(L"NtResumeThread");
                auto BgpFwQueryBootGraphicsInformation = parser.GetSymbolRva(L"BgpFwQueryBootGraphicsInformation");
                auto PsEnumProcessThreads = parser.GetSymbolRva(L"PsEnumProcessThreads");
                auto KeResumeThread = parser.GetSymbolRva(L"KeResumeThread");
                auto PspCreateThread = parser.GetSymbolRva(L"PspCreateThread");
                auto PspSetQuotaLimits = parser.GetSymbolRva(L"PspSetQuotaLimits");
                auto MmQueryWorkingSetInformation = parser.GetSymbolRva(L"MmQueryWorkingSetInformation");
                auto MmAdjustWorkingSetSizeEx = parser.GetSymbolRva(L"MmAdjustWorkingSetSizeEx");
                auto MiAllocateVirtualMemoryPrepare = parser.GetSymbolRva(L"MiAllocateVirtualMemoryPrepare");
                auto ExpBootEnvironmentInformation = parser.GetSymbolRva(L"ExpBootEnvironmentInformation");
                auto PspRundownSingleProcess = parser.GetSymbolRva(L"PspRundownSingleProcess");
                auto PspGetContextThreadInternal = parser.GetSymbolRva(L"PspGetContextThreadInternal");
                auto WmipSMBiosTablePhysicalAddress = parser.GetSymbolRva(L"WmipSMBiosTablePhysicalAddress");
                auto WmipQueryAllData = parser.GetSymbolRva(L"WmipQueryAllData");
                auto PiDDBLock = parser.GetSymbolRva(L"PiDDBLock");
                auto PiDDBCacheTable = parser.GetSymbolRva(L"PiDDBCacheTable");
                auto PspInsertThread = parser.GetSymbolRva(L"PspInsertThread");
                auto ZwSetInformationProcess = parser.GetSymbolRva(L"ZwSetInformationProcess");
                auto PsQueryFullProcessImageName = parser.GetSymbolRva(L"PsQueryFullProcessImageName");
                auto KiNmiInterruptStart = parser.GetSymbolRva(L"KiNmiInterruptStart");
                auto WmipSMBiosVersionInfo = parser.GetSymbolRva(L"WmipSMBiosVersionInfo");

                if (!WmipSMBiosTableLength || !PsEnumProcesses || !PspInsertProcess ||
                    !PspTerminateProcess || !MmQueryVirtualMemory || !NtResumeThread ||
                    !BgpFwQueryBootGraphicsInformation || !PsEnumProcessThreads ||
                    !KeResumeThread || !PspCreateThread || !PspSetQuotaLimits ||
                    !MmQueryWorkingSetInformation || !MmAdjustWorkingSetSizeEx ||
                    !MiAllocateVirtualMemoryPrepare || !ExpBootEnvironmentInformation ||
                    !PspRundownSingleProcess || !PspGetContextThreadInternal ||
                    !WmipSMBiosTablePhysicalAddress || !WmipQueryAllData ||
                    !PiDDBLock || !PiDDBCacheTable || !PspInsertThread ||
                    !ZwSetInformationProcess || !PsQueryFullProcessImageName ||
                    !KiNmiInterruptStart || !WmipSMBiosVersionInfo) {

                    printf("[-] Some kernel symbols not found (expected for non-kernel PDBs)!\n");
                }
                else {
                    printf("[+] All kernel symbols resolved!\n");
                }

                printf("\nKernel Symbol Offsets:\n");
                printf("WmipSMBiosTableLength = 0x%llx\n", WmipSMBiosTableLength.value_or(0));
                printf("PsEnumProcesses = 0x%llx\n", PsEnumProcesses.value_or(0));
                printf("PspInsertProcess = 0x%llx\n", PspInsertProcess.value_or(0));
                printf("PspTerminateProcess = 0x%llx\n", PspTerminateProcess.value_or(0));
                printf("MmQueryVirtualMemory = 0x%llx\n", MmQueryVirtualMemory.value_or(0));
                printf("NtResumeThread = 0x%llx\n", NtResumeThread.value_or(0));
                printf("BgpFwQueryBootGraphicsInformation = 0x%llx\n", BgpFwQueryBootGraphicsInformation.value_or(0));
                printf("PsEnumProcessThreads = 0x%llx\n", PsEnumProcessThreads.value_or(0));
                printf("KeResumeThread = 0x%llx\n", KeResumeThread.value_or(0));
                printf("PspCreateThread = 0x%llx\n", PspCreateThread.value_or(0));
                printf("PspSetQuotaLimits = 0x%llx\n", PspSetQuotaLimits.value_or(0));
                printf("MmQueryWorkingSetInformation = 0x%llx\n", MmQueryWorkingSetInformation.value_or(0));
                printf("MmAdjustWorkingSetSizeEx = 0x%llx\n", MmAdjustWorkingSetSizeEx.value_or(0));
                printf("MiAllocateVirtualMemoryPrepare = 0x%llx\n", MiAllocateVirtualMemoryPrepare.value_or(0));
                printf("ExpBootEnvironmentInformation = 0x%llx\n", ExpBootEnvironmentInformation.value_or(0));
                printf("PspRundownSingleProcess = 0x%llx\n", PspRundownSingleProcess.value_or(0));
                printf("PspGetContextThreadInternal = 0x%llx\n", PspGetContextThreadInternal.value_or(0));
                printf("WmipSMBiosTablePhysicalAddress = 0x%llx\n", WmipSMBiosTablePhysicalAddress.value_or(0));
                printf("WmipQueryAllData = 0x%llx\n", WmipQueryAllData.value_or(0));
                printf("PiDDBLock = 0x%llx\n", PiDDBLock.value_or(0));
                printf("PiDDBCacheTable = 0x%llx\n", PiDDBCacheTable.value_or(0));
                printf("PspInsertThread = 0x%llx\n", PspInsertThread.value_or(0));
                printf("ZwSetInformationProcess = 0x%llx\n", ZwSetInformationProcess.value_or(0));
                printf("PsQueryFullProcessImageName = 0x%llx\n", PsQueryFullProcessImageName.value_or(0));
                printf("KiNmiInterruptStart = 0x%llx\n", KiNmiInterruptStart.value_or(0));
                printf("WmipSMBiosVersionInfo = 0x%llx\n", WmipSMBiosVersionInfo.value_or(0));
            }
            else if (arg == L"-full") {
                hasOptions = false;
                break;
            }
        }

        if (!hasOptions) {
            analyzer.ShowBasicInfo();
            analyzer.AnalyzeSymbols();
            analyzer.ListStructures();
            analyzer.PerformanceTest();

            std::cout << "\n" << std::string(60, '=') << "\n";
            std::cout << "Interactive Examples:\n";
            std::cout << std::string(60, '=') << "\n";

            analyzer.FindSpecificSymbol(L"CreateFileW");
            analyzer.SearchByPattern(L".*Create.*");
            analyzer.AnalyzeStructure(L"_UNICODE_STRING");
            analyzer.FindStructMember(L"_UNICODE_STRING", L"Buffer");
        }

    }
    catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "\nAnalysis complete.\n";
    return 0;
}