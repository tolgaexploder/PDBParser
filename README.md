# PDBParser
Fast and powerful PDB parser and analyzer for Windows debugging and reverse engineering.
===================

Table of Contents
-----------------
- [Features](#features)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [Advanced Usage](#advanced-usage)
- [Command Line Options](#command-line-options)
- [Output Formats](#output-formats)
- [Use Cases](#use-cases)
- [Technical Notes](#technical-notes)
- [Building](#building)
- [Examples](#examples)
- [Performance](#performance)
- [Legal](#legal)

FEATURES
--------
- Auto-download PDB files from Microsoft Symbol Server with robust error handling
- Kernel symbol resolution for critical Windows functions
- Structure analysis with accurate member offsets and sizes
- Regex pattern matching and symbol search
- JSON export with complete symbol information
- Batch processing of multiple PDB files with optional JSON export
- PDB comparison and diff analysis
- Performance benchmarking with enhanced caching

REQUIREMENTS
------------
- Windows 10/11 x64
- Visual Studio 2019/2022 with DIA SDK
- Internet connection for auto-download feature

QUICK START
-----------
- Download and analyze kernel symbols:  
  `PDBParser.exe -auto C:\Windows\System32\ntoskrnl.exe -kernel`
- Analyze your own PDB:  
  `PDBParser.exe YourApp.pdb`
- Find specific symbol:  
  `PDBParser.exe app.pdb -s "CreateFileW"`
- Search by pattern:  
  `PDBParser.exe app.pdb -p ".*Thread.*"`
- Export to JSON:  
  `PDBParser.exe app.pdb -export results.json`

ADVANCED USAGE
--------------
- Compare two PDB versions:  
  `PDBParser.exe -diff old.pdb new.pdb -export changes.json`
- Batch process all PDB files in a directory and optionally export to a single JSON file:  
  `PDBParser.exe -batch C:\Symbols\ -export C:\Analysis\batch_results.json`
- Analyze a structure's layout:  
  `PDBParser.exe ntdll.pdb -t "_PEB"`
- Find a member's offset within that structure:  
  `PDBParser.exe ntdll.pdb -m "_PEB" "ProcessHeap"`
- Function hunting with regex:  
  `PDBParser.exe malware.pdb -p ".*(Crypt|Hash|Encrypt).*" -export crypto.json`
- Performance testing:  
  `PDBParser.exe large.pdb -perf`

COMMAND LINE OPTIONS
--------------------
| Mode/Option | Arguments              | Description                                           |
|------------|-------------------------|-------------------------------------------------------|
| (default)  | `<pdb_file>`            | Analyze a specific PDB file                           |
| `-auto`    | `<exe_file>`            | Download PDB for an executable from MS Symbol Server  |
| `-s`       | `<symbol>`              | Find specific symbol                                  |
| `-t`       | `<struct>`              | Analyze structure layout                              |
| `-m`       | `<struct> <member>`     | Find structure member offset                          |
| `-p`       | `<pattern>`             | Search by regex pattern                               |
| `-l`       | —                       | List structures                                       |
| `-perf`    | —                       | Performance test                                      |
| `-export`  | `<file>`                | Export to JSON                                        |
| `-kernel`  | —                       | Resolve kernel symbols                                |
| `-diff`    | `<old> <new>`           | Compare two PDB files                                 |
| `-batch`   | `<input_dir> [-export <file>]` | Process all PDBs in input directory, optionally export to a single JSON |
| `-full`    | —                       | Complete analysis (default)                           |

OUTPUT FORMATS
--------------
- Symbol information includes RVA addresses, sizes, and type IDs
- Structure analysis shows accurate member layouts and offsets
- JSON exports contain complete symbol tables and metadata
- Performance metrics show enumeration speed and cache efficiency

USE CASES
---------
- Malware analysis and reverse engineering
- Windows kernel research and exploit development
- Security vulnerability research
- Binary analysis and code archaeology
- Automated symbol extraction for tools

TECHNICAL NOTES
---------------
- Built on Microsoft DIA SDK for maximum compatibility
- Enhanced caching for faster repeated lookups
- Supports modern PDB formats and symbol types
- Memory-efficient design handles large PDB files (500MB+)
- Exception-safe code with improved error handling for PDB availability and structure analysis

BUILDING
--------
1. Clone the repository
2. Open the solution in Visual Studio 2019/2022
3. Ensure the **Desktop development with C++** workload is installed
4. Build the **Release** / **x64** configuration
5. No external dependencies required

EXAMPLES
--------
### Note on PDB Availability
Some commands, like structure analysis or finding member offsets, require a valid PDB file. If you try:

`PDBParser.exe ntdll.pdb -m "_UNICODE_STRING" "Buffer"`

and the PDB file is not present in the directory, you will get an error:

`Error: PDB file not found: ntdll.pdb`

To resolve this, use the `-auto` mode to automatically download the PDB from Microsoft:

`PDBParser.exe -auto C:\Windows\System32\ntdll.dll -t "_LDR_DATA_TABLE_ENTRY"`

This ensures that the necessary PDB is available and analysis can proceed without errors.

### Structure Analysis
`PDBParser.exe -auto C:\Windows\System32\ntdll.dll -t "_LDR_DATA_TABLE_ENTRY"`

**Output**:
```
Attempting to download PDB for executable...
Successfully downloaded PDB: C:\Symbols\ntdll.pdb\<GUID>\ntdll.pdb
================================================
Structure: _LDR_DATA_TABLE_ENTRY (Size: 312 bytes)
Members:
  +0x0000 | 00000000 | InLoadOrderLinks
  +0x0010 | 00000000 | InMemoryOrderLinks
  +0x0020 | 00000000 | InInitializationOrderLinks
  +0x0030 | 00000000 | DllBase
  +0x0038 | 00000000 | EntryPoint
  +0x0040 | 00000000 | SizeOfImage
  +0x0048 | 00000000 | FullDllName
  +0x0058 | 00000000 | BaseDllName
  +0x0068 | 00000001 | Flags
  ...
  +0x0130 | 00000000 | HotPatchState
```

### Kernel Analysis
`PDBParser.exe -auto C:\Windows\System32\ntoskrnl.exe -kernel`

**Output**:
```
Attempting to download PDB for executable...
Successfully downloaded PDB: C:\Symbols\ntkrnlmp.pdb\<GUID>\ntkrnlmp.pdb
[+] All kernel symbols resolved!
WmipSMBiosTableLength = 0x1234
PsEnumProcesses = 0x5678
PspInsertProcess = 0x9ABC
...
```

### Symbol Search
`PDBParser.exe app.pdb -s "CreateFileW"`

**Output**:
```
Found: CreateFileW @ RVA 0x123456
```

### Regex Search
`PDBParser.exe app.pdb -p ".*Thread.*"`

**Output**:
```
Found: PsCreateThread @ RVA 0x234567
Found: PsTerminateThread @ RVA 0x345678
```

### Structure Member Offset
`PDBParser.exe ntdll.pdb -m "_UNICODE_STRING" "Buffer"`

**Output**:
```
Member Buffer offset = 0x8
```

### PDB Diff
`PDBParser.exe -diff v1.pdb v2.pdb -export version_diff.json`

**Output**:
```
Differences exported to version_diff.json
```

### Batch Processing

**Note:** The `-batch` command will process PDB files in a folder, but it requires valid PDB files. If PDBs are not present, use the `-auto` mode to download them from Microsoft.

**Example: Auto-download and export a single PDB**

`PDBParser.exe -auto C:\Windows\System32\comctl32.dll -export C:\Analysis\comctl32.json`

**Output**:
```
Attempting to download PDB for executable...
Downloading PDB from: https://msdl.microsoft.com/download/symbols/comctl32.pdb/<GUID>/comctl32.pdb
Saving to: C:\Symbols\comctl32.pdb\<GUID>\comctl32.pdb
Successfully downloaded PDB: C:\Symbols\comctl32.pdb\<GUID>\comctl32.pdb
============================================================
  Export Results
============================================================
Exporting to: C:\Analysis\comctl32.json
Export successful
```

**Example: Batch processing a directory of PDBs (already downloaded)**

`PDBParser.exe -batch C:\Symbols\ -export C:\Analysis\batch_results.json`

**Output**:
```
Processing: C:\Symbols\comctl32.pdb
Processing: C:\Symbols\ntdll.pdb
...
Batch processing complete. Results exported to C:\Analysis\batch_results.json
```

### Performance Test
`PDBParser.exe large.pdb -perf`

**Output**:
```
5000 symbols parsed in ~50ms
Individual lookups in ~5 microseconds (cached)
```

PERFORMANCE
-----------
- 5000 symbols parsed in ~50ms
- Individual lookups in ~5 microseconds (cached)
- Large PDB files supported up to 500MB
- Download speeds limited by network connection

LEGAL
-----
For legitimate security research and educational use only.  
Users are responsible for compliance with applicable laws.  
Not intended for malicious purposes.
