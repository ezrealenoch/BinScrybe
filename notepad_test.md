# BinScrybe Analysis Summary

## Basic Info
File: notepad.exe
Path: C:\WINDOWS\notepad.exe
Size: 0.3 KB (360448 bytes)
MD5: 7d02feb3b0deb79d6d61b2f89fe7f1d6
SHA1: f75c9a7c6c1d31eda90cdc271dc8d4db2ec12ac9
SHA256: b862fd21ab3c38f7aabb3f41b8b6845d14692cd4273edc9dfec7b555e2c6b505
Analysis Time: 2025-04-13T00:06:32.834574

## CAPA Capabilities Detected
Total capabilities found: 22


### Host-Interaction
Total capabilities in this category: 16
- host-interaction/cli: accept command line arguments @ 0x140010108, 0x140010143
- host-interaction/clipboard: open clipboard @ 0x14000F1D0, 0x14000F2DE
- host-interaction/file-system/create: create directory @ 0x140022370, 0x140022385
- host-interaction/file-system/delete: delete file (2 matches) @ 0x140011A28, 0x1400121E2, 0x140022918, 0x140022DB7
- host-interaction/file-system/exists: check if file exists (5 matches) @ 0x140008804
- host-interaction/file-system/meta: get file attributes @ 0x140011A98, 0x140011A28, 0x140011AA4
- host-interaction/file-system/read: read file on Windows @ 0x14000C940
- host-interaction/file-system/write: write file on Windows (2 matches) @ 0x140010B3C, 0x140010C4F, 0x140011A28
- host-interaction/file-system: set current directory @ 0x140022918, 0x140022C52
- host-interaction/gui/window/get-text: get graphical window text (3 matches) @ 0x140011994
- host-interaction/gui/window/hide: hide graphical window (2 matches) @ 0x14001FB6E, 0x14001F954
- host-interaction/hardware/storage: get disk size @ 0x140022370, 0x140022456
- host-interaction/log/debug/write-event: print debug messages (4 matches) @ 0x1400030CC, 0x14000384B, 0x14000339C, 0x1400035D6, 0x140003614 (+ 3 more)
- host-interaction/process/create: create process on Windows (2 matches) @ 0x14001FCC0, 0x14001FCDC, 0x140023B30, 0x140023C02
- host-interaction/registry/create: set registry value (4 matches) @ 0x14000A9F4, 0x14000AA27, 0x14001E948
- host-interaction/registry/delete: delete registry key @ 0x140022918

### Collection
Total capabilities in this category: 1
- collection: get geographical location (3 matches) @ 0x1400104B0, 0x140010542, 0x1400106C8, 0x1400106EA, 0x1400130AC (+ 1 more)

### Executable
Total capabilities in this category: 1
- executable/resource: extract resource via kernel32 functions @ 0x140023D58, 0x140023DAE, 0x140023E12

### Load-Code
Total capabilities in this category: 1
- load-code/pe: parse PE header (2 matches) @ 0x1400022A4

### Linking
Total capabilities in this category: 1
- linking/runtime-linking: link function at runtime on Windows (16 matches) @ 0x14000638D, 0x14000638D, 0x140006680, 0x140006680, 0x140007C94 (+ 27 more)

### Uncategorized
Total capabilities in this category: 2
- contain loop (71 matches, only showing first match of library rule) @ 0x140001094
- create or open file (11 matches, only showing first match of library rule) @ 0x14000C98C, 0x14000C98C

### Detailed Rule Triggers
- **Block [B0001.019]**
  - Found at 2 locations:
    - 0x1400142DC
    - 0x1400130AC
- **contain loop (71 matches, only showing first match of library rule)**
  - Found at 1 locations:
    - 0x140001094
- **create or open file (11 matches, only showing first match of library rule)**
  - Found at 2 locations:
    - 0x14000C98C
    - 0x14000C98C
- **System::Registry::Open Registry Key [C0036.003]**
  - Found at 2 locations:
    - 0x140012984
    - 0x140012A1C
- **https://github.com/LordNoteworthy/al-khaser/blob/master/al-khaser/…**
  - Found at 3 locations:
    - 0x140004320
    - 0x140004254
    - 0x140004329
- **regex: /(?<!\w)ida?(\.exe)?$/i**
  - Found at 1 locations:
    - 0x4BC4F
- **Instructions [B0001.034]**
  - Found at 1 locations:
    - 0x1400130AC
- **collection: get geographical location (3 matches)**
  - Found at 6 locations:
    - 0x1400104B0
    - 0x140010542
    - 0x1400106C8
    - 0x1400106EA
    - 0x1400130AC
    - 0x14001327B
- **Algorithm [E1027.m02], Data::Encode Data::XOR [C0026.002]**
  - Found at 2 locations:
    - 0x140013D00
    - 0x1400130AC
- **number: 0x8101010101010100 = 0x8101010101010100 = ~0x7EFEFEFEFEFEFEFF**
  - Found at 2 locations:
    - 0x14001400C
    - 0x1400130AC
- **number: 0x8101010101010100 = 0x8101010101010100 = ~0x7EFEFEFEFEFEFEFF**
  - Found at 2 locations:
    - 0x140015177
    - 0x1400130AC
- **number: 0x8101010101010100 = 0x8101010101010100 = ~0x7EFEFEFEFEFEFEFF**
  - Found at 2 locations:
    - 0x140015332
    - 0x1400130AC
- **number: 0x8101010101010100 = 0x8101010101010100 = ~0x7EFEFEFEFEFEFEFF**
  - Found at 2 locations:
    - 0x1400168C9
    - 0x1400130AC
- **number: 0x8101010101010100 = 0x8101010101010100 = ~0x7EFEFEFEFEFEFEFF**
  - Found at 2 locations:
    - 0x140016BF0
    - 0x1400130AC
- **number: 0x8101010101010100 = 0x8101010101010100 = ~0x7EFEFEFEFEFEFEFF**
  - Found at 2 locations:
    - 0x14001C2AB
    - 0x1400130AC
- **number: 0x8101010101010100 = 0x8101010101010100 = ~0x7EFEFEFEFEFEFEFF**
  - Found at 2 locations:
    - 0x14001C46B
    - 0x1400130AC
- **number: 0x8101010101010100 = 0x8101010101010100 = ~0x7EFEFEFEFEFEFEFF**
  - Found at 2 locations:
    - 0x14001D78D
    - 0x1400130AC
- **number: 0x8101010101010100 = 0x8101010101010100 = ~0x7EFEFEFEFEFEFEFF**
  - Found at 2 locations:
    - 0x14001DA8B
    - 0x1400130AC
- **executable/resource: extract resource via kernel32 functions**
  - Found at 3 locations:
    - 0x140023D58
    - 0x140023DAE
    - 0x140023E12
- **optional:**
  - Found at 1 locations:
    - 0x140023D96
- **host-interaction/cli: accept command line arguments**
  - Found at 2 locations:
    - 0x140010108
    - 0x140010143
- **host-interaction/clipboard: open clipboard**
  - Found at 2 locations:
    - 0x14000F1D0
    - 0x14000F2DE
- **optional:**
  - Found at 1 locations:
    - 0x14000F300
- **anushka.virgaonkar@mandiant.com**
  - Found at 6 locations:
    - 0x140021EF4
    - 0x140021F37
    - 0x140022030
    - 0x140022045
    - 0x140023AB0
    - 0x140023AD7
- **host-interaction/file-system: set current directory**
  - Found at 2 locations:
    - 0x140022918
    - 0x140022C52
- **host-interaction/file-system/create: create directory**
  - Found at 2 locations:
    - 0x140022370
    - 0x140022385
- **host-interaction/file-system/delete: delete file (2 matches)**
  - Found at 4 locations:
    - 0x140011A28
    - 0x1400121E2
    - 0x140022918
    - 0x140022DB7
- **host-interaction/file-system/exists: check if file exists (5 matches)**
  - Found at 1 locations:
    - 0x140008804
- **basic block:**
  - Found at 1 locations:
    - 0x1400088BA
- **number: 0x2 = ERROR_FILE_NOT_FOUND @ 0x1400088C6**
  - Found at 3 locations:
    - 0x14000B3C0
    - 0x14000B412
    - 0x140011A28
- **basic block:**
  - Found at 1 locations:
    - 0x140011AA4
- **number: 0xFFFFFFFF = INVALID_FILE_ATTRIBUTES @ 0x140011AB0**
  - Found at 2 locations:
    - 0x140011AE2
    - 0x14001E504
- **basic block:**
  - Found at 1 locations:
    - 0x14001E69E
- **number: 0x2 = ERROR_FILE_NOT_FOUND @ 0x14001E6AA**
  - Found at 2 locations:
    - 0x14001E760
    - 0x14001E76B
- **host-interaction/file-system/meta: get file attributes**
  - Found at 3 locations:
    - 0x140011A98
    - 0x140011A28
    - 0x140011AA4
- **host-interaction/file-system/read: read file on Windows**
  - Found at 1 locations:
    - 0x14000C940
- **match: create or open file @ 0x14000C98C**
  - Found at 2 locations:
    - 0x14000C98C
    - 0x14000C9C3
- **host-interaction/file-system/write: write file on Windows (2 matches)**
  - Found at 3 locations:
    - 0x140010B3C
    - 0x140010C4F
    - 0x140011A28
- **match: create or open file @ 0x140011B18**
  - Found at 5 locations:
    - 0x140011B18
    - 0x140011C4C
    - 0x140011D46
    - 0x140011DA0
    - 0x140011DF7
- **host-interaction/gui/window/get-text: get graphical window text (3 matches)**
  - Found at 1 locations:
    - 0x140011994
- **number: 0xD = WM_GETTEXT @ 0x14001FA7B**
  - Found at 2 locations:
    - 0x14001FA83
    - 0x14001F954
- **number: 0xD = WM_GETTEXT @ 0x14001FA7B**
  - Found at 3 locations:
    - 0x14001FA83
    - 0x1400205E4
    - 0x140020AEC
- **host-interaction/gui/window/hide: hide graphical window (2 matches)**
  - Found at 2 locations:
    - 0x14001FB6E
    - 0x14001F954
- **number: 0x0 = SW_HIDE @ 0x14001FC3A**
  - Found at 3 locations:
    - 0x14001FBC7
    - 0x14001FB6E
    - 0x14001F954
- **number: 0x0 = SW_HIDE @ 0x14001FC3A**
  - Found at 1 locations:
    - 0x14001FBC7
- **[T1614.001]**
  - Found at 3 locations:
    - 0x14000E880
    - 0x14000EE5E
    - 0x1400130AC
- **optional:**
  - Found at 2 locations:
    - 0x14001327B
    - 0x140013C24
- **host-interaction/hardware/storage: get disk size**
  - Found at 2 locations:
    - 0x140022370
    - 0x140022456
- **host-interaction/log/debug/write-event: print debug messages (4 matches)**
  - Found at 8 locations:
    - 0x1400030CC
    - 0x14000384B
    - 0x14000339C
    - 0x1400035D6
    - 0x140003614
    - 0x14000384B
    - 0x140005F4C
    - 0x140006208
- **mehunhoff@google.com**
  - Found at 4 locations:
    - 0x1400042D3
    - 0x1400042D3
    - 0x1400046F9
    - 0x1400046F9
- **host-interaction/process/create: create process on Windows (2 matches)**
  - Found at 4 locations:
    - 0x14001FCC0
    - 0x14001FCDC
    - 0x140023B30
    - 0x140023C02
- **anushka.virgaonkar@mandiant.com**
  - Found at 5 locations:
    - 0x14000B314
    - 0x14000B35C
    - 0x14001E8E0
    - 0x14001E91C
    - 0x14001E948
- **match: create or open registry key @ 0x14001E9AD**
  - Found at 5 locations:
    - 0x14001E9C2
    - 0x14001E994
    - 0x14001EA24
    - 0x14001EA6C
    - 0x140022918
- **match: create or open registry key @ 0x140022918, 0x14002297D**
  - Found at 3 locations:
    - 0x140022965
    - 0x140022994
    - 0x140022A60
- **host-interaction/registry/create: set registry value (4 matches)**
  - Found at 3 locations:
    - 0x14000A9F4
    - 0x14000AA27
    - 0x14001E948
- **match: create or open registry key @ 0x14001E9AD**
  - Found at 6 locations:
    - 0x14001E9C2
    - 0x14001E9F3
    - 0x14001EAB0
    - 0x14001EAD0
    - 0x14001EAE8
    - 0x14001EB38
- **host-interaction/registry/delete: delete registry key**
  - Found at 1 locations:
    - 0x140022918
- **match: create or open registry key @ 0x140022918, 0x14002297D**
  - Found at 3 locations:
    - 0x140022965
    - 0x140022994
    - 0x140022DD5
- **linking/runtime-linking: link function at runtime on Windows (16 matches)**
  - Found at 32 locations:
    - 0x14000638D
    - 0x14000638D
    - 0x140006680
    - 0x140006680
    - 0x140007C94
    - 0x140007C94
    - 0x140007D1A
    - 0x140007D1A
    - 0x1400084D5
    - 0x1400084D5
    - 0x1400084D5
    - 0x1400084D5
    - 0x140008B2D
    - 0x140008B2D
    - 0x140008D68
    - 0x140008D68
    - 0x140008EE5
    - 0x140008EE5
    - 0x140009764
    - 0x140009764
    - (+ 12 more addresses)
- **https://www.ired.team/offensive-security/code-injection-process-in…**
  - Found at 1 locations:
    - 0x140022F18
- **load-code/pe: parse PE header (2 matches)**
  - Found at 1 locations:
    - 0x1400022A4
- **number: 0x5A4D = IMAGE_DOS_SIGNATURE (MZ) @ 0x1400022B5**
  - Found at 1 locations:
    - 0x1400130AC
- **[T1614.001]**
  - Found at 2 locations:
    - 0x1400104B0
    - 0x14001055A

## Detect It Easy (DIE) Analysis
### File Information
- File format: Not detected
- Compiler: Not detected
- Packer: Not detected
- Linker: Not detected
- Entropy: Not calculated

### Suspicious Indicators
- No suspicious indicators detected by DIE

## PE-sieve Analysis
### Process Hollowing Detection
- No process hollowing detected

### Anomalies
- No anomalies detected

### Injected Sections
- No injected sections detected

---

## Conclusion
No significant security indicators were detected in this binary. Threat assessment: **Low** risk.

---

## Analysis Tools Used
- BinScrybe: Binary analysis and summary generation
- CAPA: Capability detection
- DIE (Detect It Easy): Format and compiler detection
- PE-sieve: PE file anomaly detection