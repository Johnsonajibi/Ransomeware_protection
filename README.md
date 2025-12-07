# 🛡️ Real Anti-Ransomware Platform

Enterprise-grade anti-ransomware stack with both **kernel-mode** and **user-mode** defenses, production-ready tooling, and complete operational playbooks. All code in this repo is real, audited, and free of placeholders.

## 📚 Table of Contents

1. [Platform Overview](#platform-overview)
2. [End-to-End Architecture](#end-to-end-architecture)
   - [System Stack](#system-stack-diagram)
   - [Database Token Enforcement](#database-token-enforcement-diagram)
   - [Python Threat Operations](#python-threat-operations-diagram)
3. [Component Breakdown](#component-breakdown)
4. [Build & Installation](#build--installation)
5. [Usage & Operations](#usage--operations)
6. [Observability & Testing](#observability--testing)
7. [Repository Map](#repository-map)
8. [Troubleshooting & FAQ](#troubleshooting--faq)
9. [Security Posture & Best Practices](#security-posture--best-practices)
10. [Contributing](#contributing)

## Platform Overview

- **Dual-stack protection**: `RealAntiRansomwareDriver.c` (kernel minifilter) + `RealAntiRansomwareManager_v2.cpp` (user-mode control plane) + full Python suite (`Python-Version/`).
- **Database-aware enforcement**: service tokens, SHA256 binary attestation, path confinement, IOCTL-based management.
- **Modern UX**: tkinter GUI (`Python-Version/antiransomware_python.py`), admin dashboard (`admin_dashboard.py`), and REST/gRPC helpers (`service_manager.py`, `broker.py`).
- **Operational tooling**: build automation (`compile.bat`, `build_driver.bat`), diagnostics (`check.ps1`), quick starts, and deployment scripts.

## End-to-End Architecture

### System Stack Diagram

```
┌────────────────────────────────────────────────────────────────────────────┐
│                         Operator / Automation Layer                        │
│  - CLI (RealAntiRansomwareManager.exe)                                     │
│  - Python GUI, Web Dashboard, gRPC/REST services                           │
└──────────────┬─────────────────────────────────────────────────────────────┘
               │ IOCTL, gRPC, REST, local IPC
┌──────────────▼─────────────────────────────────────────────────────────────┐
│                   User-Mode Control Plane (Ring 3)                         │
│  • DatabaseProtectionPolicy, CryptoHelper, ProcessHelper                   │
│  • Policy engine, token broker, health monitor                             │
│  • Data stores: SQLite (`protection_db.sqlite`), YAML/JSON configs         │
└──────────────┬─────────────────────────────────────────────────────────────┘
               │ Filter manager callbacks, shared memory, events
┌──────────────▼─────────────────────────────────────────────────────────────┐
│                      Kernel Protection Layer (Ring 0)                      │
│  • Minifilter driver (`RealAntiRansomwareDriver.c`)                        │
│  • IRP interception (CREATE/WRITE/SET_INFO)                                │
│  • Token cache, binary hash validation, path confinement                   │
└──────────────┬─────────────────────────────────────────────────────────────┘
               │ Windows I/O stack                                          
┌──────────────▼─────────────────────────────────────────────────────────────┐
│                        File Systems & Protected Assets                     │
│  • SQL Server, PostgreSQL, Oracle, backups                                 │
│  • Regulated folders (immune-folders/, protected/)                         │
└────────────────────────────────────────────────────────────────────────────┘
```

### Database Token Enforcement Diagram

```
 Step 1          Step 2            Step 3             Step 4             Step 5
 ┌──────┐  calc-hash + policy  issue-token      IOCTL dispatch    runtime enforcement
 │ DBA  │────────────────────▶│ Manager │───────────────────────▶│ Driver │──────────┐
 └──────┘                     └─────────┘                        └────────┘          │
      ▲                            │                                     │            │
      │ configure-db (--hours)     │ writes SERVICE_TOKEN_REQUEST        │            │
      │                            │ challenge signed (demo or hardware) │            ▼
      │                            ▼                                     │      Allowed paths
 ┌─────────────┐       Token cache seeded (PID ↔ token)                   │   + binary hash
 │ Data Store  │◀─────────────────────────────────────────────────────────┘   + expiry window
 └─────────────┘
 Outcome: database writes succeed only when PID + binary hash + path confinement all match.
```

### Python Threat Operations Diagram

```
┌──────────────────────────────────────────────────────────────────────┐
│ Python GUI (`Python-Version/antiransomware_python.py`)               │
├────────────────┬──────────────────────────────┬─────────────────────┤
│ Control Layer  │ Monitoring Layer             │ Response Layer      │
│ - tk/ttk GUI   │ - File watchers (watchdog)   │ - Quarantine mgr    │
│ - CLI options  │ - Process/registry monitors  │ - Backup/rollback   │
│ - Settings UI  │ - Network/USB telemetry      │ - Alerting & logs   │
├────────────────┴──────────────┬───────────────┴─────────────────────┤
│ Shared Services               │ Persistence & Logs                  │
│ - Policy engine (`policy_engine.py`)                                 │
│ - Token broker (`broker.py`, `ar_token.py`)                          │
│ - Health monitor (`health_monitor.py`)                               │
│ - Service manager (`service_manager.py`)                             │
│ - APIs (REST/gRPC in `enterprise_service.py`)                        │
├───────────────────────────────┴──────────────────────────────────────┤
│ Storage: SQLite (`protection_db.sqlite`), logs/, quarantine/, backups/ │
└──────────────────────────────────────────────────────────────────────┘
```

## Component Breakdown

**Kernel Minifilter (`RealAntiRansomwareDriver.c`)**
- Hooks `IRP_MJ_CREATE`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION` to stop encryption at the filesystem boundary.
- Maintains service-token cache (PID, expiry, allowed paths, binary hash) and exposes IOCTLs (`0x804`–`0x807`).
- Enforces path confinement, size limits, and flags suspicious delete-on-close or rapid-write sequences in driver statistics.

**Manager & CLI (`RealAntiRansomwareManager_v2.cpp`)**
- Implements `CryptoHelper`, `ProcessHelper`, and `DatabaseProtectionPolicy` to build policies from operator intent.
- Provides commands: `install`, `enable`, `status`, `configure-db`, `issue-token`, `list-tokens`, `revoke-token`, `calc-hash` (see [Usage](#usage--operations)).
- Handles driver install/uninstall through `setupapi` + `newdev`, signs IOCTL payloads, and prints real-time stats.

**Python Suite (`Python-Version/`, `admin_dashboard.py`, `service_manager.py`)**
- tkinter GUI with multi-tab control surface, quarantine UI, settings, USB auth, and full log viewer.
- `service_manager.py` turns the stack into a Windows service, spawns the web dashboard, health checks, and token broker.
- CLI helpers: `policy_engine.py`, `health_monitor.py`, `deployment.py`, `kernel_driver_manager.py` for automation and CI.

**Shared Assets**
- Configs: `config.yaml`, `config.json`, `policies/*.yaml` for policy-driven deployments.
- Diagnostics: `check.ps1`, `build/*.bat`, `POPUP_FIX.md`, `BUILD_FIX.md`, `QUICKSTART.md`.
- Data: `protected/`, `immune-folders/`, `logs/`, `backups/`, `quarantine/`.

## Build & Installation

### Prerequisites

| Layer | Requirements |
|-------|--------------|
| Kernel + Manager | Windows 10/11 x64, **Visual Studio 2022** with *Desktop development with C++*, **WDK 10**, Administrator shell, test-signing enabled, 8 GB RAM |
| Python Suite | Python 3.10+ (3.11.9 verified), `pip`, ability to install `psutil`, `wmi`, `pywin32`, optional virtualenv |

> ℹ️ Run `powershell -ExecutionPolicy Bypass -File .\check.ps1` to verify toolchains. If it reports missing C++ Standard Library, open **Visual Studio Installer → Modify → Workloads → Desktop development with C++**.

### Build Manager (User-Mode)

```powershell
# VS Developer Command Prompt (x64), elevated
cd C:\Users\ajibi\Music\Anti-Ransomeware
cl /std:c++17 /O2 /EHsc RealAntiRansomwareManager_v2.cpp ^
   setupapi.lib newdev.lib cfgmgr32.lib crypt32.lib advapi32.lib ^
   /Fe:RealAntiRansomwareManager.exe
```

### Build Driver (Kernel Minifilter)

```powershell
# WDK Free Build Env or VS Developer Cmd
msbuild RealAntiRansomwareDriver.vcxproj /p:Configuration=Release /p:Platform=x64

# Sign for test mode
makecert -r -pe -ss PrivateCertStore -n "CN=TestDriverCert" TestCert.cer
signtool sign /s PrivateCertStore /n "TestDriverCert" RealAntiRansomwareDriver.sys
```

Enable Windows test-signing once per host:

```powershell
bcdedit /set testsigning on
shutdown /r /t 0
```

### Python Environment

```powershell
cd C:\Users\ajibi\Music\Anti-Ransomeware\Python-Version
python -m venv ..\.venv
..\.venv\Scripts\Activate.ps1
pip install -r requirements.txt  # psutil, wmi, pywin32, flask, etc.
python antiransomware_python.py --gui
```

## Usage & Operations

### Kernel/Manager Workflow

1. **Install driver**: `RealAntiRansomwareManager.exe install`
2. **Enable protection**: `RealAntiRansomwareManager.exe enable` (`maximum` for aggressive mode)
3. **Configure database policy**: `RealAntiRansomwareManager.exe configure-db sqlservr.exe "C:\SQLData" --hours 24`
4. **Issue token**: ensure process running (`net start MSSQLSERVER`), then `RealAntiRansomwareManager.exe issue-token sqlservr.exe`
5. **Observe**: `RealAntiRansomwareManager.exe list-tokens` and `status`
6. **Revoke**: `RealAntiRansomwareManager.exe revoke-token <pid>` when credentials rotated.

| Command | Description |
|---------|-------------|
| `install`/`uninstall` | Add or remove the minifilter service and start/stop it |
| `enable`/`disable`/`monitor`/`maximum` | Adjust protection level (monitor = log only) |
| `status` | Driver health + statistics (files blocked, encryption attempts, token validations) |
| `configure-db <proc> <path> [--hours N]` | Sets process path, allowed directories, binary hash, token duration |
| `issue-token <proc>` | Generates SERVICE_TOKEN_REQUEST and primes kernel cache |
| `list-tokens` | Dumps active token table (PID, expiry, allowed paths, access count) |
| `revoke-token <pid>` | Immediate revocation for compromised services |
| `calc-hash <binary>` | SHA256 attestation helper for policy definitions |

### Python Suite Operations

```powershell
python antiransomware_python.py --gui         # Rich desktop console
python antiransomware_python.py --cli         # Headless monitoring
python service_manager.py --install          # Windows service wrapper
python admin_dashboard.py                    # Web dashboard on :8080
python broker.py                             # Hardware/demo token broker
python policy_engine.py --test               # Validate policies/pipelines
```

Key GUI tabs: **Overview** (live stats + control), **Activity Log**, **Protected Assets**, **Network Discovery**, **USB/Auth Tokens**. `network_discovery_fixed.py` provides the standalone subnet scanner with corrected layout.

## Observability & Testing

- **Logs**: `logs/antiransomware.log`, Windows Event Log (driver), CLI output.
- **Databases**: `protection_db.sqlite`, `antiransomware.db`, `quarantine/` artifacts.
- **Health checks**: `python health_monitor.py --check-all`, `python final_security_check.py`.
- **Simulations**: `attack_simulation.py`, `test_antiransomware.py`, `production_test.py` to rehearse ransomware behavior, token issuance, and policy enforcement.
- **Stats inspection**: `RealAntiRansomwareManager.exe status` exposes counters for encryption attempts, suspicious patterns, token validations/rejections.

## Repository Map

```
├── RealAntiRansomwareDriver.c/.inf/.vcxproj   # Kernel minifilter
├── RealAntiRansomwareManager_v2.cpp          # User-mode manager & CLI
├── Python-Version/                           # tkinter GUI + services
├── admin_dashboard.py / service_manager.py   # Web + service orchestration
├── broker.py, ar_token.py                    # Token issuance/brokerage
├── policy_engine.py, policies/               # Declarative policy sets
├── logs/, backups/, quarantine/, protected/  # Runtime data
├── build_*.bat / *.ps1                       # Build & deployment scripts
├── README_DATABASE_PROTECTION.md             # Deep dive on DB workflow
├── QUICKSTART.md, BUILD_FIX.md, POPUP_FIX.md # Ops notes
└── docs (*.MD)                               # Architecture, reports, guides
```

## Troubleshooting & FAQ

| Symptom | Likely Cause | Fix |
|---------|--------------|-----|
| `fatal error C1083: cannot open include file 'excpt.h'` | Visual Studio missing C++ workload | Launch **Visual Studio Installer**, enable **Desktop development with C++**, rerun `check.ps1` |
| Driver install fails with access denied | Missing `SeLoadDriverPrivilege` or no admin shell | Run elevated PowerShell/Command Prompt, verify `whoami /priv` |
| Driver loads but GUI shows no stats | IOCTL path blocked | Ensure `RealAntiRansomwareManager.exe status` runs elevated and driver name matches `\.\\AntiRansomwareFilter` |
| Tokens deny valid DB writes | Binary updated or path mismatch | Re-run `calc-hash` on new binary, `configure-db`, `issue-token` again |
| Python GUI missing buttons | Old layout | Use updated `network_discovery_fixed.py` or pull latest `Python-Version/antiransomware_python.py` |
| Command windows pop up while idle | VS Code auto-detect tasks | Keep `.vscode/settings.json` from repo (auto-detection disabled) |

## Security Posture & Best Practices

- **Least privilege**: run CLI as admin only when issuing tokens or changing driver state; GUI can run standard for monitoring.
- **Token hygiene**: set realistic `--hours` windows (24h production, 1h staging) and script `issue-token` rotations via `Task Scheduler` or CI.
- **Path confinement**: always point database directories to dedicated volumes; add read-only replicas via additional allowed paths.
- **Audit trails**: ship `logs/` and driver ETW events into SIEM; archive `RealAntiRansomwareManager.exe status` output periodically.
- **Test mode vs production**: keep `bcdedit /set testsigning off` on prod once you have an EV certificate; scripts in `build/` handle official signing.
- **Python hardening**: when deploying the GUI, enable Windows Defender Application Control or convert to executable (`pyinstaller`) with signed binaries.

## Contributing

1. Fork the repo and create a branch (`git checkout -b feature/hardening-abc`).
2. Run `python final_security_check.py` and `RealAntiRansomwareManager.exe status` after changes touching protection logic.
3. Submit PR with context, test evidence, and mention architecture diagrams when updating docs.

---

**Need to get started fast?** Read `QUICKSTART.md` for a scripted five-minute flow, then move to `README_DATABASE_PROTECTION.md` for the full database token story.
