---
layout: default
title: Anti-Ransomware Protection Platform
---

<link rel="stylesheet" href="assets/style.css">

# Anti-Ransomware Protection Platform

A professional, hardware-gated, kernel-backed protection system for Windows that prevents unauthorized encryption, file modification, and destructive actions across the OS. The platform combines a Windows minifilter driver (kernel mode), a user-mode enforcement engine, and token-gated access that ties access permissions to hardware-verifiable identity.

## What This Does
- Kernel-level interception of file I/O, process creation, and registry changes
- Policy-based blocking for encryption attempts, mass file renames, and deletion
- Hardware-gated token enforcement (TPM + device fingerprint; optional USB token)
- Administrative dashboard with audit logging, alerts, and policy management
- Clean integration paths: IOCTLs, REST API, and Python SDK

## Key Features
- Kernel minifilter driver for early, reliable interception
- Real-time behavioral detection and targeted blocking
- Token-gated access policies with cryptographic verification
- Fail-safe mode with audit-only operation and staged rollout
- Comprehensive logs for incident response and compliance

## How It Works
- Kernel driver (Ring 0) intercepts sensitive operations before the OS completes them
- User-mode service applies policies and adjudicates decisions from behavior models
- Token-gated access binds permissions to hardware signals and signed tokens
- Admin dashboard provides visibility, audit, and control

## Installation
- See the Quick Start for installation, driver build, and setup
- Guidance covers developer and production builds, signing, and service registration

## Documentation Library
- Architecture Overview: [architecture](architecture.md)
- Security Model & Hardening: [security-model](security-model.md)
- API Reference: [api-reference](api-reference.md)
- Quick Start: [Quick Start Guide](guides/QUICK_START_GUIDE.md)
- Deployment Guide: [deployment](guides/deployment.md)
- Operations Guide: [operations](guides/operations.md)

## System Requirements
- Windows 10 or 11
- Administrator privileges for driver installation and service configuration
- Visual Studio Build Tools or WDK/Visual Studio (for driver builds)
- Python 3.11+ (if using the Python SDK or admin tooling)

## Licensing
MIT License — see the repository license for details

## Implementation Overview

### Approach A: WDK Kernel Driver
Status: Code complete, ready to compile
Time: 2–3 hours
Protection: Maximum
Complexity: Advanced

Description:
- Windows filter driver compiled to a `.sys` binary
- Operates in kernel mode (Ring 0)
- Intercepts I/O before Windows processes it
- Blocks ransomware at the earliest interception point

References:
- antiransomware_minifilter.c — source code
- WDK_SETUP_AND_COMPILATION.md — setup guide

### Approach B: Python Enforcement (User Mode)
Status: Actively working
Time: Immediate
Protection: Strong
Complexity: Moderate

Description:
- User-mode service that detects suspicious behaviors
- Blocks encryption processes, mass renames, and destructive actions
- Integrates with token-gated access enforcement

References:
- aggressive_protection.py — enforcement logic
- blocking_protection.py — process and file blocking controls

### Approach C: Combined Three-Layer Protection
Status: Recommended for production
Time: Immediate + kernel build window
Protection: Very strong
Complexity: Moderate to advanced

Description:
- Combine kernel driver, user-mode enforcement, and token-gated access
- Achieves layered defense and higher assurance

## Getting Started
Review the Quick Start and system requirements, then proceed to deployment:
- Quick Start: [Quick Start Guide](guides/QUICK_START_GUIDE.md)
- Deployment Models: [guides/deployment](guides/deployment.md)

## Contact and Support
- Issues: use GitHub Issues in the repository
- Security: responsible disclosure guidance in the repository
- Roadmap: see the advanced features documents in the repo
