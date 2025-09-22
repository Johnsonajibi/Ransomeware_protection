# Policy Engine & User Experience

## Policy Engine
- Policy files: YAML/JSON, signed by admin key
- Per-path scopes: glob, regex, canonical path, junction-aware
- Per-process rules: signer hash, Publisher CN, Team-ID, CDHash, IMA hash, SELinux label
- Quota tuple: files/min, bytes/min, entropy bypass flag, interactive-consent flag
- Time windows: maintenance schedules, emergency bypass slots
- Context rules: e.g., "deny winword.exe if parent is powershell.exe"

### Example Policy (YAML)
```yaml
folders:
  - path: "C:/Protected"
    allowed_ops: [read, write]
    quota:
      files_per_min: 10
      bytes_per_min: 1048576
    time_window:
      start: "22:00"
      end: "06:00"
process:
  - name: "winword.exe"
    deny_if_parent: "powershell.exe"
```

## User Experience
- Folder appears read-only in Explorer/Finder
- Double-click: opens read-only
- Drag-drop: instant toast "Access denied"
- Legitimate app: secure-desktop prompt "Insert dongle + PIN?"
- One touch: writable for 5 min, re-locks when idle or dongle removed

---

# Admin & Fleet Features
- Central broker: gRPC/REST API for token request, key rotation, event streaming
- MDM/GPO push: policy, dongle whitelist, revocations
- Dashboard: live file-churn heat-map, denied-process list, dongle inventory
- SIEM/CEF/LEEF syslog + webhook
- Break-glass: TPM-sealed EFI binary → boot without driver → full audit trail
