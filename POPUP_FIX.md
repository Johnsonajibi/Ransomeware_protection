# Command Prompt Pop-ups Fixed

## What was causing it:
- VS Code C++ extension was trying to auto-compile on file changes
- Multiple batch files in workspace
- Background IntelliSense processes

## What I fixed:
1. Created `.vscode/settings.json` to disable:
   - Auto-compilation
   - IntelliSense auto-run
   - Task auto-detection
   - File watchers for build outputs

2. Killed any lingering cmd processes

## To completely stop pop-ups:

**Reload VS Code window:**
- Press `Ctrl+Shift+P`
- Type "Reload Window"
- Press Enter

OR

**Close and reopen VS Code**

## To compile manually when ready:
```cmd
.\compile.bat
```

The pop-ups should now be gone!
