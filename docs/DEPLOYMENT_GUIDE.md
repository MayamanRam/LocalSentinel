# Deployment & Distribution Guide — LocalSentinel EDR v2.0

## 1. Prerequisites

- **Operating System**: Windows 10 (Build 19041+) or Windows 11 / Windows Server 2022+ (x64).
- **Runtime**: .NET Desktop Runtime 10.0 (or self-contained deployment).
- **Permissions**: Standard user privileges for general monitoring; Administrator privileges recommended for full WMI command-line inspection of protected system processes.

## 2. Standalone Build & Publishing

To create a single-file, self-contained standalone executable that runs without requiring a pre-installed .NET SDK or runtime:

```powershell
dotnet publish D:\Projects\LocalSentinel\LocalSentinel\LocalSentinel.csproj `
  -c Release `
  -r win-x64 `
  --self-contained true `
  -p:PublishSingleFile=true `
  -p:EnableCompressionInSingleFile=true `
  -o D:\Projects\LocalSentinel\publish\
```

The output will be placed in `D:\Projects\LocalSentinel\publish\LocalSentinel.exe`.

## 3. Code Signing (Production Recommendation)

To prevent SmartScreen warnings on Windows endpoints, sign the published executable using an Authenticode code-signing certificate:
```powershell
signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 D:\Projects\LocalSentinel\publish\LocalSentinel.exe
```

## 4. Uninstallation & Data Purge

- To remove runtime telemetry: Delete `%LOCALAPPDATA%\LocalSentinel\LocalSentinel.db`.
- To remove the application: Delete the deployment directory. No registry keys or background services are persisted outside the user profile.
