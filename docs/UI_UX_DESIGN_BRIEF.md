# UI/UX Design Brief & Accessibility Standards — LocalSentinel EDR v2.0

## 1. Visual Identity & Design Principles

LocalSentinel is designed with a professional Cybersecurity Operations Center (SOC) aesthetic. It employs a dark theme optimized for low eye fatigue during extended forensic triage while delivering immediate, high-contrast visual cues for threat severity.

### 1.1 Color Palette & Design Tokens

| Token | Hex Value | Usage |
| :--- | :--- | :--- |
| **Background Dark** | `#0B0F19` | Application base background |
| **Card / Surface Dark** | `#111827` | Metric cards and panel background |
| **Border Neutral** | `#1F2937` | Outer card borders |
| **Border Active / Separator** | `#334155` | Table grid lines and header borders |
| **Accent Primary (Cyan)** | `#38BDF8` | Brand text, active tabs, telemetry highlights |
| **Critical Severity** | `#DC2626` / `#EF4444` | Ransomware, shadow deletion, critical badges |
| **High Severity** | `#EA580C` / `#F97316` | LOLBins, double extensions, suspicious shells |
| **Medium Severity** | `#D97706` / `#F59E0B` | Unsigned staging execution, script sockets |
| **Low / Info Severity** | `#2563EB` / `#3B82F6` | Removable USB attachments, informational logs |
| **Success / Safe (Emerald)** | `#16A34A` / `#34D399` | Trusted signatures, active collector state |

### 1.2 Typography & Readability
- Header / KPI Font: SemiBold and Bold sans-serif with distinct numeral hierarchy.
- Grid Content: 13px clean typography with monospace formatting for SHA-256 hashes, timestamps, and network sockets.
- Column alignment: Numeric columns (PID, Ports, Row counts) right- or center-aligned; text columns left-aligned with ellipsis truncation.

## 2. Accessibility & WCAG 2.2 AA Compliance

- **Contrast Ratios**: All foreground text on dark surfaces exceeds the minimum 4.5:1 ratio (e.g. White `#FFFFFF` on `#111827` delivers > 15:1 contrast; `#38BDF8` on `#0B0F19` delivers > 8:1 contrast).
- **Non-Color Dependent Indicators**: Severity status is communicated via textual pills (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) in addition to color coding.
- **Keyboard Navigation**: Standard Tab key navigation across controls; data grids support arrow key row selection and clipboard copying.
- **Empty States**: Clear, contextual empty-state messages inform operators whether no events have occurred or if an active filter query has yielded zero matches.
