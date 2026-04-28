# Jigsaw XDR+ OmniParser

**Jigsaw XDR+ OmniParser** is a Windows EVTX investigation, detection, timeline, and correlation GUI built for defensive security analysis, DFIR triage, lab analysis, and Windows event-log hunting.

It is designed to help analysts load Windows `.evtx` artefacts, run rule-based detections, inspect evidence, pivot across users/hosts/IPs/processes, and generate investigation reports from a single desktop interface.

> Author: Kennedy Aikohi

---

## Screenshots

### Dashboard
![Jigsaw Dashboard](assets/JIGSAW_1.png)

### Detections
![Jigsaw Detections](assets/JIGSAW_2.png)

### All Events
![Jigsaw All Events](assets/JIGSAW_3.png)

### Jigsaw Rules
![Jigsaw Rules](assets/JIGSAW_4.png)

### Timeline
![Jigsaw Timeline](assets/JIGSAW_5.png)

### Analysis Results
![Jigsaw Analysis Results](assets/JIGSAW_6.png)

### Correlation
![Jigsaw Correlation](assets/JIGSAW_7.png)

---

## Key Features

- Windows EVTX parsing and investigation workflow
- Detection-first hunting engine
- Jigsaw rule support
- Event ID search
- Keyword and regex filtering
- IP correlation filtering
- ProcessGuid tracing
- Date/time range filtering
- Detection dashboard with severity breakdown
- Detections table with rule, severity, category, MITRE, Event ID, computer, process, and detail fields
- All-events viewer for parsed records
- Timeline view for chronological investigation
- Correlation view for users, hosts, IPs, processes, and user-host pivots
- PowerShell bridge for live artefact queries and enrichment
- Export support for JSON, CSV, TXT, and reports
- Freeze-safe GUI row caps for large result sets

---

## What Makes Jigsaw Different

Jigsaw is built around a GUI-first workflow. Instead of forcing analysts to jump between command-line output, spreadsheets, and separate timeline/correlation tools, Jigsaw brings parsing, detection, filtering, timeline review, evidence inspection, and correlation into one interface.

The goal is not only to show alerts, but to help analysts answer:

- What event raised the detection?
- Which rule triggered?
- Which user, host, IP, process, or command line was involved?
- What happened before and after it?
- Which entities are connected?
- What evidence supports the finding?

---

## Installation

### Option 1: Run from Python source

```powershell
cd jigsaw
python -m pip install -r requirements.txt
python jigsaw.py
```

### Option 2: Build Windows executable

```powershell
cd jigsaw
build.bat
```

The built application will be created under the `dist` folder.

---

## Basic Usage

1. Open Jigsaw.
2. Click **ADD FILE(S)** to load one or more `.evtx` files, or **ADD DIR** to load a folder of logs.
3. Leave filters blank for the first run.
4. Click **RUN HUNT**.
5. Review:
   - **Dashboard** for totals and top detections
   - **Detections** for rule hits
   - **All Events** for parsed records
   - **Timeline** for chronological analysis
   - **Analysis Results** for summary reporting
   - **Correlation** for entity pivots
6. Click a detection to view the evidence behind the finding.
7. Export results using JSON, CSV, TXT, or report export.

---

## Recommended Workflow

### 1. Start broad
Run without filters first. This allows Jigsaw to parse all available logs and produce detection-first results.

### 2. Review high-severity hits
Start with **CRITICAL** and **HIGH** severity detections.

### 3. Pivot into root-cause evidence
Click a detection and inspect:

- Rule name
- Detection reason
- Event ID
- Timestamp
- User
- Host
- IP address
- Process
- Command line
- Event message
- Normalized event fields
- Raw event data where available

### 4. Use timeline
Move to the **Timeline** tab to understand event order.

### 5. Use correlation
Move to the **Correlation** tab to identify entity relationships such as:

- User ↔ Host
- IP ↔ Host
- Process activity
- Repeated users or service accounts

### 6. Narrow with filters
After broad review, use filters such as:

- Event IDs
- Keyword search
- Regex pattern
- IP correlation
- ProcessGuid trace
- Date/time range

---

## PowerShell Console Usage

The PowerShell console helps query live or offline artefacts from inside the GUI.

Typical commands:

```powershell
Get-Date
```

```powershell
Get-WinEvent -Path "C:\case\Security.evtx" -MaxEvents 50
```

```powershell
Get-WinEvent -Path "C:\case\Security.evtx" -FilterHashtable @{Id=4625} -MaxEvents 50
```

```powershell
wevtutil epl Security C:\case\Security.evtx
```

Use **RUN + INGEST** when you want PowerShell output pushed back into Jigsaw views.

---

## Rules

Jigsaw rules are stored in the project rules folder. Rules should describe:

- Rule ID
- Name
- Severity
- Category
- Event IDs
- Detection logic
- Description
- MITRE technique where applicable

Example structure:

```yaml
id: JIG-EXAMPLE-001
name: Suspicious Process Execution
severity: HIGH
category: Execution
event_ids:
  - 4688
keywords:
  - powershell
  - encodedcommand
description: Detects suspicious encoded PowerShell execution.
```

---

## Exporting Results

Use the export buttons in the left sidebar:

- **JSON** for structured output
- **CSV** for spreadsheet analysis
- **TXT** for quick reporting
- **Export Report** from Analysis Results for summary output

---

## Performance Notes

Large EVTX collections can contain hundreds of thousands or millions of records. Jigsaw uses GUI row caps to keep the application responsive. Full results can still be exported.

Recommended approach:

- Load targeted case folders first.
- Run detection-first mode before applying filters.
- Export full data for deeper offline review.
- Use Event ID/date/IP filters for very large cases.

---

## Troubleshooting

### The GUI shows zero hits
Try these steps:

1. Clear all filters.
2. Click **SHOW ALL / CLEAR FILTERS**.
3. Confirm the EVTX file contains records.
4. Check the Hunt Log tab.
5. Try a known active log such as Security, System, PowerShell, or Sysmon.

### The GUI freezes or slows down
Use a smaller folder, apply a date range, or export results instead of rendering every row in the GUI.

### PowerShell returns too many results
Always limit commands:

```powershell
Get-WinEvent -LogName Security -MaxEvents 100
```

### Build fails with PyInstaller
Clean the build folders and retry:

```powershell
rmdir /s /q build
rmdir /s /q dist
python -m pip install --upgrade pyinstaller
build.bat
```

---

## Disclaimer

Jigsaw is intended for authorized defensive security, incident response, digital forensics, malware-lab, and research use only. Use it only on systems, evidence, or lab data you are authorized to analyze.

---

## License

Add your chosen license here, for example:

- MIT
- Apache-2.0
- GPL-3.0
- Custom/private license

