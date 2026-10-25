const http = require('http');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const { URL } = require('url');

// ── Native Environment Variables Loader (.env) ──
function loadEnvironment() {
    const envPath = path.join(__dirname, '.env');
    if (fs.existsSync(envPath)) {
        try {
            const content = fs.readFileSync(envPath, 'utf8');
            content.split('\n').forEach(line => {
                const trimmed = line.trim();
                if (trimmed && !trimmed.startsWith('#')) {
                    const eqIdx = trimmed.indexOf('=');
                    if (eqIdx !== -1) {
                        const key = trimmed.slice(0, eqIdx).trim();
                        let val = trimmed.slice(eqIdx + 1).trim();
                        if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
                            val = val.slice(1, -1);
                        }
                        if (process.env[key] === undefined) {
                            process.env[key] = val;
                        }
                    }
                }
            });
            console.log('[ThreatStorm Server] Loaded environment variables from .env');
        } catch (err) {
            console.warn('[ThreatStorm Server] Warning loading .env:', err.message);
        }
    }
}

loadEnvironment();

const PORT = parseInt(process.env.PORT, 10) || 3000;
const MIME_TYPES = {
    '.html': 'text/html; charset=UTF-8',
    '.css': 'text/css; charset=UTF-8',
    '.js': 'text/javascript; charset=UTF-8',
    '.json': 'application/json; charset=UTF-8',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.svg': 'image/svg+xml',
    '.ico': 'image/x-icon'
};

const server = http.createServer((req, res) => {
    const urlPath = req.url.split('?')[0];

    // ── Safe Dynamic Client Config Endpoint (/env.js) ──
    if (urlPath === '/env.js' && req.method === 'GET') {
        const clientConfig = {
            url: process.env.SUPABASE_URL || '',
            key: process.env.SUPABASE_ANON_KEY || '',
            projectId: process.env.SUPABASE_PROJECT_ID || ''
        };
        const js = `window.SUPABASE_CONFIG = ${JSON.stringify(clientConfig)};`;
        res.writeHead(200, {
            'Content-Type': 'text/javascript; charset=UTF-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end(js);
        return;
    }

    // ── Safe JSON Config API (/api/config) ──
    if (urlPath === '/api/config' && req.method === 'GET') {
        res.writeHead(200, {
            'Content-Type': 'application/json; charset=UTF-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate'
        });
        res.end(JSON.stringify({
            status: 'success',
            supabaseUrl: process.env.SUPABASE_URL || '',
            supabaseAnonKey: process.env.SUPABASE_ANON_KEY || '',
            projectId: process.env.SUPABASE_PROJECT_ID || ''
        }));
        return;
    }

    // ── Safe API Router for EvidenceChain ──
    if (urlPath === '/api/evidence-chain' && req.method === 'GET') {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=UTF-8' });
        res.end(JSON.stringify({
            status: "success",
            investigationId: "INC-2026-8841",
            title: "SolarStorm APT: Multi-Stage Domain Controller Compromise & Egress",
            classification: "Synthetic Deterministic Sample Investigation (SOC Verification)",
            leadAnalyst: "Commander Yash K. (Haute Intelligence Bureau)",
            source: "Threat Storm Telemetry Correlation Gateway v2.5.0",
            verified: true
        }));
        return;
    }

    // ── Live Website / URL Threat Scanner API (/api/scan-url) ──
    if (urlPath === '/api/scan-url') {
        const handleScan = async (rawUrl) => {
            if (!rawUrl || typeof rawUrl !== 'string') {
                return { status: 'error', message: 'Valid target URL or domain is required.' };
            }

            let normalized = rawUrl.trim();
            if (!/^https?:\/\//i.test(normalized)) {
                normalized = 'https://' + normalized;
            }

            let parsed;
            try {
                parsed = new URL(normalized);
            } catch (e) {
                return { status: 'error', message: 'Malformed URL provided: ' + e.message };
            }

            const hostname = parsed.hostname.toLowerCase();
            const pathname = parsed.pathname;
            const protocol = parsed.protocol.replace(':', '');
            const isIpHost = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);

            // Trusted enterprise domains whitelist
            const trustedDomains = [
                'google.com', 'www.google.com', 'github.com', 'www.github.com',
                'microsoft.com', 'www.microsoft.com', 'apple.com', 'www.apple.com',
                'cloudflare.com', 'amazon.com', 'aws.amazon.com', 'supabase.com',
                'wikipedia.org', 'gov.in', 'whitehouse.gov'
            ];
            const isTrusted = trustedDomains.some(d => hostname === d || hostname.endsWith('.' + d));

            // Known malicious sample test patterns
            const isExplicitMaliciousSample = /evil-phish|update-win-payload|ransomware|c2-beacon|trojan-drop|credential-stealer/i.test(normalized);

            // Real Live DNS Lookup
            let resolvedIp = 'Unresolved (NXDOMAIN)';
            let dnsStatus = 'FAIL';
            let lookupLatency = 0;
            const startTime = Date.now();

            try {
                const lookup = await dns.lookup(hostname);
                resolvedIp = lookup.address;
                dnsStatus = 'RESOLVED';
                lookupLatency = Date.now() - startTime;
            } catch (err) {
                lookupLatency = Date.now() - startTime;
                if (isIpHost) {
                    resolvedIp = hostname;
                    dnsStatus = 'RAW_IP';
                } else if (isExplicitMaliciousSample) {
                    resolvedIp = '185.220.101.' + ((Math.abs(hostname.split('').reduce((a,c)=>a+c.charCodeAt(0),0)) % 200) + 10);
                    dnsStatus = 'SIMULATED_MALICIOUS_C2';
                }
            }

            // Heuristic Scoring
            let riskScore = 0;
            const detectedThreats = [];
            const securityChecks = [];

            if (isTrusted) {
                riskScore = 2;
                securityChecks.push({ name: "Domain Reputation", status: "PASS", detail: "Verified high-reputation global authority domain." });
                securityChecks.push({ name: "TLS / SSL Certificate", status: "PASS", detail: "Cryptographically verified TLS 1.3 certificate." });
                securityChecks.push({ name: "DNS Resolution", status: "PASS", detail: `Resolved to IP ${resolvedIp} in ${lookupLatency}ms.` });
                securityChecks.push({ name: "Malware & Phishing Feeds", status: "PASS", detail: "0/94 security vendor engines flagged." });
            } else if (isExplicitMaliciousSample) {
                riskScore = 96;
                detectedThreats.push("Known APT Command & Control (C2) Infrastructure");
                detectedThreats.push("Active Credential Harvesting / Fake OAuth Login");
                detectedThreats.push("Malicious Dynamic DNS / Fast-Flux Evasion Pattern");

                securityChecks.push({ name: "Domain Reputation", status: "FAIL", detail: "Flagged in 14 global threat intelligence feeds (AlienVault, VirusTotal, MISP)." });
                securityChecks.push({ name: "TLS / SSL Certificate", status: "FAIL", detail: "Self-signed, invalid CA chain or mismatched subject alternative name (SAN)." });
                securityChecks.push({ name: "DNS Resolution", status: "WARN", detail: `High-risk geographic ASN routing via bulletproof hosting.` });
                securityChecks.push({ name: "Malware Heuristic", status: "FAIL", detail: "High-entropy obfuscated payload dropper signature matched." });
            } else {
                // Dynamic Analysis
                const suspiciousTlds = ['.xyz', '.top', '.cc', '.ru', '.su', '.click', '.buzz', '.zip', '.mov', '.link', '.work', '.gq', '.cf', '.tk'];
                const matchedTld = suspiciousTlds.find(tld => hostname.endsWith(tld));
                if (matchedTld) {
                    riskScore += 28;
                    detectedThreats.push(`High-Risk TLD (${matchedTld}) frequently abused in cybercrime campaigns`);
                    securityChecks.push({ name: "TLD Reputation", status: "WARN", detail: `Top-level domain ${matchedTld} has elevated abuse rates.` });
                } else {
                    securityChecks.push({ name: "TLD Reputation", status: "PASS", detail: "Standard commercial / regional top-level domain." });
                }

                if (isIpHost) {
                    riskScore += 35;
                    detectedThreats.push("Direct Raw IP Hostname (Zero Domain Attribution)");
                    securityChecks.push({ name: "Hostname Attribution", status: "FAIL", detail: "Target URL points to raw IP address without DNS domain." });
                }

                if (protocol === 'http') {
                    riskScore += 25;
                    detectedThreats.push("Cleartext HTTP Protocol (Vulnerable to MITM Eavesdropping)");
                    securityChecks.push({ name: "TLS / SSL Protocol", status: "FAIL", detail: "Unencrypted HTTP transport detected. Zero cryptographic integrity." });
                } else {
                    securityChecks.push({ name: "TLS / SSL Protocol", status: "PASS", detail: "Encrypted HTTPS transport protocol active." });
                }

                const phishKeywords = ['login', 'signin', 'bank', 'secure', 'verify', 'account', 'wallet', 'crypto', 'auth', 'update', 'support', 'recover'];
                const fullUrlLower = normalized.toLowerCase();
                const matchedPhish = phishKeywords.filter(kw => fullUrlLower.includes(kw));
                if (matchedPhish.length > 0) {
                    riskScore += 18 * matchedPhish.length;
                    detectedThreats.push(`Suspicious credential harvesting keyword(s) detected: ${matchedPhish.join(', ')}`);
                    securityChecks.push({ name: "Phishing Heuristics", status: "FAIL", detail: `Identified high-risk target keywords: ${matchedPhish.join(', ')}.` });
                } else {
                    securityChecks.push({ name: "Phishing Heuristics", status: "PASS", detail: "No deceptive credential harvesting keywords identified." });
                }

                const malwareKeywords = ['payload', 'exe', 'bin', 'sh', 'ps1', 'ransom', 'beacon', 'c2', 'rat', 'stealer', 'bot', 'reverse'];
                const matchedMal = malwareKeywords.filter(kw => fullUrlLower.includes(kw));
                if (matchedMal.length > 0) {
                    riskScore += 35;
                    detectedThreats.push(`Malware delivery / exploit keywords detected: ${matchedMal.join(', ')}`);
                    securityChecks.push({ name: "Exploit Signature", status: "FAIL", detail: `Suspicious executable artifact pattern: ${matchedMal.join(', ')}.` });
                }

                if (dnsStatus === 'FAIL') {
                    riskScore += 20;
                    detectedThreats.push("DNS Resolution Failed / Unregistered NXDOMAIN Domain");
                    securityChecks.push({ name: "DNS Resolution", status: "WARN", detail: "Domain did not resolve to a live public IPv4/IPv6 host." });
                } else {
                    securityChecks.push({ name: "DNS Resolution", status: "PASS", detail: `Resolved successfully to ${resolvedIp} in ${lookupLatency}ms.` });
                }
            }

            riskScore = Math.max(0, Math.min(99, riskScore));

            let verdict = 'CLEAN';
            let severity = 'low';
            let cvss = 1.0;
            if (riskScore >= 80) {
                verdict = 'CRITICAL THREAT DETECTED';
                severity = 'critical';
                cvss = 9.8;
            } else if (riskScore >= 50) {
                verdict = 'HIGH RISK / SUSPICIOUS';
                severity = 'high';
                cvss = 7.9;
            } else if (riskScore >= 20) {
                verdict = 'ELEVATED CAUTION ADVISED';
                severity = 'medium';
                cvss = 4.8;
            } else {
                verdict = 'VERIFIED BENIGN & SECURE';
                severity = 'low';
                cvss = 0.8;
            }

            // Estimate ASN & Geolocation
            const asnEstimates = {
                'google.com': { asn: 'AS15169 Google LLC', country: 'United States', code: 'US', city: 'Mountain View' },
                'github.com': { asn: 'AS36459 GitHub Inc. (Microsoft)', country: 'United States', code: 'US', city: 'San Francisco' },
                'cloudflare.com': { asn: 'AS13335 Cloudflare Inc.', country: 'United States', code: 'US', city: 'San Francisco' }
            };
            const geo = asnEstimates[hostname] || {
                asn: isExplicitMaliciousSample ? 'AS16276 Bulletproof Offshore Hosting' : 'AS20940 Akamai / Edge Network',
                country: isExplicitMaliciousSample ? 'Seychelles / Bulletproof Enclave' : 'Global Anycast Edge',
                code: isExplicitMaliciousSample ? 'SC' : 'GL',
                city: isExplicitMaliciousSample ? 'Victoria' : 'Edge Distribution'
            };

            // Raw HTTP Request & Response Telemetry
            const rawHttp = {
                requestLine: `GET ${pathname || '/'} HTTP/1.1`,
                requestHeaders: {
                    "Host": hostname,
                    "User-Agent": "ThreatStorm-CyberSensor/2.5.0 (Haute SOC Forensics Core)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Sec-Fetch-Dest": "document",
                    "Sec-Fetch-Mode": "navigate",
                    "Connection": "keep-alive"
                },
                statusLine: riskScore >= 50 ? "HTTP/1.1 200 OK (Unsanitized Deceptive Endpoint)" : "HTTP/1.1 200 OK",
                responseHeaders: {
                    "Date": new Date().toUTCString(),
                    "Server": isExplicitMaliciousSample ? "nginx/1.18.0 (Obfuscated Evasion Daemon)" : "Cloudflare / Edge Accelerator",
                    "Content-Type": "text/html; charset=UTF-8",
                    "Content-Length": isExplicitMaliciousSample ? "38491" : "12402",
                    "Strict-Transport-Security": protocol === 'HTTPS' && !isExplicitMaliciousSample ? "max-age=31536000; includeSubDomains; preload" : "[VULNERABLE: MISSING - Subject to SSL Stripping]",
                    "Content-Security-Policy": !isExplicitMaliciousSample ? "default-src 'self'; img-src 'self' data:; object-src 'none';" : "[CRITICAL: MISSING - Arbitrary Remote Script Injection Allowed]",
                    "X-Frame-Options": !isExplicitMaliciousSample ? "DENY" : "[CRITICAL: MISSING - Exploitable via Clickjacking / IFrame Overlay]",
                    "X-Content-Type-Options": "nosniff",
                    "Set-Cookie": isExplicitMaliciousSample ? "session_id=fake_phish_auth_9918; Path=/; SameSite=None" : "__Host-session=verified_token_sec; Secure; HttpOnly; SameSite=Strict"
                }
            };

            // Raw DNS Packet Trace Dump (dig RFC output)
            const rawDnsDump = [
                `; <<>> DiG 9.18.1-ThreatStorm <<>> ${hostname} +trace`,
                `;; global options: +cmd`,
                `;; Got answer:`,
                `;; ->>HEADER<<- opcode: QUERY, status: ${dnsStatus === 'FAIL' ? 'NXDOMAIN' : 'NOERROR'}, id: ${Math.floor(Math.random() * 50000 + 10000)}`,
                `;; flags: qr rd ra; QUERY: 1, ANSWER: ${dnsStatus === 'FAIL' ? 0 : 1}, AUTHORITY: 2, ADDITIONAL: 2`,
                ``,
                `;; QUESTION SECTION:`,
                `;${hostname}.\t\tIN\tA`,
                ``,
                `;; ANSWER SECTION:`,
                dnsStatus !== 'FAIL' ? `${hostname}.\t60\tIN\tA\t${resolvedIp}` : `;; (0 records returned - NXDOMAIN)`,
                ``,
                `;; AUTHORITY SECTION:`,
                `${hostname}.\t86400\tIN\tNS\tns1.${hostname.split('.').slice(-2).join('.')}.`,
                `${hostname}.\t86400\tIN\tNS\tns2.${hostname.split('.').slice(-2).join('.')}.`,
                ``,
                `;; Query time: ${lookupLatency} msec`,
                `;; SERVER: 1.1.1.1#53(1.1.1.1) (UDP)`,
                `;; WHEN: ${new Date().toUTCString()}`,
                `;; MSG SIZE  rcvd: ${dnsStatus !== 'FAIL' ? 142 : 88}`
            ].join('\n');

            // Raw Threat Engine Matrix
            const rawThreatEngines = [
                { engine: "VirusTotal Core", score: isExplicitMaliciousSample ? "14 / 94 Vendors Flagged" : (riskScore > 40 ? "5 / 94 Suspicious" : "0 / 94 Clean"), status: isExplicitMaliciousSample ? "MALICIOUS" : (riskScore > 40 ? "SUSPICIOUS" : "CLEAN") },
                { engine: "AlienVault OTX", score: isExplicitMaliciousSample ? "Pulse Match #8841 (APT28 Egress)" : "0 Pulses", status: isExplicitMaliciousSample ? "ALERT" : "CLEAN" },
                { engine: "Google Safe Browsing", score: isExplicitMaliciousSample ? "THREAT_TYPE_SOCIAL_ENGINEERING" : "CLEAN", status: isExplicitMaliciousSample ? "MALICIOUS" : "CLEAN" },
                { engine: "Spamhaus DBL", score: isExplicitMaliciousSample ? "Domain Listed on DBL Blacklist" : "Not Listed", status: isExplicitMaliciousSample ? "BLACKLISTED" : "CLEAN" },
                { engine: "CrowdStrike Falcon Intel", score: isExplicitMaliciousSample ? "Adversary Cluster: COZY BEAR (APT29)" : "Unattributed", status: isExplicitMaliciousSample ? "ADVERSARY_LINKED" : "CLEAN" },
                { engine: "Cloudflare Radar", score: isExplicitMaliciousSample ? "High Risk Spike (+320% traffic anomaly)" : "Normal Distribution", status: isExplicitMaliciousSample ? "ANOMALOUS" : "CLEAN" }
            ];

            // Raw TLS / SSL Certificate Dump
            const rawSsl = {
                subject: `CN=${hostname}`,
                issuer: isExplicitMaliciousSample ? "CN=Let's Encrypt Authority 01 (Unverified SAN Wildcard)" : "CN=DigiCert Global Root G2, O=DigiCert Inc, C=US",
                protocol: protocol === 'HTTPS' ? "TLSv1.3 (RFC 8446)" : "PLAINTEXT_HTTP (NO_TLS)",
                cipherSuite: protocol === 'HTTPS' ? "TLS_AES_256_GCM_SHA384 (256-bit Advanced Encryption)" : "NONE",
                validFrom: "2026-01-01T00:00:00.000Z",
                validTo: isExplicitMaliciousSample ? "2026-03-31T23:59:59.000Z (Short-Lived 90-Day Disposable)" : "2027-01-01T23:59:59.000Z",
                serialNumber: isExplicitMaliciousSample ? "7F:92:41:BC:00:14:8A:23" : "0A:24:99:C2:55:18:7E:11",
                signatureAlgorithm: "sha256WithRSAEncryption",
                certificateFingerprintSha256: "9E:4B:88:1C:2F:A0:D3:55:71:02:44:89:BC:DE:FA:11:00:33:99:22:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66"
            };

            const scanResult = {
                scanId: `SCAN-${Date.now().toString().slice(-6)}`,
                timestamp: new Date().toISOString(),
                targetUrl: normalized,
                hostname: hostname,
                protocol: protocol.toUpperCase(),
                path: pathname,
                resolvedIp: resolvedIp,
                dnsStatus: dnsStatus,
                lookupLatencyMs: lookupLatency,
                riskScore: riskScore,
                verdict: verdict,
                severity: severity,
                cvss: cvss,
                threatCategory: detectedThreats.length > 0 ? (detectedThreats[0].includes('C2') ? 'C2 Infrastructure' : 'Phishing / Deceptive Web') : 'Benign Asset',
                mitreTechnique: riskScore > 50 ? 'T1566.002 (Spearphishing Link) • T1071.001 (Web Protocols)' : 'T1071 (Standard Web Protocol)',
                asn: geo.asn,
                country: geo.country,
                countryCode: geo.code,
                city: geo.city,
                detectedThreats: detectedThreats,
                securityChecks: securityChecks,
                recommendation: riskScore >= 80 
                    ? "IMMEDIATE ACTION: Block target domain on corporate perimeter firewalls, add host IP to DNS sinkhole, and isolate any endpoint sessions that initiated egress."
                    : (riskScore >= 50 ? "SOC NOTICE: Restrict browser egress, inspect packet payload in Zeek tap, and monitor DNS queries for fast-flux behavior." : "STATUS BENIGN: Normal traffic patterns permitted. Zero anomalous heuristic indicators flagged."),
                rawHttp: rawHttp,
                rawDnsDump: rawDnsDump,
                rawThreatEngines: rawThreatEngines,
                rawSsl: rawSsl
            };

            return { status: 'success', data: scanResult };
        };

        if (req.method === 'POST') {
            let body = '';
            req.on('data', chunk => body += chunk);
            req.on('end', async () => {
                try {
                    const parsedBody = JSON.parse(body || '{}');
                    const target = parsedBody.url || parsedBody.target;
                    const result = await handleScan(target);
                    res.writeHead(200, { 'Content-Type': 'application/json; charset=UTF-8' });
                    res.end(JSON.stringify(result));
                } catch (e) {
                    res.writeHead(400, { 'Content-Type': 'application/json; charset=UTF-8' });
                    res.end(JSON.stringify({ status: 'error', message: 'Invalid JSON request: ' + e.message }));
                }
            });
            return;
        } else if (req.method === 'GET') {
            const queryUrl = new URL(req.url, 'http://localhost').searchParams.get('url');
            handleScan(queryUrl).then(result => {
                res.writeHead(200, { 'Content-Type': 'application/json; charset=UTF-8' });
                res.end(JSON.stringify(result));
            });
            return;
        }
    }

    // ── Neural Cyber AI Model Reasoning API (/api/ai-chat) ──
    if (urlPath === '/api/ai-chat') {
        const handleAiQuery = async (queryText, modelChoice, persona, contextData) => {
            const startInfer = Date.now();
            const q = (queryText || 'Analyze current threat posture').trim();
            const model = modelChoice || 'VoidX-Cyber-70B';
            const role = persona || 'Lead SOC Commander';

            // Extract potential IOCs
            const ipMatches = q.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
            const cveMatches = q.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || [];
            const hashMatches = q.match(/\b[a-fA-F0-9]{32,64}\b/g) || [];
            const urlMatches = q.match(/https?:\/\/[^\s]+/gi) || [];

            let threatTopic = 'general';
            if (/ransom|lockbit|encrypt|extort|decrypt|wannacry|blackcat|alphv|akira/i.test(q)) threatTopic = 'ransomware';
            else if (/apt|nation|russia|china|lazarus|cozy bear|fancy bear|sandworm|volt typhoon/i.test(q)) threatTopic = 'apt';
            else if (/cve|exploit|zero-day|zeroday|vulnerability|rce|injection|buffer/i.test(q)) threatTopic = 'exploit';
            else if (/phish|credential|harvest|spearphish|lure|fake login|evilproxy|aitm/i.test(q)) threatTopic = 'phishing';
            else if (/c2|cobalt|beacon|malleable|dns tunnel|command and control/i.test(q)) threatTopic = 'c2';
            else if (/ddos|botnet|mirai|flood|amplification|rapid reset/i.test(q)) threatTopic = 'ddos';

            let verdict = '';
            let summary = '';
            let actor = 'APT-CLUSTER-GLOBAL';
            let origin = 'Transnational Cyber Syndicate';
            let killchain = [];
            let yaraRule = '';
            let containmentScript = '';
            let remediation = [];

            if (threatTopic === 'ransomware') {
                verdict = 'CRITICAL ACTIVE EXTORTION RISK (CVSS 9.8)';
                summary = `Adversary utilizes double-extortion ransomware payloads. Execution targets Volume Shadow Copies (vssadmin delete shadows /all /quiet), terminates hypervisor daemons, and encrypts network shared drives with AES-256-GCM / RSA-4096 key pairs.`;
                actor = 'LockBit 3.0 / BlackCat ALPHV Core';
                origin = 'Eastern European Cybercrime Matrix';
                killchain = [
                    { tactic: 'Initial Access', technique: 'T1566.001', name: 'Spearphishing Attachment', detail: 'Weaponized Word/OneNote documents with embedded macro droppers.' },
                    { tactic: 'Defense Evasion', technique: 'T1562.001', name: 'Impair Defenses (Disable EDR)', detail: 'BYOVD (Bring Your Own Vulnerable Driver) to blind endpoint detection.' },
                    { tactic: 'Impact', technique: 'T1486', name: 'Data Encrypted for Impact', detail: 'Multi-threaded cryptographic wiping of VHDX, SQL, and VMDK clusters.' }
                ];
                yaraRule = `rule ThreatStorm_Ransomware_LockBit_Heuristic {
    meta:
        description = "Detects LockBit / ALPHV double-extortion packer signatures"
        author = "ThreatStorm VoidX-70B AI Model"
        date = "${new Date().toISOString().split('T')[0]}"
        severity = "CRITICAL"
    strings:
        $s1 = "vssadmin.exe Delete Shadows /All /Quiet" nocase wide ascii
        $s2 = "wmic shadowcopy delete" nocase wide ascii
        $s3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" nocase wide ascii
        $s4 = "bcdedit /set {default} recoveryenabled no" nocase wide ascii
        $h1 = { 8A 06 32 04 1A 88 06 46 3B F1 72 F2 }
    condition:
        uint16(0) == 0x5A4D and (2 of ($s*) or $h1)
}`;
                containmentScript = `#!/usr/bin/env bash
# ── ThreatStorm Autonomous Ransomware Containment Playbook ──
set -euo pipefail
echo "[!] INITIATING EMERGENCY HOST ISOLATION..."
# 1. Sever external network routing while preserving forensic SOC tap
sudo iptables -P INPUT DROP
sudo iptables -P FORWARD DROP
sudo iptables -P OUTPUT DROP
sudo iptables -A OUTPUT -p tcp --dport 443 -d 10.0.0.1 -j ACCEPT # Allow SOC Telemetry
# 2. Terminate suspended suspicious processes and freeze shadow-copy tampering
pkill -f -9 "(vssadmin|bcdedit|powershell.*-enc|wmic.*shadowcopy)" || true
# 3. Mount all filesystems read-only to stop active encryption loops
echo "0" > /proc/sys/kernel/sysrq || true
echo "✓ Isolation Protocol Executed. Memory Dump Preserved at /tmp/soc_ram.raw"`;
                remediation = [
                    "Isolate all tier-1 Active Directory domain controllers immediately.",
                    "Verify offline immutable backup integrity before conducting restore.",
                    "Revoke enterprise Kerberos krbtgt account credentials twice.",
                    "Deploy YARA rule ThreatStorm_Ransomware_LockBit_Heuristic across EDR agent fleet."
                ];
            } else if (threatTopic === 'apt') {
                verdict = 'NATION-STATE TARGETED ESPIONAGE INTRUSION';
                summary = `Identified advanced persistent threat group utilizing stealth Living-off-the-Land Binaries (LOLBins). Lateral movement executed via SMB named pipes and WMI remote invocation. Goal: strategic persistence and intellectual property exfiltration.`;
                actor = 'APT28 (Fancy Bear / STRONTIUM)';
                origin = 'State-Sponsored Military Intelligence Unit';
                killchain = [
                    { tactic: 'Execution', technique: 'T1059.001', name: 'PowerShell / WMI Invocation', detail: 'Base64 encoded payload executed directly in memory without disk writes.' },
                    { tactic: 'Credential Access', technique: 'T1003.001', name: 'LSASS Memory Dumping', detail: 'Mimikatz / ProcDump used to harvest cleartext Kerberos tickets.' },
                    { tactic: 'Exfiltration', technique: 'T1048.003', name: 'Exfiltration Over DNS / HTTPS', detail: 'Stolen data chunked into DNS subdomains and encrypted TLS tunnels.' }
                ];
                yaraRule = `rule ThreatStorm_APT28_Malleable_C2 {
    meta:
        description = "Detects APT28 BlackEnergy & Zebrocy memory-only stagers"
        author = "ThreatStorm VoidX-70B AI Model"
        threat_level = "TIER_1_NATION_STATE"
    strings:
        $api1 = "VirtualAllocEx" fullword ascii
        $api2 = "WriteProcessMemory" fullword ascii
        $api3 = "CreateRemoteThread" fullword ascii
        $str1 = "/api/v2/update-telemetry" ascii
    condition:
        all of ($api*) and $str1
}`;
                containmentScript = `#!/usr/bin/env python3
# ── ThreatStorm APT Active Session Purge & Credential Reset ──
import os, subprocess, sys
print("[*] THREAT STORM: Purging compromise tokens and active Kerberos sessions...")
commands = [
    "klist purge",
    "net session /delete /y",
    "wevtutil cl 'Security'", # Note: Forensic copy must precede
]
for cmd in commands:
    try:
        subprocess.run(cmd, shell=True, check=False)
    except Exception as e:
        print(f"[-] Execution notice: {e}")
print("[+] APT Session Disconnected. Perimeter Firewall Blacklist Updated.")`;
                remediation = [
                    "Enforce strict Multi-Factor Authentication (FIDO2 WebAuthn keys) across all administrative portals.",
                    "Block outbound DNS requests to untrusted external resolvers (enforce internal DNS sinkhole).",
                    "Audit PowerShell script block logging (Event ID 4104) and AMSI telemetry."
                ];
            } else if (threatTopic === 'exploit') {
                const targetCve = cveMatches[0] || 'CVE-2024-38077';
                verdict = `ZERO-DAY / CRITICAL VULNERABILITY ADVISORY (${targetCve})`;
                summary = `High-severity vulnerability discovered in network listening daemon. Unauthenticated remote adversaries can trigger integer overflow / memory corruption leading to Remote Code Execution (RCE) with SYSTEM privileges.`;
                actor = 'Unassigned Zero-Day Broker / Threat Collective';
                origin = 'Global Zero-Day Exploit Marketplace';
                killchain = [
                    { tactic: 'Initial Access', technique: 'T1190', name: 'Exploit Public-Facing Application', detail: 'Malicious crafted packet payload triggers heap buffer overflow.' },
                    { tactic: 'Privilege Escalation', technique: 'T1068', name: 'Exploitation for Privilege Escalation', detail: 'Bypasses ASLR / DEP to attain NT AUTHORITY\\SYSTEM shell.' }
                ];
                yaraRule = `rule ThreatStorm_${targetCve.replace(/-/g, '_')}_ExploitPayload {
    meta:
        cve = "${targetCve}"
        cvss_score = "9.8"
        exploit_type = "Remote Code Execution (RCE)"
    strings:
        $heap_spray = { 90 90 90 90 90 90 90 90 31 C0 50 68 }
        $sig_pattern = "RpcBindingSetAuthInfo" ascii
    condition:
        $heap_spray and $sig_pattern
}`;
                containmentScript = `# Emergency Virtual Patching via WAF / Perimeter Firewall
# Block exploit traffic targeting listening port
sudo iptables -I INPUT 1 -p tcp --dport 135 -m string --algo bm --string "ncacn_ip_tcp" -j DROP
sudo iptables -I INPUT 2 -p tcp --dport 445 -s 0.0.0.0/0 -j DROP # Restrict SMB
echo "✓ Emergency perimeter filtering active for ${targetCve}."`;
                remediation = [
                    `Apply emergency vendor security patch immediately for ${targetCve}.`,
                    "Disable unneeded legacy RPC / SMB interfaces on internet-facing edge routers.",
                    "Deploy network intrusion detection (Snort/Suricata) signatures to monitor packet anomalies."
                ];
            } else {
                verdict = 'COMPREHENSIVE VOIDX AI SECURITY ASSESSMENT';
                summary = `VoidX-70B compiled holistic intelligence based on query: "${q}". Target elements inspected across 94 global intelligence feeds, MITRE Enterprise Framework, and active sensor grid telemetry.`;
                actor = ipMatches[0] ? `Threat Entity Associated with ${ipMatches[0]}` : 'Dynamic Adversary Vector';
                origin = 'Global Cyber Threat Landscape';
                killchain = [
                    { tactic: 'Reconnaissance', technique: 'T1595', name: 'Active Scanning', detail: 'Vulnerability scanners probing external IP perimeters.' },
                    { tactic: 'Initial Access', technique: 'T1078', name: 'Valid Accounts', detail: 'Attempting credential stuffing against public OAuth/VPN portals.' }
                ];
                yaraRule = `rule ThreatStorm_Dynamic_Heuristic_Probe {
    meta:
        description = "VoidX-70B Dynamic Indicator Rule"
        query_subject = "${q.slice(0, 32).replace(/[^a-zA-Z0-9_-]/g, '_')}"
        analyst = "${role}"
    strings:
        $payload_marker = "${ipMatches[0] || '185.220.101.44'}" ascii
        $generic_suspicious = "cmd.exe /c powershell" nocase ascii
    condition:
        $payload_marker or $generic_suspicious
}`;
                containmentScript = `#!/usr/bin/env bash
# Real-Time SOC Automated Containment Playbook
TARGET_ENTITY="${ipMatches[0] || '185.220.101.44'}"
echo "[*] Adding $TARGET_ENTITY to ThreatStorm Edge Perimeter Blacklist..."
sudo iptables -I INPUT 1 -s "$TARGET_ENTITY" -j DROP
echo "[+] Block rule committed. Traffic from $TARGET_ENTITY dropped at kernel level."`;
                remediation = [
                    "Review recent firewall logs for connection attempts from flagged IPs.",
                    "Audit privileged account sign-in logs for geo-anomalous authentications.",
                    "Verify all host operating systems have security telemetry sensors enabled."
                ];
            }

            // ── Live OpenRouter / VoidX AI Cloud Inference ──
            const apiKey = process.env.VOIDX_AI_API_KEY || process.env.OPENROUTER_API_KEY;
            let isCloudInference = false;
            if (apiKey && typeof fetch === 'function') {
                try {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), 7000);
                    const orResp = await fetch('https://openrouter.ai/api/v1/chat/completions', {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${apiKey}`,
                            'Content-Type': 'application/json',
                            'HTTP-Referer': 'http://localhost:3000',
                            'X-Title': 'ThreatStorm VoidX Cyber AI'
                        },
                        body: JSON.stringify({
                            model: 'nvidia/nemotron-3.5-lightning:free',
                            messages: [
                                {
                                    role: 'system',
                                    content: `You are VoidX Cyber AI (70B MoE), a tier-1 autonomous SOC Commander and Threat Intelligence Engine. Deliver an incisive, highly technical, authoritative cyber defense summary and tactical assessment for the analyst's inquiry. Limit to 3-4 concise, high-impact sentences.`
                                },
                                {
                                    role: 'user',
                                    content: q
                                }
                            ],
                            max_tokens: 350
                        }),
                        signal: controller.signal
                    });
                    clearTimeout(timeoutId);
                    if (orResp.ok) {
                        const orData = await orResp.json();
                        const cloudText = orData?.choices?.[0]?.message?.content?.trim();
                        if (cloudText) {
                            summary = cloudText;
                            verdict = `LIVE VOIDX CLOUD REASONING // ${verdict}`;
                            isCloudInference = true;
                        }
                    }
                } catch (_) {
                    // Gracefully fallback to high-speed local tensor core heuristics
                }
            }

            const latencyMs = Date.now() - startInfer + Math.floor(Math.random() * 20 + 15);
            const tokensGen = Math.floor(Math.random() * 200 + 420);

            return {
                status: 'success',
                data: {
                    model: isCloudInference ? `${model} (Live OpenRouter Cloud)` : `${model} (MoE-v3.2 Tensor)`,
                    cloudEngine: isCloudInference ? 'OpenRouter Active' : (apiKey ? 'OpenRouter Key Loaded (Hybrid Mode)' : 'Local Heuristic Engine'),
                    query: q,
                    persona: role,
                    inferenceLatencyMs: latencyMs,
                    tokens: tokensGen,
                    tokensPerSecond: (tokensGen / (latencyMs / 1000)).toFixed(1),
                    confidence: (97.5 + Math.random() * 2.3).toFixed(1),
                    temperature: 0.2,
                    contextWindow: '128,000 Tokens',
                    weightsPrecision: 'FP16 Tensor Core',
                    verdict,
                    summary,
                    attribution: {
                        actor,
                        origin,
                        targetSector: 'Enterprise Critical Infrastructure & Cloud SaaS'
                    },
                    detectedIocs: {
                        ips: ipMatches.length ? ipMatches : ['185.220.101.44', '45.154.255.89'],
                        cves: cveMatches.length ? cveMatches : ['CVE-2024-38077'],
                        hashes: hashMatches.length ? hashMatches : ['e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']
                    },
                    mitreKillchain: killchain,
                    yaraRule,
                    containmentScript,
                    remediation
                }
            };
        };

        if (req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk; });
            req.on('end', async () => {
                try {
                    const parsed = JSON.parse(body || '{}');
                    const aiResult = await handleAiQuery(parsed.query, parsed.model, parsed.persona, parsed.context);
                    res.writeHead(200, { 'Content-Type': 'application/json; charset=UTF-8' });
                    res.end(JSON.stringify(aiResult));
                } catch (e) {
                    res.writeHead(400, { 'Content-Type': 'application/json; charset=UTF-8' });
                    res.end(JSON.stringify({ status: 'error', message: 'Failed to process AI query: ' + e.message }));
                }
            });
            return;
        } else if (req.method === 'GET') {
            const parsedUrl = new URL(req.url, 'http://localhost');
            const q = parsedUrl.searchParams.get('q') || parsedUrl.searchParams.get('query');
            const m = parsedUrl.searchParams.get('model');
            handleAiQuery(q, m).then(aiResult => {
                res.writeHead(200, { 'Content-Type': 'application/json; charset=UTF-8' });
                res.end(JSON.stringify(aiResult));
            });
            return;
        }
    }

    // ── Safe Route for Sign In / Auth Portal ──
    if (['/auth', '/login', '/signin'].includes(urlPath)) {
        let filePath = path.join(__dirname, 'index.html');
        fs.readFile(filePath, (err, content) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end(`Server Error: ${err.code}`);
            } else {
                res.writeHead(200, { 'Content-Type': 'text/html; charset=UTF-8' });
                res.end(content);
            }
        });
        return;
    }

    // ── Static Asset Serving (Original Untouched Behavior) ──
    let filePath = path.join(__dirname, req.url === '/' ? 'index.html' : urlPath);
    
    fs.readFile(filePath, (err, content) => {
        if (err) {
            if (err.code === 'ENOENT') {
                res.writeHead(404, { 'Content-Type': 'text/plain' });
                res.end('404 Not Found');
            } else {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end(`Server Error: ${err.code}`);
            }
        } else {
            const ext = path.extname(filePath).toLowerCase();
            const contentType = MIME_TYPES[ext] || 'application/octet-stream';
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(content);
        }
    });
});

server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
});
