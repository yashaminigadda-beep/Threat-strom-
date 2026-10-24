/* ═══════════════════════════════════════════════════════════════
   THREAT STORM — CYBER INTELLIGENCE BUREAU PLATFORM LOGIC
   Interactive 3D Earth Globe, 2D Telemetry Map & Command Suite
   ═══════════════════════════════════════════════════════════════ */

(function () {
    'use strict';

    // ── Master State ──
    const alerts = (typeof DEMO_THREATS !== 'undefined') ? [...DEMO_THREATS] : [];
    let activeAlertId = null;

    // ── DOM References ──
    const DOM = {
        // Clock
        liveUtcClock: document.getElementById('live-utc-clock'),

        // Canvases
        earthGlobeCanvas: document.getElementById('earth-globe-canvas'),
        worldTelemetryCanvas: document.getElementById('world-telemetry-canvas'),
        globeCalloutBadge: document.getElementById('globe-callout-badge'),
        mapTouchHint: document.getElementById('map-touch-hint'),

        // Sparklines
        sparklineActive: document.getElementById('sparkline-active'),
        sparklineBlocked: document.getElementById('sparkline-blocked'),
        sparklineVuln: document.getElementById('sparkline-vuln'),
        sparklineMttd: document.getElementById('sparkline-mttd'),

        // Donut
        threatDonutCanvas: document.getElementById('threat-donut-canvas'),

        // Alerts Table
        alertsTableBody: document.getElementById('alerts-table-body'),
        btnViewAllAlerts: document.getElementById('btn-view-all-alerts'),
        btnViewAllIntel: document.getElementById('btn-view-all-intel'),
        btnExploreMore: document.getElementById('btn-explore-more'),

        // Top Tabs
        topNavTabs: document.querySelectorAll('.tab-pill'),

        // Deep Intel Panel
        intelOverlay: document.getElementById('intel-overlay'),
        intelPanel: document.getElementById('intel-panel'),
        intelClose: document.getElementById('intel-close'),
        intelTitle: document.getElementById('intel-title'),
        intelSeverityBadge: document.getElementById('intel-severity-badge'),
        intelStatusBadge: document.getElementById('intel-status-badge'),
        intelCvssBadge: document.getElementById('intel-cvss-badge'),
        intelTimestamp: document.querySelector('#intel-timestamp span:last-child'),
        intelAsset: document.querySelector('#intel-asset span:last-child'),
        intelSource: document.querySelector('#intel-source span:last-child'),
        intelMitre: document.querySelector('#intel-mitre span:last-child'),
        intelRegion: document.querySelector('#intel-region span:last-child'),
        intelReasonContent: document.getElementById('intel-reason-content'),
        intelEvidenceContent: document.getElementById('intel-evidence-content'),
        intelConfidenceContent: document.getElementById('intel-confidence-content'),
        intelKnownContent: document.getElementById('intel-known-content'),
        intelImpactContent: document.getElementById('intel-impact-content'),
        intelInvestigationContent: document.getElementById('intel-investigation-content'),
        intelStatusChange: document.getElementById('intel-status-change'),
        intelApplyStatus: document.getElementById('intel-apply-status'),
        intelAnalystNotes: document.getElementById('intel-analyst-notes'),
        intelSaveNotes: document.getElementById('intel-save-notes'),
        intelExportJson: document.getElementById('intel-export-json')
    };

    // ═══════════════════════════════════════════════════════════
    // 1. LIVE UTC CLOCK
    // ═══════════════════════════════════════════════════════════

    function startLiveUtcClock() {
        if (!DOM.liveUtcClock) return;
        function updateClock() {
            const now = new Date();
            const dateStr = now.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
            const timeStr = now.toTimeString().split(' ')[0];
            DOM.liveUtcClock.textContent = `Live Intelligence • ${dateStr} • ${timeStr} (UTC)`;
        }
        updateClock();
        setInterval(updateClock, 1000);
    }

    // ═══════════════════════════════════════════════════════════
    // 2. 3D PLANETARY EARTH GLOBE ENGINE
    // ═══════════════════════════════════════════════════════════

    function init3DEarthGlobe() {
        const canvas = DOM.earthGlobeCanvas;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        let width = canvas.width;
        let height = canvas.height;
        let rotationY = 0.8;
        let rotationX = 0.25;
        let autoRotateSpeed = 0.0035;
        let isDragging = false;
        let lastMouseX = 0;
        let lastMouseY = 0;

        // Pre-cached dimensions for zero-reflow 60/120fps rendering
        let cx = 0, cy = 0, radius = 0;
        let globeInView = true;

        function resize() {
            const rect = canvas.getBoundingClientRect();
            const dpr = Math.min(window.devicePixelRatio || 1, 2);
            width = rect.width;
            height = rect.height;
            canvas.width = Math.floor(width * dpr);
            canvas.height = Math.floor(height * dpr);
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            cx = width * 0.48;
            cy = height * 0.50;
            radius = Math.min(width, height) * 0.40;
        }
        window.addEventListener('resize', resize, { passive: true });
        resize();

        if ('IntersectionObserver' in window) {
            const observer = new IntersectionObserver((entries) => {
                globeInView = entries[0].isIntersecting;
            }, { threshold: 0.05 });
            observer.observe(canvas);
        }

        // Mouse Drag Interaction on 3D Globe
        canvas.addEventListener('mousedown', (e) => {
            isDragging = true;
            lastMouseX = e.clientX;
            lastMouseY = e.clientY;
        });
        window.addEventListener('mousemove', (e) => {
            if (!isDragging) return;
            const dx = e.clientX - lastMouseX;
            const dy = e.clientY - lastMouseY;
            rotationY += dx * 0.006;
            rotationX = Math.max(-0.6, Math.min(0.6, rotationX + dy * 0.004));
            lastMouseX = e.clientX;
            lastMouseY = e.clientY;
        });
        window.addEventListener('mouseup', () => { isDragging = false; });

        // Touch Interaction on 3D Globe
        canvas.addEventListener('touchstart', (e) => {
            if (e.touches.length > 0) {
                lastMouseX = e.touches[0].clientX;
                lastMouseY = e.touches[0].clientY;
            }
        }, { passive: true });
        canvas.addEventListener('touchmove', (e) => {
            if (e.touches.length > 0) {
                const dx = e.touches[0].clientX - lastMouseX;
                const dy = e.touches[0].clientY - lastMouseY;
                rotationY += dx * 0.006;
                rotationX = Math.max(-0.6, Math.min(0.6, rotationX + dy * 0.004));
                lastMouseX = e.touches[0].clientX;
                lastMouseY = e.touches[0].clientY;
            }
        }, { passive: true });

        // Real-World Earth Satellite Asset
        const realEarthImg = new Image();
        realEarthImg.src = 'earth_real.jpg';
        let earthImgLoaded = false;
        realEarthImg.onload = () => {
            earthImgLoaded = true;
        };

        // Key Global Cyber Intelligence Hubs on Real Earth
        const majorHubs = [
            { name: 'US-East (Virginia)', lat: 0.68, lon: -1.35, color: '#e11d48', status: 'CRITICAL', ping: 0 },
            { name: 'London / Frankfurt', lat: 0.90, lon: 0.15, color: '#f59e0b', status: 'HIGH', ping: 0.3 },
            { name: 'Tokyo / APAC', lat: 0.62, lon: 2.45, color: '#e11d48', status: 'ELEVATED', ping: 0.6 },
            { name: 'Sydney Hub', lat: -0.58, lon: 2.65, color: '#00e676', status: 'NORMAL', ping: 0.8 },
            { name: 'Middle East (Dubai)', lat: 0.44, lon: 0.95, color: '#38bdf8', status: 'MONITORING', ping: 0.4 },
            { name: 'São Paulo', lat: -0.40, lon: -0.80, color: '#f59e0b', status: 'HIGH', ping: 0.5 }
        ];

        // Global Attack Laser Arcs on the 3D Sphere
        const globeArcs = [
            { fromLat: 0.68, fromLon: -1.35, toLat: 0.90, toLon: 0.15, color: '#e11d48', progress: 0.2 }, // US-East to Europe
            { fromLat: 0.90, fromLon: 0.15, toLat: 0.62, toLon: 2.45, color: '#f59e0b', progress: 0.6 },  // Europe to East Asia
            { fromLat: 0.44, fromLon: 0.95, toLat: -0.58, toLon: 2.65, color: '#e11d48', progress: 0.85 }, // Mid East to Australia
            { fromLat: 0.62, fromLon: 2.45, toLat: 0.68, toLon: -1.35, color: '#38bdf8', progress: 0.45 } // Asia to US
        ];

        // 3D Render Loop (Zero forced reflows, silky 60/120fps)
        function renderGlobe() {
            if (!globeInView) {
                requestAnimationFrame(renderGlobe);
                return;
            }

            ctx.clearRect(0, 0, width, height);

            if (!isDragging) {
                rotationY += autoRotateSpeed;
            }

            // 1. Deep Atmospheric Outer Corona & Cyan Ozone Glow
            const coronaGrad = ctx.createRadialGradient(cx, cy, radius * 0.94, cx, cy, radius * 1.38);
            coronaGrad.addColorStop(0, 'rgba(56, 189, 248, 0.45)');
            coronaGrad.addColorStop(0.25, 'rgba(14, 116, 220, 0.25)');
            coronaGrad.addColorStop(0.65, 'rgba(10, 45, 110, 0.08)');
            coronaGrad.addColorStop(1, 'rgba(4, 7, 16, 0)');
            ctx.fillStyle = coronaGrad;
            ctx.beginPath();
            ctx.arc(cx, cy, radius * 1.38, 0, Math.PI * 2);
            ctx.fill();

            // 2. Real World Earth Satellite Globe
            ctx.save();
            ctx.beginPath();
            ctx.arc(cx, cy, radius, 0, Math.PI * 2);
            ctx.clip();

            if (earthImgLoaded) {
                // Draw real photographic satellite Earth with smooth rotation
                ctx.save();
                ctx.translate(cx, cy);
                ctx.rotate(Math.sin(rotationY * 0.35) * 0.05); // Elegant natural axial tilt
                ctx.drawImage(realEarthImg, -radius, -radius, radius * 2, radius * 2);
                ctx.restore();

                // Luminous Cyan Atmosphere Edge Fresnel Rim (Zero black shading)
                const fresnelGrad = ctx.createRadialGradient(cx, cy, radius * 0.82, cx, cy, radius);
                fresnelGrad.addColorStop(0, 'rgba(56, 189, 248, 0)');
                fresnelGrad.addColorStop(0.85, 'rgba(56, 189, 248, 0.15)');
                fresnelGrad.addColorStop(1, 'rgba(125, 211, 252, 0.5)');
                ctx.fillStyle = fresnelGrad;
                ctx.fillRect(cx - radius, cy - radius, radius * 2, radius * 2);
            } else {
                // Fallback while asset initializes
                const sphereGrad = ctx.createRadialGradient(cx - radius * 0.35, cy - radius * 0.35, radius * 0.1, cx, cy, radius);
                sphereGrad.addColorStop(0, '#0d2244');
                sphereGrad.addColorStop(0.6, '#081226');
                sphereGrad.addColorStop(1, '#040711');
                ctx.fillStyle = sphereGrad;
                ctx.fillRect(cx - radius, cy - radius, radius * 2, radius * 2);
            }
            ctx.restore();

            // 3. Crisp Cyan Atmosphere Boundary Rim
            ctx.beginPath();
            ctx.arc(cx, cy, radius, 0, Math.PI * 2);
            ctx.strokeStyle = 'rgba(56, 189, 248, 0.75)';
            ctx.lineWidth = 1.6;
            ctx.stroke();

            // 4. Rotating Orbital Telemetry HUD Rings
            ctx.save();
            ctx.translate(cx, cy);

            // Outer dashed orbit ring
            ctx.beginPath();
            ctx.arc(0, 0, radius * 1.15, 0, Math.PI * 2);
            ctx.strokeStyle = 'rgba(56, 189, 248, 0.22)';
            ctx.lineWidth = 1;
            ctx.setLineDash([3, 7]);
            ctx.stroke();
            ctx.setLineDash([]);

            // Equatorial tracking ellipse
            ctx.beginPath();
            ctx.ellipse(0, 0, radius * 1.12, radius * 0.26, rotationX * 0.5, 0, Math.PI * 2);
            ctx.strokeStyle = 'rgba(212, 175, 55, 0.35)';
            ctx.lineWidth = 1;
            ctx.stroke();
            ctx.restore();

            // 5. Render 3D Perspective Cyber Hubs & Radar Blips
            const cosX = Math.cos(rotationX);
            const sinX = Math.sin(rotationX);
            const cosY = Math.cos(rotationY);
            const sinY = Math.sin(rotationY);

            majorHubs.forEach(hub => {
                hub.ping = (hub.ping + 0.02) % 1;

                const px = Math.cos(hub.lat) * Math.sin(hub.lon);
                const py = Math.sin(hub.lat);
                const pz = Math.cos(hub.lat) * Math.cos(hub.lon);

                const x1 = px * cosY - pz * sinY;
                const z1 = px * sinY + pz * cosY;
                const y2 = py * cosX - z1 * sinX;
                const z2 = py * sinX + z1 * cosX;

                // Visible on hemisphere
                if (z2 > 0) {
                    const sx = cx + x1 * radius;
                    const sy = cy - y2 * radius;
                    const alpha = Math.max(0.2, z2);

                    // Expanding radar ring
                    ctx.beginPath();
                    ctx.arc(sx, sy, 4 + hub.ping * 14, 0, Math.PI * 2);
                    ctx.strokeStyle = hub.color;
                    ctx.lineWidth = 1.2;
                    ctx.globalAlpha = (1 - hub.ping) * alpha;
                    ctx.stroke();
                    ctx.globalAlpha = 1.0;

                    // Central node dot
                    ctx.beginPath();
                    ctx.arc(sx, sy, 3, 0, Math.PI * 2);
                    ctx.fillStyle = '#ffffff';
                    ctx.fill();

                    ctx.beginPath();
                    ctx.arc(sx, sy, 4.5, 0, Math.PI * 2);
                    ctx.strokeStyle = hub.color;
                    ctx.lineWidth = 1.5;
                    ctx.stroke();
                }
            });

            // 6. Render 3D Curved Laser Attack Arcs Over Real World
            globeArcs.forEach(arc => {
                arc.progress = (arc.progress + 0.007) % 1;

                const steps = 24;
                const curvePoints = [];

                for (let s = 0; s <= steps; s++) {
                    const t = s / steps;
                    const curLat = arc.fromLat + (arc.toLat - arc.fromLat) * t;
                    const curLon = arc.fromLon + (arc.toLon - arc.fromLon) * t;

                    const elevation = 1.0 + Math.sin(t * Math.PI) * 0.18;

                    const px = Math.cos(curLat) * Math.sin(curLon) * elevation;
                    const py = Math.sin(curLat) * elevation;
                    const pz = Math.cos(curLat) * Math.cos(curLon) * elevation;

                    const x1 = px * cosY - pz * sinY;
                    const z1 = px * sinY + pz * cosY;
                    const y2 = py * cosX - z1 * sinX;
                    const z2 = py * sinX + z1 * cosX;

                    curvePoints.push({
                        x: cx + x1 * radius,
                        y: cy - y2 * radius,
                        z: z2
                    });
                }

                // Draw Arc Line
                ctx.beginPath();
                let started = false;
                curvePoints.forEach(p => {
                    if (p.z > -0.15) {
                        if (!started) {
                            ctx.moveTo(p.x, p.y);
                            started = true;
                        } else {
                            ctx.lineTo(p.x, p.y);
                        }
                    }
                });
                ctx.strokeStyle = arc.color === '#e11d48' ? 'rgba(225, 29, 72, 0.55)' : 'rgba(245, 158, 11, 0.55)';
                ctx.lineWidth = 1.5;
                ctx.setLineDash([3, 4]);
                ctx.stroke();
                ctx.setLineDash([]);

                // Draw Moving Photon Missile on Arc
                const missileIdx = Math.floor(arc.progress * steps);
                const ptHead = curvePoints[missileIdx];
                if (ptHead && ptHead.z > 0) {
                    ctx.beginPath();
                    ctx.arc(ptHead.x, ptHead.y, 3.5, 0, Math.PI * 2);
                    ctx.fillStyle = '#ffffff';
                    ctx.fill();

                    ctx.beginPath();
                    ctx.arc(ptHead.x, ptHead.y, 7, 0, Math.PI * 2);
                    ctx.strokeStyle = arc.color;
                    ctx.lineWidth = 1.5;
                    ctx.stroke();
                }
            });

            requestAnimationFrame(renderGlobe);
        }

        requestAnimationFrame(renderGlobe);
    }

    // ═══════════════════════════════════════════════════════════
    // 3. 2D WORLD THREAT MAP WITH INTERACTIVE TRAVELING PACKETS
    // ═══════════════════════════════════════════════════════════

    function init2DWorldMap() {
        const canvas = DOM.worldTelemetryCanvas;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');

        let mapW = 0, mapH = 0;
        let mapInView = true;

        function resize() {
            const rect = canvas.getBoundingClientRect();
            const dpr = Math.min(window.devicePixelRatio || 1, 2);
            mapW = rect.width;
            mapH = rect.height;
            canvas.width = Math.floor(mapW * dpr);
            canvas.height = Math.floor(mapH * dpr);
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        }
        window.addEventListener('resize', resize, { passive: true });
        resize();

        if ('IntersectionObserver' in window) {
            const observer = new IntersectionObserver((entries) => {
                mapInView = entries[0].isIntersecting;
            }, { threshold: 0.05 });
            observer.observe(canvas);
        }

        // 12 Hub Nodes accurately placed across Continents on world_map.jpg
        const mapNodes = [
            { id: 'node-na-east', x: 0.22, y: 0.33, label: 'US-East (Virginia)', sev: 'critical', alertTitle: 'Phishing Campaign Vector' },
            { id: 'node-na-west', x: 0.14, y: 0.33, label: 'US-West (Silicon Valley)', sev: 'high', alertTitle: 'Credential Abuse' },
            { id: 'node-sa', x: 0.31, y: 0.65, label: 'Sao Paulo (DC-Cluster)', sev: 'high', alertTitle: 'Malware Distribution Hub' },
            { id: 'node-eu-west', x: 0.49, y: 0.26, label: 'London / Frankfurt', sev: 'critical', alertTitle: 'Ransomware Staging Node' },
            { id: 'node-eu-east', x: 0.55, y: 0.26, label: 'Bucharest Gateway', sev: 'high', alertTitle: 'MFA Bypass Infiltration' },
            { id: 'node-me', x: 0.60, y: 0.42, label: 'Dammam SCADA Grid', sev: 'critical', alertTitle: 'OT Governor Interference' },
            { id: 'node-asia-east', x: 0.86, y: 0.32, label: 'Tokyo / Seoul', sev: 'critical', alertTitle: 'Volumetric DDoS Vector' },
            { id: 'node-se-asia', x: 0.78, y: 0.55, label: 'Singapore Transit', sev: 'medium', alertTitle: 'API Botnet Abuse' },
            { id: 'node-aus', x: 0.86, y: 0.73, label: 'Sydney Uplink', sev: 'high', alertTitle: 'Credential Extraction' },
            { id: 'node-africa', x: 0.53, y: 0.65, label: 'Johannesburg Node', sev: 'medium', alertTitle: 'Exfiltration Relay' },
            { id: 'node-india', x: 0.70, y: 0.45, label: 'Mumbai Data Fabric', sev: 'high', alertTitle: 'Banking Trojan Traffic' }
        ];

        // Active Flight Arcs with Continuously Moving Telemetry Packets
        const trajectories = [
            { from: mapNodes[0], to: mapNodes[3], progress: 0.1, speed: 0.004, color: '#f43f5e' }, // US-East -> London
            { from: mapNodes[3], to: mapNodes[6], progress: 0.5, speed: 0.0035, color: '#e11d48' }, // Europe -> Tokyo
            { from: mapNodes[6], to: mapNodes[8], progress: 0.8, speed: 0.0045, color: '#f59e0b' }, // Tokyo -> Sydney
            { from: mapNodes[2], to: mapNodes[0], progress: 0.3, speed: 0.003, color: '#f59e0b' },  // SA -> US-East
            { from: mapNodes[7], to: mapNodes[5], progress: 0.65, speed: 0.0038, color: '#38bdf8' }  // Singapore -> Mid East
        ];

        const shockwaves = [];
        let hoveredNode = null;

        // Quadratic Bezier Helper
        function getBezierPoint(p0, p1, p2, t) {
            const x = (1 - t) * (1 - t) * p0.x + 2 * (1 - t) * t * p1.x + t * t * p2.x;
            const y = (1 - t) * (1 - t) * p0.y + 2 * (1 - t) * t * p1.y + t * t * p2.y;
            return { x, y };
        }

        // Touch & Click Event Handler: Launches Live Packets across the Map
        function handleMapInteraction(clientX, clientY) {
            const rect = canvas.getBoundingClientRect();
            const clickX = clientX - rect.left;
            const clickY = clientY - rect.top;
            const w = rect.width;
            const h = rect.height;

            // Spawn double sonar wave at click point
            shockwaves.push({
                x: clickX,
                y: clickY,
                radius: 4,
                maxRadius: 80,
                opacity: 0.9,
                color: '#38bdf8'
            });
            shockwaves.push({
                x: clickX,
                y: clickY,
                radius: 1,
                maxRadius: 40,
                opacity: 0.7,
                color: '#d4af37'
            });

            // Find closest node to origin of click
            let closest = mapNodes[0];
            let minDist = Infinity;
            for (const n of mapNodes) {
                const dist = Math.hypot(clickX - n.x * w, clickY - n.y * h);
                if (dist < minDist) {
                    minDist = dist;
                    closest = n;
                }
            }

            // Pick a distant target node on another continent
            const candidates = mapNodes.filter(n => n !== closest);
            const target = candidates[Math.floor(Math.random() * candidates.length)];

            // Launch new high-speed intercept packet trajectory!
            trajectories.push({
                from: closest,
                to: target,
                progress: 0,
                speed: 0.0075,
                color: '#e11d48',
                ephemeral: true
            });

            // Update hint banner with dynamic coordinates
            if (DOM.mapTouchHint) {
                DOM.mapTouchHint.textContent = `TELEMETRY PULSE LAUNCHED: ${closest.label} ➔ ${target.label}`;
                setTimeout(() => {
                    if (DOM.mapTouchHint) {
                        DOM.mapTouchHint.textContent = 'TOUCH / CLICK MAP TO LAUNCH INTERCEPT TELEMETRY PACKETS';
                    }
                }, 3500);
            }

            // If user clicked near a node, open intelligence panel
            if (hoveredNode) {
                openIntelDossier(hoveredNode.id);
            }
        }

        canvas.addEventListener('click', (e) => handleMapInteraction(e.clientX, e.clientY));
        canvas.addEventListener('touchstart', (e) => {
            if (e.touches.length > 0) {
                handleMapInteraction(e.touches[0].clientX, e.touches[0].clientY);
            }
        }, { passive: true });

        // Hover tracking
        canvas.addEventListener('mousemove', (e) => {
            const rect = canvas.getBoundingClientRect();
            const mx = e.clientX - rect.left;
            const my = e.clientY - rect.top;
            const w = rect.width;
            const h = rect.height;

            let found = null;
            for (const node of mapNodes) {
                if (Math.hypot(mx - node.x * w, my - node.y * h) < 18) {
                    found = node;
                    break;
                }
            }
            hoveredNode = found;
            canvas.style.cursor = found ? 'pointer' : 'crosshair';
        });

        // Main Render Loop for 2D Map Canvas (Zero layout reflows)
        function drawMap() {
            if (!mapInView) {
                requestAnimationFrame(drawMap);
                return;
            }
            const w = mapW;
            const h = mapH;
            const now = Date.now() * 0.002;

            ctx.clearRect(0, 0, w, h);

            // 1. Draw Active Flight Arcs and Moving Packets
            for (let i = trajectories.length - 1; i >= 0; i--) {
                const traj = trajectories[i];
                const x1 = traj.from.x * w;
                const y1 = traj.from.y * h;
                const x2 = traj.to.x * w;
                const y2 = traj.to.y * h;
                const mx = (x1 + x2) / 2;
                const my = Math.min(y1, y2) - 40; // Arc elevation

                const p0 = { x: x1, y: y1 };
                const p1 = { x: mx, y: my };
                const p2 = { x: x2, y: y2 };

                // Draw base curved trajectory
                ctx.beginPath();
                ctx.moveTo(x1, y1);
                ctx.quadraticCurveTo(mx, my, x2, y2);
                ctx.strokeStyle = traj.color === '#e11d48' ? 'rgba(225, 29, 72, 0.45)' : 'rgba(245, 158, 11, 0.4)';
                ctx.lineWidth = 1.2;
                ctx.setLineDash([3, 5]);
                ctx.stroke();
                ctx.setLineDash([]);

                // Advance Progress
                traj.progress += traj.speed;
                if (traj.progress > 1) {
                    if (traj.ephemeral) {
                        // Impact shockwave at arrival node
                        shockwaves.push({
                            x: x2,
                            y: y2,
                            radius: 3,
                            maxRadius: 50,
                            opacity: 0.85,
                            color: traj.color
                        });
                        trajectories.splice(i, 1);
                        continue;
                    } else {
                        traj.progress = 0;
                    }
                }

                // Moving Glowing Photon Head + Comet Tail
                const ptHead = getBezierPoint(p0, p1, p2, traj.progress);
                const ptTail = getBezierPoint(p0, p1, p2, Math.max(0, traj.progress - 0.09));

                const grad = ctx.createLinearGradient(ptTail.x, ptTail.y, ptHead.x, ptHead.y);
                grad.addColorStop(0, 'rgba(0,0,0,0)');
                grad.addColorStop(1, traj.color);

                ctx.lineWidth = 2.6;
                ctx.strokeStyle = grad;
                ctx.beginPath();
                ctx.moveTo(ptTail.x, ptTail.y);
                ctx.lineTo(ptHead.x, ptHead.y);
                ctx.stroke();

                // Bright Photon Head
                ctx.beginPath();
                ctx.arc(ptHead.x, ptHead.y, 3, 0, Math.PI * 2);
                ctx.fillStyle = '#ffffff';
                ctx.fill();

                ctx.beginPath();
                ctx.arc(ptHead.x, ptHead.y, 7, 0, Math.PI * 2);
                ctx.strokeStyle = traj.color;
                ctx.lineWidth = 1.2;
                ctx.stroke();
            }

            // 2. Draw Expanding Sonar Shockwaves
            for (let i = shockwaves.length - 1; i >= 0; i--) {
                const sw = shockwaves[i];
                sw.radius += 1.8;
                sw.opacity -= 0.022;

                if (sw.opacity <= 0 || sw.radius >= sw.maxRadius) {
                    shockwaves.splice(i, 1);
                    continue;
                }

                ctx.beginPath();
                ctx.arc(sw.x, sw.y, sw.radius, 0, Math.PI * 2);
                ctx.strokeStyle = sw.color;
                ctx.lineWidth = 1.5;
                ctx.globalAlpha = Math.max(0, sw.opacity);
                ctx.stroke();
                ctx.globalAlpha = 1.0;
            }

            // 3. Draw Tactical Nodes
            mapNodes.forEach((node, idx) => {
                const nx = node.x * w;
                const ny = node.y * h;
                const pulse = Math.sin(now * 3 + idx) * 3;
                const isCrit = node.sev === 'critical';

                // Beacon Ring
                ctx.beginPath();
                ctx.arc(nx, ny, 7 + Math.max(0, pulse), 0, Math.PI * 2);
                ctx.strokeStyle = isCrit ? 'rgba(225, 29, 72, 0.45)' : 'rgba(245, 158, 11, 0.4)';
                ctx.lineWidth = 1;
                ctx.stroke();

                // Core Dot
                ctx.beginPath();
                ctx.arc(nx, ny, hoveredNode === node ? 5 : 3.5, 0, Math.PI * 2);
                ctx.fillStyle = isCrit ? '#e11d48' : '#f59e0b';
                ctx.fill();
            });

            requestAnimationFrame(drawMap);
        }

        requestAnimationFrame(drawMap);
    }

    // ═══════════════════════════════════════════════════════════
    // 4. SPARKLINE GENERATOR (High-Performance Zero-Reflow Neon Graphs)
    // ═══════════════════════════════════════════════════════════

    let sparklineAnimPhase = 0;
    let sparklinesInView = true;
    let sparklineItems = [];

    const sparklineConfigs = [
        { id: 'sparkline-active', color: '#ff2d55', harmonicColor: 'rgba(255, 45, 85, 0.35)', phaseOffset: 0.4 },
        { id: 'sparkline-blocked', color: '#00e676', harmonicColor: 'rgba(0, 230, 118, 0.35)', phaseOffset: 1.2 },
        { id: 'sparkline-vuln', color: '#f59e0b', harmonicColor: 'rgba(245, 158, 11, 0.35)', phaseOffset: 2.0 },
        { id: 'sparkline-mttd', color: '#00a8ff', harmonicColor: 'rgba(0, 168, 255, 0.35)', phaseOffset: 2.8 }
    ];

    function setupSparklineCanvases() {
        const dpr = Math.min(window.devicePixelRatio || 1, 2);
        sparklineItems = sparklineConfigs.map(cfg => {
            const canvas = document.getElementById(cfg.id);
            if (!canvas) return null;
            const ctx = canvas.getContext('2d', { alpha: true });
            const rect = canvas.getBoundingClientRect();
            const w = rect.width;
            const h = rect.height;
            if (w === 0 || h === 0) return null;
            canvas.width = Math.floor(w * dpr);
            canvas.height = Math.floor(h * dpr);
            ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
            return { canvas, ctx, w, h, ...cfg };
        }).filter(Boolean);
    }

    function renderSparklineItem(item, time) {
        const { ctx, w, h, color, harmonicColor, phaseOffset } = item;
        ctx.clearRect(0, 0, w, h);

        // 1. Cyber Telemetry Grid
        ctx.strokeStyle = 'rgba(56, 189, 248, 0.07)';
        ctx.lineWidth = 1;
        ctx.setLineDash([2, 5]);

        const y1 = h * 0.33;
        const y2 = h * 0.66;
        ctx.beginPath();
        ctx.moveTo(0, y1); ctx.lineTo(w, y1);
        ctx.moveTo(0, y2); ctx.lineTo(w, y2);
        ctx.stroke();

        ctx.beginPath();
        for (let i = 1; i <= 5; i++) {
            const x = (w / 6) * i;
            ctx.moveTo(x, 0); ctx.lineTo(x, h);
        }
        ctx.stroke();
        ctx.setLineDash([]);

        // 2. Secondary Harmonic Wave (Optimized 40 steps)
        ctx.beginPath();
        const steps = 40;
        for (let i = 0; i <= steps; i++) {
            const x = (i / steps) * w;
            const t = (i / steps) * Math.PI * 2.8 + phaseOffset - time * 0.45;
            const y = h * 0.52 + Math.sin(t) * (h * 0.22) + Math.cos(t * 1.4) * (h * 0.05);
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
        }
        ctx.strokeStyle = harmonicColor;
        ctx.lineWidth = 1.3;
        ctx.stroke();

        // 3. Primary Glowing Neon Wave
        ctx.save();
        ctx.shadowBlur = 10;
        ctx.shadowColor = color;
        ctx.strokeStyle = color;
        ctx.lineWidth = 2.2;

        ctx.beginPath();
        const wavePoints = [];
        for (let i = 0; i <= steps; i++) {
            const x = (i / steps) * w;
            const t = (i / steps) * Math.PI * 2.6 + phaseOffset + 0.8 + time * 0.6;
            const y = h * 0.50 + Math.sin(t) * (h * 0.28);
            if (i === 0) ctx.moveTo(x, y);
            else ctx.lineTo(x, y);
            wavePoints.push({ x, y });
        }
        ctx.stroke();
        ctx.restore();

        // 4. Glowing Hot Beacons
        const beaconIndices = [
            Math.floor(steps * 0.28),
            Math.floor(steps * 0.68),
            steps
        ];

        beaconIndices.forEach(idx => {
            const pt = wavePoints[idx];
            if (!pt) return;

            ctx.beginPath();
            ctx.arc(pt.x, pt.y, 4, 0, Math.PI * 2);
            ctx.fillStyle = color;
            ctx.shadowBlur = 8;
            ctx.shadowColor = color;
            ctx.fill();

            ctx.beginPath();
            ctx.arc(pt.x, pt.y, 1.8, 0, Math.PI * 2);
            ctx.fillStyle = '#ffffff';
            ctx.shadowBlur = 4;
            ctx.shadowColor = '#ffffff';
            ctx.fill();
        });
    }

    function initSparklines() {
        setupSparklineCanvases();
        window.addEventListener('resize', setupSparklineCanvases, { passive: true });

        const statsGrid = document.getElementById('stats-grid');
        if ('IntersectionObserver' in window && statsGrid) {
            const observer = new IntersectionObserver((entries) => {
                sparklinesInView = entries[0].isIntersecting;
            }, { threshold: 0.05 });
            observer.observe(statsGrid);
        }

        let lastTime = 0;
        function renderAllSparklines(timestamp) {
            if (sparklinesInView && timestamp - lastTime > 20) {
                lastTime = timestamp;
                sparklineAnimPhase += 0.02;
                for (let i = 0; i < sparklineItems.length; i++) {
                    renderSparklineItem(sparklineItems[i], sparklineAnimPhase);
                }
            }
            requestAnimationFrame(renderAllSparklines);
        }
        requestAnimationFrame(renderAllSparklines);
    }

    // ═══════════════════════════════════════════════════════════
    // 5. THREAT DISTRIBUTION DONUT CHART
    // ═══════════════════════════════════════════════════════════

    function initThreatDonut() {
        const canvas = DOM.threatDonutCanvas;
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        const rect = canvas.getBoundingClientRect();
        const dpr = window.devicePixelRatio || 1;
        canvas.width = rect.width * dpr;
        canvas.height = rect.height * dpr;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        const w = rect.width;
        const h = rect.height;
        const cx = w / 2;
        const cy = h / 2;
        const outerRadius = w * 0.44;
        const innerRadius = w * 0.30;

        const segments = [
            { pct: 0.32, color: '#ff2d55' }, // Malware (Red)
            { pct: 0.24, color: '#f97316' }, // Phishing (Orange)
            { pct: 0.15, color: '#f59e0b' }, // DDoS (Yellow/Gold)
            { pct: 0.14, color: '#06b6d4' }, // Ransomware (Cyan)
            { pct: 0.12, color: '#a855f7' }  // Others (Purple)
        ];

        ctx.clearRect(0, 0, w, h);

        // Soft outer neon glow behind donut ring
        ctx.save();
        ctx.shadowBlur = 16;
        ctx.shadowColor = 'rgba(255, 45, 85, 0.35)';

        let startAngle = -Math.PI / 2;
        const gap = 0.035;

        segments.forEach(seg => {
            const angle = seg.pct * Math.PI * 2;
            const endAngle = startAngle + angle - gap;

            ctx.beginPath();
            ctx.arc(cx, cy, outerRadius, startAngle, endAngle);
            ctx.arc(cx, cy, innerRadius, endAngle, startAngle, true);
            ctx.closePath();
            ctx.fillStyle = seg.color;
            ctx.shadowColor = seg.color;
            ctx.fill();

            startAngle = endAngle + gap;
        });

        ctx.restore();
    }

    // ═══════════════════════════════════════════════════════════
    // 6. DEEP INTELLIGENCE SLIDE-OVER DOSSIER
    // ═══════════════════════════════════════════════════════════

    function openIntelDossier(alertId) {
        const item = alerts.find(a => a.id === alertId) || alerts[0];
        if (!item || !DOM.intelPanel) return;

        activeAlertId = item.id;

        // Title and badges
        DOM.intelTitle.textContent = item.title;
        DOM.intelSeverityBadge.textContent = item.severity.toUpperCase();
        DOM.intelSeverityBadge.className = `intel-panel__severity-badge sev-badge--${item.severity}`;
        DOM.intelStatusBadge.textContent = item.status.toUpperCase();
        DOM.intelCvssBadge.textContent = `CVSS ${item.cvss || '9.4'}`;

        // Metadata items
        if (DOM.intelTimestamp) DOM.intelTimestamp.textContent = new Date(item.timestamp).toUTCString();
        if (DOM.intelAsset) DOM.intelAsset.textContent = item.asset;
        if (DOM.intelSource) DOM.intelSource.textContent = item.source;
        if (DOM.intelMitre) DOM.intelMitre.textContent = `MITRE: ${item.mitre}`;
        if (DOM.intelRegion) DOM.intelRegion.textContent = item.region;

        // Narrative Context
        DOM.intelReasonContent.innerHTML = `<p>${item.reason}</p>`;

        // Evidence Artifacts
        DOM.intelEvidenceContent.innerHTML = (item.evidence || []).map(ev => `
            <div style="margin-bottom: 8px;">
                <code>[${ev.ref}]</code> ${ev.text}
            </div>
        `).join('');

        // Confidence
        DOM.intelConfidenceContent.innerHTML = `
            <p><strong>Assessment Score: ${item.confidence?.level || 92}% (${item.confidence?.label || 'High'})</strong></p>
            <p>${item.confidence?.explanation || 'Signals cross-correlated across global sensor matrix.'}</p>
        `;

        // Known vs Unverified
        const knownHtml = (item.known || []).map(k => `<li>✓ ${k}</li>`).join('');
        const unverifiedHtml = (item.unverified || []).map(u => `<li>⚠ ${u}</li>`).join('');
        DOM.intelKnownContent.innerHTML = `
            <p><strong>Verified Telemetry Facts:</strong></p>
            <ul style="margin: 4px 0 12px 18px;">${knownHtml}</ul>
            <p><strong>Gaps Under Investigation:</strong></p>
            <ul style="margin: 4px 0 0 18px;">${unverifiedHtml}</ul>
        `;

        // Blast Radius
        const recs = (item.recommendations || []).map(r => `<li>${r}</li>`).join('');
        DOM.intelImpactContent.innerHTML = `
            <p style="margin-bottom: 8px;">${item.impact}</p>
            <p><strong>Defensive Interventions:</strong></p>
            <ol style="margin-left: 18px;">${recs}</ol>
        `;

        // Investigation Audit Log
        const timeline = (item.investigation?.timeline || []).map(tl => `
            <div style="font-size: 11px; margin-bottom: 4px; font-family: var(--font-mono);">
                <span style="color: var(--medium);">${new Date(tl.at).toLocaleTimeString()}</span> — ${tl.action} <em>(${tl.actor})</em>
            </div>
        `).join('');
        DOM.intelInvestigationContent.innerHTML = timeline || '<p>Investigation opened by Autonomous Correlation Engine.</p>';

        // Show Slide-Over
        DOM.intelOverlay.classList.add('is-active');
        document.body.style.overflow = 'hidden';
    }

    function closeIntelDossier() {
        if (!DOM.intelOverlay) return;
        DOM.intelOverlay.classList.remove('is-active');
        document.body.style.overflow = '';
    }

    // ═══════════════════════════════════════════════════════════
    // 7. EVENT BINDINGS
    // ═══════════════════════════════════════════════════════════

    function bindEvents() {
        // Table Row Click to Open Intel Panel
        const rows = document.querySelectorAll('.table-row');
        rows.forEach(r => {
            r.addEventListener('click', () => {
                const id = r.dataset.id;
                openIntelDossier(id);
            });
            r.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    openIntelDossier(r.dataset.id);
                }
            });
        });

        // Intel Panel Controls
        if (DOM.intelClose) DOM.intelClose.addEventListener('click', closeIntelDossier);
        if (DOM.intelOverlay) {
            DOM.intelOverlay.addEventListener('click', (e) => {
                if (e.target === DOM.intelOverlay) closeIntelDossier();
            });
        }
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && DOM.intelOverlay && DOM.intelOverlay.classList.contains('is-active')) {
                closeIntelDossier();
            }
        });

        // Status Change in Intel Panel
        if (DOM.intelApplyStatus) {
            DOM.intelApplyStatus.addEventListener('click', () => {
                const newStatus = DOM.intelStatusChange.value;
                if (!newStatus) return;
                const current = alerts.find(a => a.id === activeAlertId);
                if (current) {
                    current.status = newStatus;
                    DOM.intelStatusBadge.textContent = newStatus.toUpperCase();
                    DOM.intelInvestigationContent.innerHTML += `
                        <div style="font-size: 11px; margin-top: 4px; font-family: var(--font-mono); color: var(--gold-bright);">
                            <span>${new Date().toLocaleTimeString()}</span> — Status changed to ${newStatus.toUpperCase()} (Analyst YK)
                        </div>
                    `;
                }
            });
        }

        // Analyst Notes
        if (DOM.intelSaveNotes) {
            DOM.intelSaveNotes.addEventListener('click', () => {
                const text = DOM.intelAnalystNotes.value.trim();
                if (!text) return;
                DOM.intelInvestigationContent.innerHTML += `
                    <div style="font-size: 11px; margin-top: 6px; padding: 6px 10px; background: rgba(212,175,55,0.08); border-left: 2px solid var(--gold); border-radius: 2px;">
                        <strong>Analyst Note:</strong> ${text}
                    </div>
                `;
                DOM.intelAnalystNotes.value = '';
            });
        }

        // Export JSON
        if (DOM.intelExportJson) {
            DOM.intelExportJson.addEventListener('click', () => {
                const current = alerts.find(a => a.id === activeAlertId);
                if (!current) return;
                const blob = new Blob([JSON.stringify(current, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${current.id}_Dossier.json`;
                a.click();
                URL.revokeObjectURL(url);
            });
        }

        // Top Navigation Tabs
        DOM.topNavTabs.forEach(tab => {
            tab.addEventListener('click', () => {
                DOM.topNavTabs.forEach(t => t.classList.remove('tab-pill--active'));
                tab.classList.add('tab-pill--active');
            });
        });

        // View All Buttons
        if (DOM.btnViewAllAlerts) {
            DOM.btnViewAllAlerts.addEventListener('click', () => {
                openIntelDossier('TS-2026-0001');
            });
        }
        if (DOM.btnViewAllIntel) {
            DOM.btnViewAllIntel.addEventListener('click', () => {
                openIntelDossier('TS-2026-0007');
            });
        }
        if (DOM.btnExploreMore) {
            DOM.btnExploreMore.addEventListener('click', () => {
                openIntelDossier('TS-2026-0003');
            });
        }
    }

    // ═══════════════════════════════════════════════════════════
    // GOLD TOUCH & CLICK RIPPLE ENGINE
    // ═══════════════════════════════════════════════════════════

    function initGoldTouchRipple() {
        const interactiveSelector = 'button, .tab-pill, .action-btn, .editorial-poster-btn, .view-all-link, .feature-badge, .intel-actions__btn, .intel-panel__close-btn, .user-avatar, .nav-item';

        document.addEventListener('pointerdown', (e) => {
            const target = e.target.closest(interactiveSelector);
            if (!target) return;

            // Add immediate golden touch pressed class
            target.classList.add('gold-touch-pressed');
            setTimeout(() => {
                target.classList.remove('gold-touch-pressed');
            }, 350);

            // Calculate touch/click position relative to button
            const rect = target.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            const size = Math.max(rect.width, rect.height) * 2.2;

            const ripple = document.createElement('span');
            ripple.className = 'gold-touch-ripple';
            ripple.style.width = `${size}px`;
            ripple.style.height = `${size}px`;
            ripple.style.left = `${x}px`;
            ripple.style.top = `${y}px`;

            target.appendChild(ripple);

            // Clean up ripple after animation
            setTimeout(() => {
                if (ripple.parentNode === target) {
                    target.removeChild(ripple);
                }
            }, 650);
        }, { passive: true });
    }

    // ═══════════════════════════════════════════════════════════
    // BOOTSTRAP
    // ═══════════════════════════════════════════════════════════

    function init() {
        startLiveUtcClock();
        init3DEarthGlobe();
        init2DWorldMap();
        initSparklines();
        initThreatDonut();
        initGoldTouchRipple();
        bindEvents();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
