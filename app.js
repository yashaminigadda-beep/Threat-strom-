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
    // 6. RAW AI TELEMETRY ENGINE & DEEP DOSSIER
    // ═══════════════════════════════════════════════════════════

    function showToast(msg) {
        const toast = document.getElementById('toast-hud');
        const msgEl = document.getElementById('toast-msg');
        if (!toast || !msgEl) return;
        msgEl.textContent = msg;
        toast.classList.add('is-visible');
        setTimeout(() => {
            toast.classList.remove('is-visible');
        }, 2800);
    }

    function generateRawAiTelemetry(threat) {
        const numId = (threat.id || "TS-2026-0001").replace(/\D/g, '') || "8841";
        const ipSuffix = (parseInt(numId, 10) % 240) + 10;
        return {
            telemetry_packet_id: `PKT-2026-${numId}-RAW-AI`,
            correlation_engine: "THREAT_STORM // AUTONOMOUS_AI_CORRELATOR_v4.2.0",
            ingestion_timestamp: threat.timestamp || new Date().toISOString(),
            incident_id: threat.id,
            threat_designation: threat.title,
            severity_tier: (threat.severity || "CRITICAL").toUpperCase(),
            cvss_score: threat.cvss || 9.4,
            affected_infrastructure: {
                fqdn: threat.asset || "core-node.internal",
                sector: threat.sector || "Financial Core Infrastructure",
                geographical_region: threat.region || "Global Hub",
                active_sensor: threat.source || "EDR Behavioral Engine"
            },
            mitre_attack_context: {
                technique_ids: (threat.mitre || "T1078").split(',').map(s => s.trim()),
                tactic_classification: threat.category || "Exfiltration / Privilege Escalation"
            },
            verified_sensor_evidence_chain: (threat.evidence || []).map((ev, i) => ({
                evidence_id: ev.ref || `EVT-${numId}-${i + 1}`,
                raw_observation: ev.text,
                cryptographic_status: "SHA256_MATCHED_AUTHORITATIVE",
                pipeline_confidence: 96.8
            })),
            raw_network_pcap_sample: {
                source_socket: `10.14.8.${ipSuffix}:52140`,
                destination_socket: "185.220.101.44:443",
                ip_protocol: "TCP // TLS_1_3_CHACHA20_POLY1305",
                ja3_fingerprint: "771,4865-4866-4867-49195,0-23-65281-10-11-35-16,29-23-24,0",
                packet_count: 1420 + parseInt(numId, 10),
                total_bytes_transferred: 2450120 + parseInt(numId, 10) * 12
            },
            raw_process_execution_trace: {
                parent_process: "svchost.exe (PID 844)",
                spawned_binary: `C:\\Windows\\System32\\rundll32.exe (PID ${10000 + parseInt(numId, 10)})`,
                command_line_parameters: `powershell.exe -NoP -NonI -W Hidden -Enc SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLi4u`,
                amsi_scan_result: "AMSI_RESULT_DETECTED // HEURISTIC_MATCH_POSITIVE"
            },
            ai_threat_intelligence_assessment: {
                autonomous_model: "CyberSentinel-LLM-Transformer v5.4.1",
                heuristic_confidence_percent: threat.confidence?.level || 92,
                confidence_rating: threat.confidence?.label || "High",
                ai_reasoning: threat.confidence?.explanation || threat.reason,
                blast_radius_assessment: threat.impact,
                prescribed_countermeasures: threat.recommendations || [
                    "Immediate EDR automated network quarantine",
                    "Invalidate domain Kerberos TGT and rotate credentials",
                    "Acquire triage memory dump for deep forensic timeline"
                ]
            }
        };
    }

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
                <span style="color: var(--medium);">${new Date(tl.at || Date.now()).toLocaleTimeString()}</span> — ${tl.action || tl.text} <em>(${tl.actor || 'AI Correlator'})</em>
            </div>
        `).join('');
        DOM.intelInvestigationContent.innerHTML = timeline || '<p>Investigation opened by Autonomous Correlation Engine.</p>';

        // Raw AI Telemetry & SIEM Sensor Payload
        const rawContent = document.getElementById('intel-raw-content');
        const rawTelemetry = generateRawAiTelemetry(item);
        if (rawContent) {
            rawContent.innerHTML = `
                <div style="display: flex; gap: 8px; margin-bottom: 8px;">
                    <span class="ev-badge-chip ev-chip--gold">PKT_ID: ${rawTelemetry.telemetry_packet_id}</span>
                    <span class="ev-badge-chip ev-chip--sample">JA3: ${rawTelemetry.raw_network_pcap_sample.ja3_fingerprint.split(',')[0]}</span>
                    <span class="ev-badge-chip ev-chip--crit">${rawTelemetry.raw_network_pcap_sample.total_bytes_transferred} Bytes</span>
                </div>
                <pre class="intel-raw-code-box"><code id="intel-raw-json-code">${JSON.stringify(rawTelemetry, null, 2)}</code></pre>
            `;
        }

        // Wire Copy Raw button
        const btnCopyRaw = document.getElementById('intel-btn-copy-raw');
        if (btnCopyRaw) {
            btnCopyRaw.onclick = () => {
                const text = JSON.stringify(rawTelemetry, null, 2);
                if (navigator.clipboard) {
                    navigator.clipboard.writeText(text).then(() => {
                        showToast(`✓ Raw AI Telemetry for ${item.id} Copied to Clipboard!`);
                    }).catch(() => {
                        showToast(`✓ Telemetry Copied!`);
                    });
                } else {
                    showToast(`✓ Telemetry Ready`);
                }
            };
        }

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
    // 7. MASTER MULTI-PAGE VIEW ROUTER (AI INTELLIGENCE VIEWS)
    // ═══════════════════════════════════════════════════════════

    const VIEW_SECTIONS = {
        planetary: ['hero-section', 'middle-dashboard', 'recent-threats-section'],
        'evidence-chain': ['evidence-chain'],
        feed: ['view-feed'],
        sector: ['view-sector'],
        reports: ['view-reports'],
        settings: ['view-settings'],
        alerts: ['view-alerts'],
        auth: ['view-auth']
    };

    function switchAppView(viewName) {
        if (!VIEW_SECTIONS[viewName] && viewName !== 'evidence-chain') {
            viewName = 'planetary';
        }

        // Hide all sections first
        const allSectionIds = [
            'hero-section',
            'middle-dashboard',
            'recent-threats-section',
            'evidence-chain',
            'view-feed',
            'view-sector',
            'view-reports',
            'view-settings',
            'view-alerts',
            'view-auth'
        ];

        allSectionIds.forEach(id => {
            const el = document.getElementById(id);
            if (el) {
                if (id === 'evidence-chain') {
                    el.classList.remove('ev-view--active');
                } else {
                    el.style.display = 'none';
                }
            }
        });

        // Show requested view sections
        if (viewName === 'evidence-chain') {
            if (window.EvidenceChainEngine && window.EvidenceChainEngine.switchToEvidenceChainView) {
                window.EvidenceChainEngine.switchToEvidenceChainView();
            } else {
                const evEl = document.getElementById('evidence-chain');
                if (evEl) evEl.classList.add('ev-view--active');
            }
        } else {
            const targetIds = VIEW_SECTIONS[viewName] || VIEW_SECTIONS.planetary;
            targetIds.forEach(id => {
                const el = document.getElementById(id);
                if (el) el.style.display = '';
            });
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        // Synchronize Top Tab Pills
        document.querySelectorAll('.tab-pill').forEach(pill => pill.classList.remove('tab-pill--active'));
        const tabMapping = {
            planetary: 'tab-planetary',
            'evidence-chain': 'tab-evidence-chain',
            feed: 'tab-feed',
            sector: 'tab-sector',
            reports: 'tab-reports',
            settings: 'tab-settings'
        };
        const activeTabId = tabMapping[viewName];
        if (activeTabId) {
            const activeTab = document.getElementById(activeTabId);
            if (activeTab) activeTab.classList.add('tab-pill--active');
        }

        // Synchronize Sidebar Navigation Items
        document.querySelectorAll('.sidebar__nav .nav-item').forEach(item => item.classList.remove('nav-item--active'));
        const menuMapping = {
            planetary: 'menu-threat-map',
            'evidence-chain': 'menu-evidence-chain',
            feed: 'menu-feed',
            sector: 'menu-sector',
            alerts: 'menu-alerts',
            reports: 'menu-reports',
            settings: 'menu-settings'
        };
        const activeMenuId = menuMapping[viewName];
        if (activeMenuId) {
            const activeMenu = document.getElementById(activeMenuId);
            if (activeMenu) activeMenu.classList.add('nav-item--active');
        }

        // Render dynamic content for target view
        if (viewName === 'feed') renderFeedView();
        if (viewName === 'sector') renderSectorView();
        if (viewName === 'reports') renderReportsView();
        if (viewName === 'settings') renderSettingsView();
        if (viewName === 'alerts') renderFullAlertsTable();
    }

    window.switchAppView = switchAppView;

    // ── Render Views Functions ──

    function renderFeedView(filterSeverity = 'all', searchQuery = '') {
        const container = document.getElementById('feed-cards-container');
        if (!container) return;

        let filtered = alerts.filter(a => {
            if (filterSeverity !== 'all' && a.severity.toLowerCase() !== filterSeverity.toLowerCase()) return false;
            if (searchQuery) {
                const q = searchQuery.toLowerCase();
                const match = (a.id && a.id.toLowerCase().includes(q)) ||
                              (a.title && a.title.toLowerCase().includes(q)) ||
                              (a.asset && a.asset.toLowerCase().includes(q)) ||
                              (a.mitre && a.mitre.toLowerCase().includes(q)) ||
                              (a.sector && a.sector.toLowerCase().includes(q));
                if (!match) return false;
            }
            return true;
        });

        container.innerHTML = filtered.map(item => {
            const numId = (item.id || "TS-2026-0001").replace(/\D/g, '') || "8841";
            const ipSuffix = (parseInt(numId, 10) % 240) + 10;
            return `
                <div class="feed-threat-card">
                    <div class="feed-threat-top">
                        <div>
                            <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                                <span class="sev-badge sev-badge--${item.severity}">${item.severity.toUpperCase()}</span>
                                <span class="ev-badge-chip ev-chip--gold">CVSS ${item.cvss || 9.4}</span>
                                <span class="ev-badge-chip ev-chip--sample">${item.category || 'Security Alert'}</span>
                            </div>
                            <h3 class="feed-threat-title">${item.title}</h3>
                        </div>
                    </div>

                    <div class="feed-threat-meta">
                        <span>🖥️ ${item.asset}</span>
                        <span>🌐 ${item.region}</span>
                        <span>⚡ MITRE ${item.mitre}</span>
                    </div>

                    <p style="font-size:12px; color:var(--text-secondary); line-height:1.45; margin:0;">
                        ${item.reason.length > 140 ? item.reason.substring(0, 138) + '…' : item.reason}
                    </p>

                    <div class="feed-raw-ioc-box">
                        <div><strong>RAW IOC:</strong> 185.220.101.${ipSuffix}:443 // TCP_ESTABLISHED</div>
                        <div><strong>HASH:</strong> e3b0c44298fc1c149afbf4c8996fb92427ae${numId}</div>
                    </div>

                    <div class="feed-card-actions">
                        <button type="button" class="feed-btn-inspect" data-action="inspect" data-id="${item.id}">
                            <span>⚡ Inspect Raw AI Data</span>
                        </button>
                        <button type="button" class="feed-btn-copy" data-action="copy" data-id="${item.id}" title="Copy raw payload to clipboard">
                            <span>📋 Copy JSON</span>
                        </button>
                    </div>
                </div>
            `;
        }).join('');

        // Attach buttons
        container.querySelectorAll('[data-action="inspect"]').forEach(btn => {
            btn.addEventListener('click', () => {
                openIntelDossier(btn.getAttribute('data-id'));
            });
        });

        container.querySelectorAll('[data-action="copy"]').forEach(btn => {
            btn.addEventListener('click', () => {
                const id = btn.getAttribute('data-id');
                const threat = alerts.find(a => a.id === id);
                if (threat) {
                    const raw = generateRawAiTelemetry(threat);
                    if (navigator.clipboard) {
                        navigator.clipboard.writeText(JSON.stringify(raw, null, 2)).then(() => {
                            showToast(`✓ Raw AI Telemetry for ${id} Copied to Clipboard!`);
                        });
                    }
                }
            });
        });
    }

    function renderSectorView() {
        const container = document.getElementById('sector-cards-container');
        if (!container) return;

        const SECTORS = [
            { name: "Financial Core & Custody Clearing", risk: 94, incidents: 5, mttd: "3.2m", actor: "APT28 / Lazarus", sensor: "ONLINE (0ms)", icon: "🏦" },
            { name: "Healthcare Clinical Data & PACS", risk: 88, incidents: 4, mttd: "4.8m", actor: "BlackCat / ALPHV", sensor: "ONLINE (1ms)", icon: "🏥" },
            { name: "Defense Industrial Base & Weapons R&D", risk: 96, incidents: 6, mttd: "2.1m", actor: "APT-Vanguard", sensor: "ONLINE (0ms)", icon: "🛡️" },
            { name: "Energy Grid & Industrial SCADA Logic", risk: 82, incidents: 3, mttd: "5.4m", actor: "Sandworm / Industroyer", sensor: "ONLINE (2ms)", icon: "⚡" },
            { name: "Cloud & Sovereign Hyperscale Core", risk: 74, incidents: 2, mttd: "3.9m", actor: "Scattered Spider", sensor: "ONLINE (1ms)", icon: "☁️" },
            { name: "Telecommunications & BGP Autonomous", risk: 79, incidents: 3, mttd: "4.1m", actor: "Volt Typhoon", sensor: "ONLINE (1ms)", icon: "📡" },
            { name: "Government Identity & Citizen Portal", risk: 85, incidents: 3, mttd: "3.5m", actor: "Midnight Blizzard", sensor: "ONLINE (0ms)", icon: "🏛️" },
            { name: "Global Retail Logistics & Supply Chain", risk: 68, incidents: 2, mttd: "6.2m", actor: "FIN7 Syndicate", sensor: "ONLINE (2ms)", icon: "📦" }
        ];

        container.innerHTML = SECTORS.map(sec => `
            <div class="sector-card">
                <div class="sector-header">
                    <span style="font-size:24px;">${sec.icon}</span>
                    <span class="sector-risk-badge" style="background:${sec.risk >= 90 ? 'rgba(255,45,85,0.2)' : 'rgba(245,158,11,0.2)'}; color:${sec.risk >= 90 ? '#ff2d55' : '#f59e0b'}; border:1px solid ${sec.risk >= 90 ? '#ff2d55' : '#f59e0b'};">
                        RISK INDEX ${sec.risk}%
                    </span>
                </div>
                <h3 class="sector-name">${sec.name}</h3>
                <div class="sector-metrics-row">
                    <div class="sector-metric-item">
                        <span>Active Incidents</span>
                        <div style="font-size:16px; font-weight:700; color:#ff2d55;">${sec.incidents} Threats</div>
                    </div>
                    <div class="sector-metric-item">
                        <span>Mean Triage Speed</span>
                        <div style="font-size:16px; font-weight:700; color:#00e676;">${sec.mttd}</div>
                    </div>
                </div>
                <div style="font-family:var(--font-mono); font-size:10px; color:var(--text-tertiary);">
                    <div><strong>PRIMARY ACTOR:</strong> ${sec.actor}</div>
                    <div style="color:#00e676;"><strong>SENSOR PIPELINE:</strong> ${sec.sensor}</div>
                </div>
                <button type="button" class="feed-btn-inspect" data-sector="${sec.name}">
                    <span>⚡ Inspect Raw Sector Telemetry</span>
                </button>
            </div>
        `).join('');

        container.querySelectorAll('[data-sector]').forEach(btn => {
            btn.addEventListener('click', () => {
                const matching = alerts.find(a => a.sector && a.sector.toLowerCase().includes('fin')) || alerts[0];
                openIntelDossier(matching.id);
            });
        });
    }

    function renderReportsView() {
        const container = document.getElementById('reports-cards-container');
        if (!container) return;

        const REPORTS = [
            { id: "INC-2026-8841", title: "SolarStorm APT: Multi-Stage Domain Controller Compromise & Egress", sev: "CRITICAL", cvss: 9.8, artifacts: 26, nodes: 8, lead: "Commander Yash K.", time: "24 Oct 2026" },
            { id: "TS-2026-0001", title: "Credential Exfiltration via Reverse-Tunneled C2 Channel", sev: "CRITICAL", cvss: 9.8, artifacts: 18, nodes: 6, lead: "Analyst YK", time: "24 Oct 2026" },
            { id: "TS-2026-0002", title: "Ransomware Pre-Deployment Shadow Copy Purge & Boot Tamper", sev: "CRITICAL", cvss: 9.6, artifacts: 15, nodes: 5, lead: "Incident Cmdr YK", time: "23 Oct 2026" },
            { id: "TS-2026-0003", title: "Industrial SCADA Logic Controller Firmware Tamper", sev: "CRITICAL", cvss: 9.7, artifacts: 22, nodes: 7, lead: "Analyst YK", time: "22 Oct 2026" },
            { id: "TS-2026-0004", title: "Kubernetes API Server Service Account Token Compromise", sev: "CRITICAL", cvss: 9.5, artifacts: 19, nodes: 6, lead: "SOC Lead YK", time: "21 Oct 2026" },
            { id: "TS-2026-0005", title: "DNS Tunneling C2 Channel over IPv6 Protocol Stack", sev: "HIGH", cvss: 8.8, artifacts: 14, nodes: 4, lead: "Analyst YK", time: "20 Oct 2026" }
        ];

        container.innerHTML = REPORTS.map(r => `
            <div class="report-card">
                <div>
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:8px;">
                        <span class="ev-badge-chip ev-chip--gold">DOSSIER // ${r.id}</span>
                        <span class="sev-badge sev-badge--${r.sev.toLowerCase()}">${r.sev} • CVSS ${r.cvss}</span>
                    </div>
                    <h3 style="font-family:var(--font-heading); font-size:16px; font-weight:700; color:#ffffff; line-height:1.4;">${r.title}</h3>
                </div>

                <div style="display:grid; grid-template-columns:1fr 1fr; gap:8px; background:#020409; padding:10px 12px; border-radius:4px; font-family:var(--font-mono); font-size:10px;">
                    <div><span style="color:var(--text-tertiary);">ARTIFACTS:</span> <strong style="color:#00e676;">${r.artifacts} Verified</strong></div>
                    <div><span style="color:var(--text-tertiary);">ANALYST:</span> <strong style="color:#ffffff;">${r.lead}</strong></div>
                    <div><span style="color:var(--text-tertiary);">STATUS:</span> <strong style="color:var(--gold-bright);">PUBLISHED</strong></div>
                    <div><span style="color:var(--text-tertiary);">DATE:</span> <strong style="color:#38bdf8;">${r.time}</strong></div>
                </div>

                <div style="display:flex; gap:8px; flex-wrap:wrap;">
                    <button type="button" class="feed-btn-inspect" data-report-id="${r.id}">
                        <span>⚡ Inspect Raw AI Data</span>
                    </button>
                    <button type="button" class="feed-btn-copy" data-action="download-json" data-report-id="${r.id}">
                        <span>💾 JSON</span>
                    </button>
                    <button type="button" class="feed-btn-copy" data-action="download-md" data-report-id="${r.id}">
                        <span>📝 Markdown</span>
                    </button>
                </div>
            </div>
        `).join('');

        container.querySelectorAll('[data-report-id]').forEach(btn => {
            const id = btn.getAttribute('data-report-id');
            const action = btn.getAttribute('data-action');
            if (action === 'download-json') {
                btn.onclick = () => {
                    const threat = alerts.find(a => a.id === id) || alerts[0];
                    const raw = generateRawAiTelemetry(threat);
                    const blob = new Blob([JSON.stringify(raw, null, 2)], { type: 'application/json' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `${id}_AI_Dossier.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                    showToast(`✓ Downloaded ${id}_AI_Dossier.json`);
                };
            } else if (action === 'download-md') {
                btn.onclick = () => {
                    const threat = alerts.find(a => a.id === id) || alerts[0];
                    let md = `# THREAT STORM — INCIDENT BRIEFING // ${id}\n\n`;
                    md += `**Title:** ${threat.title}\n`;
                    md += `**Severity:** ${threat.severity.toUpperCase()} (CVSS ${threat.cvss || 9.4})\n`;
                    md += `**Classification:** TOP SECRET // ORCON // SOC VERIFIED\n\n`;
                    md += `## Detection Narrative\n${threat.reason}\n\n`;
                    md += `## Impact Assessment\n${threat.impact}\n`;
                    const blob = new Blob([md], { type: 'text/markdown' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `${id}_Briefing.md`;
                    a.click();
                    URL.revokeObjectURL(url);
                    showToast(`✓ Downloaded ${id}_Briefing.md`);
                };
            } else {
                btn.onclick = () => {
                    openIntelDossier(id);
                };
            }
        });
    }

    function renderSettingsView() {
        const tbody = document.getElementById('settings-sensors-body');
        if (!tbody) return;

        const SENSORS = [
            { id: "SNR-001", name: "EDR Behavioral Engine (Sysmon EID 1/3/10)", host: "Endpoints (4,250 Agents)", status: "ONLINE", latency: "0.8ms", tput: "1.4 MB/s" },
            { id: "SNR-002", name: "Zeek Network Packet Intercept Tap", host: "Core Switch Fabric (40 Gbps)", status: "ONLINE", latency: "1.2ms", tput: "24.8 MB/s" },
            { id: "SNR-003", name: "Active Directory Forwarding Agent (EID 4662)", host: "Domain Controllers (dc-auth-01/03)", status: "ONLINE", latency: "2.1ms", tput: "420 KB/s" },
            { id: "SNR-004", name: "Darknet Honeytoken Canary Intercept", host: "Global Active Directory Forest", status: "ONLINE", latency: "0.4ms", tput: "12 KB/s" },
            { id: "SNR-005", name: "CloudTrail Multi-Region GuardDuty Pipe", host: "AWS & Azure Hybrid Enclaves", status: "ONLINE", latency: "1.8ms", tput: "890 KB/s" },
            { id: "SNR-006", name: "AMSI ScriptBlock Reassembly Daemon", host: "Workstations ws-fin-001..099", status: "ONLINE", latency: "1.5ms", tput: "650 KB/s" },
            { id: "SNR-007", name: "Threat Intelligence Reputation Cluster", host: "Haute Cyber Bureau Cloud", status: "ONLINE", latency: "0.6ms", tput: "3.2 MB/s" }
        ];

        tbody.innerHTML = SENSORS.map(s => `
            <tr>
                <td style="color:var(--gold-bright); font-weight:700;">${s.id}</td>
                <td style="color:#ffffff;">${s.name}</td>
                <td>${s.host}</td>
                <td><span class="ev-badge-chip ev-chip--gold" style="color:#00e676; border-color:#00e676;">✓ ${s.status}</span></td>
                <td style="color:#38bdf8;">${s.latency}</td>
                <td>${s.tput}</td>
                <td><button type="button" class="feed-btn-copy" style="padding:3px 8px; font-size:10px;" onclick="window.switchAppView('feed')">Inspect Data</button></td>
            </tr>
        `).join('');
    }

    function renderFullAlertsTable(searchQuery = '', filterSeverity = 'all') {
        const tbody = document.getElementById('full-alerts-body');
        if (!tbody) return;

        let filtered = alerts.filter(a => {
            if (filterSeverity !== 'all' && a.severity.toLowerCase() !== filterSeverity.toLowerCase()) return false;
            if (searchQuery) {
                const q = searchQuery.toLowerCase();
                const match = (a.id && a.id.toLowerCase().includes(q)) ||
                              (a.title && a.title.toLowerCase().includes(q)) ||
                              (a.asset && a.asset.toLowerCase().includes(q)) ||
                              (a.source && a.source.toLowerCase().includes(q));
                if (!match) return false;
            }
            return true;
        });

        tbody.innerHTML = filtered.map(a => `
            <tr class="table-row" data-id="${a.id}" tabindex="0" style="cursor:pointer;" title="Click to inspect raw AI telemetry dossier">
                <td style="color:var(--gold-bright); font-family:var(--font-mono); font-weight:700;">${a.id}</td>
                <td class="col-time">${new Date(a.timestamp).toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' })}</td>
                <td class="col-threat"><strong>${a.title}</strong></td>
                <td class="col-source">${a.source}</td>
                <td class="col-target">${a.asset}</td>
                <td><span style="font-family:var(--font-mono); font-size:10.5px; color:#38bdf8;">${a.mitre}</span></td>
                <td class="col-sev"><span class="sev-badge sev-badge--${a.severity}">${a.severity.toUpperCase()}</span></td>
                <td class="col-status"><span class="status-pill status-pill--${a.status}">${a.status}</span></td>
                <td>
                    <button type="button" class="feed-btn-copy" style="padding:3px 8px; font-size:10px;" data-raw-id="${a.id}">
                        ⚡ Raw AI
                    </button>
                </td>
            </tr>
        `).join('');

        // Wire click handlers on rows
        tbody.querySelectorAll('.table-row').forEach(row => {
            row.addEventListener('click', () => {
                openIntelDossier(row.getAttribute('data-id'));
            });
        });

        tbody.querySelectorAll('[data-raw-id]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.stopPropagation();
                openIntelDossier(btn.getAttribute('data-raw-id'));
            });
        });
    }

    // ═══════════════════════════════════════════════════════════
    // 8. EVENT BINDINGS (ALL BUTTONS WIRED TO VALID RAW DATA)
    // ═══════════════════════════════════════════════════════════

    function bindEvents() {
        // Table Row Click to Open Intel Panel in Recent Threats
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

        // Clickable Latest Intelligence Items
        document.querySelectorAll('.intel-item--clickable').forEach(item => {
            item.addEventListener('click', () => {
                const id = item.getAttribute('data-id') || 'TS-2026-0001';
                openIntelDossier(id);
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
                    showToast(`✓ Incident ${current.id} status updated to ${newStatus.toUpperCase()}`);
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
                showToast("✓ Technical Analyst Note appended to dossier");
            });
        }

        // Export JSON
        if (DOM.intelExportJson) {
            DOM.intelExportJson.addEventListener('click', () => {
                const current = alerts.find(a => a.id === activeAlertId);
                if (!current) return;
                const raw = generateRawAiTelemetry(current);
                const blob = new Blob([JSON.stringify(raw, null, 2)], { type: 'application/json' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `${current.id}_Dossier.json`;
                a.click();
                URL.revokeObjectURL(url);
                showToast(`✓ Exported ${current.id}_Dossier.json`);
            });
        }

        // ── Top Navigation Tabs (Switch to valid pages) ──
        const tabPlanetary = document.getElementById('tab-planetary');
        const tabEvidence = document.getElementById('tab-evidence-chain');
        const tabFeed = document.getElementById('tab-feed');
        const tabSector = document.getElementById('tab-sector');
        const tabReports = document.getElementById('tab-reports');
        const tabSettings = document.getElementById('tab-settings');

        if (tabPlanetary) tabPlanetary.addEventListener('click', () => switchAppView('planetary'));
        if (tabEvidence) tabEvidence.addEventListener('click', () => switchAppView('evidence-chain'));
        if (tabFeed) tabFeed.addEventListener('click', () => switchAppView('feed'));
        if (tabSector) tabSector.addEventListener('click', () => switchAppView('sector'));
        if (tabReports) tabReports.addEventListener('click', () => switchAppView('reports'));
        if (tabSettings) tabSettings.addEventListener('click', () => switchAppView('settings'));

        // ── Sidebar Menu Links ──
        const menuThreatMap = document.getElementById('menu-threat-map');
        const menuEvidence = document.getElementById('menu-evidence-chain');
        const menuFeed = document.getElementById('menu-feed');
        const menuSector = document.getElementById('menu-sector');
        const menuAlerts = document.getElementById('menu-alerts');
        const menuReports = document.getElementById('menu-reports');
        const menuSettings = document.getElementById('menu-settings');

        if (menuThreatMap) menuThreatMap.addEventListener('click', (e) => { e.preventDefault(); switchAppView('planetary'); });
        if (menuEvidence) menuEvidence.addEventListener('click', (e) => { e.preventDefault(); switchAppView('evidence-chain'); });
        if (menuFeed) menuFeed.addEventListener('click', (e) => { e.preventDefault(); switchAppView('feed'); });
        if (menuSector) menuSector.addEventListener('click', (e) => { e.preventDefault(); switchAppView('sector'); });
        if (menuAlerts) menuAlerts.addEventListener('click', (e) => { e.preventDefault(); switchAppView('alerts'); });
        if (menuReports) menuReports.addEventListener('click', (e) => { e.preventDefault(); switchAppView('reports'); });
        if (menuSettings) menuSettings.addEventListener('click', (e) => { e.preventDefault(); switchAppView('settings'); });

        // ── View All Buttons ──
        if (DOM.btnViewAllAlerts) {
            DOM.btnViewAllAlerts.addEventListener('click', () => switchAppView('alerts'));
        }
        if (DOM.btnViewAllIntel) {
            DOM.btnViewAllIntel.addEventListener('click', () => switchAppView('feed'));
        }
        if (DOM.btnExploreMore) {
            DOM.btnExploreMore.addEventListener('click', () => switchAppView('sector'));
        }

        // ── Search & Filter Inputs in Views ──
        const feedSearch = document.getElementById('feed-search-input');
        const feedFilter = document.getElementById('feed-severity-filter');
        if (feedSearch) {
            feedSearch.addEventListener('input', () => {
                renderFeedView(feedFilter ? feedFilter.value : 'all', feedSearch.value.trim());
            });
        }
        if (feedFilter) {
            feedFilter.addEventListener('change', () => {
                renderFeedView(feedFilter.value, feedSearch ? feedSearch.value.trim() : '');
            });
        }

        const alertsSearch = document.getElementById('alerts-search-input');
        const alertsFilter = document.getElementById('alerts-severity-filter');
        if (alertsSearch) {
            alertsSearch.addEventListener('input', () => {
                renderFullAlertsTable(alertsSearch.value.trim(), alertsFilter ? alertsFilter.value : 'all');
            });
        }
        if (alertsFilter) {
            alertsFilter.addEventListener('change', () => {
                renderFullAlertsTable(alertsSearch ? alertsSearch.value.trim() : '', alertsFilter.value);
            });
        }

        // ── Ping Sensors Button ──
        const btnPingSensors = document.getElementById('btn-ping-all-sensors');
        if (btnPingSensors) {
            btnPingSensors.addEventListener('click', () => {
                showToast("⚡ 28/28 Planetary Sensors Responding • 0 Buffer Drops • Mean Latency 0.8ms");
            });
        }

        // ── Supabase Cloud Integration Handlers ──
        initSupabaseUI();
        initAuthSystem();
    }

    // ═══════════════════════════════════════════════════════════
    // SUPABASE CLOUD DATABASE UI ENGINE
    // ═══════════════════════════════════════════════════════════

    function initSupabaseUI() {
        const inputUrl = document.getElementById('sb-input-url');
        const inputKey = document.getElementById('sb-input-key');
        const btnConnect = document.getElementById('btn-sb-connect');
        const btnPush = document.getElementById('btn-sb-sync-push');
        const btnPull = document.getElementById('btn-sb-sync-pull');
        const btnDisconnect = document.getElementById('btn-sb-disconnect');
        const badge = document.getElementById('sb-status-badge');
        const statusText = document.getElementById('sb-status-text');
        const feedback = document.getElementById('sb-feedback-box');

        if (!btnConnect || !window.ThreatStormSupabase) return;

        // Populate existing credentials if saved
        const existingConfig = window.ThreatStormSupabase.getConfig();
        if (existingConfig.url) inputUrl.value = existingConfig.url;
        if (existingConfig.key) inputKey.value = existingConfig.key;

        function updateBadge(state, text) {
            if (!badge || !statusText) return;
            badge.className = 'sb-status-badge';
            if (state === 'online') {
                badge.classList.add('sb-badge--online');
                statusText.textContent = text || 'CONNECTED (SUPABASE CLOUD)';
            } else if (state === 'warning') {
                badge.classList.add('sb-badge--warning');
                statusText.textContent = text || 'CONNECTED (SCHEMA NEEDED)';
            } else {
                badge.classList.add('sb-badge--offline');
                statusText.textContent = text || 'LOCAL IN-MEMORY MODE';
            }
        }

        function showFeedback(msg, type) {
            if (!feedback) return;
            feedback.style.display = 'block';
            feedback.style.background = type === 'error' ? 'rgba(239, 68, 68, 0.12)' : (type === 'warn' ? 'rgba(212, 175, 55, 0.12)' : 'rgba(62, 207, 142, 0.12)');
            feedback.style.border = `1px solid ${type === 'error' ? '#ef4444' : (type === 'warn' ? '#d4af37' : '#3ECF8E')}`;
            feedback.style.color = type === 'error' ? '#fca5a5' : (type === 'warn' ? '#fde047' : '#86efac');
            feedback.innerHTML = msg;
        }

        // Check initial state
        if (window.ThreatStormSupabase.isConnected()) {
            updateBadge('online', 'CONNECTED (SUPABASE CLOUD)');
        }

        // Connect button
        btnConnect.addEventListener('click', async () => {
            const url = inputUrl.value.trim();
            const key = inputKey.value.trim();

            if (!url || !key) {
                showFeedback('⚠️ Please enter both your Supabase Project URL and Anon Public Key.', 'warn');
                return;
            }

            btnConnect.disabled = true;
            btnConnect.innerHTML = '<span>⏳ Verifying...</span>';
            showFeedback('Verifying handshake with Supabase PostgreSQL cluster...', 'warn');

            const result = await window.ThreatStormSupabase.testConnection(url, key);
            btnConnect.disabled = false;
            btnConnect.innerHTML = '<span>⚡ Connect &amp; Verify</span>';

            if (result.success) {
                if (result.warning) {
                    updateBadge('warning', 'CONNECTED (SCHEMA NEEDED)');
                    showFeedback(`✓ ${result.warning}`, 'warn');
                    showToast('⚠️ Connected! Note: Execute supabase_schema.sql in Supabase SQL Editor.');
                } else {
                    updateBadge('online', `LIVE CLOUD (${result.latency}ms)`);
                    showFeedback(`✓ Handshake verified with Supabase! Round-trip latency: ${result.latency}ms`, 'success');
                    showToast(`⚡ Supabase Live Connected (${result.latency}ms)`);
                }
            } else {
                updateBadge('offline', 'CONNECTION FAILED');
                showFeedback(`✕ Error connecting to Supabase: ${result.message}`, 'error');
                showToast(`✕ Supabase connection failed: ${result.message}`);
            }
        });

        // Push Local Threats to Supabase
        if (btnPush) {
            btnPush.addEventListener('click', async () => {
                btnPush.disabled = true;
                btnPush.innerHTML = '<span>⏳ Uploading...</span>';
                const res = await window.ThreatStormSupabase.syncLocalThreatsToCloud(alerts);
                btnPush.disabled = false;
                btnPush.innerHTML = '<span>☁ Push 28 Local Threats to Cloud</span>';

                if (res.success) {
                    showFeedback(`✓ ${res.message}`, 'success');
                    showToast(`☁ Synced ${res.count} Threats to Supabase Cloud!`);
                } else {
                    showFeedback(`✕ Upload failed: ${res.message}`, 'error');
                    showToast(`✕ Sync failed: ${res.message}`);
                }
            });
        }

        // Pull Live Threats from Supabase
        if (btnPull) {
            btnPull.addEventListener('click', async () => {
                btnPull.disabled = true;
                btnPull.innerHTML = '<span>⏳ Fetching...</span>';
                const cloudThreats = await window.ThreatStormSupabase.fetchThreatsFromCloud();
                btnPull.disabled = false;
                btnPull.innerHTML = '<span>📥 Pull Cloud Incidents</span>';

                if (cloudThreats && cloudThreats.length) {
                    // Update in-memory alerts
                    alerts = cloudThreats.map(ct => ({
                        id: ct.id,
                        title: ct.title,
                        severity: ct.severity,
                        category: ct.category,
                        region: ct.region,
                        lat: ct.lat,
                        lng: ct.lng,
                        details: ct.details,
                        threatActor: ct.actor || 'APT_CLUSTER',
                        aiConfidence: ct.confidence ? `${Math.round(ct.confidence * 100)}%` : '96%',
                        status: 'active'
                    }));

                    // Re-render views
                    renderThreatsTable();
                    renderFullAlertsTable();
                    renderFeedView();
                    renderSectorView();

                    showFeedback(`✓ Pulled ${cloudThreats.length} live threats from Supabase PostgreSQL database.`, 'success');
                    showToast(`📥 Pulled ${cloudThreats.length} live threats from Supabase!`);
                } else {
                    showFeedback('No cloud threats found or Supabase is not connected. Push threats first or verify table.', 'warn');
                    showToast('⚠️ No records returned from Supabase.');
                }
            });
        }

        // Disconnect / Reset
        if (btnDisconnect) {
            btnDisconnect.addEventListener('click', () => {
                window.ThreatStormSupabase.disconnect();
                inputUrl.value = '';
                inputKey.value = '';
                updateBadge('offline', 'LOCAL IN-MEMORY MODE');
                if (feedback) feedback.style.display = 'none';
                showToast('✓ Disconnected. Running in Local In-Memory Mode.');
            });
        }
    }

    // ═══════════════════════════════════════════════════════════
    // CYBER SOC AUTHENTICATION & SESSION ENGINE
    // ═══════════════════════════════════════════════════════════

    function initAuthSystem() {
        const btnOpenAuth = document.getElementById('btn-open-auth');
        const authModal = document.getElementById('auth-modal');
        const btnCloseAuth = document.getElementById('auth-modal-close');
        const tabSignIn = document.getElementById('tab-auth-signin');
        const tabSignUp = document.getElementById('tab-auth-signup');
        const groupCallsign = document.getElementById('group-auth-callsign');
        const inputCallsign = document.getElementById('auth-input-callsign');
        const inputEmail = document.getElementById('auth-input-email');
        const inputPassword = document.getElementById('auth-input-password');
        const btnTogglePass = document.getElementById('btn-toggle-password');
        const btnSubmit = document.getElementById('btn-auth-submit');
        const submitLabel = document.getElementById('auth-submit-label');
        const btnDemo = document.getElementById('btn-auth-demo');
        const feedback = document.getElementById('auth-feedback-box');

        const profileBadge = document.getElementById('user-profile-badge');
        const navAvatar = document.getElementById('nav-user-avatar');
        const navInitials = document.getElementById('nav-user-initials');
        const navCallsign = document.getElementById('nav-user-callsign');
        const navClearance = document.getElementById('nav-user-clearance');
        const dropdown = document.getElementById('user-menu-dropdown');
        const dropdownEmail = document.getElementById('dropdown-user-email');
        const dropdownRole = document.getElementById('dropdown-user-role');
        const btnMenuSettings = document.getElementById('btn-menu-settings');
        const btnSignOut = document.getElementById('btn-auth-signout');

        let authMode = 'signin'; // 'signin' or 'signup'

        function showAuthFeedback(msg, type) {
            if (!feedback) return;
            feedback.style.display = 'block';
            feedback.style.background = type === 'error' ? 'rgba(239, 68, 68, 0.12)' : (type === 'warn' ? 'rgba(212, 175, 55, 0.12)' : 'rgba(62, 207, 142, 0.12)');
            feedback.style.border = `1px solid ${type === 'error' ? '#ef4444' : (type === 'warn' ? '#d4af37' : '#3ECF8E')}`;
            feedback.style.color = type === 'error' ? '#fca5a5' : (type === 'warn' ? '#fde047' : '#86efac');
            feedback.innerHTML = msg;
        }

        function updateAuthUI() {
            if (!window.ThreatStormSupabase) return;
            const currentUser = window.ThreatStormSupabase.getCurrentUser();

            if (currentUser) {
                if (btnOpenAuth) btnOpenAuth.style.display = 'none';
                if (profileBadge) profileBadge.style.display = 'inline-flex';

                const name = currentUser.callsign || currentUser.email || 'Analyst';
                const initials = name.split(' ').map(n => n[0]).slice(0, 2).join('').toUpperCase() || 'AN';

                if (navInitials) navInitials.textContent = initials;
                if (navCallsign) navCallsign.textContent = name;
                if (navClearance) navClearance.textContent = currentUser.clearance || 'SECRET // LEVEL 3';
                if (dropdownEmail) dropdownEmail.textContent = currentUser.email || 'analyst@threatstorm.defense';
                if (dropdownRole) dropdownRole.textContent = currentUser.role || 'SOC Cyber Analyst';
            } else {
                if (btnOpenAuth) btnOpenAuth.style.display = 'inline-flex';
                if (profileBadge) profileBadge.style.display = 'none';
                if (dropdown) dropdown.classList.remove('is-open');
                if (profileBadge) profileBadge.classList.remove('menu-open');
            }
        }

        // Open Dedicated Full-Page Cyber SOC Portal
        if (btnOpenAuth) {
            btnOpenAuth.addEventListener('click', () => {
                switchAppView('auth');
            });
        }

        // Close Modal fallback
        function closeAuthModal() {
            if (authModal) authModal.style.display = 'none';
        }

        if (btnCloseAuth) btnCloseAuth.addEventListener('click', closeAuthModal);
        if (authModal) {
            authModal.addEventListener('click', (e) => {
                if (e.target === authModal) closeAuthModal();
            });
        }

        // Modal Tabs
        if (tabSignIn && tabSignUp) {
            tabSignIn.addEventListener('click', () => {
                authMode = 'signin';
                tabSignIn.classList.add('auth-tab--active');
                tabSignUp.classList.remove('auth-tab--active');
                if (groupCallsign) groupCallsign.style.display = 'none';
                if (submitLabel) submitLabel.textContent = '⚡ Sign In to SOC Portal';
                if (feedback) feedback.style.display = 'none';
            });

            tabSignUp.addEventListener('click', () => {
                authMode = 'signup';
                tabSignUp.classList.add('auth-tab--active');
                tabSignIn.classList.remove('auth-tab--active');
                if (groupCallsign) groupCallsign.style.display = 'block';
                if (submitLabel) submitLabel.textContent = '🛡️ Create SOC Account';
                if (feedback) feedback.style.display = 'none';
            });
        }

        // Modal Password Show/Hide
        if (btnTogglePass && inputPassword) {
            btnTogglePass.addEventListener('click', () => {
                const isPass = inputPassword.type === 'password';
                inputPassword.type = isPass ? 'text' : 'password';
                btnTogglePass.textContent = isPass ? 'Hide' : 'Show';
            });
        }

        // Modal Form Submit
        if (btnSubmit) {
            btnSubmit.addEventListener('click', async () => {
                const email = inputEmail.value.trim();
                const password = inputPassword.value;
                const callsign = inputCallsign ? inputCallsign.value.trim() : '';

                if (!email || !password) {
                    showAuthFeedback('⚠️ Please enter both work email and password.', 'warn');
                    return;
                }

                btnSubmit.disabled = true;
                btnSubmit.innerHTML = '<span>⏳ Authenticating...</span>';

                let result;
                if (authMode === 'signup') {
                    result = await window.ThreatStormSupabase.signUp(email, password, callsign);
                } else {
                    result = await window.ThreatStormSupabase.signIn(email, password);
                }

                btnSubmit.disabled = false;
                btnSubmit.innerHTML = `<span>${authMode === 'signup' ? '🛡️ Create SOC Account' : '⚡ Sign In to SOC Portal'}</span>`;

                if (result.success) {
                    if (result.confirmationRequired) {
                        showAuthFeedback(`✓ ${result.message}`, 'warn');
                        showToast('✉ Verification link sent to your email.');
                    } else {
                        updateAuthUI();
                        closeAuthModal();
                        switchAppView('planetary');
                        showToast(`✓ Welcome, ${result.user.callsign}! Access Clearance Verified.`);
                    }
                } else {
                    showAuthFeedback(`✕ Authentication failed: ${result.message}`, 'error');
                }
            });
        }

        // Modal Instant Demo Login
        if (btnDemo) {
            btnDemo.addEventListener('click', () => {
                const demoUser = window.ThreatStormSupabase.loginDemoAnalyst();
                updateAuthUI();
                closeAuthModal();
                switchAppView('planetary');
                showToast(`✓ Access Granted: ${demoUser.callsign} (${demoUser.clearance})`);
            });
        }

        // ═══════════════════════════════════════════════════════════
        // DEDICATED FULL-PAGE AUTHENTICATION PORTAL ENGINE (#view-auth)
        // ═══════════════════════════════════════════════════════════

        const portalTabSignIn = document.getElementById('portal-tab-signin');
        const portalTabSignUp = document.getElementById('portal-tab-signup');
        const portalGroupCallsign = document.getElementById('portal-group-callsign');
        const portalInputCallsign = document.getElementById('portal-input-callsign');
        const portalInputEmail = document.getElementById('portal-input-email');
        const portalInputPass = document.getElementById('portal-input-password');
        const portalBtnTogglePass = document.getElementById('portal-btn-toggle-pass');
        const portalBtnSubmit = document.getElementById('portal-btn-submit');
        const portalSubmitLabel = document.getElementById('portal-submit-label');
        const portalBtnDemo = document.getElementById('portal-btn-demo');
        const portalBtnBack = document.getElementById('portal-btn-back');
        const portalFeedback = document.getElementById('portal-feedback-box');

        let portalMode = 'signin';

        function showPortalFeedback(msg, type) {
            if (!portalFeedback) return;
            portalFeedback.style.display = 'block';
            portalFeedback.style.background = type === 'error' ? 'rgba(239, 68, 68, 0.14)' : (type === 'warn' ? 'rgba(212, 175, 55, 0.14)' : 'rgba(62, 207, 142, 0.14)');
            portalFeedback.style.border = `1px solid ${type === 'error' ? '#ef4444' : (type === 'warn' ? '#d4af37' : '#3ECF8E')}`;
            portalFeedback.style.color = type === 'error' ? '#fca5a5' : (type === 'warn' ? '#fde047' : '#86efac');
            portalFeedback.innerHTML = msg;
        }

        if (portalTabSignIn && portalTabSignUp) {
            portalTabSignIn.addEventListener('click', () => {
                portalMode = 'signin';
                portalTabSignIn.classList.add('portal-tab--active');
                portalTabSignUp.classList.remove('portal-tab--active');
                if (portalGroupCallsign) portalGroupCallsign.style.display = 'none';
                if (portalSubmitLabel) portalSubmitLabel.textContent = '⚡ Authenticate & Access Command Grid';
                if (portalFeedback) portalFeedback.style.display = 'none';
            });

            portalTabSignUp.addEventListener('click', () => {
                portalMode = 'signup';
                portalTabSignUp.classList.add('portal-tab--active');
                portalTabSignIn.classList.remove('portal-tab--active');
                if (portalGroupCallsign) portalGroupCallsign.style.display = 'flex';
                if (portalSubmitLabel) portalSubmitLabel.textContent = '🛡️ Register Callsign & Access Grid';
                if (portalFeedback) portalFeedback.style.display = 'none';
            });
        }

        if (portalBtnTogglePass && portalInputPass) {
            portalBtnTogglePass.addEventListener('click', () => {
                const isPass = portalInputPass.type === 'password';
                portalInputPass.type = isPass ? 'text' : 'password';
                portalBtnTogglePass.textContent = isPass ? 'Hide' : 'Show';
            });
        }

        if (portalBtnSubmit) {
            portalBtnSubmit.addEventListener('click', async () => {
                const email = portalInputEmail.value.trim();
                const password = portalInputPass.value;
                const callsign = portalInputCallsign ? portalInputCallsign.value.trim() : '';

                if (!email || !password) {
                    showPortalFeedback('⚠️ Please provide your SOC email and security key.', 'warn');
                    return;
                }

                portalBtnSubmit.disabled = true;
                portalBtnSubmit.innerHTML = '<span>⏳ Verifying Cryptographic Clearance...</span>';

                let result;
                if (portalMode === 'signup') {
                    result = await window.ThreatStormSupabase.signUp(email, password, callsign);
                } else {
                    result = await window.ThreatStormSupabase.signIn(email, password);
                }

                portalBtnSubmit.disabled = false;
                portalBtnSubmit.innerHTML = `<span>${portalMode === 'signup' ? '🛡️ Register Callsign & Access Grid' : '⚡ Authenticate & Access Command Grid'}</span>`;

                if (result.success) {
                    if (result.confirmationRequired) {
                        showPortalFeedback(`✓ ${result.message}`, 'warn');
                        showToast('✉ Check email for verification link.');
                    } else {
                        updateAuthUI();
                        showToast(`✓ Clearance Verified: Welcome, ${result.user.callsign}!`);
                        setTimeout(() => {
                            switchAppView('planetary');
                        }, 400);
                    }
                } else {
                    showPortalFeedback(`✕ Authentication failed: ${result.message}`, 'error');
                }
            });
        }

        if (portalBtnDemo) {
            portalBtnDemo.addEventListener('click', () => {
                const demoUser = window.ThreatStormSupabase.loginDemoAnalyst();
                updateAuthUI();
                showToast(`✓ Level 5 SOC Clearance Granted: ${demoUser.callsign}`);
                setTimeout(() => {
                    switchAppView('planetary');
                }, 300);
            });
        }

        if (portalBtnBack) {
            portalBtnBack.addEventListener('click', () => {
                switchAppView('planetary');
            });
        }

        const portalBtnGoogle = document.getElementById('portal-btn-google');
        const btnModalGoogle = document.getElementById('btn-auth-google');

        async function handleGoogleLogin() {
            showToast('⚡ Redirecting to Google Authentication...');
            const res = await window.ThreatStormSupabase.signInWithOAuth('google');
            if (!res.success) {
                showPortalFeedback(`✕ Google OAuth error: ${res.message}`, 'error');
                showToast(`✕ Google login error: ${res.message}`);
            }
        }

        if (portalBtnGoogle) portalBtnGoogle.addEventListener('click', handleGoogleLogin);
        if (btnModalGoogle) btnModalGoogle.addEventListener('click', handleGoogleLogin);

        // Profile Badge & Dropdown
        if (profileBadge && dropdown) {
            profileBadge.addEventListener('click', (e) => {
                e.stopPropagation();
                const isOpen = dropdown.classList.toggle('is-open');
                profileBadge.classList.toggle('menu-open', isOpen);
            });

            document.addEventListener('click', (e) => {
                if (!profileBadge.contains(e.target)) {
                    dropdown.classList.remove('is-open');
                    profileBadge.classList.remove('menu-open');
                }
            });
        }

        // Dropdown Menu: Settings
        if (btnMenuSettings) {
            btnMenuSettings.addEventListener('click', () => {
                if (dropdown) dropdown.classList.remove('is-open');
                if (profileBadge) profileBadge.classList.remove('menu-open');
                switchAppView('settings');
            });
        }

        // Dropdown Menu: Sign Out
        if (btnSignOut) {
            btnSignOut.addEventListener('click', async () => {
                await window.ThreatStormSupabase.signOut();
                updateAuthUI();
                showToast('✓ Signed out of SOC Terminal. Session terminated.');
            });
        }

        // Initialize state on load & sync Supabase Auth (e.g. after Google redirect)
        updateAuthUI();
        if (window.ThreatStormSupabase && window.ThreatStormSupabase.syncAuthSession) {
            window.ThreatStormSupabase.syncAuthSession().then(user => {
                if (user) updateAuthUI();
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
