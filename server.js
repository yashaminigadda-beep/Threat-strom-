const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 3000;
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
    // ── Safe API Router for EvidenceChain ──
    const urlPath = req.url.split('?')[0];
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
