module.exports = (req, res) => {
    res.setHeader('Content-Type', 'application/json; charset=UTF-8');
    
    const evidenceData = {
        status: "success",
        investigationId: "INC-2026-8841",
        title: "SolarStorm APT: Multi-Stage Domain Controller Compromise & Egress",
        classification: "Synthetic Deterministic Sample Investigation (SOC Verification)",
        leadAnalyst: "Commander Yash K. (Haute Intelligence Bureau)",
        source: "Threat Storm Telemetry Correlation Gateway v2.5.0",
        verified: true
    };

    if (typeof res.status === 'function') {
        res.status(200).json(evidenceData);
    } else {
        res.writeHead(200);
        res.end(JSON.stringify(evidenceData));
    }
};
