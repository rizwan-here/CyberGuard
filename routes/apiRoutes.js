// routes/apiRoutes.js
const express = require('express');
const router = express.Router();
const Ioc = require('../models/Ioc');
const { detectIocType, normalizeIocValue } = require("../utils/detectIocType");

// Middleware to verify API key
const apiAuth = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    const expectedKey = process.env.CYBERGUARD_API_KEY;
    
    if (!expectedKey) {
        return res.status(500).json({ error: "Server API Key not configured." });
    }

    if (apiKey && apiKey === expectedKey) {
        return next();
    }
    return res.status(401).json({ error: "Unauthorized. Invalid API Key." });
};

// POST /api/ingest - Endpoint for automated TIP feeds
router.post('/ingest', apiAuth, async (req, res) => {
    const { indicators, source } = req.body; 
    
    if (!indicators || !Array.isArray(indicators)) {
        return res.status(400).json({ error: "Invalid payload format. Expected an array of 'indicators'." });
    }

    let added = 0;
    let duplicates = 0;

    for (let ind of indicators) {
        try {
            const value = normalizeIocValue(ind.value);
            if (!value) continue;

            const exists = await Ioc.findOne({ value });
            if (!exists) {
                await Ioc.create({
                    value: value,
                    iocType: ind.type || detectIocType(value),
                    threatType: ind.threatType || 'malware',
                    severity: ind.severity || 'Medium',
                    source: source || 'API_Ingest',
                    tags: ind.tags || ['automated-ingest']
                });
                added++;
            } else {
                duplicates++;
            }
        } catch (error) {
            console.error("API Ingest Error on item:", ind.value, error.message);
        }
    }

    res.status(200).json({ 
        message: "Ingestion complete", 
        stats: { added, duplicates } 
    });
});

module.exports = router;