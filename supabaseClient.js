/**
 * Threat Storm Cyber Defense Platform
 * Supabase Client Integration & Realtime Sync Engine
 */

(function () {
    const STORAGE_KEY_URL = 'threatstorm_sb_url';
    const STORAGE_KEY_KEY = 'threatstorm_sb_key';
    const DEFAULT_URL = 'https://vlwdxlwmljigbxncxqdm.supabase.co';

    let supabaseInstance = null;
    let isConnected = false;

    function normalizeUrl(rawUrl) {
        if (!rawUrl) return '';
        return rawUrl.trim().replace(/\/rest\/v1\/?$/i, '').replace(/\/$/, '');
    }

    // Retrieve stored credentials or pre-configured environment
    function getConfig() {
        const rawUrl = localStorage.getItem(STORAGE_KEY_URL) || (window.SUPABASE_CONFIG && window.SUPABASE_CONFIG.url) || DEFAULT_URL;
        const key = localStorage.getItem(STORAGE_KEY_KEY) || (window.SUPABASE_CONFIG && window.SUPABASE_CONFIG.key) || '';
        return { url: normalizeUrl(rawUrl), key: key.trim() };
    }

    // Initialize Supabase instance safely
    function getClient() {
        if (supabaseInstance) return supabaseInstance;

        const { url, key } = getConfig();
        if (!url || !key) return null;

        if (typeof window.supabase !== 'undefined' && typeof window.supabase.createClient === 'function') {
            try {
                supabaseInstance = window.supabase.createClient(url, key);
                return supabaseInstance;
            } catch (err) {
                console.warn('[Supabase] Initialization error:', err);
                return null;
            }
        }
        return null;
    }

    // Test connection with Supabase
    async function testConnection(customUrl, customKey) {
        const url = normalizeUrl(customUrl || getConfig().url || '');
        const key = (customKey || getConfig().key || '').trim();

        if (!url || !key) {
            return {
                success: false,
                message: 'Supabase URL and Anon Key are required.'
            };
        }

        if (typeof window.supabase === 'undefined' || typeof window.supabase.createClient !== 'function') {
            return {
                success: false,
                message: 'Supabase library not loaded. Check internet connection.'
            };
        }

        try {
            const tempClient = window.supabase.createClient(url, key);
            const startTime = performance.now();
            const { data, error } = await tempClient.from('threats').select('id').limit(1);
            const latency = Math.round(performance.now() - startTime);

            if (error) {
                // If table doesn't exist yet, it's still a valid connection to project
                if (error.code === '42P01') {
                    return {
                        success: true,
                        latency,
                        warning: 'Connected to Supabase, but "threats" table not found. Please run supabase_schema.sql in SQL Editor.'
                    };
                }
                return {
                    success: false,
                    message: error.message || 'Failed to authenticate with Supabase.'
                };
            }

            // Successfully connected
            localStorage.setItem(STORAGE_KEY_URL, url);
            localStorage.setItem(STORAGE_KEY_KEY, key);
            supabaseInstance = tempClient;
            isConnected = true;

            return {
                success: true,
                latency,
                message: `Connected successfully! Latency: ${latency}ms`
            };
        } catch (err) {
            return {
                success: false,
                message: err.message || 'Network error connecting to Supabase.'
            };
        }
    }

    // Disconnect & Reset to Local In-Memory Mode
    function disconnect() {
        localStorage.removeItem(STORAGE_KEY_URL);
        localStorage.removeItem(STORAGE_KEY_KEY);
        supabaseInstance = null;
        isConnected = false;
    }

    // Sync Local Threats to Supabase Database
    async function syncLocalThreatsToCloud(threatsList) {
        const client = getClient();
        if (!client) {
            return { success: false, message: 'Please connect Supabase first in Settings.' };
        }

        const sourceList = threatsList || (typeof DEMO_THREATS !== 'undefined' ? DEMO_THREATS : []);
        if (!sourceList || !sourceList.length) {
            return { success: false, message: 'No local threats to sync.' };
        }

        try {
            const rows = sourceList.map(t => {
                const rawAi = (typeof window.generateRawAiTelemetry === 'function') 
                    ? window.generateRawAiTelemetry(t) 
                    : { threat_id: t.id, title: t.title, severity: t.severity };

                return {
                    id: t.id,
                    title: t.title,
                    severity: t.severity,
                    category: t.category,
                    region: t.region,
                    lat: t.lat,
                    lng: t.lng,
                    details: t.details,
                    actor: t.threatActor || 'APT_CLUSTER',
                    confidence: t.aiConfidence ? parseFloat(t.aiConfidence) : 0.95,
                    raw_telemetry: rawAi
                };
            });

            const { data, error } = await client.from('threats').upsert(rows, { onConflict: 'id' });

            if (error) {
                return { success: false, message: error.message };
            }

            return {
                success: true,
                count: rows.length,
                message: `Successfully synced ${rows.length} threats with raw AI telemetry to Supabase!`
            };
        } catch (err) {
            return { success: false, message: err.message };
        }
    }

    // Fetch Live Threats from Supabase Database
    async function fetchThreatsFromCloud() {
        const client = getClient();
        if (!client) return null;

        try {
            const { data, error } = await client.from('threats').select('*').order('created_at', { ascending: false });
            if (error || !data) {
                console.warn('[Supabase] Failed to fetch threats:', error);
                return null;
            }
            return data;
        } catch (err) {
            console.warn('[Supabase] Fetch exception:', err);
            return null;
        }
    }

    // Save EvidenceChain Investigation
    async function saveEvidenceChain(investigationData, nodes) {
        const client = getClient();
        if (!client) return { success: false, message: 'Supabase offline; changes saved to local memory.' };

        try {
            // Save main investigation row
            const { error: invErr } = await client.from('evidence_chains').upsert({
                investigation_id: investigationData.investigationId,
                title: investigationData.title,
                classification: investigationData.classification,
                lead_analyst: investigationData.leadAnalyst,
                source: investigationData.source,
                verified: investigationData.verified
            }, { onConflict: 'investigation_id' });

            if (invErr) throw invErr;

            // Save nodes if provided
            if (nodes && nodes.length) {
                const nodeRows = nodes.map((n, i) => ({
                    id: n.id,
                    investigation_id: investigationData.investigationId,
                    phase: n.phase,
                    title: n.title,
                    timestamp: n.timestamp,
                    entity: n.entity,
                    status: n.status,
                    description: n.description,
                    ioc_signature: n.ioc_signature || n.iocSignature || '',
                    order_index: i
                }));
                const { error: nodeErr } = await client.from('evidence_nodes').upsert(nodeRows, { onConflict: 'id' });
                if (nodeErr) throw nodeErr;
            }

            return { success: true, message: 'Investigation synced with Supabase Cloud.' };
        } catch (err) {
            return { success: false, message: err.message };
        }
    }

    // Expose API globally
    window.ThreatStormSupabase = {
        getConfig,
        getClient,
        testConnection,
        disconnect,
        syncLocalThreatsToCloud,
        fetchThreatsFromCloud,
        saveEvidenceChain,
        isConnected: () => !!getClient()
    };
})();
