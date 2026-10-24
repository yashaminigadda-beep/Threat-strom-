-- =====================================================================
-- THREAT STORM CYBER DEFENSE PLATFORM - SUPABASE POSTGRESQL SCHEMA
-- =====================================================================
-- Run this script in your Supabase Dashboard: SQL Editor -> New Query -> Run
-- =====================================================================

-- 1. Enable UUID Extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 2. Create Threats Table
CREATE TABLE IF NOT EXISTS public.threats (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category TEXT NOT NULL,
    region TEXT NOT NULL,
    lat DOUBLE PRECISION NOT NULL,
    lng DOUBLE PRECISION NOT NULL,
    details TEXT,
    actor TEXT DEFAULT 'UNKNOWN_APT',
    confidence DOUBLE PRECISION DEFAULT 0.95,
    raw_telemetry JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 3. Create Evidence Chains Table (Investigations)
CREATE TABLE IF NOT EXISTS public.evidence_chains (
    investigation_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    classification TEXT NOT NULL,
    lead_analyst TEXT NOT NULL,
    source TEXT NOT NULL,
    verified BOOLEAN DEFAULT true,
    metadata JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 4. Create Evidence Nodes Table (Correlated Forensic Steps)
CREATE TABLE IF NOT EXISTS public.evidence_nodes (
    id TEXT PRIMARY KEY,
    investigation_id TEXT REFERENCES public.evidence_chains(investigation_id) ON DELETE CASCADE,
    phase TEXT NOT NULL,
    title TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    entity TEXT NOT NULL,
    status TEXT NOT NULL,
    description TEXT,
    ioc_signature TEXT,
    metadata JSONB,
    order_index INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- 5. Create Sensor Telemetry Table
CREATE TABLE IF NOT EXISTS public.sensor_telemetry (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    node_name TEXT NOT NULL,
    region TEXT NOT NULL,
    status TEXT NOT NULL,
    latency_ms DOUBLE PRECISION DEFAULT 12.4,
    throughput TEXT DEFAULT '14.2 Gbps',
    recorded_at TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc'::text, now()) NOT NULL
);

-- =====================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- =====================================================================
-- Enable RLS on all tables
ALTER TABLE public.threats ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence_chains ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.evidence_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.sensor_telemetry ENABLE ROW LEVEL SECURITY;

-- Anonymous public read & write policies for demonstration
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Allow public read on threats') THEN
        CREATE POLICY "Allow public read on threats" ON public.threats FOR SELECT TO anon, authenticated USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Allow public insert/update on threats') THEN
        CREATE POLICY "Allow public insert/update on threats" ON public.threats FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
    END IF;
    
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Allow public read on evidence_chains') THEN
        CREATE POLICY "Allow public read on evidence_chains" ON public.evidence_chains FOR SELECT TO anon, authenticated USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Allow public insert/update on evidence_chains') THEN
        CREATE POLICY "Allow public insert/update on evidence_chains" ON public.evidence_chains FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Allow public read on evidence_nodes') THEN
        CREATE POLICY "Allow public read on evidence_nodes" ON public.evidence_nodes FOR SELECT TO anon, authenticated USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Allow public insert/update on evidence_nodes') THEN
        CREATE POLICY "Allow public insert/update on evidence_nodes" ON public.evidence_nodes FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Allow public read on sensor_telemetry') THEN
        CREATE POLICY "Allow public read on sensor_telemetry" ON public.sensor_telemetry FOR SELECT TO anon, authenticated USING (true);
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Allow public insert/update on sensor_telemetry') THEN
        CREATE POLICY "Allow public insert/update on sensor_telemetry" ON public.sensor_telemetry FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
    END IF;
END
$$;

-- Indexes for fast querying
CREATE INDEX IF NOT EXISTS idx_threats_severity ON public.threats(severity);
CREATE INDEX IF NOT EXISTS idx_threats_category ON public.threats(category);
CREATE INDEX IF NOT EXISTS idx_threats_created_at ON public.threats(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_evidence_nodes_inv ON public.evidence_nodes(investigation_id);

-- =====================================================================
-- INITIAL SEED DATA (Verification Sample)
-- =====================================================================
INSERT INTO public.evidence_chains (investigation_id, title, classification, lead_analyst, source, verified)
VALUES (
    'INC-2026-8841',
    'SolarStorm APT: Multi-Stage Domain Controller Compromise & Egress',
    'Classified Top Secret // SIEM Forensic Audit',
    'Commander Yash K. (Haute Intelligence Bureau)',
    'Threat Storm Telemetry Correlation Gateway v2.5.0',
    true
) ON CONFLICT (investigation_id) DO NOTHING;
