-- =====================================================================
-- THREAT STORM CYBER DEFENSE PLATFORM
-- SUPABASE AUTHENTICATION SETUP SQL
-- =====================================================================
-- HOW TO RUN:
--   1. Go to https://supabase.com/dashboard
--   2. Open your Supabase project
--   3. Click: SQL Editor → New Query
--   4. Paste this ENTIRE script and click RUN
-- =====================================================================

-- ─────────────────────────────────────────────────────────────────────
-- STEP 1: Enable Extensions
-- ─────────────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─────────────────────────────────────────────────────────────────────
-- STEP 2: Create User Profiles Table
--   Links to Supabase Auth's built-in auth.users table
--   Stores analyst metadata (callsign, clearance, role, avatar)
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.profiles (
    id              UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    callsign        TEXT NOT NULL DEFAULT 'Analyst',
    email           TEXT,
    role            TEXT NOT NULL DEFAULT 'SOC Junior Analyst',
    clearance       TEXT NOT NULL DEFAULT 'SECRET // LEVEL 2',
    avatar_url      TEXT,
    is_demo         BOOLEAN DEFAULT false,
    provider        TEXT DEFAULT 'email',             -- 'email' | 'google'
    last_sign_in_at TIMESTAMP WITH TIME ZONE,
    created_at      TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc', now()) NOT NULL,
    updated_at      TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc', now()) NOT NULL
);

-- ─────────────────────────────────────────────────────────────────────
-- STEP 3: Analyst Activity / Audit Log Table
--   Records sign-in events, changes, and SOC actions
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.analyst_activity (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID REFERENCES auth.users(id) ON DELETE SET NULL,
    action      TEXT NOT NULL,       -- 'sign_in', 'sign_out', 'register', 'google_oauth', 'demo_access'
    details     JSONB DEFAULT '{}',
    ip_hint     TEXT,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc', now()) NOT NULL
);

-- ─────────────────────────────────────────────────────────────────────
-- STEP 4: SOC Sessions Table (optional, tracks active analyst sessions)
-- ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.soc_sessions (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID REFERENCES auth.users(id) ON DELETE CASCADE,
    session_tag TEXT DEFAULT 'STORM-SEC-GATEWAY-v2.5',
    clearance   TEXT DEFAULT 'SECRET // LEVEL 2',
    started_at  TIMESTAMP WITH TIME ZONE DEFAULT timezone('utc', now()) NOT NULL,
    ended_at    TIMESTAMP WITH TIME ZONE,
    is_active   BOOLEAN DEFAULT true
);

-- ─────────────────────────────────────────────────────────────────────
-- STEP 5: Enable Row Level Security (RLS) on all auth-related tables
-- ─────────────────────────────────────────────────────────────────────
ALTER TABLE public.profiles          ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.analyst_activity  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.soc_sessions      ENABLE ROW LEVEL SECURITY;

-- ─────────────────────────────────────────────────────────────────────
-- STEP 6: RLS Policies — Profiles Table
-- ─────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    -- Users can read their own profile
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Users can view own profile') THEN
        CREATE POLICY "Users can view own profile"
            ON public.profiles FOR SELECT
            TO authenticated
            USING (auth.uid() = id);
    END IF;

    -- Users can insert their own profile (on first sign up)
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Users can insert own profile') THEN
        CREATE POLICY "Users can insert own profile"
            ON public.profiles FOR INSERT
            TO authenticated
            WITH CHECK (auth.uid() = id);
    END IF;

    -- Users can update their own profile
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Users can update own profile') THEN
        CREATE POLICY "Users can update own profile"
            ON public.profiles FOR UPDATE
            TO authenticated
            USING (auth.uid() = id)
            WITH CHECK (auth.uid() = id);
    END IF;

    -- Authenticated analysts can read any profile (SOC command visibility)
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Authenticated can read all profiles') THEN
        CREATE POLICY "Authenticated can read all profiles"
            ON public.profiles FOR SELECT
            TO authenticated
            USING (true);
    END IF;

END $$;

-- ─────────────────────────────────────────────────────────────────────
-- STEP 7: RLS Policies — Analyst Activity Table
-- ─────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Users can read own activity') THEN
        CREATE POLICY "Users can read own activity"
            ON public.analyst_activity FOR SELECT
            TO authenticated
            USING (auth.uid() = user_id);
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Users can log own activity') THEN
        CREATE POLICY "Users can log own activity"
            ON public.analyst_activity FOR INSERT
            TO authenticated
            WITH CHECK (auth.uid() = user_id);
    END IF;

    -- Allow anon to insert demo/guest activity
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Anon can log activity') THEN
        CREATE POLICY "Anon can log activity"
            ON public.analyst_activity FOR INSERT
            TO anon
            WITH CHECK (true);
    END IF;
END $$;

-- ─────────────────────────────────────────────────────────────────────
-- STEP 8: RLS Policies — SOC Sessions
-- ─────────────────────────────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE policyname = 'Users can manage own sessions') THEN
        CREATE POLICY "Users can manage own sessions"
            ON public.soc_sessions FOR ALL
            TO authenticated
            USING (auth.uid() = user_id)
            WITH CHECK (auth.uid() = user_id);
    END IF;
END $$;

-- ─────────────────────────────────────────────────────────────────────
-- STEP 9: Trigger Function — Auto-create profile on new user sign-up
--   This fires automatically when a user signs up (email OR Google OAuth)
-- ─────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
    INSERT INTO public.profiles (
        id,
        callsign,
        email,
        role,
        clearance,
        avatar_url,
        provider
    ) VALUES (
        NEW.id,
        COALESCE(
            NEW.raw_user_meta_data->>'callsign',
            NEW.raw_user_meta_data->>'full_name',
            NEW.raw_user_meta_data->>'name',
            SPLIT_PART(NEW.email, '@', 1)
        ),
        NEW.email,
        CASE
            WHEN NEW.raw_user_meta_data->>'callsign' IS NOT NULL THEN 'SOC Incident Responder'
            WHEN NEW.app_metadata->>'provider' = 'google' THEN 'SOC Analyst (Google Auth)'
            ELSE 'SOC Junior Analyst'
        END,
        CASE
            WHEN NEW.app_metadata->>'provider' = 'google' THEN 'TOP SECRET // LEVEL 4'
            ELSE 'SECRET // LEVEL 2'
        END,
        NEW.raw_user_meta_data->>'avatar_url',
        COALESCE(NEW.app_metadata->>'provider', 'email')
    )
    ON CONFLICT (id) DO UPDATE SET
        email       = EXCLUDED.email,
        avatar_url  = EXCLUDED.avatar_url,
        updated_at  = timezone('utc', now());

    RETURN NEW;
END;
$$;

-- ─────────────────────────────────────────────────────────────────────
-- STEP 10: Register the Trigger on auth.users
-- ─────────────────────────────────────────────────────────────────────
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_new_user();

-- ─────────────────────────────────────────────────────────────────────
-- STEP 11: Trigger — Update profile updated_at on changes
-- ─────────────────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = timezone('utc', now());
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS profiles_updated_at ON public.profiles;

CREATE TRIGGER profiles_updated_at
    BEFORE UPDATE ON public.profiles
    FOR EACH ROW
    EXECUTE FUNCTION public.set_updated_at();

-- ─────────────────────────────────────────────────────────────────────
-- STEP 12: Indexes for Performance
-- ─────────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_profiles_email        ON public.profiles(email);
CREATE INDEX IF NOT EXISTS idx_profiles_clearance    ON public.profiles(clearance);
CREATE INDEX IF NOT EXISTS idx_activity_user_id      ON public.analyst_activity(user_id);
CREATE INDEX IF NOT EXISTS idx_activity_action       ON public.analyst_activity(action);
CREATE INDEX IF NOT EXISTS idx_activity_created_at   ON public.analyst_activity(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id      ON public.soc_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_active       ON public.soc_sessions(is_active);

-- ─────────────────────────────────────────────────────────────────────
-- STEP 13: Grant permissions for anon and authenticated roles
-- ─────────────────────────────────────────────────────────────────────
GRANT USAGE ON SCHEMA public TO anon, authenticated;
GRANT SELECT ON public.profiles TO authenticated;
GRANT INSERT, UPDATE ON public.profiles TO authenticated;
GRANT SELECT, INSERT ON public.analyst_activity TO authenticated, anon;
GRANT SELECT, INSERT, UPDATE ON public.soc_sessions TO authenticated;

-- ─────────────────────────────────────────────────────────────────────
-- STEP 14: Verify Installation
-- ─────────────────────────────────────────────────────────────────────
SELECT
    table_name,
    (SELECT COUNT(*) FROM information_schema.columns c2 WHERE c2.table_name = t.table_name) AS column_count
FROM information_schema.tables t
WHERE table_schema = 'public'
  AND table_name IN ('profiles', 'analyst_activity', 'soc_sessions', 'threats', 'evidence_chains')
ORDER BY table_name;

-- ✅ If you see the tables listed above, setup is complete!
-- Next: Enable Email Auth and Google OAuth in Supabase Dashboard → Authentication → Providers
