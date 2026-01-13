-- Service Account Setup for BidDeed.AI
--
-- Creates separate service accounts (roles) for each agent with minimum
-- required privileges following the principle of least privilege.
--
-- Part of Phase 2 - Week 1: Privilege Control
--
-- IMPORTANT: In Supabase, you need to create service accounts via:
-- 1. Supabase Dashboard > Settings > API
-- 2. Create new service role keys
-- 3. Apply these SQL scripts to grant appropriate permissions
--

-- ============================================================================
-- ROLE CREATION
-- ============================================================================

-- Note: Supabase manages roles differently than standard PostgreSQL
-- These are conceptual roles - in practice, you'll use service_role keys
-- with RLS policies to enforce separation

-- Create roles (if they don't exist)
DO $$
BEGIN
    -- Scraper Agent Role (write to historical_auctions, multi_county_auctions)
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scraper_readonly') THEN
        CREATE ROLE scraper_readonly;
    END IF;
    
    -- Analysis Agent Role (read auctions, write insights/metrics)
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'analysis_agent') THEN
        CREATE ROLE analysis_agent;
    END IF;
    
    -- Report Agent Role (read-only access to all tables)
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'report_agent') THEN
        CREATE ROLE report_agent;
    END IF;
    
    -- QA Agent Role (read all, write metrics/errors)
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qa_agent') THEN
        CREATE ROLE qa_agent;
    END IF;
END
$$;

-- ============================================================================
-- GRANT TABLE-LEVEL PERMISSIONS
-- ============================================================================

-- SCRAPER AGENT: Can write to auction tables
GRANT SELECT, INSERT ON historical_auctions TO scraper_readonly;
GRANT SELECT, INSERT, UPDATE ON multi_county_auctions TO scraper_readonly;
GRANT INSERT ON activities TO scraper_readonly;
GRANT INSERT ON errors TO scraper_readonly;
GRANT INSERT ON security_alerts TO scraper_readonly;
GRANT INSERT ON anomaly_metrics TO scraper_readonly;

-- ANALYSIS AGENT: Read auctions, write insights/metrics
GRANT SELECT ON historical_auctions TO analysis_agent;
GRANT SELECT ON multi_county_auctions TO analysis_agent;
GRANT SELECT, INSERT ON insights TO analysis_agent;
GRANT SELECT, INSERT ON daily_metrics TO analysis_agent;
GRANT SELECT, INSERT ON metrics TO analysis_agent;
GRANT SELECT, INSERT ON activities TO analysis_agent;
GRANT SELECT, INSERT ON errors TO analysis_agent;
GRANT INSERT ON security_alerts TO analysis_agent;
GRANT INSERT ON anomaly_metrics TO analysis_agent;

-- REPORT AGENT: Read-only access to all tables
GRANT SELECT ON historical_auctions TO report_agent;
GRANT SELECT ON multi_county_auctions TO report_agent;
GRANT SELECT ON insights TO report_agent;
GRANT SELECT ON daily_metrics TO report_agent;
GRANT SELECT ON metrics TO report_agent;
GRANT SELECT ON activities TO report_agent;
GRANT SELECT ON errors TO report_agent;
GRANT SELECT ON anomaly_metrics TO report_agent;

-- QA AGENT: Read all, write metrics/errors
GRANT SELECT ON ALL TABLES IN SCHEMA public TO qa_agent;
GRANT INSERT ON metrics TO qa_agent;
GRANT INSERT ON errors TO qa_agent;
GRANT INSERT ON activities TO qa_agent;
GRANT INSERT ON security_alerts TO qa_agent;
GRANT INSERT ON anomaly_metrics TO qa_agent;

-- ============================================================================
-- GRANT SEQUENCE PERMISSIONS (for auto-increment columns)
-- ============================================================================

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO scraper_readonly;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO analysis_agent;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO qa_agent;
-- report_agent doesn't need sequences (read-only)

-- ============================================================================
-- REVOKE DANGEROUS PERMISSIONS
-- ============================================================================

-- Ensure no agent can drop tables or modify schema
REVOKE CREATE ON SCHEMA public FROM scraper_readonly;
REVOKE CREATE ON SCHEMA public FROM analysis_agent;
REVOKE CREATE ON SCHEMA public FROM report_agent;
REVOKE CREATE ON SCHEMA public FROM qa_agent;

-- Ensure no agent can truncate tables
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM scraper_readonly;
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM analysis_agent;
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM report_agent;
REVOKE TRUNCATE ON ALL TABLES IN SCHEMA public FROM qa_agent;

-- ============================================================================
-- SUPABASE-SPECIFIC CONFIGURATION
-- ============================================================================

-- In Supabase, you need to:
-- 1. Go to Settings > API
-- 2. Create separate service role keys for each agent:
--    - scraper_service_key
--    - analysis_service_key
--    - report_service_key
--    - qa_service_key
-- 3. Update environment variables:

/*
# .env.production
SUPABASE_URL=https://mocerqjnksmhcjzxrewo.supabase.co

# Separate keys for each agent
SUPABASE_SCRAPER_KEY=<scraper_service_role_key>
SUPABASE_ANALYSIS_KEY=<analysis_service_role_key>
SUPABASE_REPORT_KEY=<report_service_role_key>
SUPABASE_QA_KEY=<qa_service_role_key>

# Keep admin key for migrations only
SUPABASE_ADMIN_KEY=<full_service_role_key>
*/

-- ============================================================================
-- AGENT INITIALIZATION FUNCTION
-- ============================================================================

-- Function to verify agent privileges
CREATE OR REPLACE FUNCTION verify_agent_privileges(agent_role TEXT)
RETURNS TABLE(
    table_name TEXT,
    has_select BOOLEAN,
    has_insert BOOLEAN,
    has_update BOOLEAN,
    has_delete BOOLEAN
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        t.tablename::TEXT,
        has_table_privilege(agent_role, t.schemaname || '.' || t.tablename, 'SELECT'),
        has_table_privilege(agent_role, t.schemaname || '.' || t.tablename, 'INSERT'),
        has_table_privilege(agent_role, t.schemaname || '.' || t.tablename, 'UPDATE'),
        has_table_privilege(agent_role, t.schemaname || '.' || t.tablename, 'DELETE')
    FROM pg_tables t
    WHERE t.schemaname = 'public'
    ORDER BY t.tablename;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Check privileges for scraper_readonly
SELECT * FROM verify_agent_privileges('scraper_readonly');

-- Check privileges for analysis_agent
SELECT * FROM verify_agent_privileges('analysis_agent');

-- Check privileges for report_agent
SELECT * FROM verify_agent_privileges('report_agent');

-- Check privileges for qa_agent
SELECT * FROM verify_agent_privileges('qa_agent');

-- Summary of all role privileges
SELECT 
    grantee,
    table_name,
    privilege_type
FROM information_schema.role_table_grants
WHERE table_schema = 'public'
AND grantee IN ('scraper_readonly', 'analysis_agent', 'report_agent', 'qa_agent')
ORDER BY grantee, table_name, privilege_type;

-- ============================================================================
-- ROLLBACK (if needed)
-- ============================================================================

/*
-- Revoke all privileges
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM scraper_readonly;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM analysis_agent;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM report_agent;
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM qa_agent;

REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM scraper_readonly;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM analysis_agent;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM qa_agent;

-- Drop roles
DROP ROLE IF EXISTS scraper_readonly;
DROP ROLE IF EXISTS analysis_agent;
DROP ROLE IF EXISTS report_agent;
DROP ROLE IF EXISTS qa_agent;

-- Drop verification function
DROP FUNCTION IF EXISTS verify_agent_privileges(TEXT);
*/

-- ============================================================================
-- TESTING
-- ============================================================================

-- Test scraper_readonly can insert
-- SET ROLE scraper_readonly;
-- INSERT INTO historical_auctions (case_number, status) VALUES ('TEST-001', 'test');
-- RESET ROLE;

-- Test analysis_agent cannot insert to historical_auctions
-- SET ROLE analysis_agent;
-- INSERT INTO historical_auctions (case_number, status) VALUES ('TEST-002', 'test');  -- Should fail
-- RESET ROLE;

-- Test report_agent cannot modify anything
-- SET ROLE report_agent;
-- INSERT INTO insights (data) VALUES ('test');  -- Should fail
-- UPDATE historical_auctions SET status = 'modified' WHERE case_number = 'TEST-001';  -- Should fail
-- RESET ROLE;
