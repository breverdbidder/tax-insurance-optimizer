-- Row-Level Security (RLS) Policies for BidDeed.AI
-- 
-- Implements fine-grained access control at the row level to prevent
-- unauthorized data access and lateral movement between agents.
--
-- Part of Phase 2 - Week 1: Privilege Control
-- 
-- Usage: Run this script as postgres/supabase admin user
--

-- ============================================================================
-- STEP 1: Enable RLS on All Tables
-- ============================================================================

-- Core data tables
ALTER TABLE historical_auctions ENABLE ROW LEVEL SECURITY;
ALTER TABLE multi_county_auctions ENABLE ROW LEVEL SECURITY;
ALTER TABLE activities ENABLE ROW LEVEL SECURITY;
ALTER TABLE insights ENABLE ROW LEVEL SECURITY;
ALTER TABLE daily_metrics ENABLE ROW LEVEL SECURITY;

-- Security and monitoring tables
ALTER TABLE security_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE anomaly_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE errors ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- STEP 2: Create Service Roles (if not exist)
-- ============================================================================

-- Note: In Supabase, you create service accounts via the dashboard
-- These policies reference roles that should be created separately
-- See service_account_setup.sql for role creation

-- ============================================================================
-- STEP 3: Historical Auctions Policies
-- ============================================================================

-- Scraper Agent: Can insert new records and read own records
CREATE POLICY "scraper_can_insert_auctions"
ON historical_auctions
FOR INSERT
TO scraper_readonly  -- Note: Will be scraper_writeonly for inserts
WITH CHECK (
    -- Allow insert of new records
    true
);

CREATE POLICY "scraper_can_read_own_auctions"
ON historical_auctions
FOR SELECT
TO scraper_readonly
USING (
    -- Can only read records from last 30 days
    created_at > NOW() - INTERVAL '30 days'
);

-- Analysis Agent: Can read processed records, write to insights
CREATE POLICY "analysis_can_read_processed_auctions"
ON historical_auctions
FOR SELECT
TO analysis_agent
USING (
    -- Can only read records marked as processed
    status = 'processed' OR status = 'completed'
);

CREATE POLICY "analysis_cannot_modify_auctions"
ON historical_auctions
FOR UPDATE
TO analysis_agent
USING (false);  -- Deny all updates

CREATE POLICY "analysis_cannot_delete_auctions"
ON historical_auctions
FOR DELETE
TO analysis_agent
USING (false);  -- Deny all deletes

-- Report Agent: Read-only access to completed records
CREATE POLICY "report_can_read_completed_auctions"
ON historical_auctions
FOR SELECT
TO report_agent
USING (
    -- Can only read completed records
    status = 'completed' OR status = 'processed'
);

CREATE POLICY "report_cannot_modify_auctions"
ON historical_auctions
FOR ALL  -- Block INSERT, UPDATE, DELETE
TO report_agent
USING (false);

-- QA Agent: Read-only access for quality checks
CREATE POLICY "qa_can_read_all_auctions"
ON historical_auctions
FOR SELECT
TO qa_agent
USING (true);  -- Can read all for quality analysis

CREATE POLICY "qa_cannot_modify_auctions"
ON historical_auctions
FOR ALL
TO qa_agent
USING (false);

-- ============================================================================
-- STEP 4: Multi-County Auctions Policies
-- ============================================================================

-- Scraper Agent: Full access (creates these records)
CREATE POLICY "scraper_full_access_multi_county"
ON multi_county_auctions
FOR ALL
TO scraper_readonly
USING (true)
WITH CHECK (true);

-- Analysis Agent: Read-only
CREATE POLICY "analysis_can_read_multi_county"
ON multi_county_auctions
FOR SELECT
TO analysis_agent
USING (
    -- Can read auctions from last 7 days
    auction_date > CURRENT_DATE - INTERVAL '7 days'
);

-- Report Agent: Read-only
CREATE POLICY "report_can_read_multi_county"
ON multi_county_auctions
FOR SELECT
TO report_agent
USING (true);

-- ============================================================================
-- STEP 5: Insights Table Policies
-- ============================================================================

-- Analysis Agent: Can insert insights
CREATE POLICY "analysis_can_insert_insights"
ON insights
FOR INSERT
TO analysis_agent
WITH CHECK (true);

CREATE POLICY "analysis_can_read_own_insights"
ON insights
FOR SELECT
TO analysis_agent
USING (
    -- Can read insights from last 90 days
    created_at > NOW() - INTERVAL '90 days'
);

-- Report Agent: Read-only access
CREATE POLICY "report_can_read_insights"
ON insights
FOR SELECT
TO report_agent
USING (true);

-- QA Agent: Read-only for validation
CREATE POLICY "qa_can_read_insights"
ON insights
FOR SELECT
TO qa_agent
USING (true);

-- ============================================================================
-- STEP 6: Metrics and Monitoring Policies
-- ============================================================================

-- Metrics table: Analysis and QA agents can write
CREATE POLICY "analysis_can_write_metrics"
ON metrics
FOR INSERT
TO analysis_agent
WITH CHECK (true);

CREATE POLICY "qa_can_write_metrics"
ON metrics
FOR INSERT
TO qa_agent
WITH CHECK (true);

-- All agents can read metrics
CREATE POLICY "all_agents_can_read_metrics"
ON metrics
FOR SELECT
TO scraper_readonly, analysis_agent, report_agent, qa_agent
USING (true);

-- Errors table: All agents can log errors
CREATE POLICY "all_agents_can_log_errors"
ON errors
FOR INSERT
TO scraper_readonly, analysis_agent, report_agent, qa_agent
WITH CHECK (true);

-- QA agent can read all errors
CREATE POLICY "qa_can_read_all_errors"
ON errors
FOR SELECT
TO qa_agent
USING (true);

-- Other agents can only read their own errors
CREATE POLICY "agents_can_read_own_errors"
ON errors
FOR SELECT
TO scraper_readonly, analysis_agent, report_agent
USING (
    -- Filter by agent name in metadata
    metadata->>'agent' = current_user
);

-- ============================================================================
-- STEP 7: Security Alerts Policies
-- ============================================================================

-- All agents can insert security alerts
CREATE POLICY "all_agents_can_log_security_alerts"
ON security_alerts
FOR INSERT
TO scraper_readonly, analysis_agent, report_agent, qa_agent
WITH CHECK (true);

-- Only QA agent and admin can read security alerts
CREATE POLICY "qa_can_read_security_alerts"
ON security_alerts
FOR SELECT
TO qa_agent
USING (true);

-- ============================================================================
-- STEP 8: Anomaly Metrics Policies
-- ============================================================================

-- All agents can write anomaly metrics
CREATE POLICY "all_agents_can_write_anomaly_metrics"
ON anomaly_metrics
FOR INSERT
TO scraper_readonly, analysis_agent, report_agent, qa_agent
WITH CHECK (true);

-- All agents can read their own anomaly metrics
CREATE POLICY "agents_can_read_own_anomaly_metrics"
ON anomaly_metrics
FOR SELECT
TO scraper_readonly, analysis_agent, report_agent, qa_agent
USING (
    -- Filter by node name or agent identifier
    node = current_user OR metadata->>'agent' = current_user
);

-- QA agent can read all
CREATE POLICY "qa_can_read_all_anomaly_metrics"
ON anomaly_metrics
FOR SELECT
TO qa_agent
USING (true);

-- ============================================================================
-- STEP 9: Daily Metrics Policies
-- ============================================================================

-- Analysis agent can write daily metrics
CREATE POLICY "analysis_can_write_daily_metrics"
ON daily_metrics
FOR INSERT
TO analysis_agent
WITH CHECK (true);

-- All agents can read daily metrics
CREATE POLICY "all_agents_can_read_daily_metrics"
ON daily_metrics
FOR SELECT
TO scraper_readonly, analysis_agent, report_agent, qa_agent
USING (true);

-- ============================================================================
-- STEP 10: Activities Policies
-- ============================================================================

-- All agents can log activities
CREATE POLICY "all_agents_can_log_activities"
ON activities
FOR INSERT
TO scraper_readonly, analysis_agent, report_agent, qa_agent
WITH CHECK (true);

-- All agents can read their own activities
CREATE POLICY "agents_can_read_own_activities"
ON activities
FOR SELECT
TO scraper_readonly, analysis_agent, report_agent, qa_agent
USING (
    -- Filter by user or agent identifier
    metadata->>'agent' = current_user
);

-- QA agent can read all activities
CREATE POLICY "qa_can_read_all_activities"
ON activities
FOR SELECT
TO qa_agent
USING (true);

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================

-- Check RLS status for all tables
SELECT 
    schemaname,
    tablename,
    rowsecurity as rls_enabled
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY tablename;

-- Check policies for a specific table
SELECT 
    schemaname,
    tablename,
    policyname,
    permissive,
    roles,
    cmd,
    qual,
    with_check
FROM pg_policies
WHERE schemaname = 'public'
AND tablename = 'historical_auctions';

-- Count policies per table
SELECT 
    tablename,
    COUNT(*) as policy_count
FROM pg_policies
WHERE schemaname = 'public'
GROUP BY tablename
ORDER BY policy_count DESC;

-- ============================================================================
-- ROLLBACK (if needed)
-- ============================================================================

-- To disable RLS and drop all policies:
/*
DROP POLICY IF EXISTS "scraper_can_insert_auctions" ON historical_auctions;
DROP POLICY IF EXISTS "scraper_can_read_own_auctions" ON historical_auctions;
DROP POLICY IF EXISTS "analysis_can_read_processed_auctions" ON historical_auctions;
DROP POLICY IF EXISTS "analysis_cannot_modify_auctions" ON historical_auctions;
DROP POLICY IF EXISTS "analysis_cannot_delete_auctions" ON historical_auctions;
DROP POLICY IF EXISTS "report_can_read_completed_auctions" ON historical_auctions;
DROP POLICY IF EXISTS "report_cannot_modify_auctions" ON historical_auctions;
DROP POLICY IF EXISTS "qa_can_read_all_auctions" ON historical_auctions;
DROP POLICY IF EXISTS "qa_cannot_modify_auctions" ON historical_auctions;

ALTER TABLE historical_auctions DISABLE ROW LEVEL SECURITY;
ALTER TABLE multi_county_auctions DISABLE ROW LEVEL SECURITY;
ALTER TABLE activities DISABLE ROW LEVEL SECURITY;
ALTER TABLE insights DISABLE ROW LEVEL SECURITY;
ALTER TABLE daily_metrics DISABLE ROW LEVEL SECURITY;
ALTER TABLE security_alerts DISABLE ROW LEVEL SECURITY;
ALTER TABLE anomaly_metrics DISABLE ROW LEVEL SECURITY;
ALTER TABLE metrics DISABLE ROW LEVEL SECURITY;
ALTER TABLE errors DISABLE ROW LEVEL SECURITY;
*/
