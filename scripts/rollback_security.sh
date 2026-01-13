#!/bin/bash
#
# rollback_security.sh
# Emergency rollback of security features
#
# Usage: ./scripts/rollback_security.sh <db_password> [component]
#
# Components:
#   rls       - Disable RLS and drop policies
#   roles     - Drop service account roles
#   all       - Complete rollback (default)
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "======================================================================"
echo -e "${RED}SECURITY ROLLBACK - EMERGENCY PROCEDURE${NC}"
echo "======================================================================"
echo ""

# Check arguments
if [ -z "$1" ]; then
    echo -e "${RED}❌ Error: Database password required${NC}"
    echo ""
    echo "Usage: ./scripts/rollback_security.sh <db_password> [component]"
    echo ""
    echo "Components:"
    echo "  rls       - Disable RLS and drop policies"
    echo "  roles     - Drop service account roles"
    echo "  all       - Complete rollback (default)"
    echo ""
    exit 1
fi

DB_PASSWORD="$1"
COMPONENT="${2:-all}"

# Load environment
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

if [ -z "$SUPABASE_URL" ]; then
    echo -e "${RED}❌ Error: SUPABASE_URL not set${NC}"
    exit 1
fi

# Extract database URL
PROJECT_REF=$(echo $SUPABASE_URL | sed -E 's|https://([^.]+)\.supabase\.co.*|\1|')
DB_HOST="db.${PROJECT_REF}.supabase.co"
DB_PORT="5432"
DB_NAME="postgres"
DB_USER="postgres"
DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"

echo -e "${YELLOW}⚠️  WARNING: This will rollback security features${NC}"
echo "  Project: $PROJECT_REF"
echo "  Component: $COMPONENT"
echo ""
echo -n "Are you sure? (type 'yes' to confirm): "
read CONFIRM

if [ "$CONFIRM" != "yes" ]; then
    echo -e "${YELLOW}Aborted${NC}"
    exit 0
fi

echo ""

# Rollback RLS
if [ "$COMPONENT" == "rls" ] || [ "$COMPONENT" == "all" ]; then
    echo -e "${YELLOW}📝 Rolling back RLS policies...${NC}"
    
    # Disable RLS on tables
    TABLES=(
        "historical_auctions"
        "multi_county_auctions"
        "insights"
        "daily_metrics"
        "metrics"
        "errors"
        "security_alerts"
        "anomaly_metrics"
        "activities"
    )
    
    for table in "${TABLES[@]}"; do
        echo "  Disabling RLS on $table..."
        PGPASSWORD=$DB_PASSWORD psql "$DATABASE_URL" -c "ALTER TABLE $table DISABLE ROW LEVEL SECURITY;" 2>/dev/null || true
    done
    
    # Drop all policies
    echo "  Dropping policies..."
    PGPASSWORD=$DB_PASSWORD psql "$DATABASE_URL" << 'EOSQL' 2>/dev/null || true
DO $$
DECLARE
    pol RECORD;
BEGIN
    FOR pol IN 
        SELECT schemaname, tablename, policyname
        FROM pg_policies
        WHERE schemaname = 'public'
    LOOP
        EXECUTE format('DROP POLICY IF EXISTS %I ON %I.%I',
            pol.policyname, pol.schemaname, pol.tablename);
    END LOOP;
END $$;
EOSQL
    
    echo -e "${GREEN}✅ RLS rolled back${NC}"
    echo ""
fi

# Rollback roles
if [ "$COMPONENT" == "roles" ] || [ "$COMPONENT" == "all" ]; then
    echo -e "${YELLOW}📝 Rolling back service account roles...${NC}"
    
    ROLES=(
        "scraper_readonly"
        "analysis_agent"
        "report_agent"
        "qa_agent"
    )
    
    for role in "${ROLES[@]}"; do
        echo "  Dropping role $role..."
        PGPASSWORD=$DB_PASSWORD psql "$DATABASE_URL" -c "DROP ROLE IF EXISTS $role;" 2>/dev/null || true
    done
    
    echo -e "${GREEN}✅ Roles dropped${NC}"
    echo ""
fi

# Verify rollback
echo -e "${YELLOW}🔍 Verifying rollback...${NC}"

# Check RLS
RLS_COUNT=$(PGPASSWORD=$DB_PASSWORD psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public' AND rowsecurity = true;")
RLS_COUNT=$(echo $RLS_COUNT | xargs)
echo "  RLS enabled tables: $RLS_COUNT"

# Check policies
POLICY_COUNT=$(PGPASSWORD=$DB_PASSWORD psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM pg_policies WHERE schemaname = 'public';")
POLICY_COUNT=$(echo $POLICY_COUNT | xargs)
echo "  Active policies: $POLICY_COUNT"

# Check roles
ROLE_COUNT=$(PGPASSWORD=$DB_PASSWORD psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM pg_roles WHERE rolname IN ('scraper_readonly', 'analysis_agent', 'report_agent', 'qa_agent');")
ROLE_COUNT=$(echo $ROLE_COUNT | xargs)
echo "  Service account roles: $ROLE_COUNT"

echo ""
echo "======================================================================"
if [ "$RLS_COUNT" == "0" ] && [ "$POLICY_COUNT" == "0" ] && [ "$ROLE_COUNT" == "0" ]; then
    echo -e "${GREEN}✅ ROLLBACK COMPLETE${NC}"
else
    echo -e "${YELLOW}⚠️  PARTIAL ROLLBACK${NC}"
    echo "  Some components may still be active"
fi
echo "======================================================================"
echo ""
echo "Next steps:"
echo "  1. Update application code to remove security layer calls"
echo "  2. Remove agent-specific keys from .env"
echo "  3. Use SUPABASE_SERVICE_ROLE_KEY for all operations"
echo "  4. Monitor application for issues"
echo ""
echo -e "${YELLOW}⚠️  Security features are now disabled${NC}"
echo ""
