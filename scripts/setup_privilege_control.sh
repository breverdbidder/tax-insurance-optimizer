#!/bin/bash
#
# setup_privilege_control.sh
# One-command deployment of privilege control (RLS + service accounts)
#
# Usage: ./scripts/setup_privilege_control.sh <db_password>
#

set -e  # Exit on error

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "======================================================================"
echo "PRIVILEGE CONTROL SETUP - AUTONOMOUS DEPLOYMENT"
echo "======================================================================"
echo ""

# Check arguments
if [ -z "$1" ]; then
    echo -e "${RED}❌ Error: Database password required${NC}"
    echo ""
    echo "Usage: ./scripts/setup_privilege_control.sh <db_password>"
    echo ""
    exit 1
fi

DB_PASSWORD="$1"

# Load environment variables
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Check required variables
if [ -z "$SUPABASE_URL" ]; then
    echo -e "${RED}❌ Error: SUPABASE_URL not set${NC}"
    exit 1
fi

# Extract database URL from Supabase URL
# Format: https://<project-ref>.supabase.co
PROJECT_REF=$(echo $SUPABASE_URL | sed -E 's|https://([^.]+)\.supabase\.co.*|\1|')
DB_HOST="db.${PROJECT_REF}.supabase.co"
DB_PORT="5432"
DB_NAME="postgres"
DB_USER="postgres"

DATABASE_URL="postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"

echo -e "${YELLOW}📦 Deployment Configuration${NC}"
echo "  Project: $PROJECT_REF"
echo "  Database: $DB_HOST"
echo ""

# Step 1: Deploy service account setup
echo -e "${YELLOW}📝 Step 1: Creating service accounts...${NC}"

if [ -f sql/security/service_account_setup.sql ]; then
    PGPASSWORD=$DB_PASSWORD psql "$DATABASE_URL" -f sql/security/service_account_setup.sql
    echo -e "${GREEN}✅ Service accounts created${NC}"
else
    echo -e "${RED}❌ File not found: sql/security/service_account_setup.sql${NC}"
    exit 1
fi

echo ""

# Step 2: Deploy RLS policies
echo -e "${YELLOW}🔒 Step 2: Enabling RLS and creating policies...${NC}"

if [ -f sql/security/rls_policies.sql ]; then
    PGPASSWORD=$DB_PASSWORD psql "$DATABASE_URL" -f sql/security/rls_policies.sql
    echo -e "${GREEN}✅ RLS policies deployed${NC}"
else
    echo -e "${RED}❌ File not found: sql/security/rls_policies.sql${NC}"
    exit 1
fi

echo ""

# Step 3: Verify deployment
echo -e "${YELLOW}🔍 Step 3: Verifying deployment...${NC}"

# Check roles
echo "  Checking roles..."
ROLES=$(PGPASSWORD=$DB_PASSWORD psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM pg_roles WHERE rolname IN ('scraper_readonly', 'analysis_agent', 'report_agent', 'qa_agent');")
ROLES=$(echo $ROLES | xargs)  # Trim whitespace

if [ "$ROLES" == "4" ]; then
    echo -e "  ${GREEN}✅ All 4 roles created${NC}"
else
    echo -e "  ${RED}❌ Expected 4 roles, found $ROLES${NC}"
fi

# Check RLS status
echo "  Checking RLS status..."
RLS_TABLES=$(PGPASSWORD=$DB_PASSWORD psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM pg_tables WHERE schemaname = 'public' AND tablename IN ('historical_auctions', 'multi_county_auctions', 'insights', 'daily_metrics', 'metrics', 'errors', 'security_alerts', 'anomaly_metrics', 'activities') AND rowsecurity = true;")
RLS_TABLES=$(echo $RLS_TABLES | xargs)

if [ "$RLS_TABLES" == "9" ]; then
    echo -e "  ${GREEN}✅ RLS enabled on 9 tables${NC}"
else
    echo -e "  ${YELLOW}⚠️  RLS enabled on $RLS_TABLES/9 tables${NC}"
fi

# Check policy count
echo "  Checking policies..."
POLICY_COUNT=$(PGPASSWORD=$DB_PASSWORD psql "$DATABASE_URL" -t -c "SELECT COUNT(*) FROM pg_policies WHERE schemaname = 'public';")
POLICY_COUNT=$(echo $POLICY_COUNT | xargs)

if [ "$POLICY_COUNT" -ge "35" ]; then
    echo -e "  ${GREEN}✅ $POLICY_COUNT policies created${NC}"
else
    echo -e "  ${YELLOW}⚠️  Only $POLICY_COUNT policies found (expected 35+)${NC}"
fi

echo ""

# Step 4: Display next steps
echo "======================================================================"
echo -e "${GREEN}✅ PRIVILEGE CONTROL DEPLOYMENT COMPLETE${NC}"
echo "======================================================================"
echo ""
echo "Next steps:"
echo "  1. Create 4 service keys in Supabase Dashboard:"
echo "     - Settings → API → Create Service Role Key"
echo "     - Create: scraper_service_key, analysis_service_key,"
echo "               report_service_key, qa_service_key"
echo ""
echo "  2. Update .env with new keys:"
echo "     SUPABASE_SCRAPER_KEY=<scraper_key>"
echo "     SUPABASE_ANALYSIS_KEY=<analysis_key>"
echo "     SUPABASE_REPORT_KEY=<report_key>"
echo "     SUPABASE_QA_KEY=<qa_key>"
echo ""
echo "  3. Test security:"
echo "     pytest tests/security/test_privilege_control.py -v"
echo ""
echo "  4. Run security audit:"
echo "     python src/security/privilege_audit.py"
echo ""

# Optional: Run audit automatically
if command -v python3 &> /dev/null; then
    if [ -f src/security/privilege_audit.py ]; then
        echo -e "${YELLOW}🔍 Running security audit...${NC}"
        python3 src/security/privilege_audit.py || true
    fi
fi
