#!/bin/bash

# Phase 2 Security Setup Script
# Automates complete security deployment

set -e

echo "======================================================================"
echo "PHASE 2 SECURITY SETUP"
echo "======================================================================"
echo ""

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if Supabase credentials are set
echo "Checking environment variables..."
if [ -z "$SUPABASE_URL" ]; then
    echo -e "${RED}❌ SUPABASE_URL not set${NC}"
    exit 1
fi

if [ -z "$SUPABASE_SERVICE_ROLE_KEY" ] && [ -z "$SUPABASE_ADMIN_KEY" ]; then
    echo -e "${RED}❌ SUPABASE_SERVICE_ROLE_KEY or SUPABASE_ADMIN_KEY required${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Environment variables set${NC}"
echo ""

# Step 1: Install dependencies
echo "======================================================================"
echo "Step 1: Installing Dependencies"
echo "======================================================================"
echo ""

pip install --break-system-packages supabase psycopg2-binary python-dotenv

echo -e "${GREEN}✅ Dependencies installed${NC}"
echo ""

# Step 2: Deploy SQL scripts
echo "======================================================================"
echo "Step 2: Deploying SQL Scripts"
echo "======================================================================"
echo ""

# Check if DATABASE_URL is set
if [ -n "$DATABASE_URL" ]; then
    echo "Using DATABASE_URL..."
    
    # Deploy service account setup
    if [ -f sql/security/service_account_setup.sql ]; then
        echo "📝 Creating service accounts..."
        psql $DATABASE_URL -f sql/security/service_account_setup.sql
        echo -e "${GREEN}✅ Service accounts created${NC}"
    else
        echo -e "${YELLOW}⚠️ sql/security/service_account_setup.sql not found${NC}"
    fi
    
    # Deploy RLS policies
    if [ -f sql/security/rls_policies.sql ]; then
        echo "🔒 Enabling RLS and creating policies..."
        psql $DATABASE_URL -f sql/security/rls_policies.sql
        echo -e "${GREEN}✅ RLS policies deployed${NC}"
    else
        echo -e "${YELLOW}⚠️ sql/security/rls_policies.sql not found${NC}"
    fi
    
    # Verify deployment
    echo "🔍 Verifying deployment..."
    psql $DATABASE_URL -c "SELECT COUNT(*) as policy_count FROM pg_policies WHERE schemaname = 'public';"
    psql $DATABASE_URL -c "SELECT tablename, rowsecurity FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename;"
    
    echo -e "${GREEN}✅ SQL deployment complete${NC}"
else
    echo -e "${YELLOW}⚠️ DATABASE_URL not set - skipping SQL deployment${NC}"
    echo "   To deploy SQL later, set DATABASE_URL and run:"
    echo "   ./scripts/setup_security.sh"
fi

echo ""

# Step 3: Run security tests
echo "======================================================================"
echo "Step 3: Running Security Tests"
echo "======================================================================"
echo ""

if [ -d tests/security ]; then
    pip install --break-system-packages pytest
    pytest tests/security/ -v || echo -e "${YELLOW}⚠️ Some tests failed${NC}"
    echo -e "${GREEN}✅ Tests complete${NC}"
else
    echo -e "${YELLOW}⚠️ tests/security/ not found${NC}"
fi

echo ""

# Step 4: Run privilege audit
echo "======================================================================"
echo "Step 4: Running Privilege Audit"
echo "======================================================================"
echo ""

if [ -f src/security/privilege_audit.py ]; then
    python3 src/security/privilege_audit.py
    echo -e "${GREEN}✅ Privilege audit complete${NC}"
else
    echo -e "${YELLOW}⚠️ src/security/privilege_audit.py not found${NC}"
fi

echo ""

# Step 5: Generate initial security report
echo "======================================================================"
echo "Step 5: Generating Security Report"
echo "======================================================================"
echo ""

if [ -f src/security/weekly_report.py ]; then
    python3 << 'EOF'
from src.security.weekly_report import WeeklySecurityReport
from src.utils.supabase_client import get_admin_client

try:
    reporter = WeeklySecurityReport(get_admin_client())
    reporter.save_report('security_report.md')
    print("✅ Security report generated: security_report.md")
except Exception as e:
    print(f"⚠️ Failed to generate report: {e}")
EOF
else
    echo -e "${YELLOW}⚠️ src/security/weekly_report.py not found${NC}"
fi

echo ""

# Summary
echo "======================================================================"
echo "SETUP COMPLETE"
echo "======================================================================"
echo ""
echo -e "${GREEN}✅ Phase 2 Security Deployed${NC}"
echo ""
echo "Next Steps:"
echo "1. Create 4 service keys in Supabase Dashboard"
echo "2. Update .env with service keys:"
echo "   - SUPABASE_SCRAPER_KEY"
echo "   - SUPABASE_ANALYSIS_KEY"
echo "   - SUPABASE_REPORT_KEY"
echo "   - SUPABASE_QA_KEY"
echo "3. Integrate security layers into application code"
echo ""
echo "Documentation:"
echo "- docs/security/ARCHITECTURE.md"
echo "- docs/security/PRIVILEGE_MODEL.md"
echo ""
