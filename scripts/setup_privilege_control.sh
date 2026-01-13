#!/bin/bash
# Setup Privilege Control - Phase 2 Week 1
set -e

if [ -z "$1" ]; then
    echo "Usage: ./setup_privilege_control.sh <db_password>"
    exit 1
fi

export PGPASSWORD="$1"
DB_URL="${DATABASE_URL:-postgresql://postgres:$1@db.mocerqjnksmhcjzxrewo.supabase.co:5432/postgres}"

echo "🔐 Setting up privilege control..."

# Create roles
psql "$DB_URL" -f sql/security/service_account_setup.sql

# Enable RLS
psql "$DB_URL" -f sql/security/rls_policies.sql

# Verify
echo "✅ Verifying deployment..."
psql "$DB_URL" -c "SELECT COUNT(*) as policy_count FROM pg_policies WHERE schemaname = 'public';"

echo "✅ Privilege control setup complete"
