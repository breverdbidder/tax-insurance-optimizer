-- TAX INSURANCE OPTIMIZER - Supabase Schema
-- Created by: Ariel Shapira, Solo Founder - Everest Capital of Brevard LLC
-- Version: 1.0.0 | Date: 2025-12-07

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- 1. Tax Years Configuration
CREATE TABLE IF NOT EXISTS tax_years (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    year INTEGER NOT NULL UNIQUE,
    filing_status VARCHAR(50) DEFAULT 'single',
    filer_name VARCHAR(255) NOT NULL,
    target_program VARCHAR(50) DEFAULT 'medicaid',
    income_goal DECIMAL(12,2),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Rental Properties
CREATE TABLE IF NOT EXISTS rental_properties (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tax_year_id UUID REFERENCES tax_years(id),
    address VARCHAR(500) NOT NULL,
    city VARCHAR(100) DEFAULT 'Melbourne',
    state VARCHAR(2) DEFAULT 'FL',
    zip VARCHAR(10),
    property_type VARCHAR(50) DEFAULT 'single_family',
    purchase_date DATE,
    purchase_price DECIMAL(12,2),
    current_market_value DECIMAL(12,2),
    mortgage_balance DECIMAL(12,2),
    is_primary_residence BOOLEAN DEFAULT FALSE,
    depreciation_basis DECIMAL(12,2),
    annual_depreciation DECIMAL(12,2),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 3. Rental Income (Monthly Tracking)
CREATE TABLE IF NOT EXISTS rental_income (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    property_id UUID REFERENCES rental_properties(id),
    year INTEGER NOT NULL,
    month INTEGER NOT NULL CHECK (month BETWEEN 1 AND 12),
    gross_rent DECIMAL(10,2) DEFAULT 0,
    vacancy_days INTEGER DEFAULT 0,
    vacancy_loss DECIMAL(10,2) DEFAULT 0,
    other_income DECIMAL(10,2) DEFAULT 0,
    collected BOOLEAN DEFAULT FALSE,
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(property_id, year, month)
);

-- 4. Rental Expenses (Schedule E Line Items)
CREATE TABLE IF NOT EXISTS rental_expenses (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    property_id UUID REFERENCES rental_properties(id),
    year INTEGER NOT NULL,
    month INTEGER,
    category VARCHAR(50) NOT NULL,
    subcategory VARCHAR(100),
    description TEXT,
    vendor VARCHAR(255),
    amount DECIMAL(10,2) NOT NULL,
    expense_date DATE,
    receipt_url TEXT,
    deductible BOOLEAN DEFAULT TRUE,
    schedule_e_line VARCHAR(20),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 5. Insurance Program Thresholds
CREATE TABLE IF NOT EXISTS insurance_thresholds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    program VARCHAR(50) NOT NULL,
    year INTEGER NOT NULL,
    state VARCHAR(2) DEFAULT 'FL',
    household_size INTEGER DEFAULT 1,
    income_limit_annual DECIMAL(12,2),
    income_limit_monthly DECIMAL(10,2),
    fpl_percentage INTEGER,
    asset_limit DECIMAL(12,2),
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(program, year, state, household_size)
);

-- Insert 2025/2026 Florida thresholds
INSERT INTO insurance_thresholds (program, year, state, household_size, income_limit_annual, income_limit_monthly, fpl_percentage, asset_limit, notes) VALUES
('medicaid', 2025, 'FL', 1, 20121, 1677, 138, 2000, 'FL Medicaid expansion - 138% FPL'),
('medicaid', 2025, 'FL', 2, 27214, 2268, 138, 3000, 'Married couple limit'),
('aca_silver_csr', 2025, 'FL', 1, 36450, 3038, 250, NULL, 'Silver CSR 94% actuarial value'),
('aca_bronze', 2025, 'FL', 1, 58320, 4860, 400, NULL, 'Standard ACA subsidy cutoff'),
('medicaid', 2026, 'FL', 1, 20783, 1732, 138, 2000, 'Projected 2026'),
('aca_silver_csr', 2026, 'FL', 1, 37650, 3138, 250, NULL, 'Projected 2026')
ON CONFLICT (program, year, state, household_size) DO NOTHING;

-- 6. MAGI Calculations
CREATE TABLE IF NOT EXISTS magi_calculations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tax_year_id UUID REFERENCES tax_years(id),
    calculation_date DATE DEFAULT CURRENT_DATE,
    month INTEGER,
    rental_gross_income DECIMAL(12,2) DEFAULT 0,
    rental_expenses_total DECIMAL(12,2) DEFAULT 0,
    rental_net_income DECIMAL(12,2) DEFAULT 0,
    other_income DECIMAL(12,2) DEFAULT 0,
    self_employment_tax_deduction DECIMAL(10,2) DEFAULT 0,
    health_insurance_deduction DECIMAL(10,2) DEFAULT 0,
    other_adjustments DECIMAL(10,2) DEFAULT 0,
    agi DECIMAL(12,2) DEFAULT 0,
    magi DECIMAL(12,2) DEFAULT 0,
    target_program VARCHAR(50),
    program_threshold DECIMAL(12,2),
    on_track BOOLEAN DEFAULT TRUE,
    headroom DECIMAL(12,2),
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 7. Asset Tracking (For Medicaid $2,000 limit)
CREATE TABLE IF NOT EXISTS asset_tracking (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tax_year_id UUID REFERENCES tax_years(id),
    asset_date DATE DEFAULT CURRENT_DATE,
    asset_type VARCHAR(100) NOT NULL,
    institution VARCHAR(255),
    account_name VARCHAR(255),
    description TEXT,
    current_value DECIMAL(12,2) NOT NULL,
    is_countable BOOLEAN DEFAULT TRUE,
    exempt_reason TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 8. Insurance Applications
CREATE TABLE IF NOT EXISTS insurance_applications (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    program VARCHAR(50) NOT NULL,
    application_type VARCHAR(50),
    application_date DATE,
    confirmation_number VARCHAR(100),
    status VARCHAR(50) DEFAULT 'pending',
    decision_date DATE,
    coverage_start_date DATE,
    coverage_end_date DATE,
    monthly_premium DECIMAL(8,2),
    documents_submitted JSONB DEFAULT '[]',
    notes TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 9. Tax Optimization Actions
CREATE TABLE IF NOT EXISTS tax_optimization_actions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tax_year_id UUID REFERENCES tax_years(id),
    action_type VARCHAR(100) NOT NULL,
    priority INTEGER DEFAULT 5 CHECK (priority BETWEEN 1 AND 10),
    description TEXT NOT NULL,
    potential_savings DECIMAL(10,2),
    impact_on_magi DECIMAL(10,2),
    deadline DATE,
    completed BOOLEAN DEFAULT FALSE,
    completed_date DATE,
    result TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- 10. Agent Decision Log
CREATE TABLE IF NOT EXISTS tax_agent_decisions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    decision_date TIMESTAMPTZ DEFAULT NOW(),
    decision_type VARCHAR(100) NOT NULL,
    input_data JSONB,
    analysis TEXT,
    recommendation TEXT,
    confidence_score DECIMAL(3,2),
    action_taken TEXT,
    outcome TEXT,
    model_used VARCHAR(50) DEFAULT 'claude-sonnet-4',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_rental_income_year ON rental_income(year, month);
CREATE INDEX IF NOT EXISTS idx_rental_expenses_year ON rental_expenses(year, category);
CREATE INDEX IF NOT EXISTS idx_magi_year ON magi_calculations(tax_year_id, month);
CREATE INDEX IF NOT EXISTS idx_assets_year ON asset_tracking(tax_year_id, is_countable);
CREATE INDEX IF NOT EXISTS idx_tax_years_year ON tax_years(year);

-- Grant permissions
GRANT SELECT ON ALL TABLES IN SCHEMA public TO anon;
GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO anon, service_role;
