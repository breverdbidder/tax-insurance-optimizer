# 🏥 Tax Insurance Optimizer

**Life OS Module: Personal Tax Optimization for Insurance Qualification**

Part of [Shapira Life OS](https://breverdbidder.github.io/life-os) | Created by **Ariel Shapira**

---

## 🎯 Purpose

Personal AI agent that optimizes rental property taxes to qualify for optimal health insurance:

| Program | Income Limit (Single) | Asset Limit | Annual Cost |
|---------|----------------------|-------------|-------------|
| **Medicaid** | $20,121 | $2,000 | $0-200 |
| **ACA Silver CSR** | $36,450 | None | $300-800 |

**Your Target:** $9,000 MAGI → Medicaid qualification ✅

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│              LIFE OS - TAX INSURANCE OPTIMIZER              │
│                    Personal Finance Module                   │
└─────────────────────────────────────────────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│  GITHUB         │  │  SUPABASE       │  │  LIFE OS        │
│  ACTIONS        │  │  PostgreSQL     │  │  Dashboard      │
│  (Compute)      │  │  (UI)           │  │                 │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

**Stack:** GitHub + Supabase + GitHub Actions (same as Life OS core)

---

## 📊 Database Tables (Supabase)

| Table | Purpose |
|-------|---------|
| `tax_years` | Tax year configuration (2024, 2025) |
| `rental_properties` | Property details + auto depreciation |
| `rental_income` | Monthly rent tracking |
| `rental_expenses` | Schedule E categories |
| `insurance_thresholds` | Medicaid/ACA limits (pre-populated) |
| `magi_calculations` | Real-time MAGI tracking |
| `asset_tracking` | Medicaid $2,000 asset limit |
| `insurance_applications` | Application status tracking |
| `tax_optimization_actions` | AI recommendations |
| `tax_agent_decisions` | Audit trail |

---

## 🚀 Setup

### Step 1: Create Supabase Tables

Run in Supabase SQL Editor:
- URL: https://supabase.com/dashboard/project/mocerqjnksmhcjzxrewo/sql/new
- File: `sql/schema.sql`

### Step 2: Add GitHub Secrets

Go to: https://github.com/breverdbidder/tax-insurance-optimizer/settings/secrets/actions

Add:
- `SUPABASE_URL`: `https://mocerqjnksmhcjzxrewo.supabase.co`
- `SUPABASE_SERVICE_KEY`: Your service_role key

### Step 3: Run Analysis

Trigger manually or wait for weekly Monday run.

---

## 📋 Schedule E Categories

| Category | IRS Line | Examples |
|----------|----------|----------|
| `mortgage_interest` | Line 12 | Monthly mortgage payment interest |
| `property_taxes` | Line 16 | Annual property taxes |
| `insurance` | Line 9 | Homeowners, liability |
| `repairs` | Line 14 | Fixes, maintenance |
| `utilities` | Line 17 | Water, electric (if landlord pays) |
| `management_fees` | Line 11 | Property manager % |
| `depreciation` | Line 18 | Auto-calculated (27.5 years) |
| `cleaning_maintenance` | Line 7 | Cleaning between tenants |
| `advertising` | Line 5 | Listing fees |
| `legal_professional` | Line 10 | Eviction, CPA fees |

---

## 💰 Your 2024/2025 Strategy

### Income Target: $9,000 MAGI

```
Gross Rental Income:     $18,000 (estimate)
- Mortgage Interest:     -$6,000
- Property Taxes:        -$3,000
- Insurance:             -$1,200
- Repairs/Maintenance:   -$2,000
- Depreciation:          -$5,818 (auto-calc)
─────────────────────────────────────
= Net Rental Income:     $0 to $9,000 ✅

MAGI: $9,000 → QUALIFIES for Medicaid!
```

### Asset Strategy (Medicaid $2,000 limit)

**If Primary Residence:** Property is EXEMPT ✅
**If Not Primary:** Equity counts toward limit

Options if over $2,000:
1. Spend down (pay debts, prepay expenses)
2. Use ACA instead (no asset limit)

---

## 📅 Key Deadlines

| Date | Action |
|------|--------|
| **Dec 15, 2025** | ACA enrollment deadline for Jan 1 coverage |
| **Dec 31, 2025** | Final 2025 expense tracking |
| **Apr 15, 2026** | File 2025 taxes |

---

## 🔗 Integration with Life OS

This module feeds into the Life OS dashboard:
- **Domain:** PERSONAL > Health & Finance
- **Tracking:** Insurance qualification status
- **Alerts:** Deadline reminders, MAGI warnings

---

## 📞 Resources

**Medicaid:**
- Apply: www.myflorida.com/accessflorida
- Phone: (866) 762-2237
- DCF Melbourne: (321) 752-4643

**ACA:**
- Apply: www.healthcare.gov
- Phone: (800) 318-2596

**Genetic Testing Facilities:**
- Nemours Melbourne: (321) 722-5437 (LOCAL!)
- UF Health: (352) 294-5050
- Mayo Clinic: (904) 953-0853

---

*Part of Shapira Life OS - ADHD-optimized productivity system*
