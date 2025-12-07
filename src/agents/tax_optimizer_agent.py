"""
Tax Insurance Optimizer Agent
Life OS Module: Personal Finance
Created by: Ariel Shapira
Version: 1.1.0 | Date: 2025-12-07

Personal AI agent for optimizing rental property taxes to qualify for 
ACA Silver CSR insurance in FLORIDA (non-expansion state).

CRITICAL: Florida has NOT expanded Medicaid!
- Minimum income for ACA subsidies: $15,650 (100% FPL)
- Below $15,650 = COVERAGE GAP (no subsidies, no Medicaid)
- Target MAGI: $15,650 - $20,121 for BEST benefits (Silver CSR 94%)

Part of Shapira Life OS - https://breverdbidder.github.io/life-os
"""

import os
import json
from datetime import datetime, date
from decimal import Decimal
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, asdict
from supabase import create_client, Client

# Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://mocerqjnksmhcjzxrewo.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

# 2026 Federal Poverty Level (for 2026 coverage)
FPL_2026 = {
    "single": 15650,
    "two_person": 21150,
    "three_person": 26650,
    "four_person": 32150
}

# Insurance thresholds for 2026 Florida (NON-EXPANSION STATE)
# Florida did NOT expand Medicaid - minimum for ACA is 100% FPL
THRESHOLDS_2026 = {
    # BEST OPTION: ACA Silver CSR 94% (100-150% FPL)
    # $0 deductible, lowest copays, ~$1,350 out-of-pocket max
    "aca_silver_csr_94": {
        "single_min": 15650,   # 100% FPL - MINIMUM for any subsidy
        "single_max": 23475,   # 150% FPL
        "married_min": 21150,
        "married_max": 31725,
        "asset_limit": None,   # No asset test for ACA
        "fpl_percentage_min": 100,
        "fpl_percentage_max": 150,
        "actuarial_value": 94,
        "monthly_premium": "0-50",
        "deductible": 0
    },
    # GOOD: ACA Silver CSR 87% (150-200% FPL)
    "aca_silver_csr_87": {
        "single_min": 23476,
        "single_max": 31300,   # 200% FPL
        "married_min": 31726,
        "married_max": 42300,
        "asset_limit": None,
        "fpl_percentage_min": 150,
        "fpl_percentage_max": 200,
        "actuarial_value": 87,
        "monthly_premium": "50-150",
        "deductible": "250-500"
    },
    # OK: ACA Silver CSR 73% (200-250% FPL)
    "aca_silver_csr_73": {
        "single_min": 31301,
        "single_max": 39125,   # 250% FPL
        "married_min": 42301,
        "married_max": 52875,
        "asset_limit": None,
        "fpl_percentage_min": 200,
        "fpl_percentage_max": 250,
        "actuarial_value": 73,
        "monthly_premium": "100-250",
        "deductible": "500-1500"
    },
    # SUBSIDY ONLY (no CSR): 250-400% FPL
    "aca_subsidy_only": {
        "single_min": 39126,
        "single_max": 62600,   # 400% FPL - subsidy cliff
        "married_min": 52876,
        "married_max": 84600,
        "asset_limit": None,
        "fpl_percentage_min": 250,
        "fpl_percentage_max": 400,
        "actuarial_value": 70,  # Standard Silver
        "monthly_premium": "200-500",
        "deductible": "2000-5000"
    },
    # COVERAGE GAP - below 100% FPL in Florida
    "coverage_gap": {
        "single_max": 15649,
        "married_max": 21149,
        "warning": "NO SUBSIDIES - Florida coverage gap! Must increase income to $15,650+"
    }
}

# Legacy thresholds for backward compatibility
THRESHOLDS_2025 = {
    "medicaid": {
        "single": 20121,
        "married": 27214,
        "asset_limit_single": 2000,
        "asset_limit_married": 3000,
        "fpl_percentage": 138,
        "warning": "Florida has NOT expanded Medicaid - most adults don't qualify!"
    },
    "aca_silver_csr": {
        "single": 36450,
        "married": 49350,
        "asset_limit": None,
        "fpl_percentage": 250
    },
    "aca_bronze": {
        "single": 58320,
        "married": 79120,
        "asset_limit": None,
        "fpl_percentage": 400
    }
}

# OPTIMAL TARGET for Ariel Shapira in Florida
OPTIMAL_MAGI_TARGET = {
    "minimum": 15650,  # 100% FPL - absolute minimum for ACA
    "optimal_low": 15650,
    "optimal_high": 20121,  # Below old Medicaid threshold for safety
    "description": "ACA Silver CSR 94% - best coverage at lowest cost",
    "benefits": {
        "monthly_premium": "$0-50",
        "deductible": "$0",
        "doctor_visit": "$5-10",
        "specialist": "$10-20",
        "out_of_pocket_max": "$1,350",
        "mayo_clinic": "In-Network (BlueOptions PPO)",
        "uf_health": "In-Network (BlueOptions PPO)"
    }
}

# Schedule E expense categories
SCHEDULE_E_CATEGORIES = {
    "advertising": {"line": 5, "description": "Advertising"},
    "auto_travel": {"line": 6, "description": "Auto and travel"},
    "cleaning_maintenance": {"line": 7, "description": "Cleaning and maintenance"},
    "commissions": {"line": 8, "description": "Commissions"},
    "insurance": {"line": 9, "description": "Insurance"},
    "legal_professional": {"line": 10, "description": "Legal and other professional fees"},
    "management_fees": {"line": 11, "description": "Management fees"},
    "mortgage_interest": {"line": 12, "description": "Mortgage interest paid to banks"},
    "other_interest": {"line": 13, "description": "Other interest"},
    "repairs": {"line": 14, "description": "Repairs"},
    "supplies": {"line": 15, "description": "Supplies"},
    "property_taxes": {"line": 16, "description": "Taxes"},
    "utilities": {"line": 17, "description": "Utilities"},
    "depreciation": {"line": 18, "description": "Depreciation expense"},
    "other": {"line": 19, "description": "Other expenses"}
}


@dataclass
class MAGICalculation:
    """Modified Adjusted Gross Income calculation"""
    year: int
    gross_rental_income: Decimal
    total_expenses: Decimal
    net_rental_income: Decimal
    other_income: Decimal
    adjustments: Decimal
    agi: Decimal
    magi: Decimal
    target_program: str
    threshold: Decimal
    headroom: Decimal
    on_track: bool


@dataclass
class AssetSummary:
    """Asset summary for Medicaid eligibility"""
    total_countable: Decimal
    total_exempt: Decimal
    asset_limit: Decimal
    under_limit: bool
    countable_assets: List[Dict]
    exempt_assets: List[Dict]


class TaxInsuranceOptimizer:
    """
    AI Agent for Tax Optimization & Insurance Qualification
    
    Core Functions:
    1. Track rental income and expenses
    2. Calculate MAGI in real-time
    3. Monitor insurance qualification thresholds
    4. Recommend tax optimization strategies
    5. Track asset limits for Medicaid
    6. Generate Schedule E data
    """
    
    def __init__(self):
        if not SUPABASE_KEY:
            raise ValueError("SUPABASE_SERVICE_KEY environment variable required")
        self.supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
        self.current_year = datetime.now().year
        
    def get_or_create_tax_year(self, year: int, filer_name: str, 
                                filing_status: str = "single",
                                target_program: str = "medicaid") -> Dict:
        """Get or create tax year configuration"""
        result = self.supabase.table("tax_years").select("*").eq("year", year).execute()
        
        if result.data:
            return result.data[0]
        
        # Create new tax year
        income_goal = THRESHOLDS_2025.get(target_program, {}).get(filing_status, 20121)
        
        new_year = {
            "year": year,
            "filing_status": filing_status,
            "filer_name": filer_name,
            "target_program": target_program,
            "income_goal": float(income_goal)
        }
        
        result = self.supabase.table("tax_years").insert(new_year).execute()
        return result.data[0]
    
    def add_rental_property(self, tax_year_id: str, address: str,
                           purchase_price: float, current_value: float,
                           mortgage_balance: float, is_primary: bool = False,
                           city: str = "Melbourne", state: str = "FL",
                           zip_code: str = None) -> Dict:
        """Add a rental property"""
        # Calculate depreciation (27.5 years for residential)
        # Land is typically 20% of value, building 80%
        building_value = purchase_price * 0.80
        annual_depreciation = building_value / 27.5
        
        property_data = {
            "tax_year_id": tax_year_id,
            "address": address,
            "city": city,
            "state": state,
            "zip": zip_code,
            "purchase_price": purchase_price,
            "current_market_value": current_value,
            "mortgage_balance": mortgage_balance,
            "is_primary_residence": is_primary,
            "depreciation_basis": building_value,
            "annual_depreciation": annual_depreciation
        }
        
        result = self.supabase.table("rental_properties").insert(property_data).execute()
        return result.data[0]
    
    def record_rental_income(self, property_id: str, year: int, month: int,
                            gross_rent: float, vacancy_days: int = 0,
                            other_income: float = 0) -> Dict:
        """Record monthly rental income"""
        # Calculate vacancy loss (gross_rent / 30 * vacancy_days)
        daily_rate = gross_rent / 30
        vacancy_loss = daily_rate * vacancy_days
        
        income_data = {
            "property_id": property_id,
            "year": year,
            "month": month,
            "gross_rent": gross_rent,
            "vacancy_days": vacancy_days,
            "vacancy_loss": vacancy_loss,
            "other_income": other_income,
            "collected": True
        }
        
        result = self.supabase.table("rental_income").upsert(
            income_data, 
            on_conflict="property_id,year,month"
        ).execute()
        return result.data[0]
    
    def record_expense(self, property_id: str, year: int, category: str,
                      amount: float, description: str = None,
                      vendor: str = None, expense_date: str = None,
                      month: int = None) -> Dict:
        """Record a rental expense"""
        if category not in SCHEDULE_E_CATEGORIES:
            raise ValueError(f"Invalid category. Must be one of: {list(SCHEDULE_E_CATEGORIES.keys())}")
        
        expense_data = {
            "property_id": property_id,
            "year": year,
            "month": month,
            "category": category,
            "description": description,
            "vendor": vendor,
            "amount": amount,
            "expense_date": expense_date,
            "schedule_e_line": f"Line {SCHEDULE_E_CATEGORIES[category]['line']}"
        }
        
        result = self.supabase.table("rental_expenses").insert(expense_data).execute()
        return result.data[0]
    
    def calculate_magi(self, tax_year_id: str, year: int) -> MAGICalculation:
        """
        Calculate Modified Adjusted Gross Income for insurance qualification
        
        MAGI = AGI + Tax-exempt interest + Non-taxable Social Security
        For rental income: MAGI = Net Rental Income (Gross - Expenses)
        """
        # Get tax year config
        tax_year = self.supabase.table("tax_years").select("*").eq("id", tax_year_id).single().execute()
        
        # Get all properties for this tax year
        properties = self.supabase.table("rental_properties").select("id").eq("tax_year_id", tax_year_id).execute()
        property_ids = [p["id"] for p in properties.data]
        
        # Calculate gross rental income
        income_result = self.supabase.table("rental_income").select("gross_rent, vacancy_loss, other_income").in_("property_id", property_ids).eq("year", year).execute()
        
        gross_income = sum(Decimal(str(r.get("gross_rent", 0))) for r in income_result.data)
        vacancy_loss = sum(Decimal(str(r.get("vacancy_loss", 0))) for r in income_result.data)
        other_income = sum(Decimal(str(r.get("other_income", 0))) for r in income_result.data)
        
        # Calculate total expenses
        expenses_result = self.supabase.table("rental_expenses").select("amount, category").in_("property_id", property_ids).eq("year", year).execute()
        
        total_expenses = sum(Decimal(str(e.get("amount", 0))) for e in expenses_result.data)
        
        # Add depreciation from properties
        props_result = self.supabase.table("rental_properties").select("annual_depreciation").eq("tax_year_id", tax_year_id).execute()
        depreciation = sum(Decimal(str(p.get("annual_depreciation", 0))) for p in props_result.data)
        total_expenses += depreciation
        
        # Calculate net rental income
        net_rental = gross_income - vacancy_loss + other_income - total_expenses
        
        # For pure rental income, MAGI = Net Rental Income
        # (No other income sources in this simplified model)
        agi = net_rental
        magi = agi  # Add back items if needed
        
        # Get threshold for target program
        target_program = tax_year.data.get("target_program", "medicaid")
        filing_status = tax_year.data.get("filing_status", "single")
        
        threshold = Decimal(str(THRESHOLDS_2025.get(target_program, {}).get(filing_status, 20121)))
        headroom = threshold - magi
        on_track = magi <= threshold
        
        calculation = MAGICalculation(
            year=year,
            gross_rental_income=gross_income,
            total_expenses=total_expenses,
            net_rental_income=net_rental,
            other_income=other_income,
            adjustments=Decimal("0"),
            agi=agi,
            magi=magi,
            target_program=target_program,
            threshold=threshold,
            headroom=headroom,
            on_track=on_track
        )
        
        # Store calculation
        calc_data = {
            "tax_year_id": tax_year_id,
            "calculation_date": date.today().isoformat(),
            "rental_gross_income": float(gross_income),
            "rental_expenses_total": float(total_expenses),
            "rental_net_income": float(net_rental),
            "other_income": float(other_income),
            "agi": float(agi),
            "magi": float(magi),
            "target_program": target_program,
            "program_threshold": float(threshold),
            "on_track": on_track,
            "headroom": float(headroom)
        }
        
        self.supabase.table("magi_calculations").insert(calc_data).execute()
        
        return calculation
    
    def check_asset_eligibility(self, tax_year_id: str) -> AssetSummary:
        """Check if assets are under Medicaid limit"""
        tax_year = self.supabase.table("tax_years").select("filing_status").eq("id", tax_year_id).single().execute()
        filing_status = tax_year.data.get("filing_status", "single")
        
        asset_limit = THRESHOLDS_2025["medicaid"]["asset_limit_single"] if filing_status == "single" else THRESHOLDS_2025["medicaid"]["asset_limit_married"]
        
        assets = self.supabase.table("asset_tracking").select("*").eq("tax_year_id", tax_year_id).execute()
        
        countable = [a for a in assets.data if a.get("is_countable", True)]
        exempt = [a for a in assets.data if not a.get("is_countable", True)]
        
        total_countable = sum(Decimal(str(a.get("current_value", 0))) for a in countable)
        total_exempt = sum(Decimal(str(a.get("current_value", 0))) for a in exempt)
        
        return AssetSummary(
            total_countable=total_countable,
            total_exempt=total_exempt,
            asset_limit=Decimal(str(asset_limit)),
            under_limit=total_countable <= asset_limit,
            countable_assets=countable,
            exempt_assets=exempt
        )
    
    def add_asset(self, tax_year_id: str, asset_type: str, value: float,
                 description: str = None, institution: str = None,
                 is_countable: bool = True, exempt_reason: str = None) -> Dict:
        """Track an asset for Medicaid eligibility"""
        asset_data = {
            "tax_year_id": tax_year_id,
            "asset_type": asset_type,
            "current_value": value,
            "description": description,
            "institution": institution,
            "is_countable": is_countable,
            "exempt_reason": exempt_reason,
            "asset_date": date.today().isoformat()
        }
        
        result = self.supabase.table("asset_tracking").insert(asset_data).execute()
        return result.data[0]
    
    def generate_schedule_e_summary(self, property_id: str, year: int) -> Dict:
        """Generate Schedule E expense summary by category"""
        expenses = self.supabase.table("rental_expenses").select("category, amount").eq("property_id", property_id).eq("year", year).execute()
        
        # Group by category
        summary = {}
        for exp in expenses.data:
            cat = exp["category"]
            if cat not in summary:
                summary[cat] = {
                    "line": SCHEDULE_E_CATEGORIES[cat]["line"],
                    "description": SCHEDULE_E_CATEGORIES[cat]["description"],
                    "total": Decimal("0")
                }
            summary[cat]["total"] += Decimal(str(exp["amount"]))
        
        # Get depreciation from property
        prop = self.supabase.table("rental_properties").select("annual_depreciation").eq("id", property_id).single().execute()
        if prop.data and prop.data.get("annual_depreciation"):
            summary["depreciation"] = {
                "line": 18,
                "description": "Depreciation expense",
                "total": Decimal(str(prop.data["annual_depreciation"]))
            }
        
        # Calculate totals
        total_expenses = sum(s["total"] for s in summary.values())
        
        return {
            "property_id": property_id,
            "year": year,
            "expenses_by_line": summary,
            "total_expenses": float(total_expenses)
        }
    
    def get_optimization_recommendations(self, tax_year_id: str) -> List[Dict]:
        """
        Generate tax optimization recommendations for FLORIDA (non-expansion state)
        
        CRITICAL: Florida has NOT expanded Medicaid!
        - Below $15,650 = COVERAGE GAP (no insurance help!)
        - Target: $15,650 - $20,121 for ACA Silver CSR 94%
        """
        magi_calc = self.calculate_magi(tax_year_id, self.current_year)
        
        recommendations = []
        magi = float(magi_calc.magi)
        
        # CRITICAL: Check for Florida coverage gap (below 100% FPL)
        min_for_aca = OPTIMAL_MAGI_TARGET["minimum"]  # $15,650
        optimal_low = OPTIMAL_MAGI_TARGET["optimal_low"]
        optimal_high = OPTIMAL_MAGI_TARGET["optimal_high"]
        
        if magi < min_for_aca:
            # DANGER: Coverage gap!
            shortfall = min_for_aca - magi
            recommendations.append({
                "priority": 1,
                "action_type": "COVERAGE_GAP_WARNING",
                "description": f"🚨 DANGER: MAGI ${magi:,.2f} is BELOW $15,650 minimum! You're in Florida's COVERAGE GAP - NO subsidies, NO Medicaid!",
                "potential_savings": shortfall,
                "impact_on_magi": shortfall,
                "suggestions": [
                    f"INCREASE income by ${shortfall:,.2f} to reach $15,650",
                    "REDUCE deductible expenses (defer repairs to next year)",
                    "Don't prepay property taxes for 2026",
                    "Delay depreciation claims if possible",
                    "Consider taking less mortgage interest deduction"
                ]
            })
        
        elif magi >= min_for_aca and magi <= optimal_high:
            # PERFECT: In optimal range for ACA Silver CSR 94%
            headroom_low = magi - min_for_aca
            headroom_high = optimal_high - magi
            recommendations.append({
                "priority": 10,
                "action_type": "OPTIMAL_RANGE",
                "description": f"✅ PERFECT! MAGI ${magi:,.2f} qualifies for ACA Silver CSR 94% (best coverage!)",
                "potential_savings": 0,
                "impact_on_magi": 0,
                "suggestions": [
                    f"You're ${headroom_low:,.2f} above minimum ($15,650)",
                    f"You have ${headroom_high:,.2f} headroom before losing CSR 94%",
                    "Enroll in Florida Blue BlueOptions Silver PPO by Dec 15",
                    "Mayo Clinic & UF Health are IN-NETWORK",
                    "Expected premium: $0-50/month, $0 deductible"
                ]
            })
        
        elif magi > optimal_high and magi <= 23475:
            # GOOD: Still CSR 94% but approaching CSR 87% threshold
            recommendations.append({
                "priority": 5,
                "action_type": "GOOD_BUT_WATCH",
                "description": f"✅ GOOD: MAGI ${magi:,.2f} still qualifies for CSR 94%, but approaching 150% FPL",
                "potential_savings": magi - optimal_high,
                "impact_on_magi": magi - optimal_high,
                "suggestions": [
                    "Consider reducing income slightly for safety margin",
                    f"${23475 - magi:,.2f} headroom before losing CSR 94%",
                    "Enroll by December 15 for January 1 coverage"
                ]
            })
        
        elif magi > 23475 and magi <= 31300:
            # OK: CSR 87% range
            excess = magi - optimal_high
            recommendations.append({
                "priority": 3,
                "action_type": "CSR_87_RANGE",
                "description": f"⚠️ MAGI ${magi:,.2f} qualifies for CSR 87% (good, but not best)",
                "potential_savings": excess,
                "impact_on_magi": excess,
                "suggestions": [
                    f"Reduce MAGI by ${magi - optimal_high:,.2f} for CSR 94%",
                    "Increase deductible repairs/maintenance",
                    "Prepay 2026 property taxes in 2025",
                    "Current benefits: ~$250-500 deductible"
                ]
            })
        
        elif magi > 31300 and magi <= 62600:
            # SUBSIDY ONLY: No CSR
            recommendations.append({
                "priority": 2,
                "action_type": "NO_CSR",
                "description": f"⚠️ MAGI ${magi:,.2f} - subsidy only, NO cost-sharing reductions",
                "potential_savings": magi - optimal_high,
                "impact_on_magi": magi - optimal_high,
                "suggestions": [
                    f"Reduce MAGI by ${magi - optimal_high:,.2f} for CSR 94%",
                    "Higher deductibles and copays at this income",
                    "Consider maximizing all deductions"
                ]
            })
        
        else:
            # Above 400% FPL - no subsidies
            recommendations.append({
                "priority": 1,
                "action_type": "NO_SUBSIDIES",
                "description": f"❌ MAGI ${magi:,.2f} exceeds 400% FPL ($62,600) - NO subsidies available",
                "potential_savings": magi - optimal_high,
                "impact_on_magi": magi - optimal_high,
                "suggestions": [
                    "Significantly reduce taxable income",
                    "Maximize all Schedule E deductions",
                    "Consider retirement contributions"
                ]
            })
        
        # Add deadline reminder
        recommendations.append({
            "priority": 8,
            "action_type": "DEADLINE_REMINDER",
            "description": "📅 ACA Open Enrollment: Enroll by December 15 for January 1 coverage",
            "potential_savings": 0,
            "impact_on_magi": 0,
            "suggestions": [
                "Website: healthcare.gov",
                "Plan: Florida Blue BlueOptions Silver PPO",
                "Also enroll in dental (Ameritas or Delta Dental PPO)",
                "12-month waiting period for dental bridges"
            ]
        })
        
        # Store recommendations
        for rec in recommendations:
            rec_data = {
                "tax_year_id": tax_year_id,
                "action_type": rec["action_type"],
                "priority": rec["priority"],
                "description": rec["description"],
                "potential_savings": rec.get("potential_savings", 0),
                "impact_on_magi": rec.get("impact_on_magi", 0)
            }
            self.supabase.table("tax_optimization_actions").insert(rec_data).execute()
        
        return recommendations
    
    def log_decision(self, decision_type: str, input_data: Dict,
                    analysis: str, recommendation: str,
                    confidence: float = 0.8) -> Dict:
        """Log an AI agent decision for audit trail"""
        decision = {
            "decision_type": decision_type,
            "input_data": json.dumps(input_data),
            "analysis": analysis,
            "recommendation": recommendation,
            "confidence_score": confidence,
            "model_used": "claude-sonnet-4"
        }
        
        result = self.supabase.table("tax_agent_decisions").insert(decision).execute()
        return result.data[0]


def main():
    """Example usage"""
    agent = TaxInsuranceOptimizer()
    
    # Create 2024 tax year
    tax_year = agent.get_or_create_tax_year(
        year=2024,
        filer_name="Ariel Shapira",
        filing_status="married",
        target_program="medicaid"
    )
    
    print(f"Tax Year Created: {tax_year['id']}")
    
    # Calculate MAGI
    magi = agent.calculate_magi(tax_year["id"], 2024)
    print(f"\nMAGI Calculation:")
    print(f"  Gross Income: ${magi.gross_rental_income:,.2f}")
    print(f"  Expenses: ${magi.total_expenses:,.2f}")
    print(f"  Net Income: ${magi.net_rental_income:,.2f}")
    print(f"  MAGI: ${magi.magi:,.2f}")
    print(f"  Threshold: ${magi.threshold:,.2f}")
    print(f"  On Track: {magi.on_track}")
    
    # Get recommendations
    recs = agent.get_optimization_recommendations(tax_year["id"])
    print(f"\nRecommendations:")
    for rec in recs:
        print(f"  [{rec['priority']}] {rec['description']}")


if __name__ == "__main__":
    main()
