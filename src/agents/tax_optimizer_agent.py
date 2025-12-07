"""
Tax Insurance Optimizer Agent
Created by: Ariel Shapira, Solo Founder - Everest Capital of Brevard LLC
Version: 1.0.0 | Date: 2025-12-07

Agentic AI for optimizing rental property taxes to qualify for 
Medicaid or ACA insurance programs.
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

# Insurance thresholds for 2025 Florida
THRESHOLDS_2025 = {
    "medicaid": {
        "single": 20121,
        "married": 27214,
        "asset_limit_single": 2000,
        "asset_limit_married": 3000,
        "fpl_percentage": 138
    },
    "aca_silver_csr": {
        "single": 36450,
        "married": 49350,
        "asset_limit": None,  # No asset test
        "fpl_percentage": 250
    },
    "aca_bronze": {
        "single": 58320,
        "married": 79120,
        "asset_limit": None,
        "fpl_percentage": 400
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
        """Generate tax optimization recommendations"""
        magi_calc = self.calculate_magi(tax_year_id, self.current_year)
        asset_summary = self.check_asset_eligibility(tax_year_id)
        
        recommendations = []
        
        # Check if over income threshold
        if not magi_calc.on_track:
            recommendations.append({
                "priority": 1,
                "action_type": "reduce_income",
                "description": f"MAGI (${magi_calc.magi:,.2f}) exceeds {magi_calc.target_program} threshold (${magi_calc.threshold:,.2f}) by ${abs(magi_calc.headroom):,.2f}",
                "potential_savings": float(abs(magi_calc.headroom)),
                "suggestions": [
                    "Increase deductible repairs/maintenance",
                    "Prepay property taxes",
                    "Review depreciation calculations",
                    "Consider ACA instead if MAGI > $20,121"
                ]
            })
        
        # Check asset limits for Medicaid
        if magi_calc.target_program == "medicaid" and not asset_summary.under_limit:
            over_by = asset_summary.total_countable - asset_summary.asset_limit
            recommendations.append({
                "priority": 2,
                "action_type": "reduce_assets",
                "description": f"Countable assets (${asset_summary.total_countable:,.2f}) exceed Medicaid limit (${asset_summary.asset_limit:,.2f}) by ${over_by:,.2f}",
                "potential_savings": float(over_by),
                "suggestions": [
                    "Pay off debts",
                    "Prepay expenses",
                    "Purchase exempt assets (funeral, one vehicle)",
                    "Consider ACA (no asset limit)"
                ]
            })
        
        # If on track, provide status
        if magi_calc.on_track:
            recommendations.append({
                "priority": 10,
                "action_type": "status",
                "description": f"✅ ON TRACK for {magi_calc.target_program}: MAGI ${magi_calc.magi:,.2f} with ${magi_calc.headroom:,.2f} headroom",
                "potential_savings": 0,
                "suggestions": [
                    "Continue tracking expenses",
                    "Document all receipts",
                    "Apply by December 15 deadline"
                ]
            })
        
        # Store recommendations
        for rec in recommendations:
            rec_data = {
                "tax_year_id": tax_year_id,
                "action_type": rec["action_type"],
                "priority": rec["priority"],
                "description": rec["description"],
                "potential_savings": rec["potential_savings"],
                "impact_on_magi": rec.get("potential_savings", 0)
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
