"""
Insurance Recommendation Engine
Life OS Module: Personal Finance
Created by: Ariel Shapira
Version: 1.0.0 | Date: 2026-01-30

Generates personalized insurance recommendations based on MAGI,
family situation, and Florida-specific ACA rules.

CRITICAL: Florida has NOT expanded Medicaid!
- Below $15,650 = COVERAGE GAP (no help!)
- Target: $15,650 - $20,121 for best ACA Silver CSR 94%
"""

import os
from datetime import datetime, date
from decimal import Decimal
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from supabase import create_client, Client

# Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL", "https://mocerqjnksmhcjzxrewo.supabase.co")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_KEY")


# 2026 Federal Poverty Level
FPL_2026 = {
    1: 15650,
    2: 21150,
    3: 26650,
    4: 32150,
    5: 37650,
    6: 43150,
    7: 48650,
    8: 54150
}


@dataclass
class InsurancePlan:
    """Recommended insurance plan"""
    plan_type: str
    carrier: str
    plan_name: str
    metal_tier: str
    monthly_premium: str
    deductible: str
    out_of_pocket_max: str
    copay_primary: str
    copay_specialist: str
    includes_dental: bool
    includes_vision: bool
    network_type: str
    key_hospitals: List[str]
    enrollment_deadline: str
    coverage_start: str
    notes: List[str]


@dataclass
class InsuranceRecommendation:
    """Full insurance recommendation"""
    magi: float
    household_size: int
    fpl_percentage: float
    eligibility_tier: str
    tier_description: str
    recommended_plans: List[InsurancePlan]
    action_items: List[str]
    warnings: List[str]
    optimization_tips: List[str]
    annual_savings_potential: float
    generated_at: str


class InsuranceRecommendationEngine:
    """
    AI-powered insurance recommendation engine for Florida residents.
    
    Features:
    1. Determine ACA eligibility tier based on MAGI
    2. Recommend specific plans (Florida Blue, Ambetter, etc.)
    3. Calculate potential savings
    4. Generate enrollment action items
    5. Provide optimization tips to improve coverage
    """
    
    def __init__(self):
        if SUPABASE_KEY:
            self.supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)
        else:
            self.supabase = None
    
    def calculate_fpl_percentage(self, magi: float, household_size: int = 1) -> float:
        """Calculate Federal Poverty Level percentage"""
        fpl = FPL_2026.get(household_size, 15650)
        return (magi / fpl) * 100
    
    def determine_eligibility_tier(self, fpl_pct: float) -> Tuple[str, str]:
        """
        Determine ACA eligibility tier based on FPL percentage.
        
        FLORIDA SPECIFIC - Non-expansion state!
        """
        if fpl_pct < 100:
            return "coverage_gap", "🚨 COVERAGE GAP - No ACA subsidies, no Medicaid in Florida!"
        elif fpl_pct <= 150:
            return "csr_94", "✅ BEST: Silver CSR 94% - $0 deductible, lowest copays"
        elif fpl_pct <= 200:
            return "csr_87", "✅ GOOD: Silver CSR 87% - Low deductible, good copays"
        elif fpl_pct <= 250:
            return "csr_73", "⚠️ OK: Silver CSR 73% - Standard silver benefits"
        elif fpl_pct <= 400:
            return "subsidy_only", "⚠️ Subsidy only - No cost-sharing reductions"
        else:
            return "no_subsidy", "❌ NO SUBSIDIES - Above 400% FPL"
    
    def get_florida_plans(self, tier: str) -> List[InsurancePlan]:
        """Get recommended Florida marketplace plans for tier"""
        
        plans = []
        
        if tier in ["csr_94", "csr_87", "csr_73"]:
            # Florida Blue - Best network
            plans.append(InsurancePlan(
                plan_type="ACA Marketplace",
                carrier="Florida Blue",
                plan_name="BlueOptions Silver PPO",
                metal_tier="Silver + CSR",
                monthly_premium="$0-75" if tier == "csr_94" else "$50-150",
                deductible="$0" if tier == "csr_94" else "$250-1000",
                out_of_pocket_max="$1,350" if tier == "csr_94" else "$2,500-4,000",
                copay_primary="$5-10",
                copay_specialist="$10-25",
                includes_dental=False,
                includes_vision=True,
                network_type="PPO",
                key_hospitals=["Mayo Clinic Jacksonville", "UF Health", "AdventHealth", "Baptist Health"],
                enrollment_deadline="December 15",
                coverage_start="January 1",
                notes=[
                    "Largest network in Florida",
                    "No referrals needed for specialists",
                    "Mayo Clinic is IN-NETWORK",
                    "BlueCard for nationwide coverage"
                ]
            ))
            
            # Ambetter - Lower cost option
            plans.append(InsurancePlan(
                plan_type="ACA Marketplace",
                carrier="Ambetter from Sunshine Health",
                plan_name="Secure Care Silver",
                metal_tier="Silver + CSR",
                monthly_premium="$0-50" if tier == "csr_94" else "$25-100",
                deductible="$0" if tier == "csr_94" else "$200-800",
                out_of_pocket_max="$1,350" if tier == "csr_94" else "$2,000-3,500",
                copay_primary="$5",
                copay_specialist="$15-30",
                includes_dental=False,
                includes_vision=True,
                network_type="HMO",
                key_hospitals=["Cleveland Clinic Florida", "Memorial Healthcare", "AdventHealth"],
                enrollment_deadline="December 15",
                coverage_start="January 1",
                notes=[
                    "Lowest premiums",
                    "Telehealth included",
                    "Requires referrals for specialists",
                    "Good for routine care"
                ]
            ))
        
        elif tier == "subsidy_only":
            plans.append(InsurancePlan(
                plan_type="ACA Marketplace",
                carrier="Florida Blue",
                plan_name="BlueOptions Silver PPO",
                metal_tier="Silver (No CSR)",
                monthly_premium="$150-300",
                deductible="$2,000-4,000",
                out_of_pocket_max="$6,500-8,000",
                copay_primary="$30-50",
                copay_specialist="$50-75",
                includes_dental=False,
                includes_vision=True,
                network_type="PPO",
                key_hospitals=["Mayo Clinic Jacksonville", "UF Health"],
                enrollment_deadline="December 15",
                coverage_start="January 1",
                notes=[
                    "Consider reducing MAGI for CSR benefits",
                    "Bronze plan may be better value",
                    "HSA-eligible plans available"
                ]
            ))
        
        elif tier == "coverage_gap":
            # No marketplace options, recommend alternatives
            plans.append(InsurancePlan(
                plan_type="Alternative",
                carrier="Direct Primary Care",
                plan_name="Concierge/DPC Membership",
                metal_tier="N/A",
                monthly_premium="$75-150",
                deductible="N/A",
                out_of_pocket_max="N/A",
                copay_primary="$0 (included)",
                copay_specialist="Pay separately",
                includes_dental=False,
                includes_vision=False,
                network_type="Direct",
                key_hospitals=[],
                enrollment_deadline="Anytime",
                coverage_start="Immediately",
                notes=[
                    "⚠️ NOT insurance - primary care membership only",
                    "INCREASE INCOME to $15,650+ for ACA eligibility!",
                    "Consider short-term health insurance for emergencies",
                    "Negotiate cash rates at hospitals"
                ]
            ))
        
        elif tier == "no_subsidy":
            plans.append(InsurancePlan(
                plan_type="ACA Marketplace (Unsubsidized)",
                carrier="Florida Blue",
                plan_name="BlueOptions Gold PPO",
                metal_tier="Gold",
                monthly_premium="$400-600",
                deductible="$0-500",
                out_of_pocket_max="$4,000-6,000",
                copay_primary="$25",
                copay_specialist="$50",
                includes_dental=False,
                includes_vision=True,
                network_type="PPO",
                key_hospitals=["Mayo Clinic Jacksonville", "UF Health"],
                enrollment_deadline="December 15",
                coverage_start="January 1",
                notes=[
                    "Consider employer coverage if available",
                    "HSA with HDHP may reduce taxes",
                    "Health sharing ministries as alternative"
                ]
            ))
        
        # Add dental recommendation for all
        plans.append(InsurancePlan(
            plan_type="Dental",
            carrier="Delta Dental / Ameritas",
            plan_name="PPO Dental Plan",
            metal_tier="N/A",
            monthly_premium="$25-45",
            deductible="$50-100",
            out_of_pocket_max="$1,500-2,000 annual max",
            copay_primary="$0 preventive",
            copay_specialist="20-50% coinsurance",
            includes_dental=True,
            includes_vision=False,
            network_type="PPO",
            key_hospitals=[],
            enrollment_deadline="December 15",
            coverage_start="January 1",
            notes=[
                "Preventive care 100% covered",
                "12-month waiting period for major work",
                "Enroll separately from health plan",
                "Orthodontics has lifetime max"
            ]
        ))
        
        return plans
    
    def generate_action_items(self, tier: str, magi: float) -> List[str]:
        """Generate enrollment action items"""
        items = []
        
        if tier == "coverage_gap":
            shortfall = 15650 - magi
            items.append(f"🚨 URGENT: Increase taxable income by ${shortfall:,.2f} to qualify for ACA")
            items.append("Review deductions - consider reducing to increase MAGI")
            items.append("Report all side income, tips, gig work")
            items.append("DO NOT prepay property taxes or other expenses")
        else:
            items.append("Visit healthcare.gov by December 15")
            items.append("Have income documentation ready (1099s, rental income)")
            items.append("Compare at least 3 plans before enrolling")
            items.append("Check if your doctors are in-network")
            items.append("Enroll in dental separately (same deadline)")
        
        if tier in ["csr_94", "csr_87"]:
            items.append("MUST choose SILVER plan to get cost-sharing reductions")
            items.append("Bronze/Gold plans do NOT include CSR benefits")
        
        return items
    
    def generate_warnings(self, tier: str, magi: float, fpl_pct: float) -> List[str]:
        """Generate warnings based on eligibility"""
        warnings = []
        
        if tier == "coverage_gap":
            warnings.append("⚠️ FLORIDA COVERAGE GAP: You are NOT eligible for ACA subsidies or Medicaid")
            warnings.append("⚠️ Without insurance, a hospital stay could cost $50,000+")
        
        if fpl_pct >= 145 and fpl_pct <= 155:
            warnings.append("⚠️ Close to CSR tier boundary - monitor income carefully")
        
        if fpl_pct >= 395:
            warnings.append("⚠️ Close to subsidy cliff at 400% FPL - reducing MAGI could save thousands")
        
        return warnings
    
    def generate_optimization_tips(self, tier: str, magi: float, fpl_pct: float) -> Tuple[List[str], float]:
        """Generate tips to optimize coverage and calculate savings potential"""
        tips = []
        savings = 0.0
        
        if tier == "coverage_gap":
            shortfall = 15650 - magi
            tips.append(f"INCREASE income by ${shortfall:,.2f} - reduces deductions or report more income")
            tips.append("Consider Roth IRA conversion to increase MAGI (careful with taxes)")
            savings = 5000  # Estimated value of CSR benefits
        
        elif tier == "subsidy_only":
            target_magi = 39125  # Top of CSR 73%
            excess = magi - target_magi
            tips.append(f"REDUCE MAGI by ${excess:,.2f} to qualify for CSR 73%")
            tips.append("Maximize Schedule E deductions (repairs, maintenance)")
            tips.append("Prepay property taxes before year-end")
            tips.append("Increase retirement contributions (SEP-IRA, Solo 401k)")
            savings = 2000  # CSR value
        
        elif tier == "no_subsidy":
            target_magi = 62600  # Below subsidy cliff
            excess = magi - target_magi
            tips.append(f"REDUCE MAGI by ${excess:,.2f} to qualify for premium subsidies")
            tips.append("Consider health savings account (HSA) contributions")
            tips.append("Review all business expenses for optimization")
            savings = 6000  # Subsidy value
        
        elif tier in ["csr_94", "csr_87"]:
            tips.append("✅ You're in an optimal tier - maintain current income level")
            tips.append("Monitor mid-year to ensure you stay in range")
            tips.append("Consider SEP-IRA contributions if approaching tier limit")
        
        return tips, savings
    
    def generate_recommendation(self, magi: float, household_size: int = 1) -> InsuranceRecommendation:
        """Generate full insurance recommendation"""
        
        fpl_pct = self.calculate_fpl_percentage(magi, household_size)
        tier, description = self.determine_eligibility_tier(fpl_pct)
        plans = self.get_florida_plans(tier)
        action_items = self.generate_action_items(tier, magi)
        warnings = self.generate_warnings(tier, magi, fpl_pct)
        tips, savings = self.generate_optimization_tips(tier, magi, fpl_pct)
        
        recommendation = InsuranceRecommendation(
            magi=magi,
            household_size=household_size,
            fpl_percentage=round(fpl_pct, 1),
            eligibility_tier=tier,
            tier_description=description,
            recommended_plans=plans,
            action_items=action_items,
            warnings=warnings,
            optimization_tips=tips,
            annual_savings_potential=savings,
            generated_at=datetime.now().isoformat()
        )
        
        # Store recommendation if database available
        if self.supabase:
            self._store_recommendation(recommendation)
        
        return recommendation
    
    def _store_recommendation(self, rec: InsuranceRecommendation):
        """Store recommendation in database"""
        try:
            # Store as agent decision
            decision_data = {
                "decision_type": "insurance_recommendation",
                "input_data": {
                    "magi": rec.magi,
                    "household_size": rec.household_size
                },
                "analysis": f"FPL: {rec.fpl_percentage}%, Tier: {rec.eligibility_tier}",
                "recommendation": rec.tier_description,
                "confidence_score": 0.95,
                "model_used": "insurance_recommendation_engine_v1"
            }
            self.supabase.table("tax_agent_decisions").insert(decision_data).execute()
        except Exception as e:
            print(f"Warning: Could not store recommendation: {e}")
    
    def print_recommendation(self, rec: InsuranceRecommendation):
        """Pretty print recommendation"""
        print("=" * 70)
        print("🏥 INSURANCE RECOMMENDATION REPORT")
        print("=" * 70)
        print(f"Generated: {rec.generated_at}")
        print(f"\n📊 Financial Summary:")
        print(f"   MAGI: ${rec.magi:,.2f}")
        print(f"   Household Size: {rec.household_size}")
        print(f"   FPL Percentage: {rec.fpl_percentage}%")
        print(f"\n🎯 Eligibility:")
        print(f"   Tier: {rec.eligibility_tier.upper()}")
        print(f"   {rec.tier_description}")
        
        if rec.warnings:
            print(f"\n⚠️ Warnings:")
            for w in rec.warnings:
                print(f"   {w}")
        
        print(f"\n📋 Recommended Plans:")
        for i, plan in enumerate(rec.recommended_plans, 1):
            print(f"\n   {i}. {plan.carrier} - {plan.plan_name}")
            print(f"      Type: {plan.plan_type} | Metal: {plan.metal_tier}")
            print(f"      Premium: {plan.monthly_premium}/month")
            print(f"      Deductible: {plan.deductible} | OOP Max: {plan.out_of_pocket_max}")
            print(f"      Copays: PCP {plan.copay_primary}, Specialist {plan.copay_specialist}")
            if plan.key_hospitals:
                print(f"      Key Hospitals: {', '.join(plan.key_hospitals[:3])}")
        
        print(f"\n✅ Action Items:")
        for item in rec.action_items:
            print(f"   • {item}")
        
        print(f"\n💡 Optimization Tips:")
        for tip in rec.optimization_tips:
            print(f"   • {tip}")
        
        if rec.annual_savings_potential > 0:
            print(f"\n💰 Potential Annual Savings: ${rec.annual_savings_potential:,.2f}")
        
        print("\n" + "=" * 70)


def main():
    """Example usage"""
    engine = InsuranceRecommendationEngine()
    
    # Test different scenarios
    scenarios = [
        (12000, 1, "Coverage Gap"),
        (18000, 1, "CSR 94% - Optimal"),
        (25000, 1, "CSR 87%"),
        (35000, 1, "CSR 73%"),
        (50000, 1, "Subsidy Only"),
        (70000, 1, "No Subsidy")
    ]
    
    for magi, household, description in scenarios:
        print(f"\n{'='*70}")
        print(f"SCENARIO: {description} (MAGI: ${magi:,})")
        print(f"{'='*70}")
        rec = engine.generate_recommendation(magi, household)
        engine.print_recommendation(rec)


if __name__ == "__main__":
    main()
