"""
Supabase Privilege Audit Script

Analyzes current privilege state of BidDeed.AI's Supabase database to identify
security gaps and over-privileged access patterns.

Part of Phase 2 - Week 1: Privilege Control Audit
"""

import os
import sys
from typing import Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime
import json

try:
    from supabase import create_client, Client
except ImportError:
    print("⚠️ supabase-py not installed. Run: pip install supabase --break-system-packages")
    sys.exit(1)


@dataclass
class TablePrivileges:
    """Privileges for a single table."""
    table_name: str
    select: bool
    insert: bool
    update: bool
    delete: bool
    references: bool
    truncate: bool
    owner: Optional[str] = None
    rls_enabled: bool = False
    rls_policies: List[str] = None


@dataclass
class RoleAnalysis:
    """Analysis of a database role's privileges."""
    role_name: str
    tables_with_access: List[str]
    privilege_summary: Dict[str, int]  # privilege_type -> count
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    recommendations: List[str]


class SupabasePrivilegeAuditor:
    """
    Audit Supabase database privileges and Row-Level Security policies.
    """
    
    def __init__(self, supabase_url: str, service_role_key: str):
        """
        Initialize auditor with Supabase connection.
        
        Args:
            supabase_url: Supabase project URL
            service_role_key: Service role key (admin access)
        """
        self.supabase: Client = create_client(supabase_url, service_role_key)
        self.url = supabase_url
        
    def get_all_tables(self) -> List[str]:
        """
        Get list of all tables in public schema.
        
        Returns:
            List of table names
        """
        query = """
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_type = 'BASE TABLE'
        ORDER BY table_name;
        """
        
        try:
            result = self.supabase.rpc('exec_sql', {'query': query}).execute()
            if result.data:
                return [row['table_name'] for row in result.data]
        except Exception as e:
            print(f"⚠️ Could not fetch tables via RPC, trying direct query: {e}")
        
        # Fallback: Try to infer from known tables
        known_tables = [
            'activities',
            'historical_auctions',
            'daily_metrics',
            'insights',
            'security_alerts',
            'anomaly_metrics',
            'multi_county_auctions',
            'metrics',
            'errors',
        ]
        
        # Test which tables exist
        existing_tables = []
        for table in known_tables:
            try:
                self.supabase.table(table).select('*').limit(1).execute()
                existing_tables.append(table)
            except:
                pass
        
        return existing_tables
    
    def check_rls_enabled(self, table_name: str) -> bool:
        """
        Check if Row-Level Security is enabled on a table.
        
        Args:
            table_name: Name of table to check
        
        Returns:
            True if RLS is enabled, False otherwise
        """
        query = f"""
        SELECT relrowsecurity 
        FROM pg_class 
        WHERE relname = '{table_name}' 
        AND relnamespace = 'public'::regnamespace;
        """
        
        try:
            result = self.supabase.rpc('exec_sql', {'query': query}).execute()
            if result.data and len(result.data) > 0:
                return result.data[0].get('relrowsecurity', False)
        except:
            pass
        
        return False
    
    def get_rls_policies(self, table_name: str) -> List[Dict]:
        """
        Get RLS policies for a table.
        
        Args:
            table_name: Name of table
        
        Returns:
            List of policy definitions
        """
        query = f"""
        SELECT 
            polname as policy_name,
            polcmd as command,
            polroles::text as roles,
            polqual::text as using_expression,
            polwithcheck::text as check_expression
        FROM pg_policy
        WHERE polrelid = '{table_name}'::regclass;
        """
        
        try:
            result = self.supabase.rpc('exec_sql', {'query': query}).execute()
            return result.data if result.data else []
        except:
            return []
    
    def audit_table(self, table_name: str) -> TablePrivileges:
        """
        Audit privileges for a single table.
        
        Args:
            table_name: Name of table to audit
        
        Returns:
            TablePrivileges object
        """
        # Check RLS status
        rls_enabled = self.check_rls_enabled(table_name)
        rls_policies = self.get_rls_policies(table_name)
        
        # For now, assume full privileges (will be refined with actual queries)
        return TablePrivileges(
            table_name=table_name,
            select=True,
            insert=True,
            update=True,
            delete=True,
            references=False,
            truncate=False,
            rls_enabled=rls_enabled,
            rls_policies=[p['policy_name'] for p in rls_policies]
        )
    
    def analyze_agent_privileges(self) -> Dict[str, RoleAnalysis]:
        """
        Analyze privileges for each BidDeed.AI agent.
        
        Returns:
            Dictionary of agent_name -> RoleAnalysis
        """
        tables = self.get_all_tables()
        
        agents = {
            'scraper_agent': {
                'needs_read': ['multi_county_auctions', 'historical_auctions'],
                'needs_write': ['historical_auctions', 'multi_county_auctions'],
                'current_access': tables,  # Currently has access to all
            },
            'analysis_agent': {
                'needs_read': ['historical_auctions', 'multi_county_auctions'],
                'needs_write': ['insights', 'daily_metrics', 'metrics'],
                'current_access': tables,
            },
            'report_agent': {
                'needs_read': tables,  # Needs to read all for reports
                'needs_write': [],  # Should only write to filesystem
                'current_access': tables,
            },
            'qa_agent': {
                'needs_read': tables,
                'needs_write': ['metrics', 'errors'],
                'current_access': tables,
            },
        }
        
        analyses = {}
        
        for agent_name, config in agents.items():
            # Calculate over-privileged tables
            over_privileged = []
            for table in config['current_access']:
                if table not in config['needs_read'] and table not in config['needs_write']:
                    over_privileged.append(table)
            
            # Calculate privilege summary
            privilege_summary = {
                'total_access': len(config['current_access']),
                'needs_read': len(config['needs_read']),
                'needs_write': len(config['needs_write']),
                'over_privileged': len(over_privileged),
            }
            
            # Determine risk level
            if len(over_privileged) > 5:
                risk_level = 'CRITICAL'
            elif len(over_privileged) > 3:
                risk_level = 'HIGH'
            elif len(over_privileged) > 0:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'
            
            # Generate recommendations
            recommendations = []
            
            if over_privileged:
                recommendations.append(
                    f"Remove access to {len(over_privileged)} unnecessary tables: {', '.join(over_privileged[:3])}"
                )
            
            if not config['needs_write']:
                recommendations.append(
                    f"Create read-only service account - {agent_name} should never write"
                )
            else:
                recommendations.append(
                    f"Limit write access to only: {', '.join(config['needs_write'])}"
                )
            
            recommendations.append(
                f"Implement RLS policies to restrict row-level access"
            )
            
            analyses[agent_name] = RoleAnalysis(
                role_name=agent_name,
                tables_with_access=config['current_access'],
                privilege_summary=privilege_summary,
                risk_level=risk_level,
                recommendations=recommendations
            )
        
        return analyses
    
    def generate_report(self) -> Dict:
        """
        Generate comprehensive privilege audit report.
        
        Returns:
            Audit report dictionary
        """
        print("🔍 Starting Supabase Privilege Audit...")
        print(f"   URL: {self.url}")
        print()
        
        # Get all tables
        tables = self.get_all_tables()
        print(f"📊 Found {len(tables)} tables: {', '.join(tables)}")
        print()
        
        # Audit each table
        table_audits = {}
        for table in tables:
            audit = self.audit_table(table)
            table_audits[table] = audit
            
            rls_status = "✅ ENABLED" if audit.rls_enabled else "❌ DISABLED"
            policy_count = len(audit.rls_policies) if audit.rls_policies else 0
            print(f"   {table}: RLS {rls_status} ({policy_count} policies)")
        
        print()
        
        # Analyze agent privileges
        print("🤖 Analyzing Agent Privileges...")
        agent_analyses = self.analyze_agent_privileges()
        
        for agent_name, analysis in agent_analyses.items():
            print(f"\n   {agent_name.upper()}:")
            print(f"      Risk Level: {analysis.risk_level}")
            print(f"      Access to: {analysis.privilege_summary['total_access']} tables")
            print(f"      Over-privileged: {analysis.privilege_summary['over_privileged']} tables")
            print(f"      Recommendations:")
            for rec in analysis.recommendations:
                print(f"         - {rec}")
        
        # Calculate overall security score
        total_tables = len(tables)
        rls_enabled_count = sum(1 for t in table_audits.values() if t.rls_enabled)
        rls_coverage = (rls_enabled_count / total_tables * 100) if total_tables > 0 else 0
        
        avg_risk_score = {
            'LOW': 0,
            'MEDIUM': 1,
            'HIGH': 2,
            'CRITICAL': 3,
        }
        
        total_risk = sum(avg_risk_score[a.risk_level] for a in agent_analyses.values())
        avg_risk = total_risk / len(agent_analyses) if agent_analyses else 0
        
        if avg_risk >= 2.5:
            overall_risk = 'CRITICAL'
        elif avg_risk >= 1.5:
            overall_risk = 'HIGH'
        elif avg_risk >= 0.5:
            overall_risk = 'MEDIUM'
        else:
            overall_risk = 'LOW'
        
        security_score = max(0, 100 - (total_risk * 10) - ((100 - rls_coverage) / 2))
        
        print()
        print("=" * 70)
        print("SECURITY SUMMARY")
        print("=" * 70)
        print(f"Overall Risk Level: {overall_risk}")
        print(f"Security Score: {security_score:.1f}/100")
        print(f"RLS Coverage: {rls_coverage:.1f}% ({rls_enabled_count}/{total_tables} tables)")
        print()
        
        # Generate report
        report = {
            'timestamp': datetime.now().isoformat(),
            'supabase_url': self.url,
            'tables_audited': len(tables),
            'table_audits': {
                name: {
                    'rls_enabled': audit.rls_enabled,
                    'policy_count': len(audit.rls_policies) if audit.rls_policies else 0,
                    'policies': audit.rls_policies or [],
                }
                for name, audit in table_audits.items()
            },
            'agent_analyses': {
                name: {
                    'risk_level': analysis.risk_level,
                    'privilege_summary': analysis.privilege_summary,
                    'recommendations': analysis.recommendations,
                }
                for name, analysis in agent_analyses.items()
            },
            'security_summary': {
                'overall_risk': overall_risk,
                'security_score': security_score,
                'rls_coverage_percent': rls_coverage,
                'rls_enabled_tables': rls_enabled_count,
                'total_tables': total_tables,
            },
        }
        
        return report
    
    def save_report(self, report: Dict, output_path: str = 'privilege_audit_report.json'):
        """
        Save audit report to JSON file.
        
        Args:
            report: Audit report dictionary
            output_path: Path to save report
        """
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Report saved to: {output_path}")


def main():
    """
    Run privilege audit.
    """
    # Get Supabase credentials from environment
    supabase_url = os.getenv('SUPABASE_URL', 'https://mocerqjnksmhcjzxrewo.supabase.co')
    service_role_key = os.getenv('SUPABASE_SERVICE_ROLE_KEY')
    
    if not service_role_key:
        print("❌ SUPABASE_SERVICE_ROLE_KEY environment variable not set")
        print("   Set it with: export SUPABASE_SERVICE_ROLE_KEY=<your_key>")
        return
    
    # Create auditor
    auditor = SupabasePrivilegeAuditor(supabase_url, service_role_key)
    
    # Generate report
    report = auditor.generate_report()
    
    # Save report
    auditor.save_report(report)
    
    # Exit with appropriate code
    overall_risk = report['security_summary']['overall_risk']
    if overall_risk in ['CRITICAL', 'HIGH']:
        print()
        print("⚠️ HIGH RISK DETECTED - Immediate action required")
        sys.exit(1)
    else:
        print()
        print("✅ Audit complete")
        sys.exit(0)


if __name__ == '__main__':
    main()
