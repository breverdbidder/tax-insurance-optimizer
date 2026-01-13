"""
Supabase Client V14.0.0 - Multi-Agent Support

Provides agent-specific Supabase clients with separate keys for:
- Scraper Agent (read-only on auctions, write on own data)
- Analysis Agent (read processed data, write insights)
- Report Agent (read-only across all data)
- QA Agent (read all, write monitoring data)
- Admin (full access for setup/maintenance)

Part of Phase 2: Privilege Control with Row-Level Security
"""

import os
from typing import Optional
from supabase import create_client, Client


class SupabaseClientV14:
    """
    Enhanced Supabase client with multi-agent support.
    
    Environment Variables Required:
    - SUPABASE_URL: Supabase project URL
    - SUPABASE_SERVICE_ROLE_KEY: Admin key (legacy, fallback)
    
    Optional (for privilege control):
    - SUPABASE_SCRAPER_KEY: Scraper service account key
    - SUPABASE_ANALYSIS_KEY: Analysis service account key
    - SUPABASE_REPORT_KEY: Report service account key
    - SUPABASE_QA_KEY: QA service account key
    - SUPABASE_ADMIN_KEY: Admin service account key
    """
    
    _scraper_client: Optional[Client] = None
    _analysis_client: Optional[Client] = None
    _report_client: Optional[Client] = None
    _qa_client: Optional[Client] = None
    _admin_client: Optional[Client] = None
    
    @classmethod
    def get_scraper_client(cls) -> Client:
        """
        Get Supabase client for Scraper Agent.
        
        Permissions (with RLS):
        - Read: historical_auctions (30 days), multi_county_auctions
        - Write: historical_auctions, multi_county_auctions, activities, errors
        """
        if cls._scraper_client is None:
            url = os.getenv('SUPABASE_URL')
            key = os.getenv('SUPABASE_SCRAPER_KEY') or os.getenv('SUPABASE_SERVICE_ROLE_KEY')
            
            if not url or not key:
                raise ValueError("SUPABASE_URL and SUPABASE_SCRAPER_KEY required")
            
            cls._scraper_client = create_client(url, key)
        
        return cls._scraper_client
    
    @classmethod
    def get_analysis_client(cls) -> Client:
        """
        Get Supabase client for Analysis Agent.
        
        Permissions (with RLS):
        - Read: historical_auctions (processed), multi_county_auctions (7 days), insights (90 days)
        - Write: insights, daily_metrics, metrics, activities, errors
        - CANNOT: UPDATE/DELETE historical_auctions
        """
        if cls._analysis_client is None:
            url = os.getenv('SUPABASE_URL')
            key = os.getenv('SUPABASE_ANALYSIS_KEY') or os.getenv('SUPABASE_SERVICE_ROLE_KEY')
            
            if not url or not key:
                raise ValueError("SUPABASE_URL and SUPABASE_ANALYSIS_KEY required")
            
            cls._analysis_client = create_client(url, key)
        
        return cls._analysis_client
    
    @classmethod
    def get_report_client(cls) -> Client:
        """
        Get Supabase client for Report Agent.
        
        Permissions (with RLS):
        - Read: ALL tables (completed/processed records only)
        - Write: NONE (read-only)
        """
        if cls._report_client is None:
            url = os.getenv('SUPABASE_URL')
            key = os.getenv('SUPABASE_REPORT_KEY') or os.getenv('SUPABASE_SERVICE_ROLE_KEY')
            
            if not url or not key:
                raise ValueError("SUPABASE_URL and SUPABASE_REPORT_KEY required")
            
            cls._report_client = create_client(url, key)
        
        return cls._report_client
    
    @classmethod
    def get_qa_client(cls) -> Client:
        """
        Get Supabase client for QA Agent.
        
        Permissions (with RLS):
        - Read: ALL tables (for quality analysis)
        - Write: metrics, errors, activities, security_alerts, anomaly_metrics
        """
        if cls._qa_client is None:
            url = os.getenv('SUPABASE_URL')
            key = os.getenv('SUPABASE_QA_KEY') or os.getenv('SUPABASE_SERVICE_ROLE_KEY')
            
            if not url or not key:
                raise ValueError("SUPABASE_URL and SUPABASE_QA_KEY required")
            
            cls._qa_client = create_client(url, key)
        
        return cls._qa_client
    
    @classmethod
    def get_admin_client(cls) -> Client:
        """
        Get Supabase client for Admin operations.
        
        Permissions: FULL ACCESS (bypasses RLS)
        Use only for: setup, migrations, emergency fixes
        """
        if cls._admin_client is None:
            url = os.getenv('SUPABASE_URL')
            key = os.getenv('SUPABASE_ADMIN_KEY') or os.getenv('SUPABASE_SERVICE_ROLE_KEY')
            
            if not url or not key:
                raise ValueError("SUPABASE_URL and SUPABASE_ADMIN_KEY required")
            
            cls._admin_client = create_client(url, key)
        
        return cls._admin_client
    
    @classmethod
    def get_client(cls, agent: str = 'admin') -> Client:
        """
        Get Supabase client for specific agent.
        
        Args:
            agent: Agent type ('scraper', 'analysis', 'report', 'qa', 'admin')
        
        Returns:
            Supabase client with appropriate permissions
        """
        agent_map = {
            'scraper': cls.get_scraper_client,
            'analysis': cls.get_analysis_client,
            'report': cls.get_report_client,
            'qa': cls.get_qa_client,
            'admin': cls.get_admin_client,
        }
        
        if agent not in agent_map:
            raise ValueError(f"Unknown agent: {agent}. Use: scraper, analysis, report, qa, admin")
        
        return agent_map[agent]()
    
    @classmethod
    def reset(cls):
        """Reset all cached clients (useful for testing)."""
        cls._scraper_client = None
        cls._analysis_client = None
        cls._report_client = None
        cls._qa_client = None
        cls._admin_client = None


# Convenience functions for backward compatibility
def get_scraper_client() -> Client:
    """Get Supabase client for Scraper Agent."""
    return SupabaseClientV14.get_scraper_client()


def get_analysis_client() -> Client:
    """Get Supabase client for Analysis Agent."""
    return SupabaseClientV14.get_analysis_client()


def get_report_client() -> Client:
    """Get Supabase client for Report Agent."""
    return SupabaseClientV14.get_report_client()


def get_qa_client() -> Client:
    """Get Supabase client for QA Agent."""
    return SupabaseClientV14.get_qa_client()


def get_admin_client() -> Client:
    """Get Supabase client for Admin operations."""
    return SupabaseClientV14.get_admin_client()


# Legacy support
def get_supabase_client(agent: Optional[str] = None) -> Client:
    """
    Get Supabase client (legacy function).
    
    Args:
        agent: Optional agent type. If not provided, returns admin client.
    
    Returns:
        Supabase client
    """
    if agent:
        return SupabaseClientV14.get_client(agent)
    return SupabaseClientV14.get_admin_client()


if __name__ == '__main__':
    print("=" * 70)
    print("SUPABASE CLIENT V14.0.0 TEST")
    print("=" * 70)
    print()
    
    # Test environment variables
    required_vars = ['SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY']
    optional_vars = [
        'SUPABASE_SCRAPER_KEY',
        'SUPABASE_ANALYSIS_KEY',
        'SUPABASE_REPORT_KEY',
        'SUPABASE_QA_KEY',
        'SUPABASE_ADMIN_KEY'
    ]
    
    print("Required Variables:")
    for var in required_vars:
        value = os.getenv(var)
        status = "✅" if value else "❌"
        print(f"  {status} {var}: {'Set' if value else 'NOT SET'}")
    
    print()
    print("Optional Variables (for privilege control):")
    for var in optional_vars:
        value = os.getenv(var)
        status = "✅" if value else "⚠️"
        print(f"  {status} {var}: {'Set' if value else 'Using SERVICE_ROLE_KEY'}")
    
    print()
    print("Usage Examples:")
    print()
    print("# Scraper Agent")
    print("from src.utils.supabase_client import get_scraper_client")
    print("scraper = get_scraper_client()")
    print("scraper.table('historical_auctions').insert({...}).execute()")
    print()
    print("# Analysis Agent")
    print("from src.utils.supabase_client import get_analysis_client")
    print("analysis = get_analysis_client()")
    print("data = analysis.table('historical_auctions').select('*').eq('status', 'processed').execute()")
    print()
    print("# Report Agent (read-only)")
    print("from src.utils.supabase_client import get_report_client")
    print("report = get_report_client()")
    print("data = report.table('historical_auctions').select('*').execute()")
