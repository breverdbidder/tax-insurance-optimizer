"""
Multi-Agent Supabase Client with Privilege Control

Provides separate clients for different agents (scraper, analysis, report, qa, admin).
Each agent has minimum required privileges via separate service keys.

Version: 14.0.0
Part of Phase 2: Privilege Control
"""

import os
from typing import Optional
from supabase import create_client, Client


class SupabaseClientManager:
    """
    Manages Supabase clients with agent-specific privilege controls.
    
    Usage:
        # For scraper agent
        client = SupabaseClientManager.get_scraper_client()
        
        # For analysis agent
        client = SupabaseClientManager.get_analysis_client()
        
        # For admin operations
        client = SupabaseClientManager.get_admin_client()
    """
    
    _clients = {}
    
    @classmethod
    def _get_client(cls, key_env_var: str, agent_name: str) -> Client:
        """Get or create Supabase client for specific agent."""
        if agent_name in cls._clients:
            return cls._clients[agent_name]
        
        url = os.getenv('SUPABASE_URL')
        key = os.getenv(key_env_var)
        
        if not url:
            raise ValueError("SUPABASE_URL environment variable not set")
        
        if not key:
            # Fallback to service role key for backward compatibility
            key = os.getenv('SUPABASE_SERVICE_ROLE_KEY')
            if not key:
                raise ValueError(
                    f"{key_env_var} environment variable not set. "
                    f"For privilege control, set separate keys for each agent."
                )
        
        client = create_client(url, key)
        cls._clients[agent_name] = client
        return client
    
    @classmethod
    def get_scraper_client(cls) -> Client:
        """
        Get Supabase client for scraper agent.
        
        Privileges:
        - Read: historical_auctions (30 days), multi_county_auctions
        - Write: historical_auctions (INSERT), multi_county_auctions, activities, errors
        
        Environment variable: SUPABASE_SCRAPER_KEY
        """
        return cls._get_client('SUPABASE_SCRAPER_KEY', 'scraper')
    
    @classmethod
    def get_analysis_client(cls) -> Client:
        """
        Get Supabase client for analysis agent.
        
        Privileges:
        - Read: historical_auctions (processed), multi_county_auctions (7 days), insights (90 days)
        - Write: insights, daily_metrics, metrics, activities, errors
        - Restricted: CANNOT UPDATE/DELETE auctions
        
        Environment variable: SUPABASE_ANALYSIS_KEY
        """
        return cls._get_client('SUPABASE_ANALYSIS_KEY', 'analysis')
    
    @classmethod
    def get_report_client(cls) -> Client:
        """
        Get Supabase client for report agent (READ-ONLY).
        
        Privileges:
        - Read: ALL tables (completed records only)
        - Write: NONE (read-only agent)
        
        Environment variable: SUPABASE_REPORT_KEY
        """
        return cls._get_client('SUPABASE_REPORT_KEY', 'report')
    
    @classmethod
    def get_qa_client(cls) -> Client:
        """
        Get Supabase client for QA agent.
        
        Privileges:
        - Read: ALL tables (for quality analysis)
        - Write: metrics, errors, activities, security_alerts, anomaly_metrics
        
        Environment variable: SUPABASE_QA_KEY
        """
        return cls._get_client('SUPABASE_QA_KEY', 'qa')
    
    @classmethod
    def get_admin_client(cls) -> Client:
        """
        Get Supabase client with admin privileges.
        
        Privileges: FULL (bypasses RLS)
        
        Environment variable: SUPABASE_ADMIN_KEY or SUPABASE_SERVICE_ROLE_KEY
        """
        admin_key = os.getenv('SUPABASE_ADMIN_KEY') or os.getenv('SUPABASE_SERVICE_ROLE_KEY')
        
        if not admin_key:
            raise ValueError(
                "SUPABASE_ADMIN_KEY or SUPABASE_SERVICE_ROLE_KEY not set"
            )
        
        if 'admin' in cls._clients:
            return cls._clients['admin']
        
        url = os.getenv('SUPABASE_URL')
        if not url:
            raise ValueError("SUPABASE_URL not set")
        
        client = create_client(url, admin_key)
        cls._clients['admin'] = client
        return client
    
    @classmethod
    def get_client(cls, agent: Optional[str] = None) -> Client:
        """
        Get Supabase client for specified agent.
        
        Args:
            agent: One of 'scraper', 'analysis', 'report', 'qa', 'admin'
                   If None, returns admin client for backward compatibility
        
        Returns:
            Configured Supabase client
        """
        if agent is None or agent == 'admin':
            return cls.get_admin_client()
        elif agent == 'scraper':
            return cls.get_scraper_client()
        elif agent == 'analysis':
            return cls.get_analysis_client()
        elif agent == 'report':
            return cls.get_report_client()
        elif agent == 'qa':
            return cls.get_qa_client()
        else:
            raise ValueError(
                f"Unknown agent: {agent}. "
                f"Must be one of: scraper, analysis, report, qa, admin"
            )


# Convenience functions for backward compatibility
def get_scraper_client() -> Client:
    """Get scraper client (limited privileges)."""
    return SupabaseClientManager.get_scraper_client()


def get_analysis_client() -> Client:
    """Get analysis client (read processed data, write insights)."""
    return SupabaseClientManager.get_analysis_client()


def get_report_client() -> Client:
    """Get report client (read-only)."""
    return SupabaseClientManager.get_report_client()


def get_qa_client() -> Client:
    """Get QA client (full read, write metrics/errors)."""
    return SupabaseClientManager.get_qa_client()


def get_admin_client() -> Client:
    """Get admin client (full privileges, bypasses RLS)."""
    return SupabaseClientManager.get_admin_client()


def get_client(agent: Optional[str] = None) -> Client:
    """
    Get Supabase client for specified agent.
    
    Backward compatible - defaults to admin client if no agent specified.
    """
    return SupabaseClientManager.get_client(agent)


if __name__ == '__main__':
    print("=" * 70)
    print("MULTI-AGENT SUPABASE CLIENT")
    print("=" * 70)
    print()
    print("Usage:")
    print()
    print("# Get scraper client (limited privileges)")
    print("from src.utils.supabase_client import get_scraper_client")
    print("client = get_scraper_client()")
    print()
    print("# Get analysis client (read processed, write insights)")
    print("from src.utils.supabase_client import get_analysis_client")
    print("client = get_analysis_client()")
    print()
    print("# Get report client (read-only)")
    print("from src.utils.supabase_client import get_report_client")
    print("client = get_report_client()")
    print()
    print("# Get QA client (full read, write metrics)")
    print("from src.utils.supabase_client import get_qa_client")
    print("client = get_qa_client()")
    print()
    print("# Get admin client (full privileges)")
    print("from src.utils.supabase_client import get_admin_client")
    print("client = get_admin_client()")
    print()
    print("Environment Variables Required:")
    print("  SUPABASE_URL - Supabase project URL")
    print("  SUPABASE_SCRAPER_KEY - Scraper service role key")
    print("  SUPABASE_ANALYSIS_KEY - Analysis service role key")
    print("  SUPABASE_REPORT_KEY - Report service role key")
    print("  SUPABASE_QA_KEY - QA service role key")
    print("  SUPABASE_ADMIN_KEY - Admin service role key")
