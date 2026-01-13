#!/usr/bin/env python3
"""
Supabase Integration for BidDeed.AI V14.0.0 (Privilege Control)
Supports separate service accounts per agent for defense-in-depth security

Author: BidDeed.AI
Version: 14.0.0
Changes: Added multi-agent privilege separation
"""

import os
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from supabase import create_client, Client

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('SupabaseClient')

# Supabase URL (same for all agents)
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://mocerqjnksmhcjzxrewo.supabase.co")

# Agent-specific service role keys (Layer 4: Privilege Control)
# Each agent has minimum required privileges
AGENT_KEYS = {
    'scraper': os.environ.get("SUPABASE_SCRAPER_KEY"),      # Write auctions, read own data
    'analysis': os.environ.get("SUPABASE_ANALYSIS_KEY"),    # Read auctions, write insights
    'report': os.environ.get("SUPABASE_REPORT_KEY"),        # Read-only all tables
    'qa': os.environ.get("SUPABASE_QA_KEY"),                # Read all, write metrics/errors
    'admin': os.environ.get("SUPABASE_ADMIN_KEY"),          # Full access (migrations only)
}

# Legacy fallback (for backward compatibility during transition)
LEGACY_KEY = os.environ.get("SUPABASE_KEY") or os.environ.get("SUPABASE_SERVICE_ROLE_KEY")


class SupabaseClient:
    """
    Client for Supabase database operations with privilege control.
    
    Args:
        agent: Agent type ('scraper', 'analysis', 'report', 'qa', 'admin')
        url: Supabase URL (optional, defaults to env var)
        key: Explicit API key (optional, overrides agent-based key)
    
    Examples:
        # Scraper agent (can write auctions)
        client = SupabaseClient(agent='scraper')
        
        # Analysis agent (can read auctions, write insights)
        client = SupabaseClient(agent='analysis')
        
        # Report agent (read-only)
        client = SupabaseClient(agent='report')
        
        # Explicit key (legacy)
        client = SupabaseClient(key='your_key_here')
    """
    
    def __init__(
        self,
        agent: str = None,
        url: str = None,
        key: str = None
    ):
        self.url = url or SUPABASE_URL
        self.agent = agent
        
        # Determine which key to use
        if key:
            # Explicit key provided (legacy mode)
            self.key = key
        elif agent and agent in AGENT_KEYS:
            # Use agent-specific key
            self.key = AGENT_KEYS[agent]
            if not self.key:
                raise ValueError(
                    f"Agent '{agent}' key not found. "
                    f"Set SUPABASE_{agent.upper()}_KEY environment variable."
                )
        else:
            # Fallback to legacy key (for backward compatibility)
            self.key = LEGACY_KEY
            if not self.key:
                raise ValueError(
                    "No Supabase key found. Set SUPABASE_KEY or specify agent parameter."
                )
        
        self.client: Client = create_client(self.url, self.key)
        
        if agent:
            logger.info(f"✅ Supabase client initialized for agent: {agent}")
        else:
            logger.info("✅ Supabase client initialized (legacy mode)")
        
    def upsert_auction(self, data: Dict[str, Any]) -> bool:
        """Upsert a single auction record"""
        try:
            record = {
                "case_number": data.get("case_number"),
                "cfn": data.get("cfn"),
                "property_address": data.get("address"),
                "plaintiff": data.get("plaintiff"),
                "defendant": data.get("defendant"),
                "final_judgment_amount": data.get("judgment_amount"),
                "judgment_date": data.get("judgment_date"),
                "auction_date": data.get("auction_date"),
                "auction_time": data.get("auction_time"),
                "auction_status": data.get("auction_status", "Scheduled"),
                "principal": data.get("principal", 0),
                "interest": data.get("interest", 0),
                "advances": data.get("advances", 0),
                "notes": data.get("notes", ""),
                "source": data.get("source", "BECA"),
                "updated_at": datetime.now().isoformat()
            }
            
            self.client.table('auctions').upsert(record, on_conflict='case_number').execute()
            logger.info(f"✅ Upserted: {data.get('case_number')}")
            return True
        except Exception as e:
            logger.error(f"❌ Upsert failed: {e}")
            return False
    
    def upsert_batch(self, records: List[Dict[str, Any]]) -> Dict[str, int]:
        """Upsert multiple auction records"""
        results = {"success": 0, "failed": 0}
        for record in records:
            if self.upsert_auction(record):
                results["success"] += 1
            else:
                results["failed"] += 1
        return results
    
    def get_auctions_by_date(self, auction_date: str) -> List[Dict]:
        """Get all auctions for a specific date"""
        try:
            response = self.client.table('auctions').select('*').eq('auction_date', auction_date).execute()
            return response.data
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return []
    
    def get_auction_by_case(self, case_number: str) -> Optional[Dict]:
        """Get auction by case number"""
        try:
            response = self.client.table('auctions').select('*').eq('case_number', case_number).single().execute()
            return response.data
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return None


# Convenience functions for each agent type
def get_scraper_client(url: str = None) -> SupabaseClient:
    """Get Supabase client for scraper agent (write auctions)"""
    return SupabaseClient(agent='scraper', url=url)


def get_analysis_client(url: str = None) -> SupabaseClient:
    """Get Supabase client for analysis agent (read auctions, write insights)"""
    return SupabaseClient(agent='analysis', url=url)


def get_report_client(url: str = None) -> SupabaseClient:
    """Get Supabase client for report agent (read-only)"""
    return SupabaseClient(agent='report', url=url)


def get_qa_client(url: str = None) -> SupabaseClient:
    """Get Supabase client for QA agent (read all, write metrics)"""
    return SupabaseClient(agent='qa', url=url)


def get_admin_client(url: str = None) -> SupabaseClient:
    """Get Supabase client with admin privileges (migrations only)"""
    return SupabaseClient(agent='admin', url=url)


# December 3, 2025 Data (from Manus AI extraction)
DEC3_2025_DATA = [
    {
        "case_number": "05-2024-CA-038092",
        "cfn": "38902332",
        "address": "3711 BRANTLEY CIR, ROCKLEDGE, FL 32955-4724",
        "plaintiff": "COMMUNITY CREDIT UNION FLORIDA",
        "defendant": "TONYA SLIGH",
        "judgment_amount": 322244.55,
        "judgment_date": "2024-11-13",
        "auction_date": "2025-12-03",
        "auction_time": "11:00 AM",
        "principal": 314502.45,
        "interest": 4623.72,
        "advances": 3118.38,
        "notes": "Multiple bankruptcy cancellations"
    },
    {
        "case_number": "05-2025-CA-015412",
        "cfn": "40463947",
        "address": "2808 FOREST DR, MELBOURNE, FL 32901",
        "plaintiff": "LOANDEPOT LLC",
        "defendant": "LARRY KLINE",
        "judgment_amount": 339368.51,
        "judgment_date": "2025-10-28",
        "auction_date": "2025-12-03",
        "auction_time": "11:00 AM",
        "principal": 339368.51,
        "notes": "Non-homestead"
    },
    {
        "case_number": "05-2025-CA-025192",
        "cfn": "40424221",
        "address": "1639 DITTMER CIR SE, PALM BAY, FL 32909-1317",
        "plaintiff": "FREEDOM MORTGAGE CORPORATION",
        "defendant": "JUTARAT MAY",
        "judgment_amount": 277934.57,
        "judgment_date": "2025-10-20",
        "auction_date": "2025-12-03",
        "auction_time": "11:00 AM",
        "principal": 256186.55,
        "interest": 10823.05,
        "advances": 10924.97,
        "notes": "Multiple HOA defendants"
    },
    {
        "case_number": "05-2025-CA-030784",
        "cfn": "40154223",
        "address": "2116 SPRING CREEK CIR NE, PALM BAY, FL 32905-4033",
        "plaintiff": "NATIONSTAR MORTGAGE LLC",
        "defendant": "KATHERINE MUMPER",
        "judgment_amount": 273406.65,
        "judgment_date": "2025-08-22",
        "auction_date": "2025-12-03",
        "auction_time": "11:00 AM",
        "principal": 273406.65,
        "notes": "Previous cancellation 10/08/2025"
    },
    {
        "case_number": "05-2024-CA-038977",
        "cfn": "40456709",
        "address": "1060 ARON ST, MELBOURNE, FL 32935",
        "plaintiff": "LAKEVIEW LOAN SERVICING LLC",
        "defendant": "ANTHONY DAVIS JR",
        "judgment_amount": 159572.08,
        "judgment_date": "2025-12-01",
        "auction_date": "2025-12-03",
        "auction_time": "11:00 AM",
        "principal": 153285.13,
        "interest": 4600.96,
        "advances": 1685.99,
        "notes": "Address may be 4835 KEY BISCAYNE DR"
    },
    {
        "case_number": "05-2025-CA-038220",
        "cfn": "40530188",
        "address": "2150 SMATHERS CIR, MELBOURNE, FL 32935",
        "plaintiff": "CAST PROPERTIES FLORIDA LLC",
        "defendant": "SHADES OF BEAUTY INC",
        "judgment_amount": 242941.64,
        "judgment_date": "2025-11-09",
        "auction_date": "2025-12-03",
        "auction_time": "11:00 AM",
        "principal": 225000.00,
        "interest": 20416.64,
        "notes": "ADDRESS MISMATCH - Case shows 964 FOSTORIA DR"
    }
]


if __name__ == '__main__':
    print("=" * 70)
    print("SUPABASE CLIENT V14.0.0 - PRIVILEGE CONTROL TEST")
    print("=" * 70)
    print()
    
    # Test agent-specific clients
    print("Testing agent-specific clients...")
    print()
    
    try:
        # Scraper agent
        scraper = get_scraper_client()
        print("✅ Scraper client initialized")
    except ValueError as e:
        print(f"⚠️  Scraper client: {e}")
    
    try:
        # Analysis agent
        analysis = get_analysis_client()
        print("✅ Analysis client initialized")
    except ValueError as e:
        print(f"⚠️  Analysis client: {e}")
    
    try:
        # Report agent
        report = get_report_client()
        print("✅ Report client initialized")
    except ValueError as e:
        print(f"⚠️  Report client: {e}")
    
    print()
    print("To upload December 3, 2025 data, run:")
    print("  client = get_scraper_client()")
    print("  results = client.upsert_batch(DEC3_2025_DATA)")
    print(f"  # {len(DEC3_2025_DATA)} records ready to upload")
