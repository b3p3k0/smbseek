from dataclasses import dataclass
from typing import Set, List, Dict


@dataclass
class DiscoverResult:
    """Results from discovery operation"""
    query_used: str
    total_hosts: int
    authenticated_hosts: int
    host_ips: Set[str]


@dataclass
class AccessResult:
    """Results from access verification operation"""
    accessible_hosts: int        # Count of hosts with any accessible shares
    accessible_shares: int       # Total count of accessible share entries
    share_details: List[Dict]    # Detailed share information
