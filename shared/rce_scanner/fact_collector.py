"""
RCE Fact Collector

Extracts relevant facts from host context for RCE vulnerability assessment.
Normalizes data from various sources (probe, access, Shodan) into
standardized format for rule evaluation.
"""

import logging
from typing import Dict, List, Any, Optional, Set

logger = logging.getLogger(__name__)


class FactCollector:
    """
    Collects and normalizes facts from host context for RCE analysis.

    Extracts data from probe results, access verification, and Shodan
    metadata to build comprehensive host profile for signature matching.
    """

    def __init__(self):
        """Initialize fact collector."""
        self.missing_telemetry = []

    def collect_facts(self, host_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract standardized facts from host context.

        Args:
            host_context: Raw host information from probe/access operations

        Returns:
            Normalized facts dictionary for rule evaluation
        """
        facts = {}
        self.missing_telemetry = []

        # Extract basic host information
        facts.update(self._extract_basic_info(host_context))

        # Extract SMB protocol information
        facts.update(self._extract_smb_info(host_context))

        # Extract authentication and access information
        facts.update(self._extract_auth_info(host_context))

        # Extract share enumeration results
        facts.update(self._extract_share_info(host_context))

        # Extract Shodan metadata if available
        facts.update(self._extract_shodan_info(host_context))

        # Extract OS detection hints
        facts.update(self._extract_os_info(host_context))

        # Extract probe results (from SafeProbeRunner)
        facts.update(self._extract_probe_results(host_context))

        # Extract implementation markers (ksmbd, Samba)
        facts.update(self._extract_implementation_markers(host_context))

        # Log any missing telemetry for future enhancement
        if self.missing_telemetry:
            logger.debug(f"Missing telemetry for RCE analysis: {', '.join(self.missing_telemetry)}")

        return facts

    def _extract_basic_info(self, host_context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract basic host identification information."""
        return {
            "ip_address": host_context.get("ip_address", "unknown"),
            "country": host_context.get("country", "unknown"),
            "timestamp": host_context.get("timestamp", "")
        }

    def _extract_smb_info(self, host_context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract SMB protocol and negotiation information."""
        facts = {}

        # SMB dialect support (from probe or connection attempts)
        smb_dialects = self._get_smb_dialects(host_context)
        facts["smb_dialects"] = smb_dialects

        # Protocol version flags
        facts["supports_smb1"] = any("SMB1" in dialect for dialect in smb_dialects)
        facts["supports_smb2"] = any("SMB2" in dialect for dialect in smb_dialects)
        facts["supports_smb3"] = any("SMB3" in dialect for dialect in smb_dialects)

        # Signing and security features
        signing_info = self._extract_smb_signing(host_context)
        if signing_info:
            facts.update(signing_info)
        else:
            self.missing_telemetry.append("smb_signing_status")

        return facts

    def _get_smb_dialects(self, host_context: Dict[str, Any]) -> List[str]:
        """Extract SMB dialects from various context sources."""
        dialects = []

        # From direct SMB negotiation (if available)
        if "smb_dialects" in host_context:
            dialects = host_context["smb_dialects"]

        # From connection error messages or logs
        elif "connection_details" in host_context:
            details = host_context["connection_details"]
            if isinstance(details, dict) and "protocols" in details:
                dialects = details["protocols"]

        # Infer from successful connection type
        elif "auth_method" in host_context:
            # If we have successful auth, assume at least SMB2/3 unless explicitly legacy
            auth_method = host_context["auth_method"].lower()
            if "legacy" in auth_method or "smb1" in auth_method:
                dialects = ["SMB1"]
            else:
                dialects = ["SMB2", "SMB3"]

        return dialects or []

    def _extract_smb_signing(self, host_context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract SMB signing and security information."""
        signing_info = {}

        # Look for signing information in connection details
        conn_details = host_context.get("connection_details", {})
        if isinstance(conn_details, dict):
            if "signing_required" in conn_details:
                signing_info["signing_required"] = conn_details["signing_required"]
            if "encryption_supported" in conn_details:
                signing_info["encryption_supported"] = conn_details["encryption_supported"]

        return signing_info

    def _extract_auth_info(self, host_context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract authentication and access information."""
        facts = {}

        auth_method = host_context.get("auth_method", "")
        facts["auth_method"] = auth_method

        # Determine if anonymous/guest access
        anonymous_indicators = ["anonymous", "guest", "", "null"]
        facts["anonymous_access"] = auth_method.lower() in anonymous_indicators

        # Parse username/password if available
        if ":" in auth_method:
            try:
                username, password = auth_method.split(":", 1)
                facts["username"] = username
                facts["has_password"] = bool(password)
            except ValueError:
                pass

        return facts

    def _extract_share_info(self, host_context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract share enumeration and access information."""
        facts = {}

        # Accessible shares
        accessible_shares = host_context.get("accessible_shares", [])
        facts["accessible_shares"] = accessible_shares
        facts["has_accessible_shares"] = len(accessible_shares) > 0

        # Administrative shares
        admin_shares = ["admin$", "c$", "ipc$"]
        admin_accessible = [share for share in accessible_shares
                          if share.lower() in admin_shares]
        facts["admin_shares_accessible"] = admin_accessible
        facts["has_admin_access"] = len(admin_accessible) > 0

        # Normalized share names for heuristics
        normalized_accessible = [share.lower() for share in accessible_shares if isinstance(share, str)]

        # Share details if available
        share_details = host_context.get("share_details", [])
        facts["share_details"] = share_details

        # Count enumerated vs accessible
        shares_found = host_context.get("shares_found", [])
        facts["shares_found"] = shares_found
        facts["share_enumeration_successful"] = len(shares_found) > 0

        normalized_found = [share.lower() for share in shares_found if isinstance(share, str)]
        combined_shares = set(normalized_accessible + normalized_found)

        # Derived role indicators for domain-aware signatures
        facts["has_netlogon_share"] = "netlogon" in combined_shares
        facts["has_sysvol_share"] = "sysvol" in combined_shares
        facts["has_print_share"] = "print$" in combined_shares
        facts["ipc_share_accessible"] = "ipc$" in normalized_accessible
        facts["has_domain_role_indicators"] = (
            facts["has_netlogon_share"] or facts["has_sysvol_share"]
        )

        return facts

    def _extract_shodan_info(self, host_context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract Shodan metadata if available."""
        facts = {}

        shodan_data = host_context.get("shodan_data", {})
        if not isinstance(shodan_data, dict):
            return facts

        # Port information
        ports = shodan_data.get("ports", [])
        facts["shodan_ports"] = ports
        facts["has_shodan_data"] = len(ports) > 0

        # Vulnerability information
        vulns = shodan_data.get("vulns", [])
        facts["shodan_vulns"] = vulns
        facts["known_vulns_count"] = len(vulns)

        # Service banners
        services = shodan_data.get("data", [])
        if services:
            facts["service_banners"] = [
                service.get("banner", "") for service in services if service.get("banner")
            ]

        # OS information from Shodan
        os_info = shodan_data.get("os")
        if os_info:
            facts["shodan_os"] = os_info

        return facts

    def _extract_os_info(self, host_context: Dict[str, Any]) -> Dict[str, Any]:
        """Extract operating system detection information."""
        facts = {}

        # OS hints from various sources
        os_hints = host_context.get("os_hints", {})
        if isinstance(os_hints, dict):
            detected_os = os_hints.get("detected_os", "")
            if detected_os:
                facts["detected_os"] = detected_os.lower()
                facts["is_windows"] = "windows" in detected_os.lower()
                facts["is_linux"] = "linux" in detected_os.lower()

        # Version information
        os_version = os_hints.get("os_version", "") if isinstance(os_hints, dict) else ""
        if os_version:
            facts["os_version"] = os_version

        # SMB implementation hints
        smb_implementation = self._detect_smb_implementation(host_context)
        if smb_implementation:
            facts["smb_implementation"] = smb_implementation

        return facts

    def _detect_smb_implementation(self, host_context: Dict[str, Any]) -> str:
        """Detect SMB implementation (Windows, Samba, etc.) from context."""
        # Look in service banners
        banners = host_context.get("service_banners", [])
        for banner in banners:
            if isinstance(banner, str):
                banner_lower = banner.lower()
                if "samba" in banner_lower:
                    return "samba"
                elif "windows" in banner_lower:
                    return "windows"

        # Look in Shodan data
        shodan_data = host_context.get("shodan_data", {})
        if isinstance(shodan_data, dict):
            services = shodan_data.get("data", [])
            for service in services:
                if isinstance(service, dict):
                    banner = service.get("banner", "")
                    if "samba" in banner.lower():
                        return "samba"
                    elif "microsoft" in banner.lower() or "windows" in banner.lower():
                        return "windows"

        return ""

    def get_missing_telemetry(self) -> List[str]:
        """Get list of missing telemetry items from last collection."""
        return self.missing_telemetry.copy()

    def validate_host_context(self, host_context: Dict[str, Any]) -> bool:
        """
        Validate that host context contains minimum required data.

        Args:
            host_context: Host context to validate

        Returns:
            True if context has sufficient data for analysis
        """
        if not isinstance(host_context, dict):
            return False

        # Must have at least IP address
        if not host_context.get("ip_address"):
            return False

        # Should have at least one data source
        data_sources = [
            "auth_method",
            "accessible_shares",
            "smb_dialects",
            "shodan_data",
            "shares_found"
        ]

        has_data = any(host_context.get(source) for source in data_sources)
        return has_data

    def _extract_probe_results(self, host_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract results from SafeProbeRunner probes.

        These facts are populated by the probe runner during RCE analysis.
        """
        facts = {}

        # SMB dialect as integer (e.g., 0x0202, 0x0210, 0x0300, 0x0302, 0x0311)
        smb_dialect = host_context.get("smb_dialect")
        if smb_dialect is not None:
            facts["smb_dialect"] = smb_dialect
        else:
            self.missing_telemetry.append("smb_dialect")

        # Signing required flag from negotiate response
        signing_required = host_context.get("signing_required")
        if signing_required is not None:
            facts["signing_required"] = bool(signing_required)
        else:
            # Check connection_details fallback
            conn_details = host_context.get("connection_details", {})
            if isinstance(conn_details, dict) and "signing_required" in conn_details:
                facts["signing_required"] = bool(conn_details["signing_required"])
            else:
                self.missing_telemetry.append("signing_required")

        # SMB3 compression algorithms (list of algorithm IDs)
        compression_algos = host_context.get("compression_algos")
        if compression_algos is not None:
            facts["compression_algos"] = compression_algos
            facts["has_compression"] = len(compression_algos) > 0
        else:
            facts["compression_algos"] = []
            facts["has_compression"] = False

        # SMB1 possible flag (derived from legacy mode or dialect detection)
        smb1_possible = host_context.get("smb1_possible")
        if smb1_possible is not None:
            facts["smb1_possible"] = bool(smb1_possible)
        else:
            # Derive from smb_dialects if available
            dialects = host_context.get("smb_dialects", [])
            facts["smb1_possible"] = any("SMB1" in str(d) for d in dialects)

        # MS17-010 probe status (from FID0 check)
        ms17_010_status = host_context.get("ms17_010_status")
        if ms17_010_status is not None:
            facts["ms17_010_status"] = ms17_010_status

        return facts

    def _extract_implementation_markers(self, host_context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract SMB implementation markers (ksmbd, Samba, Windows).

        These help identify Linux kernel SMB server, Samba, or Windows.
        """
        facts = {
            "ksmbd_marker": False,
            "samba_marker": False,
        }

        # Check service banners for implementation hints
        banners = host_context.get("service_banners", [])
        for banner in banners:
            if isinstance(banner, str):
                banner_lower = banner.lower()
                if "ksmbd" in banner_lower:
                    facts["ksmbd_marker"] = True
                if "samba" in banner_lower:
                    facts["samba_marker"] = True

        # Check Shodan data
        shodan_data = host_context.get("shodan_data", {})
        if isinstance(shodan_data, dict):
            # Extract product/version/os from Shodan
            product = shodan_data.get("product", "")
            if product:
                facts["shodan_product"] = product
                if "samba" in product.lower():
                    facts["samba_marker"] = True
                if "ksmbd" in product.lower():
                    facts["ksmbd_marker"] = True

            version = shodan_data.get("version", "")
            if version:
                facts["shodan_version"] = version

            os_info = shodan_data.get("os", "")
            if os_info:
                facts["shodan_os"] = os_info

            # Check services in Shodan data
            services = shodan_data.get("data", [])
            for service in services:
                if isinstance(service, dict):
                    banner = service.get("banner", "")
                    if "ksmbd" in banner.lower():
                        facts["ksmbd_marker"] = True
                    if "samba" in banner.lower():
                        facts["samba_marker"] = True

                    # Also check product field in service
                    svc_product = service.get("product", "")
                    if "samba" in svc_product.lower():
                        facts["samba_marker"] = True
                    if "ksmbd" in svc_product.lower():
                        facts["ksmbd_marker"] = True

        return facts
