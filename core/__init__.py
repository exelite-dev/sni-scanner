"""SNI Scanner Pro - Core Module"""
__version__ = "2.2.0"
__author__ = "SNI Scanner Engineering Team"

from .dns_resolver import DNSResolver, DNSResolutionResult
from .tls_checker import TLSChecker, TLSCheckResult
from .reality_matcher import RealityMatcher, RealityMatchResult
from .scorer import SNIScorer, ScoredSNI
from .scanner import SNIScanner, ScanProgress
from .sources import DomainSourceManager, DomainSanitizer
from .geo_matcher import ServerGeoMatcher
from .vless_parser import VLESSParser, VLESSConfig
from .tunnel_benchmarker import TunnelBenchmarker, TunnelMetrics, LocalCoreManager
from .panel_orchestrator import PanelOrchestrator, PanelCredentials

__all__ = [
    "DNSResolver",
    "DNSResolutionResult",
    "TLSChecker",
    "TLSCheckResult",
    "RealityMatcher",
    "RealityMatchResult",
    "SNIScorer",
    "ScoredSNI",
    "SNIScanner",
    "ScanProgress",
    "DomainSourceManager",
    "DomainSanitizer",
    "ServerGeoMatcher",
    "VLESSParser",
    "VLESSConfig",
    "TunnelBenchmarker",
    "TunnelMetrics",
    "LocalCoreManager",
    "PanelOrchestrator",
    "PanelCredentials",
]
