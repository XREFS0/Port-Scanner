from dataclasses import dataclass, field
from typing import List

@dataclass(frozen=True)
class ScanConfig:
    """Configuration options for the Port Scanner engine."""
    timeout_seconds: float = 1.0
    max_concurrency: int = 100
    banner_grab_timeout: float = 2.0
    
    # Common ports to scan in preset mode
    common_ports: List[int] = field(default_factory=lambda: [
        20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5900, 8080, 8443
    ])
