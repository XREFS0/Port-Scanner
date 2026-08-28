from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class PortScanResult:
    """Represents the outcome of scanning a single port on a host."""
    ip: str
    port: int
    protocol: str
    state: str  # "Open", "Closed", "Filtered"
    service: str
    response_time_ms: Optional[float]
    banner: Optional[str] = None
