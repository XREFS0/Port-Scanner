from abc import ABC, abstractmethod
from typing import List
from app.models.scan_result import PortScanResult

class BaseExporter(ABC):
    """Abstract base class for scan result exporters."""
    
    @abstractmethod
    def export(self, filepath: str, results: List[PortScanResult], target_input: str) -> None:
        """Exports the list of scan results to the specified file path."""
        pass
