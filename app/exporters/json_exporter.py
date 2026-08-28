import json
from datetime import datetime
from typing import List
from app.exporters.base import BaseExporter
from app.models.scan_result import PortScanResult

class JSONExporter(BaseExporter):
    """Exports port scan results to a JSON file."""
    
    def export(self, filepath: str, results: List[PortScanResult], target_input: str) -> None:
        timestamp = datetime.now().isoformat()
        
        data = {
            "target_input": target_input,
            "scan_timestamp": timestamp,
            "total_ports_scanned": len(results),
            "results": [
                {
                    "ip": r.ip,
                    "port": r.port,
                    "protocol": r.protocol,
                    "state": r.state,
                    "service": r.service,
                    "response_time_ms": r.response_time_ms,
                    "banner": r.banner
                }
                for r in results
            ]
        }
        
        with open(filepath, mode='w', encoding='utf-8') as f:
            json.dump(data, f, indent=4)
