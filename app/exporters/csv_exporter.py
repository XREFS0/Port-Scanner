import csv
from datetime import datetime
from typing import List
from app.exporters.base import BaseExporter
from app.models.scan_result import PortScanResult

class CSVExporter(BaseExporter):
    """Exports port scan results to a CSV file."""
    
    def export(self, filepath: str, results: List[PortScanResult], target_input: str) -> None:
        timestamp = datetime.now().isoformat()
        
        with open(filepath, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            # Write Header
            writer.writerow([
                "Target Input", "IP Address", "Port", "Protocol", 
                "State", "Service", "Response Time (ms)", "Banner", "Scan Timestamp"
            ])
            
            # Write Rows
            for r in results:
                writer.writerow([
                    target_input,
                    r.ip,
                    r.port,
                    r.protocol,
                    r.state,
                    r.service,
                    r.response_time_ms if r.response_time_ms is not None else "",
                    r.banner if r.banner else "",
                    timestamp
                ])
