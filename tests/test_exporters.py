import unittest
import tempfile
import os
import json
import csv
from app.models.scan_result import PortScanResult
from app.exporters.csv_exporter import CSVExporter
from app.exporters.json_exporter import JSONExporter

class TestExporters(unittest.TestCase):
    def setUp(self):
        self.results = [
            PortScanResult("127.0.0.1", 80, "TCP", "Open", "http", 4.5, "Apache/2.4"),
            PortScanResult("127.0.0.1", 443, "TCP", "Closed", "https", 1.2, None)
        ]
        self.target_input = "127.0.0.1"

    def test_csv_exporter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test_results.csv")
            exporter = CSVExporter()
            exporter.export(filepath, self.results, self.target_input)
            
            self.assertTrue(os.path.exists(filepath))
            
            with open(filepath, mode='r', newline='', encoding='utf-8') as f:
                reader = csv.reader(f)
                rows = list(reader)
                
            # Expect header row + 2 data rows
            self.assertEqual(len(rows), 3)
            self.assertEqual(rows[0][0], "Target Input")
            self.assertEqual(rows[1][1], "127.0.0.1")
            self.assertEqual(rows[1][2], "80")
            self.assertEqual(rows[1][4], "Open")
            self.assertEqual(rows[1][6], "4.5")
            self.assertEqual(rows[1][7], "Apache/2.4")

    def test_json_exporter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test_results.json")
            exporter = JSONExporter()
            exporter.export(filepath, self.results, self.target_input)
            
            self.assertTrue(os.path.exists(filepath))
            
            with open(filepath, mode='r', encoding='utf-8') as f:
                data = json.load(f)
                
            self.assertEqual(data["target_input"], self.target_input)
            self.assertEqual(len(data["results"]), 2)
            self.assertEqual(data["results"][0]["port"], 80)
            self.assertEqual(data["results"][0]["state"], "Open")
            self.assertEqual(data["results"][0]["banner"], "Apache/2.4")
