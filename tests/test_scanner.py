import unittest
import asyncio
from unittest.mock import patch, AsyncMock
from app.config import ScanConfig
from app.scanner.engine import scan_single_port, scan_ports_async
from app.models.scan_result import PortScanResult

class TestScanner(unittest.TestCase):

    def test_scan_config_defaults(self):
        config = ScanConfig()
        self.assertEqual(config.timeout_seconds, 1.0)
        self.assertEqual(config.max_concurrency, 100)
        self.assertIn(80, config.common_ports)

    @patch("asyncio.open_connection")
    def test_scan_single_port_open(self, mock_open):
        # Setup mock reader/writer
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.close = unittest.mock.MagicMock()
        mock_writer.wait_closed = AsyncMock()
        mock_open.return_value = (mock_reader, mock_writer)

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(scan_single_port(
                ip="127.0.0.1",
                port=80,
                timeout=1.0,
                banner_grab=False,
                banner_timeout=1.0
            ))
            self.assertEqual(result.state, "Open")
            self.assertEqual(result.port, 80)
            self.assertEqual(result.service, "http")
            self.assertIsNotNone(result.response_time_ms)
        finally:
            loop.close()

    @patch("asyncio.open_connection")
    def test_scan_single_port_refused(self, mock_open):
        mock_open.side_effect = ConnectionRefusedError()

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(scan_single_port(
                ip="127.0.0.1",
                port=80,
                timeout=1.0,
                banner_grab=False,
                banner_timeout=1.0
            ))
            self.assertEqual(result.state, "Closed")
            self.assertEqual(result.port, 80)
        finally:
            loop.close()

    @patch("asyncio.open_connection")
    def test_scan_single_port_timeout(self, mock_open):
        mock_open.side_effect = asyncio.TimeoutError()

        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(scan_single_port(
                ip="127.0.0.1",
                port=80,
                timeout=1.0,
                banner_grab=False,
                banner_timeout=1.0
            ))
            self.assertEqual(result.state, "Filtered")
            self.assertEqual(result.port, 80)
        finally:
            loop.close()
            
    def test_scan_ports_async_cancellation(self):
        results = []
        progress_ticks = 0

        def result_cb(res):
            results.append(res)
            
        def progress_cb():
            nonlocal progress_ticks
            progress_ticks += 1
            
        # Cancel immediately
        def check_cancellation():
            return True

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(scan_ports_async(
                targets=["127.0.0.1"],
                ports=[80, 443],
                config=ScanConfig(),
                banner_grab=False,
                result_callback=result_cb,
                progress_callback=progress_cb,
                check_cancellation=check_cancellation
            ))
            self.assertEqual(len(results), 0)
            self.assertEqual(progress_ticks, 0)
        finally:
            loop.close()
