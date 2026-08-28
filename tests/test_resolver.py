import unittest
from app.networking.resolver import resolve_target, TargetResolutionError

class TestResolver(unittest.TestCase):
    
    def test_single_ip(self):
        ips = resolve_target("192.168.1.5")
        self.assertEqual(ips, ["192.168.1.5"])

    def test_localhost_resolution(self):
        # Localhost should resolve reliably on any developer machine
        ips = resolve_target("localhost")
        self.assertIn("127.0.0.1", ips)

    def test_cidr_subnet(self):
        # /30 has 4 IPs, 2 usable hosts
        ips = resolve_target("192.168.10.0/30")
        self.assertEqual(ips, ["192.168.10.1", "192.168.10.2"])

    def test_range_full_octets(self):
        ips = resolve_target("10.0.0.1-10.0.0.5")
        self.assertEqual(ips, [
            "10.0.0.1",
            "10.0.0.2",
            "10.0.0.3",
            "10.0.0.4",
            "10.0.0.5"
        ])

    def test_range_abbreviated(self):
        ips = resolve_target("10.0.0.1-5")
        self.assertEqual(ips, [
            "10.0.0.1",
            "10.0.0.2",
            "10.0.0.3",
            "10.0.0.4",
            "10.0.0.5"
        ])

    def test_multiple_targets(self):
        # Combined comma/newline/space inputs
        target_str = "192.168.1.1, 10.0.0.1-3\n192.168.1.2"
        ips = resolve_target(target_str)
        self.assertEqual(ips, [
            "10.0.0.1",
            "10.0.0.2",
            "10.0.0.3",
            "192.168.1.1",
            "192.168.1.2"
        ])

    def test_invalid_target_throws(self):
        with self.assertRaises(TargetResolutionError):
            resolve_target("invalid_ip_address_format!!!")

    def test_invalid_range_throws(self):
        with self.assertRaises(TargetResolutionError):
            resolve_target("192.168.1.100-50") # start > end
            
        with self.assertRaises(TargetResolutionError):
            resolve_target("192.168.1.1-999") # invalid octet
