import ipaddress
import socket
import re
from typing import List, Set

class TargetResolutionError(Exception):
    """Raised when target string cannot be parsed or resolved."""
    pass

def resolve_target(target_input: str) -> List[str]:
    """
    Parses a target input string which may contain multiple targets separated by
    commas, spaces, or newlines, and resolves them to a list of unique IPv4 addresses.
    
    Supports:
      - Single IP (e.g. "192.168.1.1")
      - Hostname (e.g. "localhost", "google.com")
      - CIDR Subnet (e.g. "192.168.1.0/24")
      - IP Range (e.g. "192.168.1.1-192.168.1.50" or "192.168.1.1-50")
    """
    raw_tokens = re.split(r'[\s,\n\r]+', target_input.strip())
    resolved_ips: Set[str] = set()

    for token in raw_tokens:
        token = token.strip()
        if not token:
            continue

        if '/' in token:
            try:
                network = ipaddress.IPv4Network(token, strict=False)
                for host in network.hosts():
                    resolved_ips.add(str(host))
                continue
            except ValueError as e:
                raise TargetResolutionError(f"Invalid CIDR subnet '{token}': {e}")

        if '-' in token:
            try:
                start_str, end_str = token.split('-', 1)
                start_str = start_str.strip()
                end_str = end_str.strip()
                
                start_ip = ipaddress.IPv4Address(start_str)
                if '.' in end_str:
                    end_ip = ipaddress.IPv4Address(end_str)
                else:
                    parts = start_str.split('.')
                    if len(parts) != 4:
                        raise TargetResolutionError(f"Invalid range start '{start_str}'")
                    parts[-1] = end_str
                    end_ip = ipaddress.IPv4Address('.'.join(parts))
                
                if start_ip > end_ip:
                    raise TargetResolutionError(f"Range start '{start_ip}' is greater than range end '{end_ip}'")
                
                curr = int(start_ip)
                limit = int(end_ip)
                if limit - curr > 65536:
                    raise TargetResolutionError("IP range size exceeds maximum allowed size (65536 IPs)")
                
                while curr <= limit:
                    resolved_ips.add(str(ipaddress.IPv4Address(curr)))
                    curr += 1
                continue
            except ValueError as e:
                raise TargetResolutionError(f"Invalid IP range '{token}': {e}")

        try:
            ip = ipaddress.IPv4Address(token)
            resolved_ips.add(str(ip))
            continue
        except ValueError:
            pass

        if not re.match(r'^[a-zA-Z0-9.-]+$', token):
            raise TargetResolutionError(f"Invalid hostname or IP address format: '{token}'")
        
        try:
            ip_resolved = socket.gethostbyname(token)
            resolved_ips.add(ip_resolved)
        except socket.gaierror as e:
            raise TargetResolutionError(f"Failed to resolve DNS for hostname '{token}': {e}")
            
    if not resolved_ips:
        raise TargetResolutionError("No valid targets resolved.")

    return sorted(list(resolved_ips), key=lambda ip: ipaddress.IPv4Address(ip))
