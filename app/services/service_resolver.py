import socket
import asyncio
from typing import Optional

def resolve_service_name(port: int, protocol: str = "tcp") -> str:
    """Returns the service name for a given port, or 'unknown' if not found."""
    try:
        return socket.getservbyport(port, protocol.lower())
    except OSError:
        return "unknown"

async def grab_banner(ip: str, port: int, timeout: float = 1.5) -> Optional[str]:
    """
    Attempts to retrieve a banner or greeting message from the specified port.
    Operates asynchronously and fails silently to prevent blocking the scanner.
    """
    try:
        # Create connection with a timeout
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
    except Exception:
        # If connect fails, we return None (state is handled by scanner)
        return None

    try:
        # Some services (HTTP, HTTPS, etc.) require a payload before sending data.
        # Check if the port is typically HTTP/HTTPS to send a prompt.
        is_http = port in (80, 8080, 3128)
        is_ssl_like = port in (443, 8443)
        
        banner_bytes = b""
        
        if is_http:
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
        elif is_ssl_like:
            # For SSL/TLS, standard socket write might fail or get rejected, 
            # but we can try sending a simple ClientHello or HTTP probe.
            writer.write(b"GET / HTTP/1.0\r\n\r\n")
            await writer.drain()

        # Wait for any incoming data
        try:
            banner_bytes = await asyncio.wait_for(reader.read(512), timeout=timeout)
        except asyncio.TimeoutError:
            # If no banner is sent automatically, check if we can probe it.
            if not is_http and not is_ssl_like:
                try:
                    writer.write(b"\r\n\r\n")
                    await writer.drain()
                    banner_bytes = await asyncio.wait_for(reader.read(512), timeout=1.0)
                except Exception:
                    pass
    except Exception:
        pass
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    if banner_bytes:
        # Decode and clean banner
        try:
            decoded = banner_bytes.decode('utf-8', errors='ignore').strip()
            # Clean up newlines or excessive carriage returns
            cleaned = " ".join(decoded.splitlines())
            # Limit maximum length of displayed banner
            if len(cleaned) > 100:
                cleaned = cleaned[:97] + "..."
            return cleaned if cleaned else None
        except Exception:
            pass

    return None
