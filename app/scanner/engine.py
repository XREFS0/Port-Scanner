import asyncio
import time
from typing import Callable, List, Optional
from app.config import ScanConfig
from app.models.scan_result import PortScanResult
from app.services.service_resolver import resolve_service_name, grab_banner

async def scan_single_port(
    ip: str,
    port: int,
    timeout: float,
    banner_grab: bool,
    banner_timeout: float
) -> PortScanResult:
    """
    Scans a single TCP port using a standard TCP Connect handshake.
    Measures response time and detects service/banner if open.
    """
    start_time = time.perf_counter()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        response_time = (time.perf_counter() - start_time) * 1000.0
        service = resolve_service_name(port)
        
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

        banner = None
        if banner_grab:
            banner = await grab_banner(ip, port, timeout=banner_timeout)

        return PortScanResult(
            ip=ip,
            port=port,
            protocol="TCP",
            state="Open",
            service=service,
            response_time_ms=round(response_time, 2),
            banner=banner
        )

    except asyncio.TimeoutError:
        return PortScanResult(
            ip=ip,
            port=port,
            protocol="TCP",
            state="Filtered",
            service=resolve_service_name(port),
            response_time_ms=None,
            banner=None
        )
    except ConnectionRefusedError:
        response_time = (time.perf_counter() - start_time) * 1000.0
        return PortScanResult(
            ip=ip,
            port=port,
            protocol="TCP",
            state="Closed",
            service=resolve_service_name(port),
            response_time_ms=round(response_time, 2),
            banner=None
        )
    except OSError:
        return PortScanResult(
            ip=ip,
            port=port,
            protocol="TCP",
            state="Closed",
            service=resolve_service_name(port),
            response_time_ms=None,
            banner=None
        )

async def scan_ports_async(
    targets: List[str],
    ports: List[int],
    config: ScanConfig,
    banner_grab: bool,
    result_callback: Callable[[PortScanResult], None],
    progress_callback: Callable[[], None],
    check_cancellation: Callable[[], bool]
) -> None:
    """
    Orchestrates the scan across all targets and ports using a semaphore
    to limit max concurrent connection attempts.
    """
    semaphore = asyncio.Semaphore(config.max_concurrency)

    async def worker(ip: str, port: int) -> None:
        if check_cancellation():
            return
        
        async with semaphore:
            if check_cancellation():
                return
            
            result = await scan_single_port(
                ip=ip,
                port=port,
                timeout=config.timeout_seconds,
                banner_grab=banner_grab,
                banner_timeout=config.banner_grab_timeout
            )
            
            if not check_cancellation():
                result_callback(result)
                progress_callback()

    tasks = [worker(ip, port) for ip in targets for port in ports]
    await asyncio.gather(*tasks, return_exceptions=True)
