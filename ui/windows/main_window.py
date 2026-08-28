import time
import os
from datetime import datetime
from typing import List, Dict, Any

from PySide6.QtCore import Qt, QThread, Signal, Slot
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QProgressBar, QGroupBox, QFileDialog, QMessageBox, QListWidget,
    QSplitter, QCheckBox
)
from PySide6.QtGui import QFont, QColor, QBrush

from app.config import ScanConfig
from app.models.scan_result import PortScanResult
from app.networking.resolver import resolve_target, TargetResolutionError
from app.scanner.engine import scan_ports_async
from app.exporters.csv_exporter import CSVExporter
from app.exporters.json_exporter import JSONExporter
import asyncio

class ScanWorker(QThread):
    """Worker thread running the asynchronous scanner engine."""
    result_ready = Signal(PortScanResult)
    progress_updated = Signal()
    scan_finished = Signal()

    def __init__(self, targets: List[str], ports: List[int], config: ScanConfig, banner_grab: bool):
        super().__init__()
        self.targets = targets
        self.ports = ports
        self.config = config
        self.banner_grab = banner_grab

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        def result_callback(result: PortScanResult):
            self.result_ready.emit(result)

        def progress_callback():
            self.progress_updated.emit()

        def check_cancellation() -> bool:
            return self.isInterruptionRequested()

        try:
            loop.run_until_complete(scan_ports_async(
                targets=self.targets,
                ports=self.ports,
                config=self.config,
                banner_grab=self.banner_grab,
                result_callback=result_callback,
                progress_callback=progress_callback,
                check_cancellation=check_cancellation
            ))
        except Exception:
            pass
        finally:
            loop.close()
            self.scan_finished.emit()


class MainWindow(QMainWindow):
    """Main window of the professional Port Scanner application."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Professional Network Port Scanner")
        self.resize(1100, 700)

        # State management
        self.current_results: List[PortScanResult] = []
        self.scan_history: List[Dict[str, Any]] = []
        self.worker: Optional[ScanWorker] = None
        self.scan_start_time = 0.0
        self.total_ports_to_scan = 0
        self.completed_ports_count = 0
        self.open_ports_count = 0
        self.current_target_input = ""

        # Set style
        self.setup_styling()

        # Build UI
        self.init_ui()

    def setup_styling(self):
        """Applies a clean, modern professional developer dark stylesheet."""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1e1e24;
            }
            QWidget {
                color: #e2e8f0;
                font-family: "Segoe UI", -apple-system, sans-serif;
                font-size: 13px;
            }
            QGroupBox {
                border: 1px solid #3f3f46;
                border-radius: 4px;
                margin-top: 12px;
                font-weight: bold;
                color: #a1a1aa;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
            }
            QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox {
                background-color: #27272a;
                border: 1px solid #3f3f46;
                border-radius: 4px;
                padding: 5px;
                color: #f4f4f5;
            }
            QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDoubleSpinBox:focus {
                border: 1px solid #6366f1;
            }
            QPushButton {
                background-color: #3f3f46;
                border: none;
                border-radius: 4px;
                padding: 7px 15px;
                color: #f4f4f5;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #52525b;
            }
            QPushButton:pressed {
                background-color: #27272a;
            }
            QPushButton#startBtn {
                background-color: #4f46e5;
            }
            QPushButton#startBtn:hover {
                background-color: #6366f1;
            }
            QPushButton#stopBtn {
                background-color: #b91c1c;
            }
            QPushButton#stopBtn:hover {
                background-color: #dc2626;
            }
            QTableWidget {
                background-color: #18181b;
                border: 1px solid #27272a;
                gridline-color: #27272a;
                alternate-background-color: #202023;
            }
            QHeaderView::section {
                background-color: #27272a;
                color: #a1a1aa;
                padding: 6px;
                border: 1px solid #18181b;
                font-weight: bold;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QProgressBar {
                background-color: #27272a;
                border: 1px solid #3f3f46;
                border-radius: 4px;
                text-align: center;
                color: #f4f4f5;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #4f46e5;
                border-radius: 3px;
            }
            QListWidget {
                background-color: #18181b;
                border: 1px solid #27272a;
                border-radius: 4px;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #27272a;
            }
            QListWidget::item:hover {
                background-color: #27272a;
            }
            QListWidget::item:selected {
                background-color: #3f3f46;
                color: #f4f4f5;
            }
            QLabel#statusLabel {
                font-weight: bold;
                color: #a1a1aa;
            }
        """)

    def init_ui(self):
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(12)

        # 1. Target & Options Configuration Box
        config_group = QGroupBox("Scan Settings")
        config_layout = QGridLayout(config_group)
        config_layout.setContentsMargins(15, 15, 15, 15)
        config_layout.setSpacing(10)

        # Target input
        config_layout.addWidget(QLabel("Target(s):"), 0, 0)
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("e.g. 192.168.1.1, google.com, 10.0.0.0/24, 192.168.1.1-50")
        config_layout.addWidget(self.target_input, 0, 1, 1, 3)

        # Port configuration mode
        config_layout.addWidget(QLabel("Port Range:"), 1, 0)
        self.port_mode_combo = QComboBox()
        self.port_mode_combo.addItems(["Common Ports Preset", "Custom Range", "Full TCP Range (1-65535)"])
        self.port_mode_combo.currentIndexChanged.connect(self.on_port_mode_changed)
        config_layout.addWidget(self.port_mode_combo, 1, 1)

        self.custom_ports_input = QLineEdit()
        self.custom_ports_input.setPlaceholderText("e.g. 21-23, 80, 443, 8080")
        self.custom_ports_input.setEnabled(False)
        config_layout.addWidget(self.custom_ports_input, 1, 2, 1, 2)

        # Timeout & Concurrency
        config_layout.addWidget(QLabel("Timeout (sec):"), 2, 0)
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.1, 10.0)
        self.timeout_spin.setValue(1.0)
        self.timeout_spin.setSingleStep(0.5)
        config_layout.addWidget(self.timeout_spin, 2, 1)

        config_layout.addWidget(QLabel("Max Concurrency:"), 2, 2)
        self.concurrency_spin = QSpinBox()
        self.concurrency_spin.setRange(1, 1000)
        self.concurrency_spin.setValue(100)
        config_layout.addWidget(self.concurrency_spin, 2, 3)

        # Banner Grab Option
        self.banner_grab_check = QCheckBox("Enable Service Banner Detection")
        self.banner_grab_check.setChecked(True)
        config_layout.addWidget(self.banner_grab_check, 3, 1, 1, 3)

        main_layout.addWidget(config_group)

        # 2. Actions area
        actions_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start Scan")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.clicked.connect(self.start_scan)
        actions_layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton("Stop Scan")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_scan)
        actions_layout.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("Clear Results")
        self.clear_btn.clicked.connect(self.clear_results)
        actions_layout.addWidget(self.clear_btn)

        actions_layout.addStretch()

        self.export_btn = QPushButton("Export Results")
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_results)
        actions_layout.addWidget(self.export_btn)

        main_layout.addLayout(actions_layout)

        # 3. Main Splitter: History Sidebar + Results Table
        splitter = QSplitter(Qt.Horizontal)

        # Left panel: History
        history_widget = QWidget()
        history_layout = QVBoxLayout(history_widget)
        history_layout.setContentsMargins(0, 0, 0, 0)
        history_layout.addWidget(QLabel("<b>Session History</b>"))
        self.history_list = QListWidget()
        self.history_list.itemClicked.connect(self.load_history_item)
        history_layout.addWidget(self.history_list)
        splitter.addWidget(history_widget)

        # Right panel: Table
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        table_layout.setContentsMargins(0, 0, 0, 0)
        table_layout.addWidget(QLabel("<b>Scan Results</b>"))
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "IP Address", "Port", "Protocol", "State", "Service", "Resp Time (ms)"
        ])
        
        # Configure Table properties
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.results_table.horizontalHeader().setStretchLastSection(True)
        self.results_table.setSortingEnabled(True)
        self.results_table.setAlternatingRowColors(True)
        
        table_layout.addWidget(self.results_table)
        splitter.addWidget(table_widget)

        # Adjust initial sizes
        splitter.setSizes([200, 800])
        main_layout.addWidget(splitter)

        # 4. Status Panel
        self.status_bar_layout = QHBoxLayout()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.status_bar_layout.addWidget(self.progress_bar, 2)

        stats_widget = QWidget()
        stats_layout = QGridLayout(stats_widget)
        stats_layout.setContentsMargins(5, 0, 5, 0)
        stats_layout.setVerticalSpacing(2)
        stats_layout.setHorizontalSpacing(15)

        self.lbl_status = QLabel("State: Idle")
        self.lbl_status.setObjectName("statusLabel")
        stats_layout.addWidget(self.lbl_status, 0, 0)

        self.lbl_elapsed = QLabel("Elapsed: 0.0s")
        stats_layout.addWidget(self.lbl_elapsed, 0, 1)

        self.lbl_scanned = QLabel("Scanned: 0/0")
        stats_layout.addWidget(self.lbl_scanned, 1, 0)

        self.lbl_speed = QLabel("Speed: 0 p/s")
        stats_layout.addWidget(self.lbl_speed, 1, 1)

        self.lbl_open = QLabel("Open: 0")
        stats_layout.addWidget(self.lbl_open, 0, 2)

        self.status_bar_layout.addWidget(stats_widget, 1)
        main_layout.addLayout(self.status_bar_layout)

    @Slot(int)
    def on_port_mode_changed(self, index: int):
        self.custom_ports_input.setEnabled(index == 1)

    def parse_ports(self) -> List[int]:
        """Parses user port settings and returns standard list of ports."""
        mode = self.port_mode_combo.currentIndex()
        if mode == 0:
            return ScanConfig().common_ports
        elif mode == 2:
            return list(range(1, 65536))
        
        # Custom Mode
        raw = self.custom_ports_input.text().strip()
        if not raw:
            raise ValueError("Custom ports range is empty.")
        
        ports = set()
        parts = raw.split(',')
        for part in parts:
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                start_str, end_str = part.split('-', 1)
                start = int(start_str.strip())
                end = int(end_str.strip())
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(f"Invalid range: {part}")
                ports.update(range(start, end + 1))
            else:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Port out of range: {port}")
                ports.add(port)
                
        if not ports:
            raise ValueError("No ports parsed from custom specification.")
            
        return sorted(list(ports))

    def start_scan(self):
        # 1. Gather & validate Target
        target_raw = self.target_input.text().strip()
        if not target_raw:
            QMessageBox.warning(self, "Validation Error", "Please specify a target IP, CIDR subnet, range, or hostname.")
            return

        try:
            resolved_ips = resolve_target(target_raw)
        except TargetResolutionError as e:
            QMessageBox.warning(self, "Target Resolution Error", str(e))
            return

        # 2. Gather & validate Ports
        try:
            ports = self.parse_ports()
        except ValueError as e:
            QMessageBox.warning(self, "Port Parsing Error", f"Failed to parse ports: {e}")
            return

        self.current_target_input = target_raw
        self.total_ports_to_scan = len(resolved_ips) * len(ports)
        self.completed_ports_count = 0
        self.open_ports_count = 0
        self.current_results.clear()

        # Update table
        self.results_table.setSortingEnabled(False)
        self.results_table.setRowCount(0)

        # Configure ScanConfig
        config = ScanConfig(
            timeout_seconds=self.timeout_spin.value(),
            max_concurrency=self.concurrency_spin.value()
        )

        # Start UI updates
        self.lbl_status.setText("State: Scanning...")
        self.progress_bar.setValue(0)
        self.lbl_scanned.setText(f"Scanned: 0/{self.total_ports_to_scan}")
        self.lbl_open.setText("Open: 0")
        self.lbl_elapsed.setText("Elapsed: 0.0s")
        self.lbl_speed.setText("Speed: 0 p/s")
        
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.clear_btn.setEnabled(False)
        self.export_btn.setEnabled(False)

        # Launch Worker Thread
        self.scan_start_time = time.perf_counter()
        self.worker = ScanWorker(
            targets=resolved_ips,
            ports=ports,
            config=config,
            banner_grab=self.banner_grab_check.isChecked()
        )
        self.worker.result_ready.connect(self.on_result_received)
        self.worker.progress_updated.connect(self.on_progress_tick)
        self.worker.scan_finished.connect(self.on_scan_finished)
        self.worker.start()

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.lbl_status.setText("State: Stopping...")
            self.worker.requestInterruption()
            self.stop_btn.setEnabled(False)

    def clear_results(self):
        self.results_table.setSortingEnabled(False)
        self.results_table.setRowCount(0)
        self.current_results.clear()
        self.export_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.lbl_status.setText("State: Idle")
        self.lbl_scanned.setText("Scanned: 0/0")
        self.lbl_elapsed.setText("Elapsed: 0.0s")
        self.lbl_speed.setText("Speed: 0 p/s")
        self.lbl_open.setText("Open: 0")

    @Slot(PortScanResult)
    def on_result_received(self, result: PortScanResult):
        self.current_results.append(result)
        
        # Only show open ports in the table unless user wants to see all.
        # Showing all closed/filtered ports in a large scale table degrades Qt table rendering performance.
        # Hence, we only insert 'Open' and 'Filtered' results into the GUI table to keep it sleek and fast.
        if result.state == "Open":
            self.open_ports_count += 1
            self.lbl_open.setText(f"Open: {self.open_ports_count}")

        # Update table rows if Open
        if result.state in ("Open", "Filtered"):
            row = self.results_table.rowCount()
            self.results_table.insertRow(row)

            # Columns: IP Address, Port, Protocol, State, Service, Resp Time
            ip_item = QTableWidgetItem(result.ip)
            port_item = QTableWidgetItem(str(result.port))
            proto_item = QTableWidgetItem(result.protocol)
            
            # State item with color decoration
            state_item = QTableWidgetItem(result.state)
            if result.state == "Open":
                state_item.setForeground(QBrush(QColor("#10b981"))) # Soft emerald green
            else:
                state_item.setForeground(QBrush(QColor("#f59e0b"))) # Soft amber/yellow
                
            service_item = QTableWidgetItem(result.service)
            
            resp_time_str = f"{result.response_time_ms:.2f}" if result.response_time_ms is not None else ""
            resp_item = QTableWidgetItem(resp_time_str)

            # Disable item editing
            for item in (ip_item, port_item, proto_item, state_item, service_item, resp_item):
                item.setFlags(item.flags() ^ Qt.ItemIsEditable)

            self.results_table.setItem(row, 0, ip_item)
            self.results_table.setItem(row, 1, port_item)
            self.results_table.setItem(row, 2, proto_item)
            self.results_table.setItem(row, 3, state_item)
            self.results_table.setItem(row, 4, service_item)
            self.results_table.setItem(row, 5, resp_item)

    @Slot()
    def on_progress_tick(self):
        self.completed_ports_count += 1
        elapsed = time.perf_counter() - self.scan_start_time
        
        # Update progress bar safely
        if self.total_ports_to_scan > 0:
            percentage = int((self.completed_ports_count / self.total_ports_to_scan) * 100)
            self.progress_bar.setValue(percentage)
            
        self.lbl_scanned.setText(f"Scanned: {self.completed_ports_count}/{self.total_ports_to_scan}")
        self.lbl_elapsed.setText(f"Elapsed: {elapsed:.1f}s")
        
        # Calculate speed (ports/second)
        if elapsed > 0.05:
            speed = self.completed_ports_count / elapsed
            self.lbl_speed.setText(f"Speed: {speed:.0f} p/s")

    @Slot()
    def on_scan_finished(self):
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.clear_btn.setEnabled(True)
        
        # Enable sorting on header click
        self.results_table.setSortingEnabled(True)

        if self.current_results:
            self.export_btn.setEnabled(True)

        # Check interruption
        if self.worker and self.worker.isInterruptionRequested():
            self.lbl_status.setText("State: Stopped")
        else:
            self.lbl_status.setText("State: Completed")
            self.progress_bar.setValue(100)

        # Store in local session history
        history_summary = {
            "target": self.current_target_input,
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "open_count": self.open_ports_count,
            "total_scanned": self.completed_ports_count,
            "results": list(self.current_results)
        }
        self.scan_history.append(history_summary)
        
        # Update sidebar
        self.history_list.addItem(f"[{history_summary['timestamp']}] {history_summary['target']} (Open: {history_summary['open_count']})")
        self.worker = None

    def load_history_item(self, item):
        row = self.history_list.row(item)
        if 0 <= row < len(self.scan_history):
            history_data = self.scan_history[row]
            
            # Clear UI and repopulate table with past results
            self.results_table.setSortingEnabled(False)
            self.results_table.setRowCount(0)
            self.current_results = list(history_data["results"])
            
            self.open_ports_count = history_data["open_count"]
            self.completed_ports_count = history_data["total_scanned"]
            self.total_ports_to_scan = history_data["total_scanned"]
            
            self.lbl_status.setText("State: Loaded History")
            self.lbl_scanned.setText(f"Scanned: {self.completed_ports_count}/{self.total_ports_to_scan}")
            self.lbl_open.setText(f"Open: {self.open_ports_count}")
            self.progress_bar.setValue(100)
            self.export_btn.setEnabled(True)

            for result in self.current_results:
                if result.state in ("Open", "Filtered"):
                    row_idx = self.results_table.rowCount()
                    self.results_table.insertRow(row_idx)

                    ip_item = QTableWidgetItem(result.ip)
                    port_item = QTableWidgetItem(str(result.port))
                    proto_item = QTableWidgetItem(result.protocol)
                    
                    state_item = QTableWidgetItem(result.state)
                    if result.state == "Open":
                        state_item.setForeground(QBrush(QColor("#10b981")))
                    else:
                        state_item.setForeground(QBrush(QColor("#f59e0b")))
                        
                    service_item = QTableWidgetItem(result.service)
                    resp_time_str = f"{result.response_time_ms:.2f}" if result.response_time_ms is not None else ""
                    resp_item = QTableWidgetItem(resp_time_str)

                    # Disable item editing
                    for it in (ip_item, port_item, proto_item, state_item, service_item, resp_item):
                        it.setFlags(it.flags() ^ Qt.ItemIsEditable)

                    self.results_table.setItem(row_idx, 0, ip_item)
                    self.results_table.setItem(row_idx, 1, port_item)
                    self.results_table.setItem(row_idx, 2, proto_item)
                    self.results_table.setItem(row_idx, 3, state_item)
                    self.results_table.setItem(row_idx, 4, service_item)
                    self.results_table.setItem(row_idx, 5, resp_item)
            
            self.results_table.setSortingEnabled(True)

    def export_results(self):
        if not self.current_results:
            return

        # Prompt user for export file path
        options = QFileDialog.Options()
        filepath, selected_filter = QFileDialog.getSaveFileName(
            self,
            "Export Results",
            "",
            "CSV Files (*.csv);;JSON Files (*.json)",
            options=options
        )

        if not filepath:
            return

        try:
            if filepath.endswith('.csv') or 'CSV' in selected_filter:
                if not filepath.endswith('.csv'):
                    filepath += '.csv'
                exporter = CSVExporter()
            else:
                if not filepath.endswith('.json'):
                    filepath += '.json'
                exporter = JSONExporter()

            exporter.export(filepath, self.current_results, self.current_target_input)
            QMessageBox.information(self, "Export Success", f"Successfully exported scan results to:\n{filepath}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export results: {e}")
