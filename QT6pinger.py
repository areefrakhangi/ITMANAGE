import sys
import subprocess
import platform # To determine the operating system
import csv # For reading CSV files
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QSizePolicy,
    QFileDialog, QMessageBox # Added QMessageBox for file dialog errors
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject

class Worker(QObject):
    """
    Worker class to perform network operations (ping, tracert, pathping, nmap, csv_ping)
    in a separate thread. Emits signals to update the GUI in the main thread.
    """
    ping_status_signal = pyqtSignal(bool, str) # (success, output_message) for ping/pathping/nmap status
    # This signal now also carries individual ping results for CSV batch operations
    result_update_signal = pyqtSignal(str) # (output) for tracert/pathping/nmap results and continuous CSV ping updates
    finished_signal = pyqtSignal() # Signal when all operations are done

    def __init__(self, target_host, operation="ping_tracert", hosts_list=None):
        super().__init__()
        self.target_host = target_host # Used for single-host operations
        self.operation = operation
        self.hosts_list = hosts_list # Used for CSV ping operations

    def run(self):
        """
        Main method to execute the network checks based on the specified operation.
        """
        self.result_update_signal.emit("Starting operation...\n")
        if self.operation == "ping_tracert":
            ping_success, ping_output = self._ping_host(self.target_host)
            self.ping_status_signal.emit(ping_success, ping_output)

            if ping_success:
                tracert_output = self._tracert_host(self.target_host)
                self.result_update_signal.emit(tracert_output)
            else:
                self.result_update_signal.emit("Ping failed. No tracert performed.\n" + ping_output)
        elif self.operation == "pathping":
            pathping_output = self._pathping_host(self.target_host)
            if "Error" in pathping_output or "Timed out" in pathping_output or "command not found" in pathping_output:
                self.ping_status_signal.emit(False, "Status: Pathping Failed")
            else:
                self.ping_status_signal.emit(True, "Status: Pathping Complete")
            self.result_update_signal.emit(pathping_output)
        elif self.operation == "nmap":
            nmap_output = self._nmap_host(self.target_host)
            if "Error" in nmap_output or "command not found" in nmap_output:
                self.ping_status_signal.emit(False, "Status: Nmap Failed")
            else:
                self.ping_status_signal.emit(True, "Status: Nmap Complete")
            self.result_update_signal.emit(nmap_output)
        elif self.operation == "csv_ping":
            self.ping_status_signal.emit(False, "Status: Running CSV Ping...")
            full_results = ""
            if self.hosts_list:
                for i, host in enumerate(self.hosts_list):
                    host_stripped = host.strip()
                    if not host_stripped:
                        continue # Skip empty lines
                    self.result_update_signal.emit(f"\n--- Pinging {host_stripped} ({i + 1}/{len(self.hosts_list)}) ---\n")
                    ping_success, ping_output = self._ping_host(host_stripped)
                    status_line = f"{host_stripped}: {'Alive' if ping_success else 'Unable to contact'}\n"
                    self.result_update_signal.emit(status_line + ping_output + "\n")
                    full_results += status_line # Accumulate main status line for overall summary if needed
                self.ping_status_signal.emit(True, "Status: CSV Ping Complete")
            else:
                self.ping_status_signal.emit(False, "Status: No hosts found in CSV.")
                self.result_update_signal.emit("No hosts were found in the CSV file or the file was empty.\n")


        self.finished_signal.emit()

    def _ping_host(self, host):
        """
        Performs a ping operation to the specified host.
        :param host: IP address or hostname to ping.
        :return: Tuple (success_boolean, output_string)
        """
        # Determine the correct ping command based on OS
        if platform.system() == "Windows":
            # Windows: -n 1 sends 1 echo request
            command = ["ping", "-n", "1", host]
        else:
            # Linux/macOS: -c 1 sends 1 echo request
            command = ["ping", "-c", "1", host]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                encoding='utf-8',
                timeout=5 # Add a timeout for ping
            )
            # Ping is successful if return code is 0
            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stdout + "\n" + result.stderr
        except FileNotFoundError:
            return False, "Error: Ping command not found. Make sure ping is installed and in your PATH."
        except subprocess.TimeoutExpired:
            return False, "Ping timed out. Host might be unreachable or blocking ICMP."
        except Exception as e:
            return False, f"An unexpected error occurred during ping: {e}"

    def _tracert_host(self, host):
        """
        Performs a tracert (traceroute) operation to the specified host.
        :param host: IP address or hostname to tracert.
        :return: String containing the full tracert output.
        """
        # Determine the correct tracert command based on OS
        if platform.system() == "Windows":
            command = ["tracert", host]
        else:
            command = ["traceroute", host]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                encoding='utf-8',
                timeout=30 # Add a timeout for tracert, as it can take longer
            )
            return result.stdout + "\n" + result.stderr
        except FileNotFoundError:
            return "Error: Tracert/Traceroute command not found. Make sure it's installed and in your PATH."
        except subprocess.TimeoutExpired:
            return "Tracert timed out. The path might be very long or blocked."
        except Exception as e:
            return f"An unexpected error occurred during tracert: {e}"

    def _pathping_host(self, host):
        """
        Performs a pathping operation to the specified host (Windows only).
        :param host: IP address or hostname to pathping.
        :return: String containing the full pathping output.
        """
        if platform.system() == "Windows":
            command = ["pathping", host]
            try:
                result = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    check=False,
                    encoding='utf-8',
                    timeout=90 # Pathping can take a long time (e.g., 250 seconds by default for 100 queries)
                )
                return result.stdout + "\n" + result.stderr
            except FileNotFoundError:
                return "Error: Pathping command not found. Make sure pathping is installed and in your PATH."
            except subprocess.TimeoutExpired:
                return "Pathping timed out. This command can take a long time to complete."
            except Exception as e:
                return f"An unexpected error occurred during pathping: {e}"
        else:
            return "Pathping is a Windows-specific command. Not available on this operating system."

    def _nmap_host(self, host):
        """
        Performs an nmap scan on the specified host.
        :param host: IP address or hostname to scan.
        :return: String containing the full nmap output.
        """
        # Default nmap command for a quick scan (-F: fast mode, -T4: aggressive timing)
        # For more detailed scans, users would need to modify the command.
        command = ["nmap", "-F", "-T4", host]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False, # Don't raise error for non-zero exit codes (e.g., host down, no ports found)
                encoding='utf-8',
                timeout=120 # Nmap can take a significant amount of time
            )
            # Nmap output can include errors in stdout/stderr even on success, so return both.
            return result.stdout + "\n" + result.stderr
        except FileNotFoundError:
            return "Error: Nmap command not found. Please ensure Nmap is installed and added to your system's PATH."
        except subprocess.TimeoutExpired:
            return "Nmap scan timed out. The host might be unreachable, blocking, or the scan is taking too long."
        except Exception as e:
            return f"An unexpected error occurred during Nmap scan: {e}"


class NetworkReachabilityApp(QWidget):
    def __init__(self):
        """
        Initializes the PyQt6 GUI application.
        """
        super().__init__()
        self.setWindowTitle("Network Reachability Tool (PyQt6)")
        self.resize(850, 600) # Adjusted size to accommodate new button and layout

        self.thread = None # Initialize thread attribute
        self.worker = None # Initialize worker attribute

        self.init_ui()

    def init_ui(self):
        """
        Sets up the layout and widgets for the GUI.
        """
        # Main vertical layout for the entire window
        main_layout = QVBoxLayout()
        self.setLayout(main_layout)

        # --- Input and Buttons Section ---
        input_buttons_layout = QHBoxLayout()
        main_layout.addLayout(input_buttons_layout)

        # Label for IP Address/Hostname
        self.ip_label = QLabel("Enter IP Address or Hostname:")
        input_buttons_layout.addWidget(self.ip_label)

        # Entry Field for IP Address/Hostname
        self.ip_entry = QLineEdit(self)
        self.ip_entry.setPlaceholderText("e.g., google.com or 8.8.8.8")
        self.ip_entry.returnPressed.connect(self.start_ping_tracert_checks) # Connect Enter key to Ping & Tracert
        input_buttons_layout.addWidget(self.ip_entry)

        # Action Button: Ping & Tracert
        self.ping_tracert_button = QPushButton("Ping & Tracert", self)
        self.ping_tracert_button.clicked.connect(self.start_ping_tracert_checks)
        input_buttons_layout.addWidget(self.ping_tracert_button)

        # Action Button: Pathping
        self.pathping_button = QPushButton("Pathping", self)
        self.pathping_button.clicked.connect(self.start_pathping_checks)
        input_buttons_layout.addWidget(self.pathping_button)

        # Action Button: Nmap
        self.nmap_button = QPushButton("Nmap", self)
        self.nmap_button.clicked.connect(self.start_nmap_scan)
        input_buttons_layout.addWidget(self.nmap_button)

        # NEW Action Button: Check Computers (CSV Ping)
        self.csv_ping_button = QPushButton("Check Computers (CSV Ping)", self)
        self.csv_ping_button.clicked.connect(self.start_csv_ping_checks)
        input_buttons_layout.addWidget(self.csv_ping_button)

        # --- Output Display - Status Label ---
        self.ping_status_label = QLabel("Status: N/A", self)
        self.ping_status_label.setStyleSheet("color: black;")
        self.ping_status_label.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        main_layout.addWidget(self.ping_status_label)

        # --- Results Text Area ---
        self.tracert_output_text = QTextEdit(self)
        self.tracert_output_text.setReadOnly(True)
        self.tracert_output_text.setPlaceholderText("Network operation results will appear here.")
        main_layout.addWidget(self.tracert_output_text)

        # Stretch factors to make layouts compact at the top and text edit expand
        main_layout.setStretchFactor(input_buttons_layout, 0)
        main_layout.setStretchFactor(self.ping_status_label, 0)
        main_layout.setStretchFactor(self.tracert_output_text, 1)

    def _prepare_for_checks(self):
        """Common setup for initiating network checks."""
        # Disable input and all buttons during operation
        self.ip_entry.setEnabled(False)
        self.ping_tracert_button.setEnabled(False)
        self.pathping_button.setEnabled(False)
        self.nmap_button.setEnabled(False)
        self.csv_ping_button.setEnabled(False) # Disable CSV Ping button

        self.ping_status_label.setStyleSheet("color: blue;")
        self.tracert_output_text.setPlainText("Processing...\n")
        
        # Clear previous thread/worker if any
        if self.thread and self.thread.isRunning():
            self.thread.quit()
            self.thread.wait()
        self.thread = None
        self.worker = None

    def _start_worker_thread(self, target_host, operation_type, hosts_list=None):
        """Starts the worker thread with specified operation."""
        self.thread = QThread()
        self.worker = Worker(target_host, operation=operation_type, hosts_list=hosts_list)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.ping_status_signal.connect(self.update_ping_status)
        self.worker.result_update_signal.connect(self.update_output_text_append) # Connect to append for CSV results
        self.worker.finished_signal.connect(self.on_worker_finished)

        self.thread.start()

    def start_ping_tracert_checks(self):
        """Initiates ping and tracert operations."""
        target_host = self.ip_entry.text().strip()
        self._prepare_for_checks() # Prepare GUI
        if target_host:
            self.ping_status_label.setText("Status: Pinging & Tracerting...")
            self._start_worker_thread(target_host, "ping_tracert")
        else:
            self.ping_status_label.setText("Please enter an IP/Hostname")
            self.ping_status_label.setStyleSheet("color: red;")
            self.tracert_output_text.setPlainText("")
            self.on_worker_finished() # Re-enable buttons immediately

    def start_pathping_checks(self):
        """Initiates pathping operation."""
        target_host = self.ip_entry.text().strip()
        self._prepare_for_checks() # Prepare GUI
        if target_host:
            self.ping_status_label.setText("Status: Pathpinging...")
            self._start_worker_thread(target_host, "pathping")
        else:
            self.ping_status_label.setText("Please enter an IP/Hostname")
            self.ping_status_label.setStyleSheet("color: red;")
            self.tracert_output_text.setPlainText("")
            self.on_worker_finished() # Re-enable buttons immediately

    def start_nmap_scan(self):
        """Initiates nmap scan operation."""
        target_host = self.ip_entry.text().strip()
        self._prepare_for_checks() # Prepare GUI
        if target_host:
            self.ping_status_label.setText("Status: Nmap Scanning (This may take a moment)...")
            self._start_worker_thread(target_host, "nmap")
        else:
            self.ping_status_label.setText("Please enter an IP/Hostname")
            self.ping_status_label.setStyleSheet("color: red;")
            self.tracert_output_text.setPlainText("")
            self.on_worker_finished() # Re-enable buttons immediately

    def start_csv_ping_checks(self):
        """
        Opens a file dialog, reads IPs from CSV, and starts batch ping operations.
        """
        # Open file dialog to select CSV
        file_dialog = QFileDialog(self)
        csv_file_path, _ = file_dialog.getOpenFileName(
            self,
            "Open CSV File",
            "",
            "CSV Files (*.csv);;All Files (*)"
        )

        if csv_file_path:
            hosts = []
            try:
                with open(csv_file_path, 'r', newline='', encoding='utf-8') as file:
                    reader = csv.reader(file)
                    for row in reader:
                        if row: # Ensure row is not empty
                            hosts.append(row[0]) # Assume IP/hostname is in the first column
                
                if hosts:
                    self._prepare_for_checks() # Prepare GUI after file is selected and validated
                    self.ping_status_label.setText(f"Status: Pinging {len(hosts)} hosts from CSV...")
                    # Pass the list of hosts to the worker
                    self._start_worker_thread(None, "csv_ping", hosts_list=hosts)
                else:
                    QMessageBox.warning(self, "CSV Read Error", "No IP addresses or hostnames found in the first column of the CSV file.")
                    self.ping_status_label.setText("Status: CSV Read Error")
                    self.ping_status_label.setStyleSheet("color: red;")
                    self.tracert_output_text.setPlainText("No valid IP addresses or hostnames found in the CSV file.")
                    self.on_worker_finished() # Re-enable buttons
            except Exception as e:
                QMessageBox.critical(self, "File Error", f"Could not read CSV file: {e}")
                self.ping_status_label.setText("Status: File Error")
                self.ping_status_label.setStyleSheet("color: red;")
                self.tracert_output_text.setPlainText(f"Error reading CSV file: {e}")
                self.on_worker_finished() # Re-enable buttons
        else:
            self.ping_status_label.setText("Status: CSV selection cancelled.")
            self.ping_status_label.setStyleSheet("color: black;")
            self.tracert_output_text.setPlainText("")
            self.on_worker_finished() # Re-enable buttons


    def update_ping_status(self, success, output_message):
        """
        Slot to update the ping status label. Called from the worker thread via signal.
        """
        if "Status:" in output_message: # If worker explicitly sent a status message
            self.ping_status_label.setText(output_message)
            if "Failed" in output_message or "Error" in output_message:
                self.ping_status_label.setStyleSheet("color: red;")
            elif "Complete" in output_message:
                self.ping_status_label.setStyleSheet("color: green;")
            else:
                self.ping_status_label.setStyleSheet("color: black;")
        elif success: # This path is typically for single ping/tracert operation initial status
            self.ping_status_label.setText("Status: Alive")
            self.ping_status_label.setStyleSheet("color: green;")
        else:
            self.ping_status_label.setText("Status: Unable to contact")
            self.ping_status_label.setStyleSheet("color: red;")

    def update_output_text_append(self, output):
        """
        Slot to append text to the output area. Used for continuous updates like CSV ping.
        """
        self.tracert_output_text.append(output) # Use append for live updates

    def on_worker_finished(self):
        """
        Slot called when the worker thread finishes its operations.
        Re-enables GUI elements and cleans up the thread.
        """
        self.ip_entry.setEnabled(True)
        self.ping_tracert_button.setEnabled(True)
        self.pathping_button.setEnabled(True)
        self.nmap_button.setEnabled(True)
        self.csv_ping_button.setEnabled(True) # Re-enable CSV Ping button
        
        # Clean up thread
        if self.thread and self.thread.isRunning():
            self.thread.quit()
            self.thread.wait()
        self.thread = None
        self.worker = None

if __name__ == "__main__":
    # Create the QApplication instance
    app = QApplication(sys.argv)
    # Create an instance of the main window
    window = NetworkReachabilityApp()
    # Show the window
    window.show()
    # Start the application's event loop
    sys.exit(app.exec())
