import sys
import platform
import subprocess
import csv
import re
import random # Added random library
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit, QTextEdit,
    QPushButton, QFileDialog, QVBoxLayout, QHBoxLayout, QGridLayout
)
from PyQt6.QtGui import QFont, QColor, QTextCursor
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QObject
import paramiko

# Worker class for threading
class CommandWorker(QObject):
    finished = pyqtSignal(bool)
    output = pyqtSignal(str)

    def __init__(self, command_type, host, username, password, extra=None):
        super().__init__()
        self.command_type = command_type
        self.host = host
        self.username = username
        self.password = password
        self.extra = extra

    def run(self):
        try:
            result = ""
            system = platform.system()
            if self.command_type == "ping_tracert":
                self.output.emit(f"Pinging {self.host}...\n")
                ping_cmd = ["ping", "-n" if system == "Windows" else "-c", "1", self.host]
                result += subprocess.getoutput(" ".join(ping_cmd)) + "\n"
                if "TTL" in result or "ttl" in result:
                    trace_cmd = "tracert" if system == "Windows" else "traceroute"
                    self.output.emit(f"Running {trace_cmd}...\n")
                    trace_result = subprocess.getoutput(f"{trace_cmd} {self.host}")
                    result += trace_result
                else:
                    raise Exception("Ping failed")

            elif self.command_type == "pathping":
                if system != "Windows":
                    raise Exception("Pathping is only available on Windows")
                result += subprocess.getoutput(f"pathping {self.host}")

            elif self.command_type == "nmap":
                result += subprocess.getoutput(f"nmap -F {self.host}")

            elif self.command_type == "csv_ping":
                file_path = self.extra
                with open(file_path, newline='') as csvfile:
                    reader = csv.reader(csvfile)
                    for row in reader:
                        target = row[0].strip()
                        if target:
                            self.output.emit(f"Pinging {target}...\n")
                            ping_cmd = ["ping", "-n" if system == "Windows" else "-c", "1", target]
                            ping_result = subprocess.getoutput(" ".join(ping_cmd))
                            result += ping_result + "\n"

            else:  # SSH commands
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(self.host, username=self.username, password=self.password, timeout=10, allow_agent=False, look_for_keys=False)

                commands = {
                    "show_version": "show version",
                    "show_run": "show running-config",
                    "show_ip_int": "show ip interface brief",
                    "show_ip_route": "show ip route",
                    "show_log": "show logging",
                    "run_script": None  # handled separately
                }
                if self.command_type == "run_script":
                    with open(self.extra, 'r') as f:
                        lines = f.readlines()
                        chan = ssh.invoke_shell()
                        chan.settimeout(5)
                        for cmd in lines:
                            cmd = cmd.strip()
                            if cmd:
                                self.output.emit(f">>> {cmd}\n")
                                chan.send(cmd + '\n')
                                output = ""
                                while True:
                                    try:
                                        recv = chan.recv(1024).decode('utf-8')
                                        output += recv
                                        if re.search(r'[>#]\s*$', recv):  # Prompt detected
                                            break
                                    except Exception:
                                        break
                                self.output.emit(output)
                        chan.close()
                else:
                    cmd = commands.get(self.command_type)
                    self.output.emit(f">>> {cmd}\n")
                    stdin, stdout, stderr = ssh.exec_command(cmd)
                    self.output.emit(stdout.read().decode())
                    self.output.emit(stderr.read().decode())
                ssh.close()

            self.output.emit(result)
            self.finished.emit(True)
        except Exception as e:
            self.output.emit(f"Error: {str(e)}\n")
            self.finished.emit(False)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Quick Router information Tool- Areef Rakhangi")
        self.setGeometry(100, 100, 900, 600)
        # Generate a random color
        r = random.randint(100, 255)
        g = random.randint(100, 255)
        b = random.randint(100, 255)
        self.setStyleSheet(f"background-color: rgb({r},{g},{b});")
        # Widgets
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("Enter hostname, IP, or URL")

        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("SSH Username")

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("SSH Password")

        self.status_label = QLabel("Status: Idle")
        self.status_label.setStyleSheet("color: gray")

        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier New", 10))

        # Buttons
        self.buttons = {
            "ping_tracert": QPushButton("Ping & Tracert"),
            "pathping": QPushButton("Pathping (Win Only)"),
            "nmap": QPushButton("Nmap Scan"),
            "csv_ping": QPushButton("Check Computers (CSV)"),
            "show_version": QPushButton("Show Version"),
            "show_run": QPushButton("Show Running-config"),
            "show_ip_int": QPushButton("Show IP Interface Brief"),
            "show_ip_route": QPushButton("Show IP Route"),
            "show_log": QPushButton("Show Log"),
            "run_script": QPushButton("Run Script")
        }

        for key, btn in self.buttons.items():
            btn.clicked.connect(lambda _, k=key: self.run_command(k))

        # Layouts
        layout = QVBoxLayout()
        form_layout = QGridLayout()
        form_layout.addWidget(QLabel("Host:"), 0, 0)
        form_layout.addWidget(self.host_input, 0, 1, 1, 3)
        form_layout.addWidget(QLabel("SSH Username:"), 1, 0)
        form_layout.addWidget(self.username_input, 1, 1)
        form_layout.addWidget(QLabel("SSH Password:"), 1, 2)
        form_layout.addWidget(self.password_input, 1, 3)

        layout.addLayout(form_layout)
        layout.addWidget(self.status_label)

        button_grid = QGridLayout()
        positions = [(i, j) for i in range(5) for j in range(2)]
        for position, key in zip(positions, self.buttons):
            button_grid.addWidget(self.buttons[key], *position)

        layout.addLayout(button_grid)
        layout.addWidget(self.output_text)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def run_command(self, command_type):
        host = self.host_input.text().strip()
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()

        if command_type != "csv_ping" and command_type != "run_script" and not host:
            self.update_status("Host is required", success=False)
            return

        if command_type.startswith("show") or command_type == "run_script":
            if not username or not password:
                self.update_status("SSH username/password required", success=False)
                return

        self.set_buttons_enabled(False)
        self.output_text.clear()
        self.update_status("Running...", success=None)

        extra = None
        if command_type == "csv_ping" or command_type == "run_script":
            file_filter = "Text Files (*.txt);;All Files (*)" if command_type == "run_script" else "CSV Files (*.csv)"
            file_dialog = QFileDialog()
            file_dialog.setNameFilter(file_filter)
            if file_dialog.exec():
                extra = file_dialog.selectedFiles()[0]
            else:
                self.set_buttons_enabled(True)
                return

        self.thread = QThread()
        self.worker = CommandWorker(command_type, host, username, password, extra)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(lambda success: self.set_buttons_enabled(True) or self.update_status("Done" if success else "Failed", success))
        self.worker.output.connect(self.append_output)
        self.thread.start()

    def set_buttons_enabled(self, enabled):
        for key in self.buttons:
            self.buttons[key].setEnabled(enabled)
        self.host_input.setEnabled(enabled)

    def append_output(self, text):
        self.output_text.moveCursor(QTextCursor.MoveOperation.End)
        self.output_text.insertPlainText(text)
        self.output_text.moveCursor(QTextCursor.MoveOperation.End)

    def update_status(self, message, success):
        color = "green" if success else ("red" if success is False else "blue")
        self.status_label.setStyleSheet(f"color: {color}")
        self.status_label.setText(f"Status: {message}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
