from PyQt5.QtWidgets import QWidget, QHBoxLayout, QLabel, QComboBox, QPushButton
from serial.tools import list_ports

class SerialPortWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.refresh_ports()

    def init_ui(self):
        layout = QHBoxLayout()
        self.label = QLabel("串口选择：")
        self.combo = QComboBox()
        self.baud_label = QLabel("波特率：")
        self.baud_combo = QComboBox()
        self.baud_combo.addItems(["9600", "19200", "38400", "57600", "115200", "230400", "460800", "921600"])
        self.baud_combo.setCurrentText("115200")
        self.refresh_button = QPushButton("刷新")
        self.refresh_button.setToolTip("刷新串口列表")
        self.refresh_button.clicked.connect(self.refresh_ports)
        layout.addWidget(self.label)
        layout.addWidget(self.combo)
        layout.addWidget(self.baud_label)
        layout.addWidget(self.baud_combo)
        layout.addWidget(self.refresh_button)
        layout.addStretch()
        self.setLayout(layout)

    def refresh_ports(self):
        self.combo.clear()
        ports = list(list_ports.comports())
        for port in ports:
            self.combo.addItem(f"{port.device} - {port.description}", port.device)
        if ports:
            self.combo.setCurrentIndex(0)

    def get_selected_port(self):
        return self.combo.currentData()

    def get_selected_baudrate(self):
        return int(self.baud_combo.currentText()) 