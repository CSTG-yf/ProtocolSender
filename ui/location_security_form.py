from PyQt5.QtWidgets import QWidget, QFormLayout, QLineEdit, QComboBox, QPushButton, QHBoxLayout, QLabel, QVBoxLayout, QMessageBox
from PyQt5.QtCore import Qt, QRegExp
from PyQt5.QtGui import QIntValidator, QRegExpValidator
import re
from services.data_sender import DataSender
from protocol.location_security_protocol import LocationSecurityProtocol

class LocationSecurityForm(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.protocol = LocationSecurityProtocol()
        self.data_sender = DataSender()
        self.current_message_type = 0x0101  # Default message type
        self.message_content = {}  # Initialize message_content
        self.initial_bds_week, self.initial_bds_second = self.protocol._get_bds_week_and_second()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        self.identifier_edit = QLineEdit()
        self.identifier_edit.setText(f"{self.protocol.FIXED_IDENTIFIER:08X}")
        self.identifier_edit.setReadOnly(True)
        self.identifier_edit.setStyleSheet("background-color: #f0f0f0;")
        form_layout.addRow("标识符 (4字节):", self.identifier_edit)

        self.version_edit = QLineEdit()
        self.version_edit.setText(f"{self.protocol.FIXED_VERSION:02X}")
        self.version_edit.setReadOnly(True)
        self.version_edit.setStyleSheet("background-color: #f0f0f0;")
        form_layout.addRow("版本号 (1字节):", self.version_edit)

        self.package_length_edit = QLineEdit()
        self.package_length_edit.setReadOnly(True)
        self.package_length_edit.setStyleSheet("background-color: #f0f0f0;")
        form_layout.addRow("包长度 (2字节):", self.package_length_edit)

        self.message_type_combo = QComboBox()
        for code, desc in self.protocol.MESSAGE_TYPES.items():
            self.message_type_combo.addItem(f"0x{code:04X} - {desc}", code)
        self.message_type_combo.setCurrentIndex(0)
        self.message_type_combo.currentIndexChanged.connect(self.on_message_type_changed)
        form_layout.addRow("消息类型 (2字节):", self.message_type_combo)

        self.content_container = QWidget()
        self.content_layout = QFormLayout(self.content_container)
        self.content_layout.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form_layout.addRow(self.content_container)

        self.create_satellite_nav_status_fields()

        layout.addLayout(form_layout)

        button_layout = QHBoxLayout()
        self.send_button = QPushButton("发送数据")
        self.send_button.clicked.connect(self.send_data)
        button_layout.addWidget(self.send_button)
        button_layout.setAlignment(Qt.AlignmentFlag.AlignRight)

        layout.addLayout(button_layout)

        self.setLayout(layout)
        self.update_package_length()

    def on_message_type_changed(self, index):
        """消息类型改变时更新内容区域"""
        self.current_message_type = self.message_type_combo.currentData()
        
        # 根据消息类型显示不同的内容字段
        if self.current_message_type == 0x0101:
            self.create_satellite_nav_status_fields()
        elif self.current_message_type == 0x0102:
            self.create_nav_message_verification_fields()
        elif self.current_message_type == 0x0103:
            self.create_interference_warning_fields()
        elif self.current_message_type == 0x0104:
            self.create_spoofing_warning_fields()
        else:
            # 清空内容区域，显示提示
            self.clear_content_layout()
            self.content_layout.addRow(QLabel("请选择有效的消息类型查看详细字段"))
        
        self.update_package_length()

    def create_satellite_nav_status_fields(self):
        """创建卫星导航系统服务状态信息的字段"""
        self.clear_content_layout()

        self.week_edit = QLineEdit()
        self.week_edit.setText(f"{self.initial_bds_week:04X}")
        self.week_edit.setReadOnly(True)
        self.week_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("参考周计数 (2字节):", self.week_edit)

        self.second_edit = QLineEdit()
        self.second_edit.setText(f"{self.initial_bds_second:08X}")
        self.second_edit.setReadOnly(True)
        self.second_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("参考周计秒 (4字节):", self.second_edit)

        self.nav_system_combo = QComboBox()
        for code, desc in self.protocol.NAV_SYSTEM_OPTIONS.items():
            self.nav_system_combo.addItem(f"0x{code:02X} - {desc}", code)
        self.nav_system_combo.setCurrentText("0x14 - 北斗")
        self.nav_system_combo.currentIndexChanged.connect(self.update_message_content)
        self.nav_system_combo.currentIndexChanged.connect(self.update_package_length)
        self.nav_system_combo.currentIndexChanged.connect(self.update_crc_value)
        self.content_layout.addRow("导航系统标识 (1字节):", self.nav_system_combo)

        self.nav_status_combo = QComboBox()
        for code, desc in self.protocol.NAV_STATUS_OPTIONS.items():
            self.nav_status_combo.addItem(f"0x{code:02X} - {desc}", code)
        self.nav_status_combo.setCurrentIndex(0)
        self.nav_status_combo.currentIndexChanged.connect(self.update_message_content)
        self.nav_status_combo.currentIndexChanged.connect(self.update_package_length)
        self.nav_status_combo.currentIndexChanged.connect(self.update_crc_value)
        self.content_layout.addRow("导航系统状态 (1字节):", self.nav_status_combo)

        self.signal_status_edit = QLineEdit()
        self.signal_status_edit.setMaxLength(8)
        self.signal_status_edit.setPlaceholderText("4字节十六进制，不足高位补0")
        self.signal_status_edit.textChanged.connect(self.validate_hex_input)
        self.signal_status_edit.textChanged.connect(self.update_message_content)
        self.signal_status_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("导航信号状态 (4字节):", self.signal_status_edit)

        self.satellite_status_edit = QLineEdit()
        self.satellite_status_edit.setMaxLength(16)
        self.satellite_status_edit.setPlaceholderText("8字节十六进制，不足高位补0")
        self.satellite_status_edit.textChanged.connect(self.validate_hex_input)
        self.satellite_status_edit.textChanged.connect(self.update_message_content)
        self.satellite_status_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("导航卫星状态 (8字节):", self.satellite_status_edit)

        self.reserved_edit = QLineEdit("0000000000000000")
        self.reserved_edit.setReadOnly(True)
        self.reserved_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("保留字段 (8字节):", self.reserved_edit)

        # 创建CRC编辑框
        self.crc_edit = QLineEdit()
        self.crc_edit.setReadOnly(True)
        self.crc_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("CRC-24Q校验值 (3字节):", self.crc_edit)

    def create_nav_message_verification_fields(self):
        """创建导航电文验证信息的字段"""
        self.clear_content_layout()
        
        self.week_edit = QLineEdit()
        self.week_edit.setReadOnly(True)
        self.week_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("参考周计数 (2字节):", self.week_edit)
        
        self.time_edit = QLineEdit()
        self.time_edit.setReadOnly(True)
        self.time_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("参考时间 (4字节):", self.time_edit)
        
        self.nav_system_combo = QComboBox()
        for code, desc in self.protocol.NAV_SYSTEM_OPTIONS.items():
            self.nav_system_combo.addItem(f"0x{code:02X} - {desc}", code)
        self.nav_system_combo.setCurrentText("0x14 - BDS-B3I")  # 默认BDS
        self.nav_system_combo.currentIndexChanged.connect(self.update_message_content)
        self.nav_system_combo.currentIndexChanged.connect(self.update_package_length)
        self.nav_system_combo.currentIndexChanged.connect(self.update_message_type_options)
        self.nav_system_combo.currentIndexChanged.connect(self.update_nav_time_fields)  # 新增：导航系统变化时更新时间
        self.content_layout.addRow("导航系统标识 (1字节):", self.nav_system_combo)
        
        self.verification_count_edit = QLineEdit("01")
        hex_validator = QRegExpValidator(QRegExp("[0-9A-Fa-f]{0,2}"))  # 最多2位十六进制
        self.verification_count_edit.setValidator(hex_validator)
        self.verification_count_edit.textChanged.connect(self.validate_hex_input)
        self.verification_count_edit.textChanged.connect(self.update_message_content)
        self.verification_count_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("电文验证信息数N (1字节):", self.verification_count_edit)
        
        self.satellite_number_edit = QLineEdit("01")
        self.satellite_number_edit.setValidator(hex_validator)
        self.satellite_number_edit.textChanged.connect(self.validate_hex_input)
        self.satellite_number_edit.textChanged.connect(self.update_message_content)
        self.satellite_number_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("卫星号 (1字节):", self.satellite_number_edit)
        
        self.nav_message_type_combo = QComboBox()
        self.update_message_type_options()
        self.nav_message_type_combo.currentIndexChanged.connect(self.update_message_content)
        self.nav_message_type_combo.currentIndexChanged.connect(self.update_package_length)
        self.content_layout.addRow("电文类型 (1字节):", self.nav_message_type_combo)
        
        self.ref_time_edit = QLineEdit()
        self.ref_time_edit.setReadOnly(True)
        self.ref_time_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("电文参考时间 (3字节):", self.ref_time_edit)
        
        self.verification_word_edit = QLineEdit("FFFFFF")
        self.verification_word_edit.setReadOnly(True)
        self.verification_word_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("电文验证字 (3字节):", self.verification_word_edit)
        
        self.update_nav_time_fields()

    def create_interference_warning_fields(self):
        """创建压制干扰告警信息的字段"""
        self.clear_content_layout()
        
        self.week_edit = QLineEdit()
        self.week_edit.setText(f"{self.initial_bds_week:04X}")
        self.week_edit.setReadOnly(True)
        self.week_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("BDS参考周计数 (2字节):", self.week_edit)
        
        self.second_edit = QLineEdit()
        self.second_edit.setText(f"{self.initial_bds_second:08X}")
        self.second_edit.setReadOnly(True)
        self.second_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("BDS参考周内秒 (4字节):", self.second_edit)
        
        self.interference_count_edit = QLineEdit("01")
        self.interference_count_edit.setReadOnly(True)
        self.interference_count_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("压制干扰数目n (1字节):", self.interference_count_edit)
        
        self.latitude_edit = QLineEdit()
        self.latitude_edit.setMaxLength(8)
        self.latitude_edit.setPlaceholderText("4字节十六进制，不足高位补0")
        self.latitude_edit.textChanged.connect(self.validate_hex_input)
        self.latitude_edit.textChanged.connect(self.update_message_content)
        self.latitude_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("压制干扰纬度 (4字节):", self.latitude_edit)
        
        self.longitude_edit = QLineEdit()
        self.longitude_edit.setMaxLength(8)
        self.longitude_edit.setPlaceholderText("4字节十六进制，不足高位补0")
        self.longitude_edit.textChanged.connect(self.validate_hex_input)
        self.longitude_edit.textChanged.connect(self.update_message_content)
        self.longitude_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("压制干扰经度 (4字节):", self.longitude_edit)
        
        self.center_freq_edit = QLineEdit()
        self.center_freq_edit.setMaxLength(8)
        self.center_freq_edit.setPlaceholderText("4字节十六进制，不足高位补0")
        self.center_freq_edit.textChanged.connect(self.validate_hex_input)
        self.center_freq_edit.textChanged.connect(self.update_message_content)
        self.center_freq_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("压制干扰中心频率 (4字节):", self.center_freq_edit)
        
        self.bandwidth_edit = QLineEdit()
        self.bandwidth_edit.setMaxLength(4)
        self.bandwidth_edit.setPlaceholderText("2字节十六进制，不足高位补0")
        self.bandwidth_edit.textChanged.connect(self.validate_hex_input)
        self.bandwidth_edit.textChanged.connect(self.update_message_content)
        self.bandwidth_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("压制干扰带宽 (2字节):", self.bandwidth_edit)
        
        self.interference_type_combo = QComboBox()
        for code, desc in self.protocol.INTERFERENCE_TYPE_OPTIONS.items():
            self.interference_type_combo.addItem(f"{code} - {desc}", code)
        self.interference_type_combo.currentIndexChanged.connect(self.update_message_content)
        self.interference_type_combo.currentIndexChanged.connect(self.update_package_length)
        self.content_layout.addRow("压制干扰类型 (1字节):", self.interference_type_combo)
        
        self.intensity_edit = QLineEdit()
        self.intensity_edit.setMaxLength(2)
        self.intensity_edit.setPlaceholderText("1字节十六进制，不足高位补0")
        self.intensity_edit.textChanged.connect(self.validate_hex_input)
        self.intensity_edit.textChanged.connect(self.update_message_content)
        self.intensity_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("压制干扰强度 (1字节):", self.intensity_edit)
        
        self.confidence_edit = QLineEdit()
        self.confidence_edit.setMaxLength(2)
        self.confidence_edit.setPlaceholderText("2位十六进制数")
        hex_validator = QRegExpValidator(QRegExp("[0-9A-Fa-f]{0,2}"))
        self.confidence_edit.setValidator(hex_validator)
        self.confidence_edit.textChanged.connect(self.validate_hex_input)
        self.confidence_edit.textChanged.connect(self.update_message_content)
        self.confidence_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("压制干扰置信度 (1字节):", self.confidence_edit)

    def create_spoofing_warning_fields(self):
        """创建欺骗干扰告警信息的字段"""
        self.clear_content_layout()
        
        # BDS参考周计数
        self.week_edit = QLineEdit()
        self.week_edit.setText(f"{self.initial_bds_week:04X}")
        self.week_edit.setReadOnly(True)
        self.week_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("BDS参考周计数 (2字节):", self.week_edit)
        
        # BDS参考周内秒
        self.second_edit = QLineEdit()
        self.second_edit.setText(f"{self.initial_bds_second:08X}")
        self.second_edit.setReadOnly(True)
        self.second_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("BDS参考周内秒 (4字节):", self.second_edit)
        
        # 欺骗干扰数目m
        self.spoofing_count_edit = QLineEdit("01")
        self.spoofing_count_edit.setReadOnly(True)
        self.spoofing_count_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("欺骗干扰数目m (1字节):", self.spoofing_count_edit)
        
        # 欺骗干扰纬度
        self.latitude_edit = QLineEdit()
        self.latitude_edit.setMaxLength(8)
        self.latitude_edit.setPlaceholderText("4字节十六进制，不足高位补0")
        self.latitude_edit.textChanged.connect(self.validate_hex_input)
        self.latitude_edit.textChanged.connect(self.update_message_content)
        self.latitude_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("欺骗干扰纬度 (4字节):", self.latitude_edit)
        
        # 欺骗干扰经度
        self.longitude_edit = QLineEdit()
        self.longitude_edit.setMaxLength(8)
        self.longitude_edit.setPlaceholderText("4字节十六进制，不足高位补0")
        self.longitude_edit.textChanged.connect(self.validate_hex_input)
        self.longitude_edit.textChanged.connect(self.update_message_content)
        self.longitude_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("欺骗干扰经度 (4字节):", self.longitude_edit)
        
        # 欺骗干扰有效距离
        self.effective_distance_edit = QLineEdit()
        self.effective_distance_edit.setMaxLength(2)
        self.effective_distance_edit.setPlaceholderText("1字节十六进制，不足高位补0")
        self.effective_distance_edit.textChanged.connect(self.validate_hex_input)
        self.effective_distance_edit.textChanged.connect(self.update_message_content)
        self.effective_distance_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("欺骗干扰有效距离 (1字节):", self.effective_distance_edit)
        
        # 欺骗干扰的卫星导航信号
        self.nav_system_combo = QComboBox()
        for code, desc in self.protocol.NAV_SYSTEM_OPTIONS.items():
            self.nav_system_combo.addItem(f"0x{code:02X} - {desc}", code)
        self.nav_system_combo.setCurrentText("0x14 - BDS-B3I")  # 默认BDS
        self.nav_system_combo.currentIndexChanged.connect(self.update_message_content)
        self.nav_system_combo.currentIndexChanged.connect(self.update_package_length)
        self.content_layout.addRow("欺骗干扰的卫星导航信号 (1字节):", self.nav_system_combo)
        
        # 欺骗干扰置信度
        self.confidence_edit = QLineEdit()
        self.confidence_edit.setMaxLength(2)
        self.confidence_edit.setPlaceholderText("2位十六进制数")
        hex_validator = QRegExpValidator(QRegExp("[0-9A-Fa-f]{0,2}"))
        self.confidence_edit.setValidator(hex_validator)
        self.confidence_edit.textChanged.connect(self.validate_hex_input)
        self.confidence_edit.textChanged.connect(self.update_message_content)
        self.confidence_edit.textChanged.connect(self.update_package_length)
        self.content_layout.addRow("欺骗干扰置信度 (1字节):", self.confidence_edit)

    def validate_confidence(self):
        """验证置信度输入是否为有效的十六进制数"""
        if not hasattr(self, 'confidence_edit'):
            return
            
        text = self.confidence_edit.text().strip()
        if text:
            try:
                # 验证是否为有效的十六进制数
                int(text, 16)
            except ValueError:
                self.confidence_edit.setText("")

    def clear_content_layout(self):
        while self.content_layout.rowCount() > 0:
            self.content_layout.removeRow(0)

    def validate_hex_input(self):
        """验证十六进制输入"""
        sender = self.sender()
        if isinstance(sender, QLineEdit):
            text = re.sub(r'[^0-9A-Fa-f]', '', sender.text())
            sender.setText(text.upper())
    
    def update_nav_time_fields(self):
        """更新导航系统时间字段"""
        nav_system = self.nav_system_combo.currentData()
        protocol = self.protocol
        
        if nav_system in [0x11, 0x12, 0x13, 0x14, 0x15]:  # BDS系统
            week, second = protocol._get_bds_week_and_second()
            self.week_edit.setText(f"{week:04X}")
            self.time_edit.setText(f"{second:08X}")
            # 取后3字节作为电文参考时间
            ref_time = second.to_bytes(4, byteorder='big')[-3:].hex().upper()
            self.ref_time_edit.setText(ref_time)
        elif nav_system in [0x21, 0x22, 0x23, 0x24]:  # GPS系统
            week, second = protocol._get_gps_week_and_second()
            self.week_edit.setText(f"{week:04X}")
            self.time_edit.setText(f"{second:08X}")
            ref_time = second.to_bytes(4, byteorder='big')[-3:].hex().upper()
            self.ref_time_edit.setText(ref_time)
        elif nav_system in [0x41, 0x42, 0x43, 0x44]:  # GALILEO系统
            week, second = protocol._get_galileo_week_and_second()
            self.week_edit.setText(f"{week:04X}")
            self.time_edit.setText(f"{second:08X}")
            ref_time = second.to_bytes(4, byteorder='big')[-3:].hex().upper()
            self.ref_time_edit.setText(ref_time)
        elif nav_system in [0x31, 0x32, 0x33]:  # GLONASS系统
            second = protocol._get_glonass_day_second()
            self.week_edit.setText("0000")  # GLONASS不需要周计数
            self.time_edit.setText(f"{second:08X}")
            ref_time = second.to_bytes(4, byteorder='big')[-3:].hex().upper()
            self.ref_time_edit.setText(ref_time)   
    
    def update_message_type_options(self):
        """根据导航系统更新电文类型选项"""
        if hasattr(self, 'nav_message_type_combo'):
            self.nav_message_type_combo.clear()
            nav_system = self.nav_system_combo.currentData()
            if nav_system in [0x11, 0x12, 0x13, 0x14, 0x15, 0x41, 0x42, 0x43, 0x44]:
                self.nav_message_type_combo.addItem("0x01 - 类型1", 0x01)
                self.nav_message_type_combo.addItem("0x02 - 类型2", 0x02)
            else:
                self.nav_message_type_combo.addItem("0x01 - 类型1", 0x01)

    def update_message_content(self):
        """更新消息内容"""
        if not hasattr(self, 'current_message_type'):
            return
            
        if self.current_message_type == 0x0101:
            self.message_content = {
                'nav_system': self.nav_system_combo.currentData(),
                'nav_status': 0x00,  # 默认值
                'signal_status': '00000000',  # 默认值
                'satellite_status': '0000000000000000',  # 默认值
            }
        elif self.current_message_type == 0x0102:
            self.message_content = {
                'nav_system': self.nav_system_combo.currentData(),
                'verification_count': self.verification_count_edit.text(),
                'satellite_number': self.satellite_number_edit.text(),
                'message_type': self.nav_message_type_combo.currentData(),
                'ref_time': self.ref_time_edit.text(),
                'verification_word': self.verification_word_edit.text()
            }
        elif self.current_message_type == 0x0103:
            self.message_content = {
                'latitude': self.latitude_edit.text().zfill(8),
                'longitude': self.longitude_edit.text().zfill(8),
                'center_freq': self.center_freq_edit.text().zfill(8),
                'bandwidth': self.bandwidth_edit.text().zfill(4),
                'interference_type': self.interference_type_combo.currentData(),
                'intensity': self.intensity_edit.text().zfill(2),
                'confidence': self.confidence_edit.text().zfill(2)
            }
        elif self.current_message_type == 0x0104:
            self.message_content = {
                'latitude': self.latitude_edit.text().zfill(8),
                'longitude': self.longitude_edit.text().zfill(8),
                'effective_distance': self.effective_distance_edit.text().zfill(2),
                'nav_system': self.nav_system_combo.currentData(),
                'confidence': self.confidence_edit.text().zfill(2)
            }


    def send_data(self):
        """发送数据"""
        try:
            # 根据消息类型收集不同的数据
            if self.current_message_type == 0x0101:
                message_content = {
                    'nav_system': self.nav_system_combo.currentData(),
                    'nav_status': 0x00,  # 默认值
                    'signal_status': '00000000',  # 默认值
                    'satellite_status': '0000000000000000',  # 默认值
                }
            elif self.current_message_type == 0x0102:
                message_content = {
                    'nav_system': self.nav_system_combo.currentData(),
                    'verification_count': self.verification_count_edit.text(),
                    'satellite_number': self.satellite_number_edit.text(),
                    'message_type': self.nav_message_type_combo.currentData(),
                    'ref_time': self.ref_time_edit.text(),
                    'verification_word': self.verification_word_edit.text()
                }
            elif self.current_message_type == 0x0103:
                message_content = {
                    'latitude': self.latitude_edit.text().zfill(8),
                    'longitude': self.longitude_edit.text().zfill(8),
                    'center_freq': self.center_freq_edit.text().zfill(8),
                    'bandwidth': self.bandwidth_edit.text().zfill(4),
                    'interference_type': self.interference_type_combo.currentData(),
                    'intensity': self.intensity_edit.text().zfill(2),
                    'confidence': self.confidence_edit.text().zfill(2)
                }
            elif self.current_message_type == 0x0104:
                message_content = {
                    'latitude': self.latitude_edit.text().zfill(8),
                    'longitude': self.longitude_edit.text().zfill(8),
                    'effective_distance': self.effective_distance_edit.text().zfill(2),
                    'nav_system': self.nav_system_combo.currentData(),
                    'confidence': self.confidence_edit.text().zfill(2)
                }
            else:
                QMessageBox.warning(self, "错误", "不支持的消息类型")
                return

            # 序列化数据
            data_hex = self.protocol.serialize(self.current_message_type, message_content)
            
            # 发送数据
            self.data_sender.send_data(data_hex)
            
            # 显示成功消息
            QMessageBox.information(self, "成功", "数据发送成功！")
            
        except Exception as e:
            QMessageBox.critical(self, "错误", f"发送数据时出错：{str(e)}")
            import traceback
            traceback.print_exc()

    def update_crc_value(self):
        """更新CRC-24Q校验值显示"""
        if not hasattr(self, 'crc_edit'):
            return
            
        if self.current_message_type == 0x0101:
            # 收集当前内容
            self.update_message_content()
            # 序列化数据以获取包含CRC的完整数据包
            data_hex = self.protocol.serialize(self.current_message_type, self.message_content)
            # 提取CRC部分（最后6个字符，3字节=6个十六进制字符）
            if len(data_hex) >= 6:
                crc_hex = data_hex[-6:]
                self.crc_edit.setText(crc_hex)
            else:
                self.crc_edit.setText("")

    def update_package_length(self):
        """动态更新包长度显示"""
        if not hasattr(self, 'package_length_edit'):
            return
            
        # 更新消息内容以确保我们使用最新数据
        self.update_message_content()
        
        # 使用协议类计算实际包长度
        package_length = self.protocol.get_package_length(
            self.current_message_type, 
            self.message_content
        )
        self.package_length_edit.setText(f"{package_length:04X}")
        
        # 只有0x0101类型需要更新CRC值
        if self.current_message_type == 0x0101:
            self.update_crc_value()