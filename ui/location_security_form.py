from PyQt5.QtWidgets import QWidget, QFormLayout, QLineEdit, QComboBox, QPushButton, QHBoxLayout, QLabel, QVBoxLayout
from PyQt5.QtCore import Qt, QRegExp
from PyQt5.QtGui import QIntValidator, QRegExpValidator
import re
from services.data_sender import DataSender
from protocol.location_security_protocol import LocationSecurityProtocol

class LocationSecurityForm(QWidget):
    def __init__(self, parent=None):
        super().__init__()
        self.protocol = LocationSecurityProtocol()
        self.current_message_type = 0x0101  # Default message type
        self.message_content = {}  # Initialize message_content
        self.initial_bds_week, self.initial_bds_second = self.protocol._get_bds_week_and_second()
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()
        form_layout = QFormLayout()
        form_layout.setLabelAlignment(Qt.AlignRight)

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
        self.content_layout.setLabelAlignment(Qt.AlignRight)
        form_layout.addRow(self.content_container)

        self.create_satellite_nav_status_fields()

        layout.addLayout(form_layout)

        button_layout = QHBoxLayout()
        self.send_button = QPushButton("发送数据")
        self.send_button.clicked.connect(self.send_data)
        button_layout.addWidget(self.send_button)
        button_layout.setAlignment(Qt.AlignRight)

        layout.addLayout(button_layout)

        self.setLayout(layout)
        self.update_package_length()

    def on_message_type_changed(self, index):
        self.current_message_type = self.message_type_combo.currentData()
        if self.current_message_type == 0x0101:
            self.create_satellite_nav_status_fields()
        elif self.current_message_type == 0x0102:
            self.create_nav_message_verification_fields()
        else:
            self.clear_content_layout()
            self.content_layout.addRow(QLabel("请选择卫星导航系统服务状态信息或导航电文验证信息查看详细字段"))
        self.update_package_length()

    def create_satellite_nav_status_fields(self):
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
        self.signal_status_edit.textChanged.connect(self.update_package_length)
        self.signal_status_edit.textChanged.connect(self.update_crc_value)
        self.content_layout.addRow("导航信号状态 (4字节):", self.signal_status_edit)

        self.satellite_status_edit = QLineEdit()
        self.satellite_status_edit.setMaxLength(16)
        self.satellite_status_edit.setPlaceholderText("8字节十六进制，不足高位补0")
        self.satellite_status_edit.textChanged.connect(self.validate_hex_input)
        self.satellite_status_edit.textChanged.connect(self.update_package_length)
        self.satellite_status_edit.textChanged.connect(self.update_crc_value)
        self.content_layout.addRow("导航卫星状态 (8字节):", self.satellite_status_edit)

        self.reserved_edit = QLineEdit("0000000000000000")
        self.reserved_edit.setReadOnly(True)
        self.reserved_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("保留字段 (8字节):", self.reserved_edit)

        self.crc_edit = QLineEdit()
        self.crc_edit.setReadOnly(True)
        self.crc_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("CRC-24Q校验值 (3字节):", self.crc_edit)

    def create_nav_message_verification_fields(self):
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
        self.nav_system_combo.setCurrentText("0x14 - BDS-B3I")
        self.nav_system_combo.currentIndexChanged.connect(self.update_message_content)
        self.nav_system_combo.currentIndexChanged.connect(self.update_package_length)
        self.nav_system_combo.currentIndexChanged.connect(self.update_crc_value)
        self.nav_system_combo.currentIndexChanged.connect(self.update_message_type_options)
        self.nav_system_combo.currentIndexChanged.connect(self.update_nav_time_fields)
        self.content_layout.addRow("导航系统标识 (1字节):", self.nav_system_combo)

        self.verification_count_edit = QLineEdit("01")
        hex_validator = QRegExpValidator(QRegExp("[0-9A-Fa-f]{0,2}"))
        self.verification_count_edit.setValidator(hex_validator)
        self.verification_count_edit.textChanged.connect(self.validate_hex_input)
        self.verification_count_edit.textChanged.connect(self.update_message_content)
        self.verification_count_edit.textChanged.connect(self.update_package_length)
        self.verification_count_edit.textChanged.connect(self.update_crc_value)
        self.content_layout.addRow("电文验证信息数N (1字节):", self.verification_count_edit)

        self.satellite_number_edit = QLineEdit("01")
        self.satellite_number_edit.setValidator(hex_validator)
        self.satellite_number_edit.textChanged.connect(self.validate_hex_input)
        self.satellite_number_edit.textChanged.connect(self.update_message_content)
        self.satellite_number_edit.textChanged.connect(self.update_package_length)
        self.satellite_number_edit.textChanged.connect(self.update_crc_value)
        self.content_layout.addRow("卫星号 (1字节):", self.satellite_number_edit)

        self.nav_message_type_combo = QComboBox()
        self.update_message_type_options()
        self.nav_message_type_combo.currentIndexChanged.connect(self.update_message_content)
        self.nav_message_type_combo.currentIndexChanged.connect(self.update_package_length)
        self.nav_message_type_combo.currentIndexChanged.connect(self.update_crc_value)
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
            return

        # fallback 旧逻辑（不推荐覆盖 message_type_combo）        if hasattr(self, 'nav_message_type_combo'):
            self.nav_message_type_combo.clear()
            nav_system = self.nav_system_combo.currentData()
            if nav_system in [0x11, 0x12, 0x13, 0x14, 0x15, 0x41, 0x42, 0x43, 0x44]:
                self.nav_message_type_combo.addItem("0x01 - 类型1", 0x01)
                self.nav_message_type_combo.addItem("0x02 - 类型2", 0x02)
            else:
                self.nav_message_type_combo.addItem("0x01 - 类型1", 0x01)

    def clear_content_layout(self):
        while self.content_layout.rowCount() > 0:
            self.content_layout.removeRow(0)

    def validate_hex_input(self):
        sender = self.sender()
        if sender:
            text = re.sub(r'[^0-9A-Fa-f]', '', sender.text())
            sender.setText(text.upper())
    
    def on_message_type_changed(self, index):
        """消息类型改变时更新内容区域"""
        self.current_message_type = self.message_type_combo.currentData()
        
        # 根据消息类型显示不同的内容字段
        if self.current_message_type == 0x0101:
            self.create_satellite_nav_status_fields()
        elif self.current_message_type == 0x0102:
            self.create_nav_message_verification_fields()
        else:
            # 清空内容区域，显示提示
            self.clear_content_layout()
            self.content_layout.addRow(QLabel("请选择卫星导航系统服务状态信息或导航电文验证信息查看详细字段"))
        
        self.update_package_length()
    
    def create_nav_message_verification_fields(self):
        """创建导航电文验证信息的字段"""
        # 清空现有内容
        self.clear_content_layout()
        
        # 参考周计数 (固定为初始值)
        self.week_edit = QLineEdit()
        self.week_edit.setReadOnly(True)
        self.week_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("参考周计数 (2字节):", self.week_edit)
        
        # 参考时间 (固定为初始值)
        self.time_edit = QLineEdit()
        self.time_edit.setReadOnly(True)
        self.time_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("参考时间 (4字节):", self.time_edit)
        
        # 导航系统标识 (选择框)
        self.nav_system_combo = QComboBox()
        for code, desc in self.protocol.NAV_SYSTEM_OPTIONS.items():
            self.nav_system_combo.addItem(f"0x{code:02X} - {desc}", code)
        self.nav_system_combo.setCurrentText("0x14 - BDS-B3I")  # 默认BDS
        self.nav_system_combo.currentIndexChanged.connect(self.update_message_content)
        self.nav_system_combo.currentIndexChanged.connect(self.update_package_length)
        self.nav_system_combo.currentIndexChanged.connect(self.update_crc_value)
        self.nav_system_combo.currentIndexChanged.connect(self.update_message_type_options)
        self.nav_system_combo.currentIndexChanged.connect(self.update_nav_time_fields)  # 新增：导航系统变化时更新时间
        self.content_layout.addRow("导航系统标识 (1字节):", self.nav_system_combo)
        
        # 电文验证信息数N (用户输入，限制为2位十六进制)
        self.verification_count_edit = QLineEdit("01")
        hex_validator = QRegExpValidator(QRegExp("[0-9A-Fa-f]{0,2}"))  # 最多2位十六进制
        self.verification_count_edit.setValidator(hex_validator)
        self.verification_count_edit.textChanged.connect(self.validate_hex_input)
        self.verification_count_edit.textChanged.connect(self.update_message_content)
        self.verification_count_edit.textChanged.connect(self.update_package_length)
        self.verification_count_edit.textChanged.connect(self.update_crc_value)
        self.content_layout.addRow("电文验证信息数N (1字节):", self.verification_count_edit)
        
        # 卫星号 (用户输入，限制为2位十六进制)
        self.satellite_number_edit = QLineEdit("01")
        self.satellite_number_edit.setValidator(hex_validator)
        self.satellite_number_edit.textChanged.connect(self.validate_hex_input)
        self.satellite_number_edit.textChanged.connect(self.update_message_content)
        self.satellite_number_edit.textChanged.connect(self.update_package_length)
        self.satellite_number_edit.textChanged.connect(self.update_crc_value)
        self.content_layout.addRow("卫星号 (1字节):", self.satellite_number_edit)
        
        # 电文类型 (选择框)
        self.nav_message_type_combo = QComboBox()  # ✅ FIX
        self.update_message_type_options()  # 初始化选项
        self.nav_message_type_combo.currentIndexChanged.connect(self.update_message_content)
        self.nav_message_type_combo.currentIndexChanged.connect(self.update_package_length)
        self.nav_message_type_combo.currentIndexChanged.connect(self.update_crc_value)
        self.content_layout.addRow("电文类型 (1字节):", self.nav_message_type_combo)
        
        # 电文参考时间 (根据导航系统自动计算)
        self.ref_time_edit = QLineEdit()
        self.ref_time_edit.setReadOnly(True)
        self.ref_time_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("电文参考时间 (3字节):", self.ref_time_edit)
        
        # 电文验证字 (固定显示FFFFFF)
        self.verification_word_edit = QLineEdit("FFFFFF")
        self.verification_word_edit.setReadOnly(True)
        self.verification_word_edit.setStyleSheet("background-color: #f0f0f0;")
        self.content_layout.addRow("电文验证字 (3字节):", self.verification_word_edit)
        
        # 初始更新时间字段
        self.update_nav_time_fields()
        
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
            return

        # fallback 旧逻辑（不推荐覆盖 message_type_combo）        """根据导航系统更新电文类型选项"""
        self.message_type_combo.clear()
        nav_system = self.nav_system_combo.currentData()
        
        # BDS和GALILEO提供01, 02选项
        if nav_system in [0x11, 0x12, 0x13, 0x14, 0x15, 0x41, 0x42, 0x43, 0x44]:
            self.message_type_combo.addItem("0x01 - 类型1", 0x01)
            self.message_type_combo.addItem("0x02 - 类型2", 0x02)
        # GPS和GLONASS只提供01选项
        else:
            self.message_type_combo.addItem("0x01 - 类型1", 0x01)

    def update_message_content(self):
        if self.current_message_type == 0x0101:
            self.message_content = {
                'nav_system': self.nav_system_combo.currentData(),
                'nav_status': self.nav_status_combo.currentData(),
                'signal_status': self.signal_status_edit.text().zfill(8),
                'satellite_status': self.satellite_status_edit.text().zfill(16)
            }
        elif self.current_message_type == 0x0102:
            # 确保 message_type 有默认值（避免 None）
            message_type = self.nav_message_type_combo.currentData()
            if message_type is None:
                message_type = 0x01

            self.message_content = {
                'nav_system': self.nav_system_combo.currentData(),
                'verification_count': self.verification_count_edit.text().zfill(2) if self.verification_count_edit.text() else '00',
                'satellite_number': self.satellite_number_edit.text().zfill(2) if self.satellite_number_edit.text() else '00',
                'message_type': message_type,
                'ref_time': self.ref_time_edit.text(),
                'verification_word': self.verification_word_edit.text()
            }


    def send_data(self):
        """发送数据"""
        if self.current_message_type == 0x0101:
            # 收集卫星导航系统服务状态消息内容（补0处理）
            content = {
                'nav_system': self.nav_system_combo.currentData(),
                'nav_status': self.nav_status_combo.currentData(),
                'signal_status': self.signal_status_edit.text().zfill(8),  # 不足8位高位补0
                'satellite_status': self.satellite_status_edit.text().zfill(16)  # 不足16位高位补0
            }
            
            # 设置消息类型和内容
            self.protocol.set_message_type(self.current_message_type)
            self.protocol.set_satellite_nav_status_content(content)
            
            # 序列化数据
            serialized_data = self.protocol.serialize(self.current_message_type, content)
            
            # 发送数据
            data_sender = DataSender()
            data_sender.send(serialized_data)
            
            # 显示发送成功信息
            print(f"数据发送成功: {serialized_data}")
        elif self.current_message_type == 0x0102:
            # 收集导航电文验证信息内容
            content = {
                'nav_system': self.nav_system_combo.currentData(),
                'verification_count': int(self.verification_count_edit.text().zfill(2), 16) if self.verification_count_edit.text() else 0
            }
            
            # 设置消息类型和内容
            self.protocol.set_message_type(self.current_message_type)
            self.protocol.set_satellite_nav_status_content(content)
            
            # 序列化数据
            serialized_data = self.protocol.serialize(self.current_message_type, content)
            
            # 发送数据
            data_sender = DataSender()
            data_sender.send(serialized_data)
            
            # 显示发送成功信息
            print(f"数据发送成功: {serialized_data}")
        else:
            print("当前消息类型尚未实现发送功能")

    def update_crc_value(self):
        """更新CRC-24Q校验值显示"""
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
        if self.current_message_type == 0x0101:
            # 更新消息内容以确保我们使用最新数据
            self.update_message_content()
            # 使用协议类计算实际包长度（包括CRC）
            package_length = self.protocol.get_package_length(
                self.current_message_type, 
                self.message_content
            )
            self.package_length_edit.setText(f"{package_length:04X}")
        elif self.current_message_type == 0x0102:
            # 更新消息内容
            self.update_message_content()
            # 计算包长
            package_length = self.protocol.get_package_length(self.current_message_type, self.message_content)
            self.package_length_edit.setText(f"{package_length:04X}")
        else:
                # 其他消息默认长度（如只含头部）
                header_length = 4 + 1 + 2 + 2
                self.package_length_edit.setText(f"{header_length:04X}")
            # 同时更新CRC值
        self.update_crc_value()