from PyQt5.QtWidgets import (QWidget, QFormLayout, QLineEdit, QPushButton, 
                          QHBoxLayout, QVBoxLayout, QComboBox, QLabel, QStackedWidget,
                          QScrollArea, QMessageBox)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QRegExpValidator
from protocol.auxiliary_location_protocol import AuxiliaryLocationProtocol
from services.data_sender import DataSender

class AuxiliaryLocationForm(QWidget):
    def __init__(self):
        super().__init__()
        self.protocol = AuxiliaryLocationProtocol()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # 创建表单布局
        form_layout = QFormLayout()
        
        # 添加协议标识符显示（只读）
        self.protocol_id = QLineEdit()
        self.protocol_id.setReadOnly(True)
        self.protocol_id.setText(f"0x{self.protocol.PROTOCOL_IDENTIFIER:08X}")  # 确保显示8位十六进制
        form_layout.addRow("协议标识符:", self.protocol_id)
        
        # 添加协议版本号显示（只读）
        self.protocol_version = QLineEdit()
        self.protocol_version.setReadOnly(True)
        self.protocol_version.setText(f"0x{self.protocol.PROTOCOL_VERSION:02X}")  # 确保显示2位十六进制
        form_layout.addRow("协议版本号:", self.protocol_version)
        
        # 添加包长度显示（只读）
        self.packet_length = QLineEdit()
        self.packet_length.setReadOnly(True)
        self.packet_length.setText("0")  # 初始值
        form_layout.addRow("包长度:", self.packet_length)
        
        # 添加消息类型选择
        self.message_type = QComboBox()
        for msg_type, description in self.protocol.MSG_TYPE_DESCRIPTIONS.items():
            # 确保消息类型显示4位十六进制
            self.message_type.addItem(f"0x{msg_type:04X} - {description}", msg_type)
        self.message_type.currentIndexChanged.connect(self.on_message_type_changed)
        form_layout.addRow("消息类型:", self.message_type)
        
        layout.addLayout(form_layout)
        
        # 创建消息内容堆叠窗口
        self.content_stack = QStackedWidget()
        
        # 创建0x0201消息类型的表单
        self.form_0201 = QWidget()
        form_0201_layout = QFormLayout()
        
        # 概略位置X
        self.pos_x = QLineEdit()
        self.pos_x.setPlaceholderText("输入十六进制值（4字节）")
        self.setup_hex_validator(self.pos_x, 32)  # 4字节 = 32位
        self.pos_x.textChanged.connect(self.update_packet_length)
        form_0201_layout.addRow("概略位置X:", self.pos_x)
        
        # 概略位置Y
        self.pos_y = QLineEdit()
        self.pos_y.setPlaceholderText("输入十六进制值（4字节）")
        self.setup_hex_validator(self.pos_y, 32)  # 4字节 = 32位
        self.pos_y.textChanged.connect(self.update_packet_length)
        form_0201_layout.addRow("概略位置Y:", self.pos_y)
        
        # 概略位置Z
        self.pos_z = QLineEdit()
        self.pos_z.setPlaceholderText("输入十六进制值（4字节）")
        self.setup_hex_validator(self.pos_z, 32)  # 4字节 = 32位
        self.pos_z.textChanged.connect(self.update_packet_length)
        form_0201_layout.addRow("概略位置Z:", self.pos_z)
        
        # 当前时间周计数（只读）
        self.week_number = QLineEdit()
        self.week_number.setReadOnly(True)
        self.week_number.setText(f"0x{self.protocol.week_number:04X}")
        form_0201_layout.addRow("当前时间周计数:", self.week_number)
        
        # 当前时间周内秒（只读）
        self.seconds = QLineEdit()
        self.seconds.setReadOnly(True)
        self.seconds.setText(f"0x{self.protocol.seconds:08X}")
        form_0201_layout.addRow("当前时间周内秒:", self.seconds)
        
        # 位置误差
        self.pos_error = QLineEdit()
        self.pos_error.setPlaceholderText("输入十六进制值（2字节）")
        self.setup_hex_validator(self.pos_error, 16)  # 2字节 = 16位
        self.pos_error.textChanged.connect(self.update_packet_length)
        form_0201_layout.addRow("位置误差:", self.pos_error)
        
        # 时间误差
        self.time_error = QLineEdit()
        self.time_error.setPlaceholderText("输入十六进制值（2字节）")
        self.setup_hex_validator(self.time_error, 16)  # 2字节 = 16位
        self.time_error.textChanged.connect(self.update_packet_length)
        form_0201_layout.addRow("时间误差:", self.time_error)
        
        # 数据有效标志
        self.data_flag = QComboBox()
        for flag, desc in self.protocol.DATA_FLAGS.items():
            self.data_flag.addItem(f"0x{flag:02X} - {desc}", flag)
        self.data_flag.currentIndexChanged.connect(self.update_packet_length)
        form_0201_layout.addRow("数据有效标志:", self.data_flag)
        
        # 保留字段（只读）
        self.reserved = QLineEdit()
        self.reserved.setReadOnly(True)
        self.reserved.setText("0x00")
        form_0201_layout.addRow("保留字段:", self.reserved)
        
        self.form_0201.setLayout(form_0201_layout)
        
        # 创建0x0202消息类型的表单
        self.form_0202 = QWidget()
        form_0202_layout = QFormLayout()
        
        # 创建滚动区域
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QFormLayout()
        
        # BDS卫星ID
        self.bds_sat_id = QLineEdit()
        self.bds_sat_id.setPlaceholderText("输入二进制值（6位）")
        self.setup_binary_validator(self.bds_sat_id, 6)
        self.bds_sat_id.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS卫星ID:", self.bds_sat_id)
        
        # BDS周计数
        self.bds_week = QLineEdit()
        self.bds_week.setPlaceholderText("输入二进制值（13位）")
        self.setup_binary_validator(self.bds_week, 13)
        self.bds_week.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS周计数:", self.bds_week)
        
        # BDS URAI
        self.bds_urai = QLineEdit()
        self.bds_urai.setPlaceholderText("输入二进制值（4位）")
        self.setup_binary_validator(self.bds_urai, 4)
        self.bds_urai.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS URAI:", self.bds_urai)
        
        # BDS IDOT
        self.bds_idot = QLineEdit()
        self.bds_idot.setPlaceholderText("输入二进制值（14位）")
        self.setup_binary_validator(self.bds_idot, 14)
        self.bds_idot.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS IDOT:", self.bds_idot)
        
        # BDS AODE
        self.bds_aode = QLineEdit()
        self.bds_aode.setPlaceholderText("输入二进制值（5位）")
        self.setup_binary_validator(self.bds_aode, 5)
        self.bds_aode.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS AODE:", self.bds_aode)
        
        # BDS Toc
        self.bds_toc = QLineEdit()
        self.bds_toc.setPlaceholderText("输入二进制值（17位）")
        self.setup_binary_validator(self.bds_toc, 17)
        self.bds_toc.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS Toc:", self.bds_toc)
        
        # BDS a2
        self.bds_a2 = QLineEdit()
        self.bds_a2.setPlaceholderText("输入二进制值（11位）")
        self.setup_binary_validator(self.bds_a2, 11)
        self.bds_a2.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS a2:", self.bds_a2)
        
        # BDS a1
        self.bds_a1 = QLineEdit()
        self.bds_a1.setPlaceholderText("输入二进制值（22位）")
        self.setup_binary_validator(self.bds_a1, 22)
        self.bds_a1.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS a1:", self.bds_a1)
        
        # BDS a0
        self.bds_a0 = QLineEdit()
        self.bds_a0.setPlaceholderText("输入二进制值（24位）")
        self.setup_binary_validator(self.bds_a0, 24)
        self.bds_a0.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS a0:", self.bds_a0)
        
        # BDS AODC
        self.bds_aodc = QLineEdit()
        self.bds_aodc.setPlaceholderText("输入二进制值（5位）")
        self.setup_binary_validator(self.bds_aodc, 5)
        self.bds_aodc.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS AODC:", self.bds_aodc)
        
        # BDS Crs
        self.bds_crs = QLineEdit()
        self.bds_crs.setPlaceholderText("输入二进制值（18位）")
        self.setup_binary_validator(self.bds_crs, 18)
        self.bds_crs.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS Crs:", self.bds_crs)
        
        # BDS Δn
        self.bds_delta_n = QLineEdit()
        self.bds_delta_n.setPlaceholderText("输入二进制值（16位）")
        self.setup_binary_validator(self.bds_delta_n, 16)
        self.bds_delta_n.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS Δn:", self.bds_delta_n)
        
        # BDS M0
        self.bds_m0 = QLineEdit()
        self.bds_m0.setPlaceholderText("输入二进制值（32位）")
        self.setup_binary_validator(self.bds_m0, 32)
        self.bds_m0.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS M0:", self.bds_m0)
        
        # BDS Cuc
        self.bds_cuc = QLineEdit()
        self.bds_cuc.setPlaceholderText("输入二进制值（18位）")
        self.setup_binary_validator(self.bds_cuc, 18)
        self.bds_cuc.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS Cuc:", self.bds_cuc)
        
        # BDS e
        self.bds_e = QLineEdit()
        self.bds_e.setPlaceholderText("输入二进制值（32位）")
        self.setup_binary_validator(self.bds_e, 32)
        self.bds_e.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS e:", self.bds_e)
        
        # BDS Cus
        self.bds_cus = QLineEdit()
        self.bds_cus.setPlaceholderText("输入二进制值（18位）")
        self.setup_binary_validator(self.bds_cus, 18)
        self.bds_cus.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS Cus:", self.bds_cus)
        
        # BDS 根号a
        self.bds_sqrt_a = QLineEdit()
        self.bds_sqrt_a.setPlaceholderText("输入二进制值（32位）")
        self.setup_binary_validator(self.bds_sqrt_a, 32)
        self.bds_sqrt_a.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS 根号a:", self.bds_sqrt_a)
        
        # BDS toe
        self.bds_toe = QLineEdit()
        self.bds_toe.setPlaceholderText("输入二进制值（17位）")
        self.setup_binary_validator(self.bds_toe, 17)
        self.bds_toe.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS toe:", self.bds_toe)
        
        # BDS Cic
        self.bds_cic = QLineEdit()
        self.bds_cic.setPlaceholderText("输入二进制值（18位）")
        self.setup_binary_validator(self.bds_cic, 18)
        self.bds_cic.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS Cic:", self.bds_cic)
        
        # BDS Ω0
        self.bds_omega0 = QLineEdit()
        self.bds_omega0.setPlaceholderText("输入二进制值（32位）")
        self.setup_binary_validator(self.bds_omega0, 32)
        self.bds_omega0.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS Ω0:", self.bds_omega0)
        
        # BDS Cis
        self.bds_cis = QLineEdit()
        self.bds_cis.setPlaceholderText("输入二进制值（18位）")
        self.setup_binary_validator(self.bds_cis, 18)
        self.bds_cis.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS Cis:", self.bds_cis)
        
        # BDS i0
        self.bds_i0 = QLineEdit()
        self.bds_i0.setPlaceholderText("输入二进制值（32位）")
        self.setup_binary_validator(self.bds_i0, 32)
        self.bds_i0.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS i0:", self.bds_i0)
        
        # BDS Crc
        self.bds_crc = QLineEdit()
        self.bds_crc.setPlaceholderText("输入十六进制值（18位）")
        self.bds_crc.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS Crc:", self.bds_crc)
        
        # BDS ω
        self.bds_omega = QLineEdit()
        self.bds_omega.setPlaceholderText("输入十六进制值（32位）")
        self.bds_omega.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS ω:", self.bds_omega)
        
        # BDS OMEGADOT
        self.bds_omega_dot = QLineEdit()
        self.bds_omega_dot.setPlaceholderText("输入十六进制值（24位）")
        self.bds_omega_dot.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS OMEGADOT:", self.bds_omega_dot)
        
        # BDS TGD1
        self.bds_tgd1 = QLineEdit()
        self.bds_tgd1.setPlaceholderText("输入十六进制值（10位）")
        self.bds_tgd1.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS TGD1:", self.bds_tgd1)
        
        # BDS TGD2
        self.bds_tgd2 = QLineEdit()
        self.bds_tgd2.setPlaceholderText("输入十六进制值（10位）")
        self.bds_tgd2.textChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS TGD2:", self.bds_tgd2)
        
        # BDS卫星自主健康状态
        self.bds_health_combo = QComboBox()
        self.bds_health_combo.addItem("0 - 健康", 0)
        self.bds_health_combo.addItem("1 - 不健康", 1)
        self.bds_health_combo.currentIndexChanged.connect(self.update_packet_length)
        scroll_layout.addRow("BDS卫星自主健康状态:", self.bds_health_combo)
        
        scroll_widget.setLayout(scroll_layout)
        scroll_area.setWidget(scroll_widget)
        form_0202_layout.addWidget(scroll_area)
        self.form_0202.setLayout(form_0202_layout)
        
        # 将表单添加到堆叠窗口
        self.content_stack.addWidget(self.form_0201)
        self.content_stack.addWidget(self.form_0202)
        
        layout.addWidget(self.content_stack)
        
        # 添加CRC显示（只读）
        self.crc_value = QLineEdit()
        self.crc_value.setReadOnly(True)
        layout.addWidget(QLabel("CRC-24Q:"))
        layout.addWidget(self.crc_value)
        
        # 创建按钮布局
        button_layout = QHBoxLayout()
        
        # 添加预览按钮
        self.preview_button = QPushButton("预览数据")
        self.preview_button.clicked.connect(self.preview_data)
        button_layout.addWidget(self.preview_button)
        
        # 添加发送按钮
        self.send_button = QPushButton("发送数据")
        self.send_button.clicked.connect(self.send_data)
        button_layout.addWidget(self.send_button)
        
        layout.addLayout(button_layout)
        
        # 添加预览区域
        self.preview_label = QLabel()
        self.preview_label.setWordWrap(True)
        layout.addWidget(self.preview_label)
        
        self.setLayout(layout)
    
    def on_message_type_changed(self, index):
        msg_type = self.message_type.currentData()
        if msg_type == self.protocol.MSG_TYPE_0201:
            self.content_stack.setCurrentWidget(self.form_0201)
            # 更新包长度显示为十六进制
            self.packet_length.setText(f"0x{self.protocol.PACKET_LENGTH_0201:02X}")
        else:
            self.content_stack.setCurrentWidget(self.form_0202)
            self.packet_length.setText(f"0x{self.protocol.PACKET_LENGTH_0202:02X}")
    
    def _parse_hex_input(self, text: str, max_bytes: int) -> int:
        """解析十六进制输入，确保不超过指定字节数"""
        if not text:
            return 0
        text = text.strip().replace("0x", "")
        try:
            value = int(text, 16)
            max_value = (1 << (max_bytes * 8)) - 1
            return value & max_value
        except ValueError:
            return 0
    
    def update_packet_length(self):
        """更新数据包长度显示"""
        try:
            if self.message_type.currentData() == self.protocol.MSG_TYPE_0201:
                # 更新0x0201消息类型的字段值
                self.protocol.message_type = self.protocol.MSG_TYPE_0201
                self.protocol.set_0201_field('pos_x', self.pos_x.text())
                self.protocol.set_0201_field('pos_y', self.pos_y.text())
                self.protocol.set_0201_field('pos_z', self.pos_z.text())
                self.protocol.set_0201_field('pos_error', self.pos_error.text())
                self.protocol.set_0201_field('time_error', self.time_error.text())
                self.protocol.set_0201_field('data_flag', hex(self.data_flag.currentData()))
                
            elif self.message_type.currentData() == self.protocol.MSG_TYPE_0202:
                # 更新0x0202消息类型的字段值
                self.protocol.message_type = self.protocol.MSG_TYPE_0202
                self.protocol.set_0202_field('bds_sat_id', self.bds_sat_id.text())
                self.protocol.set_0202_field('bds_week', self.bds_week.text())
                self.protocol.set_0202_field('bds_urai', self.bds_urai.text())
                self.protocol.set_0202_field('bds_idot', self.bds_idot.text())
                self.protocol.set_0202_field('bds_aode', self.bds_aode.text())
                self.protocol.set_0202_field('bds_toc', self.bds_toc.text())
                self.protocol.set_0202_field('bds_a2', self.bds_a2.text())
                self.protocol.set_0202_field('bds_a1', self.bds_a1.text())
                self.protocol.set_0202_field('bds_a0', self.bds_a0.text())
                self.protocol.set_0202_field('bds_aodc', self.bds_aodc.text())
                self.protocol.set_0202_field('bds_crs', self.bds_crs.text())
                self.protocol.set_0202_field('bds_delta_n', self.bds_delta_n.text())
                self.protocol.set_0202_field('bds_m0', self.bds_m0.text())
                self.protocol.set_0202_field('bds_cuc', self.bds_cuc.text())
                self.protocol.set_0202_field('bds_e', self.bds_e.text())
                self.protocol.set_0202_field('bds_cus', self.bds_cus.text())
                self.protocol.set_0202_field('bds_sqrt_a', self.bds_sqrt_a.text())
                self.protocol.set_0202_field('bds_toe', self.bds_toe.text())
                self.protocol.set_0202_field('bds_cic', self.bds_cic.text())
                self.protocol.set_0202_field('bds_omega0', self.bds_omega0.text())
                self.protocol.set_0202_field('bds_cis', self.bds_cis.text())
                self.protocol.set_0202_field('bds_i0', self.bds_i0.text())
                self.protocol.set_0202_field('bds_crc', self.bds_crc.text())
                self.protocol.set_0202_field('bds_omega', self.bds_omega.text())
                self.protocol.set_0202_field('bds_omega_dot', self.bds_omega_dot.text())
                self.protocol.set_0202_field('bds_tgd1', self.bds_tgd1.text())
                self.protocol.set_0202_field('bds_tgd2', self.bds_tgd2.text())
                self.protocol.set_0202_field('bds_health', format(self.bds_health_combo.currentData(), 'b'))  # 转换为二进制字符串
                
            # 更新包长度显示
            packet_length = self.protocol._calculate_length()
            self.packet_length.setText(str(packet_length))
            
        except ValueError as e:
            # 输入验证失败时不更新包长度
            pass
    
    def preview_data(self):
        try:
            msg_type = self.message_type.currentData()
            self.protocol.message_type = msg_type
            
            if msg_type == self.protocol.MSG_TYPE_0201:
                # 更新0x0201消息类型的字段
                self.protocol.pos_x = self._parse_hex_input(self.pos_x.text(), 4)
                self.protocol.pos_y = self._parse_hex_input(self.pos_y.text(), 4)
                self.protocol.pos_z = self._parse_hex_input(self.pos_z.text(), 4)
                self.protocol.pos_error = self._parse_hex_input(self.pos_error.text(), 2)
                self.protocol.time_error = self._parse_hex_input(self.time_error.text(), 2)
                self.protocol.data_flag = self.data_flag.currentData()
            else:
                # 更新0x0202消息类型的字段
                self.protocol.bds_sat_id = self._parse_hex_input(self.bds_sat_id.text(), 1)
                self.protocol.bds_week = self._parse_hex_input(self.bds_week.text(), 2)
                self.protocol.bds_urai = self._parse_hex_input(self.bds_urai.text(), 1)
                self.protocol.bds_idot = self._parse_hex_input(self.bds_idot.text(), 2)
                self.protocol.bds_aode = self._parse_hex_input(self.bds_aode.text(), 1)
                self.protocol.bds_toc = self._parse_hex_input(self.bds_toc.text(), 3)
                self.protocol.bds_a2 = self._parse_hex_input(self.bds_a2.text(), 2)
                self.protocol.bds_a1 = self._parse_hex_input(self.bds_a1.text(), 3)
                self.protocol.bds_a0 = self._parse_hex_input(self.bds_a0.text(), 3)
                self.protocol.bds_aodc = self._parse_hex_input(self.bds_aodc.text(), 1)
                self.protocol.bds_crs = self._parse_hex_input(self.bds_crs.text(), 3)
                self.protocol.bds_delta_n = self._parse_hex_input(self.bds_delta_n.text(), 2)
                self.protocol.bds_m0 = self._parse_hex_input(self.bds_m0.text(), 4)
                self.protocol.bds_cuc = self._parse_hex_input(self.bds_cuc.text(), 3)
                self.protocol.bds_e = self._parse_hex_input(self.bds_e.text(), 4)
                self.protocol.bds_cus = self._parse_hex_input(self.bds_cus.text(), 3)
                self.protocol.bds_sqrt_a = self._parse_hex_input(self.bds_sqrt_a.text(), 4)
                self.protocol.bds_toe = self._parse_hex_input(self.bds_toe.text(), 3)
                self.protocol.bds_cic = self._parse_hex_input(self.bds_cic.text(), 3)
                self.protocol.bds_omega0 = self._parse_hex_input(self.bds_omega0.text(), 4)
                self.protocol.bds_cis = self._parse_hex_input(self.bds_cis.text(), 3)
                self.protocol.bds_i0 = self._parse_hex_input(self.bds_i0.text(), 4)
                self.protocol.bds_crc = self._parse_hex_input(self.bds_crc.text(), 3)
                self.protocol.bds_omega = self._parse_hex_input(self.bds_omega.text(), 4)
                self.protocol.bds_omega_dot = self._parse_hex_input(self.bds_omega_dot.text(), 3)
                self.protocol.bds_tgd1 = self._parse_hex_input(self.bds_tgd1.text(), 2)
                self.protocol.bds_tgd2 = self._parse_hex_input(self.bds_tgd2.text(), 2)
                self.protocol.bds_health = self.bds_health_combo.currentData()
            
            # 序列化数据
            data = self.protocol.serialize()
            
            # 更新CRC显示
            crc = data[-3:]
            self.crc_value.setText(f"0x{int.from_bytes(crc, 'big'):06X}")
            
            # 显示完整的十六进制数据
            hex_data = ' '.join(f"{b:02X}" for b in data)
            preview_text = "完整数据包（十六进制）：\n" + hex_data
            self.preview_label.setText(preview_text)
            
        except ValueError as e:
            self.preview_label.setText(f"错误：{str(e)}")
    
    def send_data(self):
        try:
            msg_type = self.message_type.currentData()
            self.protocol.message_type = msg_type
            
            if msg_type == self.protocol.MSG_TYPE_0201:
                # 更新0x0201消息类型的字段
                self.protocol.pos_x = self._parse_hex_input(self.pos_x.text(), 4)
                self.protocol.pos_y = self._parse_hex_input(self.pos_y.text(), 4)
                self.protocol.pos_z = self._parse_hex_input(self.pos_z.text(), 4)
                self.protocol.pos_error = self._parse_hex_input(self.pos_error.text(), 2)
                self.protocol.time_error = self._parse_hex_input(self.time_error.text(), 2)
                self.protocol.data_flag = self.data_flag.currentData()
            else:
                # 更新0x0202消息类型的字段
                self.protocol.bds_sat_id = self._parse_hex_input(self.bds_sat_id.text(), 1)
                self.protocol.bds_week = self._parse_hex_input(self.bds_week.text(), 2)
                self.protocol.bds_urai = self._parse_hex_input(self.bds_urai.text(), 1)
                self.protocol.bds_idot = self._parse_hex_input(self.bds_idot.text(), 2)
                self.protocol.bds_aode = self._parse_hex_input(self.bds_aode.text(), 1)
                self.protocol.bds_toc = self._parse_hex_input(self.bds_toc.text(), 3)
                self.protocol.bds_a2 = self._parse_hex_input(self.bds_a2.text(), 2)
                self.protocol.bds_a1 = self._parse_hex_input(self.bds_a1.text(), 3)
                self.protocol.bds_a0 = self._parse_hex_input(self.bds_a0.text(), 3)
                self.protocol.bds_aodc = self._parse_hex_input(self.bds_aodc.text(), 1)
                self.protocol.bds_crs = self._parse_hex_input(self.bds_crs.text(), 3)
                self.protocol.bds_delta_n = self._parse_hex_input(self.bds_delta_n.text(), 2)
                self.protocol.bds_m0 = self._parse_hex_input(self.bds_m0.text(), 4)
                self.protocol.bds_cuc = self._parse_hex_input(self.bds_cuc.text(), 3)
                self.protocol.bds_e = self._parse_hex_input(self.bds_e.text(), 4)
                self.protocol.bds_cus = self._parse_hex_input(self.bds_cus.text(), 3)
                self.protocol.bds_sqrt_a = self._parse_hex_input(self.bds_sqrt_a.text(), 4)
                self.protocol.bds_toe = self._parse_hex_input(self.bds_toe.text(), 3)
                self.protocol.bds_cic = self._parse_hex_input(self.bds_cic.text(), 3)
                self.protocol.bds_omega0 = self._parse_hex_input(self.bds_omega0.text(), 4)
                self.protocol.bds_cis = self._parse_hex_input(self.bds_cis.text(), 3)
                self.protocol.bds_i0 = self._parse_hex_input(self.bds_i0.text(), 4)
                self.protocol.bds_crc = self._parse_hex_input(self.bds_crc.text(), 3)
                self.protocol.bds_omega = self._parse_hex_input(self.bds_omega.text(), 4)
                self.protocol.bds_omega_dot = self._parse_hex_input(self.bds_omega_dot.text(), 3)
                self.protocol.bds_tgd1 = self._parse_hex_input(self.bds_tgd1.text(), 2)
                self.protocol.bds_tgd2 = self._parse_hex_input(self.bds_tgd2.text(), 2)
                self.protocol.bds_health = self.bds_health_combo.currentData()
            
            # 序列化数据并发送
            data = self.protocol.serialize()
            data_sender = DataSender()
            hex_data = ''.join(f"{b:02X}" for b in data)
            data_sender.send_data(hex_data)
            
            self.preview_label.setText("数据发送成功！")
            
        except ValueError as e:
            self.preview_label.setText(f"发送失败：{str(e)}")

    def validate_hex_input(self, text: str, max_bits: int) -> bool:
        """验证十六进制输入
        
        Args:
            text: 输入的文本
            max_bits: 最大位数限制
            
        Returns:
            bool: 输入是否有效
        """
        # 移除前缀"0x"如果存在
        text = text.lower().replace("0x", "")
        
        # 检查是否为有效的十六进制
        if not all(c in '0123456789abcdef' for c in text):
            return False
            
        # 检查长度是否在限制范围内
        max_hex_digits = (max_bits + 3) // 4  # 向上取整
        if len(text) > max_hex_digits:
            return False
            
        return True
        
    def validate_binary_input(self, text: str, max_bits: int) -> bool:
        """验证二进制输入
        
        Args:
            text: 输入的文本
            max_bits: 最大位数限制
            
        Returns:
            bool: 输入是否有效
        """
        # 移除前缀"0b"如果存在
        text = text.lower().replace("0b", "")
        
        # 检查是否为有效的二进制
        if not all(c in '01' for c in text):
            return False
            
        # 检查长度是否在限制范围内
        if len(text) > max_bits:
            return False
            
        return True
        
    def setup_hex_validator(self, line_edit: QLineEdit, max_bits: int):
        """设置十六进制输入验证器
        
        Args:
            line_edit: 输入框对象
            max_bits: 最大位数限制
        """
        def on_text_changed(text):
            if text and not self.validate_hex_input(text, max_bits):
                # 获取上一个有效值
                cursor_pos = line_edit.cursorPosition()
                text = line_edit.property("last_valid_value") or ""
                line_edit.setText(text)
                line_edit.setCursorPosition(min(cursor_pos, len(text)))
            else:
                # 保存当前有效值
                line_edit.setProperty("last_valid_value", text)
                
        line_edit.textChanged.connect(on_text_changed)
        
    def setup_binary_validator(self, line_edit: QLineEdit, max_bits: int):
        """设置二进制输入验证器
        
        Args:
            line_edit: 输入框对象
            max_bits: 最大位数限制
        """
        def on_text_changed(text):
            if text and not self.validate_binary_input(text, max_bits):
                # 获取上一个有效值
                cursor_pos = line_edit.cursorPosition()
                text = line_edit.property("last_valid_value") or ""
                line_edit.setText(text)
                line_edit.setCursorPosition(min(cursor_pos, len(text)))
            else:
                # 保存当前有效值
                line_edit.setProperty("last_valid_value", text)
                
        line_edit.textChanged.connect(on_text_changed)