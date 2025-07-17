from PyQt5.QtWidgets import (QWidget, QFormLayout, QLineEdit, QComboBox, 
                            QVBoxLayout, QLabel, QTextEdit, QRadioButton,
                            QButtonGroup, QHBoxLayout, QPushButton)
from PyQt5.QtCore import Qt, QRegExp, QThread, pyqtSignal
from PyQt5.QtGui import QRegExpValidator
from protocol.location_security_protocol import LocationSecurityProtocol
from protocol.auxiliary_location_protocol import AuxiliaryLocationProtocol
from .serial_port_widget import SerialPortWidget
from services.data_sender import DataSender
import serial
import time

class SerialReceiveThread(QThread):
    data_received = pyqtSignal(bytes)
    def __init__(self, port, baudrate, parent=None):
        super().__init__(parent)
        self.port = port
        self.baudrate = baudrate
        self._running = True
    def run(self):
        try:
            with serial.Serial(self.port, self.baudrate, timeout=0.2) as ser:
                buffer = b''
                while self._running:
                    data = ser.read(512)
                    if data:
                        buffer += data
                        # 尝试按包头和长度分包（假设包头4字节+1+2+2=9字节，包长在第5-7字节）
                        while len(buffer) >= 9:
                            length = int.from_bytes(buffer[5:7], 'big')
                            if len(buffer) < length:
                                break
                            packet = buffer[:length]
                            msg_type = int.from_bytes(packet[7:9], 'big')
                            if msg_type in (0x0105, 0x0106):
                                self.data_received.emit(packet)
                            buffer = buffer[length:]
                    else:
                        time.sleep(0.05)
        except Exception as e:
            pass
    def stop(self):
        self._running = False
        self.wait()

class DataReceiverForm(QWidget):
    def __init__(self):
        super().__init__()
        self.location_security_protocol = LocationSecurityProtocol()
        self.auxiliary_location_protocol = AuxiliaryLocationProtocol()
        self.serial_port_widget = SerialPortWidget()
        self.receive_thread = None
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # 串口选择控件
        layout.addWidget(self.serial_port_widget)
        # 串口接收按钮
        self.receive_button = QPushButton("开始串口接收并解析数据")
        self.stop_button = QPushButton("停止接收")
        self.stop_button.setEnabled(False)
        self.receive_button.clicked.connect(self.start_serial_receive)
        self.stop_button.clicked.connect(self.stop_serial_receive)
        layout.addWidget(self.receive_button)
        layout.addWidget(self.stop_button)
        
        # 创建协议选择区域
        protocol_layout = QHBoxLayout()
        self.protocol_group = QButtonGroup()
        
        # 定位安全数据包选项
        self.security_radio = QRadioButton("定位安全数据包")
        self.security_radio.setChecked(True)  # 默认选中
        self.protocol_group.addButton(self.security_radio)
        protocol_layout.addWidget(self.security_radio)
        
        
        layout.addLayout(protocol_layout)
        
        # 创建表单布局
        form_layout = QFormLayout()
        
        # 16进制数据输入框
        self.hex_data_edit = QLineEdit()
        self.hex_data_edit.setPlaceholderText("输入16进制数据（例如：4A 54 44 57...）")
        # 设置验证器，只允许输入16进制字符和空格
        hex_validator = QRegExpValidator(QRegExp("[0-9A-Fa-f ]+"))
        self.hex_data_edit.setValidator(hex_validator)
        self.hex_data_edit.textChanged.connect(self.parse_data)
        form_layout.addRow("16进制数据:", self.hex_data_edit)
        
        # 解析结果显示区域
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setStyleSheet("background-color: #f0f0f0;")
        form_layout.addRow("解析结果:", self.result_text)
        
        layout.addLayout(form_layout)
        self.setLayout(layout)
        
        # 连接协议选择变化信号
        self.protocol_group.buttonClicked.connect(self.parse_data)
        
    def parse_data(self):
        """解析输入的16进制数据"""
        try:
            hex_data = self.hex_data_edit.text()
            # 移除空格和0x前缀
            hex_data = hex_data.replace(' ', '').replace('0x', '')
            
            if not hex_data:
                self.result_text.clear()
                return
                
            # 确保hex_data是偶数长度
            if len(hex_data) % 2 != 0:
                hex_data = '0' + hex_data
                
            # 转换为字节数组
            data_bytes = bytes.fromhex(hex_data)
            
            # 根据选择的协议类型进行解析
            if self.security_radio.isChecked():
                self.parse_security_packet(data_bytes)
            else:
                self.parse_auxiliary_packet(data_bytes)
                
        except ValueError as e:
            self.result_text.setText('输入格式错误')
            
    def parse_security_packet(self, data_bytes):
        """解析定位安全数据包"""
        try:
            if len(data_bytes) < 9:  # 最小长度检查：标识符(4) + 版本(1) + 包长度(2) + 消息类型(2)
                self.result_text.setText("数据长度不足")
                return
                
            # 解析标识符
            identifier = int.from_bytes(data_bytes[0:4], 'big')
            if identifier != self.location_security_protocol.FIXED_IDENTIFIER:
                self.result_text.setText(f"无效的标识符: 0x{identifier:08X}")
                return
                
            # 解析版本号
            version = data_bytes[4]
            if version != self.location_security_protocol.FIXED_VERSION:
                self.result_text.setText(f"无效的版本号: 0x{version:02X}")
                return
                
            # 解析包长度
            length = int.from_bytes(data_bytes[5:7], 'big')
            
            # 解析消息类型
            msg_type = int.from_bytes(data_bytes[7:9], 'big')
            
            # 构建解析结果文本
            result = f"标识符: 0x{identifier:08X}\n"
            result += f"版本号: 0x{version:02X}\n"
            result += f"包长度: {length} 字节\n"
            result += f"消息类型: 0x{msg_type:04X}"
            
            if msg_type in self.location_security_protocol.MESSAGE_TYPES:
                result += f" ({self.location_security_protocol.MESSAGE_TYPES[msg_type]})"
            
            # 解析消息内容
            if len(data_bytes) >= length:
                content_bytes = data_bytes[9:length-3]  # 去掉头部和CRC
                result += "\n\n消息内容:\n"
                result += self.parse_security_content(msg_type, content_bytes)
            
            self.result_text.setText(result)
            
        except Exception as e:
            self.result_text.setText(f'解析错误: {str(e)}')
            
    def parse_auxiliary_packet(self, data_bytes):
        """解析辅助定位数据包"""
        try:
            if len(data_bytes) < 9:  # 最小长度检查
                self.result_text.setText("数据长度不足")
                return
                
            # 解析标识符
            identifier = int.from_bytes(data_bytes[0:4], 'big')
            if identifier != self.auxiliary_location_protocol.PROTOCOL_IDENTIFIER:
                self.result_text.setText(f"无效的标识符: 0x{identifier:08X}")
                return
                
            # 解析版本号
            version = data_bytes[4]
            if version != self.auxiliary_location_protocol.PROTOCOL_VERSION:
                self.result_text.setText(f"无效的版本号: 0x{version:02X}")
                return
                
            # 解析包长度
            length = int.from_bytes(data_bytes[5:7], 'big')
            
            # 解析消息类型
            msg_type = int.from_bytes(data_bytes[7:9], 'big')
            
            # 构建解析结果文本
            result = f"标识符: 0x{identifier:08X}\n"
            result += f"版本号: 0x{version:02X}\n"
            result += f"包长度: {length} 字节\n"
            result += f"消息类型: 0x{msg_type:04X}"
            
            if msg_type in self.auxiliary_location_protocol.MSG_TYPE_DESCRIPTIONS:
                result += f" ({self.auxiliary_location_protocol.MSG_TYPE_DESCRIPTIONS[msg_type]})"
            
            # 解析消息内容
            if len(data_bytes) >= length:
                content_bytes = data_bytes[9:length-3]  # 去掉头部和CRC
                result += "\n\n消息内容:\n"
                result += self.parse_auxiliary_content(msg_type, content_bytes)
            
            self.result_text.setText(result)
            
        except Exception as e:
            self.result_text.setText(f'解析错误: {str(e)}')
            
    def parse_security_content(self, msg_type, content_bytes):
        """解析定位安全数据包的消息内容"""
        result = ""
        try:
            if msg_type == 0x0101:
                # 解析卫星导航系统服务状态信息
                if len(content_bytes) >= 28:
                    week = int.from_bytes(content_bytes[0:2], 'big')
                    second = int.from_bytes(content_bytes[2:6], 'big')
                    nav_system = content_bytes[6]
                    nav_status = content_bytes[7]
                    signal_status = content_bytes[8:12]
                    satellite_status = content_bytes[12:20]
                    
                    result += f"BDS参考周计数: {week}\n"
                    result += f"BDS参考周内秒: {second}\n"
                    result += f"导航系统标识: 0x{nav_system:02X}\n"
                    result += f"导航系统状态: 0x{nav_status:02X}\n"
                    result += f"导航信号状态: {' '.join(f'{b:02X}' for b in signal_status)}\n"
                    result += f"导航卫星状态: {' '.join(f'{b:02X}' for b in satellite_status)}"
                    
            elif msg_type == 0x0102:
                # 解析卫星导航系统导航电文验证信息
                if len(content_bytes) >= 14:
                    week = int.from_bytes(content_bytes[0:2], 'big')
                    second = int.from_bytes(content_bytes[2:6], 'big')
                    nav_system = content_bytes[6]
                    verification_count = content_bytes[7]
                    satellite_number = content_bytes[8]
                    message_type = content_bytes[9]
                    ref_time = content_bytes[10:13]
                    
                    result += f"BDS参考周计数: {week}\n"
                    result += f"BDS参考周内秒: {second}\n"
                    result += f"导航系统标识: 0x{nav_system:02X}\n"
                    result += f"验证计数: {verification_count}\n"
                    result += f"卫星编号: {satellite_number}\n"
                    result += f"电文类型: 0x{message_type:02X}\n"
                    result += f"参考时间: {' '.join(f'{b:02X}' for b in ref_time)}"
                    
            elif msg_type == 0x0103:
                # 解析压制干扰告警信息
                if len(content_bytes) >= 19:
                    week = int.from_bytes(content_bytes[0:2], 'big')
                    second = int.from_bytes(content_bytes[2:6], 'big')
                    count = content_bytes[6]
                    latitude = content_bytes[7:11]
                    longitude = content_bytes[11:15]
                    center_freq = content_bytes[15:17]
                    interference_type = content_bytes[17]
                    intensity = content_bytes[18]
                    
                    result += f"BDS参考周计数: {week}\n"
                    result += f"BDS参考周内秒: {second}\n"
                    result += f"压制干扰数目: {count}\n"
                    result += f"纬度: {' '.join(f'{b:02X}' for b in latitude)}\n"
                    result += f"经度: {' '.join(f'{b:02X}' for b in longitude)}\n"
                    result += f"中心频率: {' '.join(f'{b:02X}' for b in center_freq)}\n"
                    result += f"干扰类型: 0x{interference_type:02X}\n"
                    result += f"干扰强度: 0x{intensity:02X}"
                    
            elif msg_type == 0x0104:
                # 解析欺骗干扰告警信息
                if len(content_bytes) >= 15:
                    week = int.from_bytes(content_bytes[0:2], 'big')
                    second = int.from_bytes(content_bytes[2:6], 'big')
                    count = content_bytes[6]
                    latitude = content_bytes[7:11]
                    longitude = content_bytes[11:15]
                    
                    result += f"BDS参考周计数: {week}\n"
                    result += f"BDS参考周内秒: {second}\n"
                    result += f"欺骗干扰数目: {count}\n"
                    result += f"纬度: {' '.join(f'{b:02X}' for b in latitude)}\n"
                    result += f"经度: {' '.join(f'{b:02X}' for b in longitude)}"
                    
            elif msg_type == 0x0105:
                # 解析模块干扰检测信息
                if len(content_bytes) >= 2:
                    # 1. 定位状态
                    pos_status = int.from_bytes(content_bytes[0:2], 'big')
                    result += f"定位状态: 0x{pos_status:04X}\n"
                    
                    # 2. 参考周计数
                    if len(content_bytes) >= 4:
                        week = int.from_bytes(content_bytes[2:4], 'big')
                        result += f"参考周计数: {week}\n"
                    
                    # 3. 参考周内秒
                    if len(content_bytes) >= 8:
                        second = int.from_bytes(content_bytes[4:8], 'big')
                        result += f"参考周内秒: {second}s\n"
                    
                    # 4-5. 纬度和经度
                    if len(content_bytes) >= 16:
                        latitude = int.from_bytes(content_bytes[8:12], 'big', signed=True)
                        longitude = int.from_bytes(content_bytes[12:16], 'big', signed=True)
                        result += f"纬度: {latitude}\n"
                        result += f"经度: {longitude}\n"
                    
                    # 6. 大地高
                    if len(content_bytes) >= 20:
                        height = int.from_bytes(content_bytes[16:20], 'big', signed=True)
                        result += f"大地高: {height}\n"
                    
                    # 7-9. 速度
                    if len(content_bytes) >= 32:
                        v_n = int.from_bytes(content_bytes[20:24], 'big', signed=True)
                        v_e = int.from_bytes(content_bytes[24:28], 'big', signed=True)
                        v_u = int.from_bytes(content_bytes[28:32], 'big', signed=True)
                        result += f"水平速度: {v_n}\n"
                        result += f"垂直速度: {v_e}\n"
                        result += f"运动航向: {v_u}\n"
                    
                    # 10. 水平精度因子
                    if len(content_bytes) >= 34:
                        hdop = int.from_bytes(content_bytes[32:34], 'big')
                        result += f"水平精度因子: {hdop}\n"
                    
                    # 11. 参与定位导航信号
                    if len(content_bytes) >= 38:
                        nav_signal = int.from_bytes(content_bytes[34:38], 'big')
                        result += f"参与定位导航信号: 0x{nav_signal:08X}\n"
                    
                    # 12-13. 卫星数
                    if len(content_bytes) >= 40:
                        total_sats = content_bytes[38]
                        north_sats = content_bytes[39]
                        result += f"参与定位卫星总数: {total_sats}\n"
                        result += f"参与定位北斗卫星数: {north_sats}\n"
                    
                    # 14-16. RAIM监测
                    raim_k = 0  # 默认值
                    if len(content_bytes) >= 41:
                        raim_k = content_bytes[40]
                        result += f"RAIM监测发现的故障信号数k: {raim_k}"
                        if raim_k <= 0:
                            result += " (无故障)\n"
                        else:
                            result += "\n"
                            # 计算RAIM监测数据的起始位置
                            raim_start = 41
                            # 循环解析k组RAIM监测数据
                            for i in range(raim_k):
                                if len(content_bytes) >= raim_start + i*2 + 2:
                                    raim_prn = content_bytes[raim_start + i*2]
                                    raim_id = content_bytes[raim_start + i*2 + 1]
                                    result += f"RAIM监测发现的故障信号{i+1}的卫星编号: {raim_prn}\n"
                                    result += f"RAIM监测发现的故障信号{i+1}的信号标识: {raim_id}\n"
                    else:
                        result += "RAIM监测数据长度不足\n"
                    
                    # 计算压制干扰数据的起始位置（在RAIM数据之后）
                    jam_start = 41 + raim_k * 2
                    
                    # 18-22. 压制干扰
                    jam_n = 0  # 默认值
                    if len(content_bytes) >= jam_start + 1:
                        jam_n = content_bytes[jam_start]
                        result += f"压制干扰数目n: {jam_n}"
                        if jam_n <= 0:
                            result += " (无压制干扰)\n"
                        else:
                            result += "\n"
                            # 循环解析n组压制干扰数据
                            for i in range(jam_n):
                                if len(content_bytes) >= jam_start + 1 + i*9 + 9:
                                    jam_freq = int.from_bytes(content_bytes[jam_start + 1 + i*9:jam_start + 5 + i*9], 'big')
                                    jam_bw = int.from_bytes(content_bytes[jam_start + 5 + i*9:jam_start + 7 + i*9], 'big')
                                    jam_type = content_bytes[jam_start + 7 + i*9]
                                    jam_strength = content_bytes[jam_start + 8 + i*9]
                                    
                                    result += f"压制干扰{i+1}中心频率: {jam_freq}\n"
                                    result += f"压制干扰{i+1}带宽: {jam_bw}\n"
                                    result += f"压制干扰{i+1}类型: {jam_type}\n"
                                    result += f"压制干扰{i+1}强度: {jam_strength}\n"
                    else:
                        result += "压制干扰数据长度不足\n"
                    
                    # 计算欺骗干扰数据的起始位置（在压制干扰数据之后）
                    spoof_start = jam_start + 1 + jam_n * 9
                    
                    # 24-25. 欺骗干扰
                    if len(content_bytes) >= spoof_start + 1:
                        spoof_m = content_bytes[spoof_start]
                        result += f"欺骗干扰数目m: {spoof_m}"
                        if spoof_m <= 0:
                            result += " (无欺骗干扰)\n"
                        else:
                            result += "\n"
                            # 循环解析m组欺骗干扰数据
                            for i in range(spoof_m):
                                if len(content_bytes) >= spoof_start + 1 + i*2 + 1:
                                    spoof_id = content_bytes[spoof_start + 1 + i*2]
                                    result += f"欺骗干扰{i+1}的卫星导航信号: 0x{spoof_id:02X}\n"
                    else:
                        result += "欺骗干扰数据长度不足\n"
                
                else:
                    result += "数据长度不足，无法解析完整字段"
                
            elif msg_type == 0x0106:
                # 解析信息交互控制指令
                if len(content_bytes) >= 5:
                    target_type = int.from_bytes(content_bytes[0:2], 'big')
                    broadcast_mode = content_bytes[2]
                    interval_time = content_bytes[3]
                    offset_time = content_bytes[4]
                    
                    result += f"目标消息类型: 0x{target_type:04X}\n"
                    result += f"播发模式: 0x{broadcast_mode:02X}\n"
                    result += f"间隔时间: 0x{interval_time:02X}\n"
                    result += f"偏移时间: 0x{offset_time:02X}"
            
            return result
            
        except Exception as e:
            return f"内容解析错误: {str(e)}"
            
    def parse_auxiliary_content(self, msg_type, content_bytes):
        """解析辅助定位数据包的消息内容"""
        result = ""
        try:
            if msg_type == self.auxiliary_location_protocol.MSG_TYPE_0201:
                # 解析位置时间辅助信息
                if len(content_bytes) >= 24:
                    pos_x = int.from_bytes(content_bytes[0:4], 'big')
                    pos_y = int.from_bytes(content_bytes[4:8], 'big')
                    pos_z = int.from_bytes(content_bytes[8:12], 'big')
                    week = int.from_bytes(content_bytes[12:14], 'big')
                    second = int.from_bytes(content_bytes[14:18], 'big')
                    pos_error = int.from_bytes(content_bytes[18:20], 'big')
                    time_error = int.from_bytes(content_bytes[20:22], 'big')
                    data_flag = content_bytes[22]
                    reserved = content_bytes[23]
                    
                    result += f"概略位置X: 0x{pos_x:08X}\n"
                    result += f"概略位置Y: 0x{pos_y:08X}\n"
                    result += f"概略位置Z: 0x{pos_z:08X}\n"
                    result += f"当前时间周计数: {week}\n"
                    result += f"当前时间周内秒: {second}\n"
                    result += f"位置误差: 0x{pos_error:04X}\n"
                    result += f"时间误差: 0x{time_error:04X}\n"
                    result += f"数据有效标志: 0x{data_flag:02X}\n"
                    result += f"保留字段: 0x{reserved:02X}"
                    
            elif msg_type == self.auxiliary_location_protocol.MSG_TYPE_0202:
                # 解析BDS星历辅助信息
                result += f"原始数据: {' '.join(f'{b:02X}' for b in content_bytes)}"
            
            return result
            
        except Exception as e:
            return f"内容解析错误: {str(e)}" 

    def handle_serial_data(self, data):
        # 只显示最新的0x0105/0x0106类型数据
        if self.security_radio.isChecked():
            self.parse_security_packet(data)
        else:
            self.parse_auxiliary_packet(data)

    def start_serial_receive(self):
        port = self.serial_port_widget.get_selected_port()
        baudrate = self.serial_port_widget.get_selected_baudrate()
        if not port:
            self.result_text.setText("请选择串口！")
            return
        self.result_text.setText("正在接收... 只显示0x0105/0x0106类型数据")
        self.receive_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.receive_thread = SerialReceiveThread(port, baudrate)
        self.receive_thread.data_received.connect(self.handle_serial_data)
        self.receive_thread.start()

    def stop_serial_receive(self):
        if self.receive_thread:
            self.receive_thread.stop()
            self.receive_thread = None
        self.receive_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.result_text.append("已停止接收") 