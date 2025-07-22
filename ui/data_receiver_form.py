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
import re

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
            # 只保留16进制字符
            hex_data = re.sub(r'[^0-9A-Fa-f]', '', hex_data)
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
                # 解析模块干扰检测信息，严格按照k/n/m值和数据长度输出
                print("content_bytes:", content_bytes.hex(), "len:", len(content_bytes))
                offset = 0
                if len(content_bytes) < 41:
                    return "数据长度不足，无法解析完整字段"
                # 1. 定位状态 (2字节)
                pos_status = int.from_bytes(content_bytes[offset:offset+2], 'big')
                result += f"1. 定位状态 (UINT16, 2字节): {pos_status:04X}\n"
                offset += 2
                # 2. 参考周计数 (2字节)
                week = int.from_bytes(content_bytes[offset:offset+2], 'big')
                result += f"2. 参考周计数 (UINT16, 2字节): {week:04X}\n"
                offset += 2
                # 3. 参考周内秒 (4字节)
                second = int.from_bytes(content_bytes[offset:offset+4], 'big')
                result += f"3. 参考周内秒 (UINT32, 4字节): {second:08X}\n"
                offset += 4
                # 4. 纬度 (4字节)
                latitude = int.from_bytes(content_bytes[offset:offset+4], 'big', signed=True)
                result += f"4. 纬度 (INT32, 4字节): {latitude:08X}\n"
                offset += 4
                # 5. 经度 (4字节)
                longitude = int.from_bytes(content_bytes[offset:offset+4], 'big', signed=True)
                result += f"5. 经度 (INT32, 4字节): {longitude:08X}\n"
                offset += 4
                # 6. 大地高 (4字节)
                height = int.from_bytes(content_bytes[offset:offset+4], 'big', signed=True)
                result += f"6. 大地高 (INT32, 4字节): {height:08X}\n"
                offset += 4
                # 7. 水平速度 (4字节)
                v_n = int.from_bytes(content_bytes[offset:offset+4], 'big', signed=True)
                result += f"7. 水平速度 (INT32, 4字节): {v_n:08X}\n"
                offset += 4
                # 8. 垂直速度 (4字节)
                v_e = int.from_bytes(content_bytes[offset:offset+4], 'big', signed=True)
                result += f"8. 垂直速度 (INT32, 4字节): {v_e:08X}\n"
                offset += 4
                # 9. 运动航向 (4字节)
                v_u = int.from_bytes(content_bytes[offset:offset+4], 'big', signed=True)
                result += f"9. 运动航向 (INT32, 4字节): {v_u:08X}\n"
                offset += 4
                # 10. 水平精度因子 (2字节)
                hdop = int.from_bytes(content_bytes[offset:offset+2], 'big')
                result += f"10. 水平精度因子 (UINT16, 2字节): {hdop:04X}\n"
                offset += 2
                # 11. 参与定位导航信号 (4字节)
                nav_signal = int.from_bytes(content_bytes[offset:offset+4], 'big')
                result += f"11. 参与定位导航信号 (UINT32, 4字节): {nav_signal:08X}\n"
                offset += 4
                # 12. 参与定位卫星总数 (1字节)
                total_sats = content_bytes[offset]
                result += f"12. 参与定位卫星总数 (UINT8, 1字节): {total_sats:02X}\n"
                offset += 1
                # 13. 参与定位北斗卫星数 (1字节)
                bds_sats = content_bytes[offset]
                result += f"13. 参与定位北斗卫星数 (UINT8, 1字节): {bds_sats:02X}\n"
                offset += 1
                # 14. RAIM监测发现的故障信号数k (1字节)
                raim_k = content_bytes[offset]
                result += f"14. RAIM监测发现的故障信号数k (INT8, 1字节): {raim_k:02X} (k={raim_k})\n"
                offset += 1
                if raim_k == 1:
                    result += f"\n由于k=1，数据项15~17存在：\n"
                    if offset+2 <= len(content_bytes):
                        raim_prn = content_bytes[offset]
                        raim_id = content_bytes[offset+1]
                        result += f"第1个故障信号的卫星编号 (UINT8, 1字节): {raim_prn:02X}\n"
                        result += f"第1个故障信号的信号标识 (UINT8, 1字节): {raim_id:02X}\n"
                        offset += 2
                    else:
                        result += "数据不足\n"
                # 15. 压制干扰数目n (1字节)
                print("offset before jam_n:", offset)
                if offset < len(content_bytes):
                    jam_n = content_bytes[offset]
                    result += f"\n压制干扰数目n (INT8, 1字节): {jam_n:02X} (n={jam_n})\n"
                    offset += 1
                    if jam_n == 1:
                        result += f"\n由于n=1，数据项19~22存在：\n"
                        if offset + 8 <= len(content_bytes):
                            jam_freq = int.from_bytes(content_bytes[offset:offset+4], 'big')
                            jam_bw = int.from_bytes(content_bytes[offset+4:offset+6], 'big')
                            jam_type = content_bytes[offset+6]
                            jam_strength = content_bytes[offset+7]
                            result += f"压制干扰中心频率 (UINT32, 4字节): {jam_freq:08X}\n"
                            result += f"压制干扰带宽 (UINT16, 2字节): {jam_bw:04X}\n"
                            result += f"压制干扰类型 (UINT8, 1字节): {jam_type:02X}\n"
                            result += f"压制干扰强度 (UINT8, 1字节): {jam_strength:02X}\n"
                            offset += 8
                        else:
                            result += "数据不足\n"
                else:
                    result += "\n压制干扰数目n (INT8, 1字节): 数据不足\n"
                # 16. 欺骗干扰数目m (1字节)
                print("offset before spoof_m:", offset)
                if offset < len(content_bytes):
                    spoof_m = content_bytes[offset]
                    result += f"\n欺骗干扰数目m (INT8, 1字节): {spoof_m:02X} (m={spoof_m})\n"
                    offset += 1
                    if spoof_m == 1:
                        result += f"\n由于m=1，数据项25存在：\n"
                        if offset < len(content_bytes):
                            spoof_id = content_bytes[offset]
                            result += f"欺骗干扰的卫星导航信号 (UINT8, 1字节): {spoof_id:02X}\n"
                            offset += 1
                        else:
                            result += "数据不足\n"
                else:
                    result += "\n欺骗干扰数目m (INT8, 1字节): 数据不足\n"
                return result
            
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