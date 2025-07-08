from PyQt5.QtWidgets import QWidget, QFormLayout, QLineEdit, QPushButton, QHBoxLayout, QVBoxLayout
from protocol.auxiliary_location_protocol import AuxiliaryLocationProtocol
from services.data_sender import DataSender

class AuxiliaryLocationForm(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # 创建表单布局
        form_layout = QFormLayout()
        
        # 添加协议字段（具体内容后续再填写）
        self.field_a = QLineEdit()
        self.field_b = QLineEdit()
        self.field_c = QLineEdit()
        
        form_layout.addRow("字段A:", self.field_a)
        form_layout.addRow("字段B:", self.field_b)
        form_layout.addRow("字段C:", self.field_c)
        
        layout.addLayout(form_layout)
        
        # 创建发送按钮
        button_layout = QHBoxLayout()
        self.send_button = QPushButton("发送数据")
        self.send_button.clicked.connect(self.send_data)
        button_layout.addWidget(self.send_button)
        
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def send_data(self):
        # 获取字段值
        field_a_value = self.field_a.text()
        field_b_value = self.field_b.text()
        field_c_value = self.field_c.text()
        
        # 创建协议对象
        protocol = AuxiliaryLocationProtocol()
        protocol.set_field_a(field_a_value)
        protocol.set_field_b(field_b_value)
        protocol.set_field_c(field_c_value)
        
        # 发送数据
        data_sender = DataSender()
        data_sender.send(protocol.serialize())