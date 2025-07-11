from PyQt5.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QComboBox, 
                           QStackedWidget, QDesktopWidget)
from PyQt5.QtCore import Qt
from .location_security_form import LocationSecurityForm
from .auxiliary_location_form import AuxiliaryLocationForm

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("协议数据发送器")
        
        # 设置窗口大小
        self.resize(800, 1500)  # 使用更合理的初始大小
        
        # 将窗口移动到屏幕中央
        self.center_window()
        
        # 创建中心部件和布局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # 创建协议选择下拉框
        self.protocol_selector = QComboBox()
        self.protocol_selector.addItem("定位安全性数据包", "location_security")
        self.protocol_selector.addItem("辅助定位数据包", "auxiliary_location")
        self.protocol_selector.currentIndexChanged.connect(self.on_protocol_changed)
        layout.addWidget(self.protocol_selector)
        
        # 创建堆叠窗口用于显示不同协议的表单
        self.stacked_widget = QStackedWidget()
        layout.addWidget(self.stacked_widget)
        
        # 创建不同协议的表单
        self.forms = {
            "location_security": LocationSecurityForm(),
            "auxiliary_location": AuxiliaryLocationForm()
        }
        
        # 将表单添加到堆叠窗口
        for form in self.forms.values():
            self.stacked_widget.addWidget(form)
        
        # 默认显示第一个表单
        self.stacked_widget.setCurrentIndex(0)
        
    def center_window(self):
        """将窗口移动到屏幕中央"""
        # 获取屏幕几何信息
        screen = QDesktopWidget().screenGeometry()
        # 获取窗口几何信息
        window = self.geometry()
        # 计算中心位置
        x = (screen.width() - window.width()) // 2
        y = (screen.height() - window.height()) // 2
        # 移动窗口
        self.move(x, y)
    
    def on_protocol_changed(self, index):
        # 获取选中的协议类型
        protocol_type = self.protocol_selector.itemData(index)
        # 显示对应的表单
        self.stacked_widget.setCurrentWidget(self.forms[protocol_type])