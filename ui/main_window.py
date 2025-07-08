from PyQt5.QtWidgets import QMainWindow, QWidget, QVBoxLayout, QComboBox, QStackedWidget
from .location_security_form import LocationSecurityForm
from .auxiliary_location_form import AuxiliaryLocationForm

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("协议数据发送器")
        self.setGeometry(100, 100, 800, 600)
        
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
    
    def on_protocol_changed(self, index):
        # 获取选中的协议类型
        protocol_type = self.protocol_selector.itemData(index)
        # 显示对应的表单
        self.stacked_widget.setCurrentWidget(self.forms[protocol_type])