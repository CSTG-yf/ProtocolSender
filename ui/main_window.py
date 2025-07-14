from PyQt5.QtWidgets import QMainWindow, QTabWidget, QWidget, QVBoxLayout,QDesktopWidget
from .location_security_form import LocationSecurityForm
from .auxiliary_location_form import AuxiliaryLocationForm
from .data_receiver_form import DataReceiverForm

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('协议数据验证工具')
        self.init_ui()
        self.center()
        
    def init_ui(self):
        # 创建中心部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 创建布局
        layout = QVBoxLayout()
        central_widget.setLayout(layout)
        
        # 创建选项卡部件
        tab_widget = QTabWidget()
        
        # 添加定位安全数据包选项卡
        location_security_form = LocationSecurityForm()
        tab_widget.addTab(location_security_form, "定位安全数据包")
        
        # 添加辅助定位数据包选项卡
        auxiliary_location_form = AuxiliaryLocationForm()
        tab_widget.addTab(auxiliary_location_form, "辅助定位数据包")
        
        # 添加数据接收选项卡
        data_receiver_form = DataReceiverForm()
        tab_widget.addTab(data_receiver_form, "数据解析")
        
        layout.addWidget(tab_widget)
        
        # 设置窗口大小
        self.setGeometry(100, 100, 800, 1600)

    def center(self):
        frame_geom = self.frameGeometry()
        screen_center = QDesktopWidget().availableGeometry().center()
        frame_geom.moveCenter(screen_center)
        self.move(frame_geom.topLeft())