import serial
from serial.tools import list_ports

class DataSender:
    def __init__(self, port=None, baudrate=115200):
        """初始化数据发送器，可指定串口端口和波特率"""
        self.port = port
        self.baudrate = baudrate

    @staticmethod
    def list_ports():
        return list(list_ports.comports())

    def send_data(self, data_hex):
        """
        发送十六进制格式的数据到串口
        Args:
            data_hex (str): 十六进制格式的数据字符串
        """
        if not self.port:
            print("未设置串口，无法发送数据！")
            return False
        try:
            # 将十六进制字符串转为字节
            data_bytes = bytes.fromhex(data_hex)
            with serial.Serial(self.port, self.baudrate, timeout=1) as ser:
                ser.write(data_bytes)
                print(f"已发送数据到串口 {self.port}: {data_hex}")
            return True
        except Exception as e:
            print(f"发送数据失败: {str(e)}")
            return False