class DataSender:
    def __init__(self):
        """初始化数据发送器"""
        pass
        
    def send_data(self, data_hex):
        """
        发送十六进制格式的数据
        
        Args:
            data_hex (str): 十六进制格式的数据字符串
        """
        try:
            # 这里可以添加实际的数据发送逻辑
            # 例如：通过串口、网络等发送数据
            print(f"发送数据: {data_hex}")
            return True
        except Exception as e:
            print(f"发送数据失败: {str(e)}")
            raise