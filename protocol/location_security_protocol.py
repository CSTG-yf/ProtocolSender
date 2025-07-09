import struct
from datetime import datetime, timedelta

class LocationSecurityProtocol:
    # 固定字段定义
    FIXED_IDENTIFIER = 0x4A544457  # 4字节标识符
    FIXED_VERSION = 0x00           # 1字节格式版本号
    BDS_EPOCH = datetime(2006, 1, 1)  # BDS时间起点
    GPS_EPOCH = datetime(1980, 1, 6)   # GPS时间起点
    GALILEO_EPOCH = datetime(1999, 8, 22)  # GALILEO时间起点
    GLONASS_EPOCH = datetime(1996, 1, 1)  # GLONASS时间起点
    
    # 消息类型定义
    MESSAGE_TYPES = {
        0x0101: "卫星导航系统服务状态信息",
        0x0102: "卫星导航系统导航电文验证信息",
        0x0103: "压制干扰告警信息",
        0x0104: "欺骗干扰告警信息",
        0x0105: "模块干扰检测信息",
        0x0106: "信息交互控制指令"
    }
    
    # 导航系统标识选项
    NAV_SYSTEM_OPTIONS = {
        0x11: "BDS-B1I",
        0x12: "BDS-B1C",
        0x13: "BDS-B2a",
        0x14: "BDS-B2b",
        0x15: "BDS-B3I",
        0x21: "GPS-L1C/A",
        0x22: "GPS-L1C",
        0x23: "GPS-L2C",
        0x24: "GPS-L5C",
        0x31: "GLONASS-G1",
        0x32: "GLONASS-G2",
        0x33: "GLONASS-G3",
        0x41: "GALILEO-E1",
        0x42: "GALILEO-E5a",
        0x43: "GALILEO-E5b",
        0x44: "GALILEO-E6"
    }
    
    # 导航系统状态选项
    NAV_STATUS_OPTIONS = {
        0x00: "正常",
        0x03: "异常"
    }
    
    # 压制干扰类型选项
    INTERFERENCE_TYPE_OPTIONS = {
        1: "窄带干扰",
        2: "宽带干扰",
        3: "其他干扰"
    }
    
    def __init__(self):
        self.message_type = 0x0101  # 默认消息类型
        self.message_content = {}
        
    def set_message_type(self, message_type):
        """设置消息类型"""
        if message_type in self.MESSAGE_TYPES:
            self.message_type = message_type
        
    def set_satellite_nav_status_content(self, content):
        """设置卫星导航系统服务状态消息内容"""
        self.message_content = content
        
    def set_interference_warning_content(self, content):
        """设置压制干扰告警信息内容"""
        self.message_content = content
        
    def _get_bds_week_and_second(self):
        """计算当前时间的BDS周计数和周计秒"""
        now = datetime.now()
        delta = now - self.BDS_EPOCH
        weeks = delta.days // 7
        seconds = delta.total_seconds() % (7 * 24 * 3600)
        return int(weeks), int(seconds)
        
    def _get_gps_week_and_second(self):
        """计算当前时间的GPS周计数和周计秒"""
        now = datetime.now()
        delta = now - self.GPS_EPOCH
        weeks = delta.days // 7
        seconds = delta.total_seconds() % (7 * 24 * 3600)
        return int(weeks), int(seconds)
        
    def _get_galileo_week_and_second(self):
        """计算当前时间的GALILEO周计数和周计秒"""
        now = datetime.now()
        delta = now - self.GALILEO_EPOCH
        weeks = delta.days // 7
        seconds = delta.total_seconds() % (7 * 24 * 3600)
        return int(weeks), int(seconds)
        
    def _get_glonass_day_second(self):
        """计算当前时间的GLONASS日计秒"""
        now = datetime.now()
        # GLONASS以UTC时间午夜为日起点
        today_start = datetime(now.year, now.month, now.day)
        delta = now - today_start
        return int(delta.total_seconds())
        
    def _calculate_crc24q(self, data):
        """计算CRC-24Q校验码（RTCM3.2标准）"""
        crc = 0x000000  # 初始值
        polynomial = 0x1864CFB  # 多项式
        for byte in data:
            crc ^= (byte << 16)  # 左移16位，与CRC高字节对齐
            for _ in range(8):
                if crc & 0x800000:  # 检查最高位
                    crc = (crc << 1) ^ polynomial
                else:
                    crc <<= 1
                crc &= 0xFFFFFF  # 保持24位
        return crc.to_bytes(3, byteorder='big')  # 转换为3字节大端格式
        
    def serialize(self, message_type, message_content):
        """序列化协议数据为16进制格式"""
        # 计算包长度：固定头部(4+1+2+2) + 消息内容长度 + CRC长度(3字节)
        header_length = 4 + 1 + 2 + 2
        
        # 根据消息类型序列化不同的内容
        if message_type == 0x0101:
            # 获取BDS周计数和周计秒
            week, second = self._get_bds_week_and_second()
            
            # 打包卫星导航系统服务状态消息内容
            content = struct.pack(
                '!H I B B 4s 8s 8s',
                week,                       # 参考周计数 (2字节)
                second,                     # 参考周计秒 (4字节)
                message_content.get('nav_system', 0x14),  # 导航系统标识 (1字节)
                message_content.get('nav_status', 0x00),  # 导航系统状态 (1字节)
                bytes.fromhex(message_content.get('signal_status', '00000000').zfill(8)[:8]),  # 导航信号状态 (4字节)
                bytes.fromhex(message_content.get('satellite_status', '0000000000000000').zfill(16)[:16]),  # 导航卫星状态 (8字节)
                b'\x00\x00\x00\x00\x00\x00\x00\x00'  # 保留字段 (8字节)
            )
            
            # 计算包长度（包含CRC）
            package_length = header_length + len(content) + 3
        elif message_type == 0x0102:
            # 获取导航系统
            nav_system = message_content.get('nav_system', 0x14)
            
            # 根据导航系统获取相应的时间
            if nav_system in [0x11, 0x12, 0x13, 0x14, 0x15]:  # BDS系统
                week, second = self._get_bds_week_and_second()
                time_seconds = second
            elif nav_system in [0x21, 0x22, 0x23, 0x24]:  # GPS系统
                week, second = self._get_gps_week_and_second()
                time_seconds = second
            elif nav_system in [0x41, 0x42, 0x43, 0x44]:  # GALILEO系统
                week, second = self._get_galileo_week_and_second()
                time_seconds = second
            elif nav_system in [0x31, 0x32, 0x33]:  # GLONASS系统
                time_seconds = self._get_glonass_day_second()
                week = 0
            else:
                time_seconds = 0
                week = 0
                
            # 打包导航电文验证信息
            content = struct.pack(
                '!H I B B B B 3s 3s',
                week,                       # 参考周计数 (2字节)
                time_seconds,               # 参考时间 (4字节)
                nav_system,                 # 导航系统标识 (1字节)
                int(message_content.get('verification_count', 0)),  # 电文验证信息数N (1字节)
                int(message_content.get('satellite_number', 0)),    # 卫星号 (1字节)
                int(message_content.get('message_type', 0x01)),     # 电文类型 (1字节)
                bytes.fromhex(message_content.get('ref_time', '000000')),  # 电文参考时间 (3字节)
                bytes.fromhex(message_content.get('verification_word', 'FFFFFF'))  # 电文验证字 (3字节)
            )
            
            # 计算包长度（不包含CRC）
            package_length = header_length + len(content)
        elif message_type == 0x0103:
            # 获取BDS周计数和周计秒
            week, second = self._get_bds_week_and_second()
            
            # 打包压制干扰告警信息
            content = struct.pack(
                '!H I B 4s 4s 4s H B B B',
                week,                       # BDS参考周计数 (2字节)
                second,                     # BDS参考周内秒 (4字节)
                0x01,                       # 压制干扰数目n (1字节，固定为0x01)
                bytes.fromhex(message_content.get('latitude', '00000000').zfill(8)),    # 压制干扰纬度 (4字节)
                bytes.fromhex(message_content.get('longitude', '00000000').zfill(8)),   # 压制干扰经度 (4字节)
                bytes.fromhex(message_content.get('center_freq', '00000000').zfill(8)), # 压制干扰中心频率 (4字节)
                int(message_content.get('bandwidth', '0000').zfill(4), 16),             # 压制干扰带宽 (2字节)
                int(message_content.get('interference_type', 1)),                        # 压制干扰类型 (1字节)
                int(message_content.get('intensity', '00').zfill(2), 16),               # 压制干扰强度 (1字节)
                int(message_content.get('confidence', '00').zfill(2), 16)               # 压制干扰置信度 (1字节)
            )
            
            # 计算包长度（不包含CRC）
            package_length = header_length + len(content)
        else:
            content = b''
            package_length = header_length
        
        # 打包固定头部
        header = struct.pack(
            '!IBHH',
            self.FIXED_IDENTIFIER,
            self.FIXED_VERSION,
            package_length,
            message_type
        )

        # 组合完整数据包
        full_package = header + content
        
        # 只有0x0101类型需要添加CRC
        if message_type == 0x0101:
            crc_bytes = self._calculate_crc24q(full_package)
            full_package += crc_bytes
        
        # 返回16进制字符串表示
        return full_package.hex().upper()

    def get_package_length(self, message_type, content):
        """计算当前消息的包长度"""
        header_length = 4 + 1 + 2 + 2  # 标识符(4) + 版本(1) + 包长度(2) + 消息类型(2)

        if message_type == 0x0101:
            # 模拟序列化过程计算内容长度（与serialize方法逻辑一致）
            signal_status = content.get('signal_status', '00000000').zfill(8)[:8]
            satellite_status = content.get('satellite_status', '0000000000000000').zfill(16)[:16]
            content_bytes = struct.pack(
                '!H I B B 4s 8s 8s',
                self._get_bds_week_and_second()[0],
                self._get_bds_week_and_second()[1],
                content.get('nav_system', 0x14),
                content.get('nav_status', 0x00),
                bytes.fromhex(signal_status),
                bytes.fromhex(satellite_status),
                b'\x00'*8
            )
            return header_length + len(content_bytes) + 3  # +3字节CRC
        elif message_type == 0x0102:
            content_bytes = struct.pack(
                '!H I B B B B 3s 3s',
                self._get_bds_week_and_second()[0],
                self._get_bds_week_and_second()[1],
                content.get('nav_system', 0x14),
                int(content.get('verification_count', 0)),
                int(content.get('satellite_number', 0)),
                int(content.get('message_type', 0x01)),
                bytes.fromhex(content.get('ref_time', '000000')),
                bytes.fromhex(content.get('verification_word', 'FFFFFF'))
            )
            return header_length + len(content_bytes)  # 不加CRC
        elif message_type == 0x0103:
            content_bytes = struct.pack(
                '!H I B 4s 4s 4s H B B B',
                self._get_bds_week_and_second()[0],
                self._get_bds_week_and_second()[1],
                0x01,  # 压制干扰数目n (固定为0x01)
                bytes.fromhex(content.get('latitude', '00000000').zfill(8)),
                bytes.fromhex(content.get('longitude', '00000000').zfill(8)),
                bytes.fromhex(content.get('center_freq', '00000000').zfill(8)),
                int(content.get('bandwidth', '0000').zfill(4), 16),
                int(content.get('interference_type', 1)),
                int(content.get('intensity', '00').zfill(2), 16),
                int(content.get('confidence', 50))
            )
            return header_length + len(content_bytes)  # 不加CRC
        else:
            return header_length  # 其他消息类型只有头部