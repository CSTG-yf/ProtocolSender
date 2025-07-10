import struct
import time
from typing import Optional
from datetime import datetime

class AuxiliaryLocationProtocol:
    # 协议标识符常量
    PROTOCOL_IDENTIFIER = 0x4A544457
    PROTOCOL_VERSION = 0x00
    
    # 消息类型常量
    MSG_TYPE_0201 = 0x0201  # 位置时间辅助信息
    MSG_TYPE_0202 = 0x0202  # BDS星历辅助信息
    
    # 消息类型描述
    MSG_TYPE_DESCRIPTIONS = {
        MSG_TYPE_0201: "位置时间辅助信息",
        MSG_TYPE_0202: "BDS星历辅助信息"
    }
    
    # 数据包长度常量
    PACKET_LENGTH_0201 = 36  # 0x0201类型的固定长度：4+1+2+2+24+3=36字节
    PACKET_LENGTH_0202 = 76  # 0x0202类型的固定长度：4+1+2+2+64+3=76字节
    
    # 数据有效标志选项
    DATA_FLAGS = {
        0x00: "全部无效",
        0x01: "仅位置有效",
        0x10: "仅时间有效",
        0x11: "位置和时间都有效"
    }
    
    def __init__(self):
        self._message_type: int = self.MSG_TYPE_0201
        self._message_content: bytes = b''
        
        # 0x0201消息类型的字段
        self._pos_x: int = 0  # 概略位置X
        self._pos_y: int = 0  # 概略位置Y
        self._pos_z: int = 0  # 概略位置Z
        # 获取当前BDS时间
        now = datetime.now()
        gps_start = datetime(1980, 1, 6)  # GPS起始时间
        total_weeks = int((now - gps_start).days / 7)
        seconds_of_week = (now - gps_start).total_seconds() % (7 * 24 * 3600)
        self._week_number: int = total_weeks  # 当前时间周计数
        self._seconds: int = int(seconds_of_week)  # 当前时间周内秒
        self._pos_error: int = 0  # 位置误差
        self._time_error: int = 0  # 时间误差
        self._data_flag: int = 0x00  # 数据有效标志
        self._reserved: int = 0x00  # 保留字段
        
        # 0x0202消息类型的字段
        self._bds_sat_id: int = 0  # BDS卫星ID
        self._bds_week: int = 0  # BDS周计数
        self._bds_urai: int = 0  # BDS URAI
        self._bds_idot: int = 0  # BDS IDOT
        self._bds_aode: int = 0  # BDS AODE
        self._bds_toc: int = 0  # BDS Toc
        self._bds_a2: int = 0  # BDS a2
        self._bds_a1: int = 0  # BDS a1
        self._bds_a0: int = 0  # BDS a0
        self._bds_aodc: int = 0  # BDS AODC
        self._bds_crs: int = 0  # BDS Crs
        self._bds_delta_n: int = 0  # BDS Δn
        self._bds_m0: int = 0  # BDS M0
        self._bds_cuc: int = 0  # BDS Cuc
        self._bds_e: int = 0  # BDS e
        self._bds_cus: int = 0  # BDS Cus
        self._bds_sqrt_a: int = 0  # BDS 根号a
        self._bds_toe: int = 0  # BDS toe
        self._bds_cic: int = 0  # BDS Cic
        self._bds_omega0: int = 0  # BDS Ω0
        self._bds_cis: int = 0  # BDS Cis
        self._bds_i0: int = 0  # BDS i0
        self._bds_crc: int = 0  # BDS Crc
        self._bds_omega: int = 0  # BDS ω
        self._bds_omega_dot: int = 0  # BDS OMEGADOT
        self._bds_tgd1: int = 0  # BDS TGD1
        self._bds_tgd2: int = 0  # BDS TGD2
        self._bds_health: int = 0  # BDS卫星自主健康状态
    
    @property
    def message_type(self) -> int:
        return self._message_type
    
    @message_type.setter
    def message_type(self, value: int):
        if value not in [self.MSG_TYPE_0201, self.MSG_TYPE_0202]:
            raise ValueError("消息类型必须是0x0201或0x0202")
        self._message_type = value
    
    @property
    def message_content(self) -> bytes:
        if self._message_type == self.MSG_TYPE_0201:
            return self._serialize_0201_content()
        elif self._message_type == self.MSG_TYPE_0202:
            return self._serialize_0202_content()
        return self._message_content
    
    @message_content.setter
    def message_content(self, value: bytes):
        if self._message_type == self.MSG_TYPE_0201:
            self._parse_0201_content(value)
        elif self._message_type == self.MSG_TYPE_0202:
            self._parse_0202_content(value)
        else:
            self._message_content = value
    
    def _serialize_0201_content(self) -> bytes:
        """
        序列化0x0201消息类型的内容
        格式：
        - 概略位置X (4字节) - I
        - 概略位置Y (4字节) - I
        - 概略位置Z (4字节) - I
        - 当前时间周计数 (2字节) - H
        - 当前时间周内秒 (4字节) - I
        - 位置误差 (2字节) - H
        - 时间误差 (2字节) - H
        - 数据有效标志 (1字节) - B
        - 保留字段 (1字节) - B
        """
        return struct.pack('>IIIHIHHBB',  # 修正格式字符串
            self._pos_x,
            self._pos_y,
            self._pos_z,
            self._week_number,
            self._seconds,
            self._pos_error,
            self._time_error,
            self._data_flag,
            self._reserved
        )
    
    def _parse_0201_content(self, data: bytes):
        if len(data) != 24:  # 0x0201消息类型固定长度为24字节
            raise ValueError("0x0201消息类型的内容长度必须为24字节")
        (
            self._pos_x,
            self._pos_y,
            self._pos_z,
            self._week_number,
            self._seconds,
            self._pos_error,
            self._time_error,
            self._data_flag,
            self._reserved
        ) = struct.unpack('>IIIHIHHBB', data)  # 修正格式字符串
    
    def _serialize_0202_content(self) -> bytes:
        """
        序列化0x0202消息类型的内容（BDS星历数据）
        总长度：64字节（512位）
        """
        # 构建电文类型号（12位，0B010000010010）
        message_type_bits = '010000010010'
        
        # 将所有字段打包成位串
        bits = (
            '0' +  # 最高位补0
            message_type_bits +  # 12位固定电文类型号
            format(self._bds_sat_id, '06b') +  # 6位BDS卫星ID
            format(self._bds_week, '013b') +  # 13位BDS周计数
            format(self._bds_urai, '04b') +  # 4位BDS URAI
            format(self._bds_idot, '014b') +  # 14位BDS IDOT
            format(self._bds_aode, '05b') +  # 5位BDS AODE
            format(self._bds_toc, '017b') +  # 17位BDS Toc
            format(self._bds_a2, '011b') +  # 11位BDS a2
            format(self._bds_a1, '022b') +  # 22位BDS a1
            format(self._bds_a0, '024b') +  # 24位BDS a0
            format(self._bds_aodc, '05b') +  # 5位BDS AODC
            format(self._bds_crs, '018b') +  # 18位BDS Crs
            format(self._bds_delta_n, '016b') +  # 16位BDS Δn
            format(self._bds_m0, '032b') +  # 32位BDS M0
            format(self._bds_cuc, '018b') +  # 18位BDS Cuc
            format(self._bds_e, '032b') +  # 32位BDS e
            format(self._bds_cus, '018b') +  # 18位BDS Cus
            format(self._bds_sqrt_a, '032b') +  # 32位BDS 根号a
            format(self._bds_toe, '017b') +  # 17位BDS toe
            format(self._bds_cic, '018b') +  # 18位BDS Cic
            format(self._bds_omega0, '032b') +  # 32位BDS Ω0
            format(self._bds_cis, '018b') +  # 18位BDS Cis
            format(self._bds_i0, '032b') +  # 32位BDS i0
            format(self._bds_crc, '018b') +  # 18位BDS Crc
            format(self._bds_omega, '032b') +  # 32位BDS ω
            format(self._bds_omega_dot, '024b') +  # 24位BDS OMEGADOT
            format(self._bds_tgd1, '010b') +  # 10位BDS TGD1
            format(self._bds_tgd2, '010b') +  # 10位BDS TGD2
            format(self._bds_health, '01b')  # 1位BDS卫星自主健康状态
        )
        
        # 将位串转换为字节
        bytes_data = bytearray()
        for i in range(0, len(bits), 8):
            byte_bits = bits[i:i+8]
            if len(byte_bits) < 8:
                byte_bits = byte_bits.ljust(8, '0')
            bytes_data.append(int(byte_bits, 2))
            
        return bytes(bytes_data)

    def _parse_0202_content(self, data: bytes):
        """
        解析0x0202消息类型的内容（BDS星历数据）
        """
        if len(data) != 64:  # 0x0202消息类型固定长度为64字节
            raise ValueError("0x0202消息类型的内容长度必须为64字节")
            
        # 将字节转换为位串
        bits = ''.join(format(b, '08b') for b in data)
        
        # 解析各个字段
        current_pos = 1  # 跳过最高位
        
        # 跳过固定电文类型号（12位）
        current_pos += 12
        
        self._bds_sat_id = int(bits[current_pos:current_pos+6], 2)
        current_pos += 6
        
        self._bds_week = int(bits[current_pos:current_pos+13], 2)
        current_pos += 13
        
        self._bds_urai = int(bits[current_pos:current_pos+4], 2)
        current_pos += 4
        
        self._bds_idot = int(bits[current_pos:current_pos+14], 2)
        current_pos += 14
        
        self._bds_aode = int(bits[current_pos:current_pos+5], 2)
        current_pos += 5
        
        self._bds_toc = int(bits[current_pos:current_pos+17], 2)
        current_pos += 17
        
        self._bds_a2 = int(bits[current_pos:current_pos+11], 2)
        current_pos += 11
        
        self._bds_a1 = int(bits[current_pos:current_pos+22], 2)
        current_pos += 22
        
        self._bds_a0 = int(bits[current_pos:current_pos+24], 2)
        current_pos += 24
        
        self._bds_aodc = int(bits[current_pos:current_pos+5], 2)
        current_pos += 5
        
        self._bds_crs = int(bits[current_pos:current_pos+18], 2)
        current_pos += 18
        
        self._bds_delta_n = int(bits[current_pos:current_pos+16], 2)
        current_pos += 16
        
        self._bds_m0 = int(bits[current_pos:current_pos+32], 2)
        current_pos += 32
        
        self._bds_cuc = int(bits[current_pos:current_pos+18], 2)
        current_pos += 18
        
        self._bds_e = int(bits[current_pos:current_pos+32], 2)
        current_pos += 32
        
        self._bds_cus = int(bits[current_pos:current_pos+18], 2)
        current_pos += 18
        
        self._bds_sqrt_a = int(bits[current_pos:current_pos+32], 2)
        current_pos += 32
        
        self._bds_toe = int(bits[current_pos:current_pos+17], 2)
        current_pos += 17
        
        self._bds_cic = int(bits[current_pos:current_pos+18], 2)
        current_pos += 18
        
        self._bds_omega0 = int(bits[current_pos:current_pos+32], 2)
        current_pos += 32
        
        self._bds_cis = int(bits[current_pos:current_pos+18], 2)
        current_pos += 18
        
        self._bds_i0 = int(bits[current_pos:current_pos+32], 2)
        current_pos += 32
        
        self._bds_crc = int(bits[current_pos:current_pos+18], 2)
        current_pos += 18
        
        self._bds_omega = int(bits[current_pos:current_pos+32], 2)
        current_pos += 32
        
        self._bds_omega_dot = int(bits[current_pos:current_pos+24], 2)
        current_pos += 24
        
        self._bds_tgd1 = int(bits[current_pos:current_pos+10], 2)
        current_pos += 10
        
        self._bds_tgd2 = int(bits[current_pos:current_pos+10], 2)
        current_pos += 10
        
        self._bds_health = int(bits[current_pos:current_pos+1], 2)

    def _parse_hex_input(self, hex_str: str) -> int:
        """解析十六进制输入字符串
        
        Args:
            hex_str: 十六进制字符串（可以带0x前缀）
            
        Returns:
            int: 解析后的整数值
        """
        # 移除0x前缀和空白字符
        hex_str = hex_str.lower().replace('0x', '').strip()
        if not hex_str:
            return 0
        return int(hex_str, 16)
        
    def _parse_binary_input(self, bin_str: str) -> int:
        """解析二进制输入字符串
        
        Args:
            bin_str: 二进制字符串（可以带0b前缀）
            
        Returns:
            int: 解析后的整数值
        """
        # 移除0b前缀和空白字符
        bin_str = bin_str.lower().replace('0b', '').strip()
        if not bin_str:
            return 0
        return int(bin_str, 2)
        
    def set_0201_field(self, field_name: str, hex_value: str):
        """设置0x0201消息类型字段的值（十六进制输入）
        
        Args:
            field_name: 字段名称
            hex_value: 十六进制字符串值
        """
        value = self._parse_hex_input(hex_value)
        if field_name == 'pos_x':
            self.pos_x = value
        elif field_name == 'pos_y':
            self.pos_y = value
        elif field_name == 'pos_z':
            self.pos_z = value
        elif field_name == 'pos_error':
            self.pos_error = value
        elif field_name == 'time_error':
            self.time_error = value
        elif field_name == 'data_flag':
            self.data_flag = value
            
    def set_0202_field(self, field_name: str, bin_value: str):
        """设置0x0202消息类型字段的值（二进制输入）
        
        Args:
            field_name: 字段名称
            bin_value: 二进制字符串值
        """
        value = self._parse_binary_input(bin_value)
        if field_name == 'bds_sat_id':
            self.bds_sat_id = value
        elif field_name == 'bds_week':
            self.bds_week = value
        elif field_name == 'bds_urai':
            self.bds_urai = value
        elif field_name == 'bds_idot':
            self.bds_idot = value
        elif field_name == 'bds_aode':
            self.bds_aode = value
        elif field_name == 'bds_toc':
            self.bds_toc = value
        elif field_name == 'bds_a2':
            self.bds_a2 = value
        elif field_name == 'bds_a1':
            self.bds_a1 = value
        elif field_name == 'bds_a0':
            self.bds_a0 = value
        elif field_name == 'bds_aodc':
            self.bds_aodc = value
        elif field_name == 'bds_crs':
            self.bds_crs = value
        elif field_name == 'bds_delta_n':
            self.bds_delta_n = value
        elif field_name == 'bds_m0':
            self.bds_m0 = value
        elif field_name == 'bds_cuc':
            self.bds_cuc = value
        elif field_name == 'bds_e':
            self.bds_e = value
        elif field_name == 'bds_cus':
            self.bds_cus = value
        elif field_name == 'bds_sqrt_a':
            self.bds_sqrt_a = value
        elif field_name == 'bds_toe':
            self.bds_toe = value
        elif field_name == 'bds_cic':
            self.bds_cic = value
        elif field_name == 'bds_omega0':
            self.bds_omega0 = value
        elif field_name == 'bds_cis':
            self.bds_cis = value
        elif field_name == 'bds_i0':
            self.bds_i0 = value
        elif field_name == 'bds_crc':
            self.bds_crc = value
        elif field_name == 'bds_omega':
            self.bds_omega = value
        elif field_name == 'bds_omega_dot':
            self.bds_omega_dot = value
        elif field_name == 'bds_tgd1':
            self.bds_tgd1 = value
        elif field_name == 'bds_tgd2':
            self.bds_tgd2 = value
        elif field_name == 'bds_health':
            self.bds_health = value
    
    # 0x0201消息类型的属性访问器
    @property
    def pos_x(self) -> int:
        return self._pos_x
    
    @pos_x.setter
    def pos_x(self, value: int):
        self._pos_x = value & 0xFFFFFFFF  # 确保是4字节
    
    @property
    def pos_y(self) -> int:
        return self._pos_y
    
    @pos_y.setter
    def pos_y(self, value: int):
        self._pos_y = value & 0xFFFFFFFF  # 确保是4字节
    
    @property
    def pos_z(self) -> int:
        return self._pos_z
    
    @pos_z.setter
    def pos_z(self, value: int):
        self._pos_z = value & 0xFFFFFFFF  # 确保是4字节
    
    @property
    def week_number(self) -> int:
        return self._week_number
    
    @week_number.setter
    def week_number(self, value: int):
        self._week_number = value & 0xFFFF  # 确保是2字节
    
    @property
    def seconds(self) -> int:
        return self._seconds
    
    @seconds.setter
    def seconds(self, value: int):
        self._seconds = value & 0xFFFFFFFF  # 确保是4字节
    
    @property
    def pos_error(self) -> int:
        return self._pos_error
    
    @pos_error.setter
    def pos_error(self, value: int):
        self._pos_error = value & 0xFFFF  # 确保是2字节
    
    @property
    def time_error(self) -> int:
        return self._time_error
    
    @time_error.setter
    def time_error(self, value: int):
        self._time_error = value & 0xFFFF  # 确保是2字节
    
    @property
    def data_flag(self) -> int:
        return self._data_flag
    
    @data_flag.setter
    def data_flag(self, value: int):
        if value not in self.DATA_FLAGS:
            raise ValueError("数据有效标志必须是0x00、0x01、0x10或0x11")
        self._data_flag = value
    
    # 0x0202消息类型的属性访问器
    @property
    def bds_sat_id(self) -> int:
        return self._bds_sat_id
    
    @bds_sat_id.setter
    def bds_sat_id(self, value: int):
        self._bds_sat_id = value & 0x3F  # 6位
    
    @property
    def bds_week(self) -> int:
        return self._bds_week
    
    @bds_week.setter
    def bds_week(self, value: int):
        self._bds_week = value & 0x1FFF  # 13位
    
    @property
    def bds_urai(self) -> int:
        return self._bds_urai
    
    @bds_urai.setter
    def bds_urai(self, value: int):
        self._bds_urai = value & 0xF  # 4位
    
    @property
    def bds_idot(self) -> int:
        return self._bds_idot
    
    @bds_idot.setter
    def bds_idot(self, value: int):
        self._bds_idot = value & 0x3FFF  # 14位
    
    @property
    def bds_aode(self) -> int:
        return self._bds_aode
    
    @bds_aode.setter
    def bds_aode(self, value: int):
        self._bds_aode = value & 0x1F  # 5位
    
    @property
    def bds_toc(self) -> int:
        return self._bds_toc
    
    @bds_toc.setter
    def bds_toc(self, value: int):
        self._bds_toc = value & 0x1FFFF  # 17位
    
    @property
    def bds_a2(self) -> int:
        return self._bds_a2
    
    @bds_a2.setter
    def bds_a2(self, value: int):
        self._bds_a2 = value & 0x7FF  # 11位
    
    @property
    def bds_a1(self) -> int:
        return self._bds_a1
    
    @bds_a1.setter
    def bds_a1(self, value: int):
        self._bds_a1 = value & 0x3FFFFF  # 22位
    
    @property
    def bds_a0(self) -> int:
        return self._bds_a0
    
    @bds_a0.setter
    def bds_a0(self, value: int):
        self._bds_a0 = value & 0xFFFFFF  # 24位
    
    @property
    def bds_aodc(self) -> int:
        return self._bds_aodc
    
    @bds_aodc.setter
    def bds_aodc(self, value: int):
        self._bds_aodc = value & 0x1F  # 5位
    
    @property
    def bds_crs(self) -> int:
        return self._bds_crs
    
    @bds_crs.setter
    def bds_crs(self, value: int):
        self._bds_crs = value & 0x3FFFF  # 18位
    
    @property
    def bds_delta_n(self) -> int:
        return self._bds_delta_n
    
    @bds_delta_n.setter
    def bds_delta_n(self, value: int):
        self._bds_delta_n = value & 0xFFFF  # 16位
    
    @property
    def bds_m0(self) -> int:
        return self._bds_m0
    
    @bds_m0.setter
    def bds_m0(self, value: int):
        self._bds_m0 = value & 0xFFFFFFFF  # 32位
    
    @property
    def bds_cuc(self) -> int:
        return self._bds_cuc
    
    @bds_cuc.setter
    def bds_cuc(self, value: int):
        self._bds_cuc = value & 0x3FFFF  # 18位
    
    @property
    def bds_e(self) -> int:
        return self._bds_e
    
    @bds_e.setter
    def bds_e(self, value: int):
        self._bds_e = value & 0xFFFFFFFF  # 32位
    
    @property
    def bds_cus(self) -> int:
        return self._bds_cus
    
    @bds_cus.setter
    def bds_cus(self, value: int):
        self._bds_cus = value & 0x3FFFF  # 18位
    
    @property
    def bds_sqrt_a(self) -> int:
        return self._bds_sqrt_a
    
    @bds_sqrt_a.setter
    def bds_sqrt_a(self, value: int):
        self._bds_sqrt_a = value & 0xFFFFFFFF  # 32位
    
    @property
    def bds_toe(self) -> int:
        return self._bds_toe
    
    @bds_toe.setter
    def bds_toe(self, value: int):
        self._bds_toe = value & 0x1FFFF  # 17位
    
    @property
    def bds_cic(self) -> int:
        return self._bds_cic
    
    @bds_cic.setter
    def bds_cic(self, value: int):
        self._bds_cic = value & 0x3FFFF  # 18位
    
    @property
    def bds_omega0(self) -> int:
        return self._bds_omega0
    
    @bds_omega0.setter
    def bds_omega0(self, value: int):
        self._bds_omega0 = value & 0xFFFFFFFF  # 32位
    
    @property
    def bds_cis(self) -> int:
        return self._bds_cis
    
    @bds_cis.setter
    def bds_cis(self, value: int):
        self._bds_cis = value & 0x3FFFF  # 18位
    
    @property
    def bds_i0(self) -> int:
        return self._bds_i0
    
    @bds_i0.setter
    def bds_i0(self, value: int):
        self._bds_i0 = value & 0xFFFFFFFF  # 32位
    
    @property
    def bds_crc(self) -> int:
        return self._bds_crc
    
    @bds_crc.setter
    def bds_crc(self, value: int):
        self._bds_crc = value & 0x3FFFF  # 18位
    
    @property
    def bds_omega(self) -> int:
        return self._bds_omega
    
    @bds_omega.setter
    def bds_omega(self, value: int):
        self._bds_omega = value & 0xFFFFFFFF  # 32位
    
    @property
    def bds_omega_dot(self) -> int:
        return self._bds_omega_dot
    
    @bds_omega_dot.setter
    def bds_omega_dot(self, value: int):
        self._bds_omega_dot = value & 0xFFFFFF  # 24位
    
    @property
    def bds_tgd1(self) -> int:
        return self._bds_tgd1
    
    @bds_tgd1.setter
    def bds_tgd1(self, value: int):
        self._bds_tgd1 = value & 0x3FF  # 10位
    
    @property
    def bds_tgd2(self) -> int:
        return self._bds_tgd2
    
    @bds_tgd2.setter
    def bds_tgd2(self, value: int):
        self._bds_tgd2 = value & 0x3FF  # 10位
    
    @property
    def bds_health(self) -> int:
        return self._bds_health
    
    @bds_health.setter
    def bds_health(self, value: int):
        self._bds_health = value & 0x1  # 1位
    
    def _calculate_length(self) -> int:
        """
        返回数据包的固定长度
        0x0201类型: 36字节
        0x0202类型: 76字节
        """
        if self._message_type == self.MSG_TYPE_0201:
            return self.PACKET_LENGTH_0201
        elif self._message_type == self.MSG_TYPE_0202:
            return self.PACKET_LENGTH_0202
        return 0  # 其他类型暂不支持
    
    def _calculate_crc24q(self, data: bytes) -> int:
        CRC24Q_POLY = 0x1864CFB  # CRC-24Q 多项式
        crc = 0
        for byte in data:
            crc ^= (byte << 16)
            for _ in range(8):
                crc <<= 1
                if crc & 0x1000000:
                    crc ^= CRC24Q_POLY
        return crc & 0xFFFFFF
    
    def serialize(self) -> bytes:
        # 构建包头
        header = struct.pack('>IB', self.PROTOCOL_IDENTIFIER, self.PROTOCOL_VERSION)
        
        # 获取包长度
        length = self._calculate_length()
        length_bytes = struct.pack('>H', length)
        
        # 构建消息类型
        msg_type = struct.pack('>H', self._message_type)
        
        # 构建消息内容
        content = self.message_content
        
        # 组合所有数据用于计算CRC
        data_for_crc = header + length_bytes + msg_type + content
        
        # 计算CRC
        crc = self._calculate_crc24q(data_for_crc)
        crc_bytes = struct.pack('>I', crc)[1:]  # 取后3字节
        
        # 返回完整的数据包
        return data_for_crc + crc_bytes
    
    def deserialize(self, data: bytes) -> bool:
        try:
            # 检查数据包最小长度
            if len(data) < 12:  # 4+1+2+2+3(不包含消息内容)
                return False
                
            # 解析协议标识符
            protocol_id = struct.unpack('>I', data[0:4])[0]
            if protocol_id != self.PROTOCOL_IDENTIFIER:
                return False
                
            # 解析版本号
            version = data[4]
            if version != self.PROTOCOL_VERSION:
                return False
                
            # 解析包长度
            length = struct.unpack('>H', data[5:7])[0]
            if length != len(data):
                return False
                
            # 解析消息类型
            self._message_type = struct.unpack('>H', data[7:9])[0]
            if self._message_type not in [self.MSG_TYPE_0201, self.MSG_TYPE_0202]:
                return False
                
            # 提取消息内容
            self._message_content = data[9:-3]
            
            # 验证CRC
            received_crc = int.from_bytes(data[-3:], 'big')
            calculated_crc = self._calculate_crc24q(data[:-3])
            
            return received_crc == calculated_crc
            
        except Exception:
            return False