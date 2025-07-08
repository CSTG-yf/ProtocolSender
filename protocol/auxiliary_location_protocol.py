class AuxiliaryLocationProtocol:
    def __init__(self):
        self.field_a = None
        self.field_b = None
        self.field_c = None
        
    def set_field_a(self, value):
        self.field_a = value
        
    def set_field_b(self, value):
        self.field_b = value
        
    def set_field_c(self, value):
        self.field_c = value
        
    def serialize(self):
        # 具体序列化逻辑后续再填写
        data = {
            "type": "auxiliary_location",
            "field_a": self.field_a,
            "field_b": self.field_b,
            "field_c": self.field_c
        }
        return str(data)