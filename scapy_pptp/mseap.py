from scapy.layers.l2 import EAP, eap_codes, eap_types
from scapy.fields import ByteEnumField, ByteField, ShortField, StrLenField, XStrLenField

eap_mschapv2_opcodes = {1: "Challenge",
                        2: "Response",
                        3: "Success",
                        4: "Failure",
                        7: "Change-Password"}


class EAP_MSCHAPv2(EAP):
    name = "EAP MSCHAPv2"
    fields_desc = [ByteEnumField("code", 4, eap_codes),
                   ByteField("id", 0),
                   ShortField("len", None),
                   ByteEnumField("type", 26, eap_types),
                   ByteEnumField("opcode", 0, eap_mschapv2_opcodes),
                   ByteField("mschapv2_id", 0),
                   ShortField("ms_len", None),
                   StrLenField("data", "", length_from=lambda p: p.len-9)]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt is not None and len(_pkt) > 5:
            opcode = ord(_pkt[5])
            if opcode == 1:
                return EAP_MSCHAPv2Challenge
        return cls


class EAP_MSCHAPv2Challenge(EAP_MSCHAPv2):
    fields_desc = [ByteEnumField("code", 4, eap_codes),
                   ByteField("id", 0),
                   ShortField("len", None),
                   ByteEnumField("type", 26, eap_types),
                   ByteEnumField("opcode", 1, eap_mschapv2_opcodes),
                   ByteField("mschapv2_id", 0),
                   ShortField("ms_len", None),
                   ByteField("value_size", 16),
                   XStrLenField("challenge", b"\0"*16, length_from=lambda p: p.value_size),
                   StrLenField("optional_name", "", length_from=lambda p: p.len-26)]