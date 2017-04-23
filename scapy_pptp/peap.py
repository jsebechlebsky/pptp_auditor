from scapy.layers.l2 import EAP, eap_codes, eap_types
from scapy.fields import ByteEnumField, ByteField, FieldLenField, BitField, ConditionalField,\
    IntField, XStrLenField


class PEAP(EAP):
    name = "EAP-TLS"
    fields_desc = [
        ByteEnumField("code", 1, eap_codes),
        ByteField("id", 0),
        FieldLenField("len", None, fmt="H", length_of="tls_data",
                      adjust=lambda p, x: x + 10 if p.L == 1 else x + 6),
        ByteEnumField("type", 25, eap_types),
        BitField('L', 0, 1),
        BitField('M', 0, 1),
        BitField('S', 0, 1),
        BitField('reserved', 0, 4),
        BitField('V', 0, 1),
        ConditionalField(IntField('tls_message_len', 0), lambda pkt: pkt.L == 1),
        XStrLenField('tls_data', '', length_from=lambda pkt: 0 if pkt.len is None else pkt.len - (6 + 4 * pkt.L))]