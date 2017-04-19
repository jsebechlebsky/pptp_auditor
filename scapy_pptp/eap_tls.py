from scapy.packet import Packet
from scapy.fields import BitField, ByteEnumField, ByteField, ConditionalField, FieldLenField,\
                         IntField, ShortField, StrLenField
from scapy.layers.l2 import eap_codes, eap_types, EAP as ORIGINAL_EAP
from scapy.packet import bind_layers, split_layers
from scapy.layers.ppp import PPP


class EAP(Packet):

    """
    RFC 3748 - Extensible Authentication Protocol (EAP)
    """

    name = "EAP"
    fields_desc = [
        ByteEnumField("code", 4, eap_codes),
        ByteField("id", 0),
        ShortField("len", None),
        ConditionalField(ByteEnumField("type", 0, eap_types),
                         lambda pkt:pkt.code not in [
                             EAP.SUCCESS, EAP.FAILURE]),
        ConditionalField(ByteEnumField("desired_auth_type", 0, eap_types),
                         lambda pkt:pkt.code == EAP.RESPONSE and pkt.type == 3),
        ConditionalField(
            StrLenField("identity", '', length_from=lambda pkt: pkt.len - 5),
                         lambda pkt: hasattr(pkt, 'type') and pkt.type == 1)
    ]

    #________________________________________________________________________
    #
    # EAP codes
    # http://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml#eap-numbers-1
    #________________________________________________________________________
    #

    REQUEST = 1
    RESPONSE = 2
    SUCCESS = 3
    FAILURE = 4
    INITIATE = 5
    FINISH = 6

    registered_options = {}

    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            c = ord(_pkt[0])
            if c in [1, 2] and len(_pkt) >= 5:
                t = ord(_pkt[4])
                return cls.registered_options.get(t, cls)
        return cls

    def answers(self, other):
        if isinstance(other, EAP):
            if self.code == self.REQUEST:
                return 0
            elif self.code == self.RESPONSE:
                if ((other.code == self.REQUEST) and
                   (other.type == self.type)):
                    return 1
            elif other.code == self.RESPONSE:
                return 1
        return 0

    def post_build(self, p, pay):
        if self.len is None:
            l = len(p) + len(pay)
            p = p[:2] + chr((l >> 8) & 0xff) + chr(l & 0xff) + p[4:]
        return p + pay


class EAP_TLS(EAP):

    """
    RFC 5216 - "The EAP-TLS Authentication Protocol"
    """

    name = "EAP-TLS"
    fields_desc = [ByteEnumField("code", 4, eap_codes),
                   ByteField("id", 0),
                   FieldLenField("len", None, fmt="H", length_of="tls_data",
                                 adjust=lambda p, x: x + 10 if p.L == 1 else x + 6),
                   ByteEnumField("type", 13, eap_types),
                   BitField('L', 0, 1),
                   BitField('M', 0, 1),
                   BitField('S', 0, 1),
                   BitField('reserved', 0, 5),
                   ConditionalField(IntField('tls_message_len', 0), lambda pkt: pkt.L == 1),
                   StrLenField('tls_data', '', length_from=lambda pkt: pkt.len-10 if pkt.L == 1 else pkt.len-6)]


class PEAP(EAP):

    name = "EAP-PEAP"
    fields_desc = [ByteEnumField("code", 4, eap_codes),
                   ByteField("id", 0),
                   FieldLenField("len", None, fmt="H", length_of="tls_data",
                                 adjust=lambda p, x: x + 10 if p.L == 1 else x + 6),
                   ByteEnumField("type", 33, eap_types),
                   BitField('L', 0, 1),
                   BitField('M', 0, 1),
                   BitField('S', 0, 1),
                   BitField('reserved', 0, 5),
                   ConditionalField(IntField('tls_message_len', 0), lambda pkt: pkt.L == 1),
                   StrLenField('tls_data', '', length_from=lambda pkt: pkt.len - 10 if pkt.L == 1 else pkt.len - 6)]


split_layers(PPP, ORIGINAL_EAP, proto=0xc227)
bind_layers( PPP, EAP, proto=0xc227)