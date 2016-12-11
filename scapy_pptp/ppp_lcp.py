from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, XByteField, LenField, StrLenField, FieldLenField,\
                         ShortField, BitField, ShortEnumField, ConditionalField, IntField,\
                         PacketListField, PacketField
from scapy.layers.ppp import _PPP_proto, PPP
from scapy_pptp.gre import GREPPTP
from scapy_pptp.eap_tls import EAP


_PPP_lcptypes = {1: "Configure-Request",
                 2: "Configure-Ack",
                 3: "Configure-Nak",
                 4: "Configure-Reject",
                 5: "Terminate-Request",
                 6: "Terminate-Ack",
                 7: "Code-Reject",
                 8: "Protocol-Reject",
                 9: "Echo-Request",
                10: "Echo-Reply",
                11: "Discard-Request"}

class PPP_LCP(Packet):
    name = "PPP Link Control Protocol"
    fields_desc = [ByteEnumField("code", None, _PPP_lcptypes),
                   XByteField("id", 0),
                   LenField("len", None),
                   StrLenField("data", None,
                               length_from=lambda p:p.len-4)]

    def extract_padding(self, pay):
        return "",pay

    @classmethod
    def dispatch_hook(cls, _pkt = None, *args, **kargs):
        if _pkt:
            o = ord(_pkt[0])
            if o in [1, 2, 3, 4]:
                return PPP_LCP_Configure
            elif o == 7:
                return PPP_LCP_Code_Reject
            elif o == 8:
                return PPP_LCP_Protocol_Reject
            elif o in [9, 10]:
                return PPP_LCP_Echo
            elif o == 11:
                return PPP_LCP_Discard_Request
            else:
                return cls
        return cls


_PPP_lcp_optiontypes = {1: "Maximum-Receive-Unit",
                        2: "Async-Control-Character-Map",
                        3: "Authentication-protocol",
                        4: "Quality-protocol",
                        5: "Magic-number",
                        7: "Protocol-Field-Compression",
                        8: "Address-and-Control-Field-Compression"}

class PPP_LCP_Option(Packet):
    name = "PPP LCP Option"
    fields_desc = [ByteEnumField("type", None, _PPP_lcp_optiontypes),
                   FieldLenField("len", None, fmt="B", length_of="data",
                                 adjust = lambda p,x:x+2),
                   StrLenField("data", None, length_from=lambda p:p.len-2)]

    def extract_padding(self, pay):
        return "", pay

    registered_options = {}

    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt = None, *args, **kargs):
        if _pkt:
            o = ord(_pkt[0])
            return cls.registered_options.get(o, cls)
        return cls

class PPP_LCP_MRU_Option(PPP_LCP_Option):
    fields_desc = [ByteEnumField("type", 1, _PPP_lcp_optiontypes),
                   FieldLenField("len", 4, fmt="B", adjust = lambda p,x:4),
                   ShortField("max_recv_unit", None)]

_PPP_LCP_auth_protocols = {0xc023: "Password authentication protocol",
                           0xc223: "Challenge-response authentication protocol",
                           0xc227: "PPP Extensible authentication protocol"}

_PPP_LCP_CHAP_algorithms = {5: "MD5",
                            6: "SHA1",
                            128: "MS-CHAP",
                            129: "MS-CHAP-v2"}


class PPP_LCP_ACCM_Option(PPP_LCP_Option):
    fields_desc = [ByteEnumField("type", 2, _PPP_lcp_optiontypes),
                   FieldLenField("len", 6, fmt="B"),
                   BitField("accm", 0x00000000, 32)]

def adjust_auth_len(pkt, x):
    if pkt.auth_protocol == 0xc223:
        return 5
    elif pkt.auth_protocol == 0xc023:
        return 4
    else:
        return x + 4


class PPP_LCP_Auth_Protocol_Option(PPP_LCP_Option):
    fields_desc = [ByteEnumField("type", 3, _PPP_lcp_optiontypes),
                   FieldLenField("len", None, fmt="B", length_of = "data",
                                 adjust=adjust_auth_len),
                   ShortEnumField("auth_protocol", 0xc023, _PPP_LCP_auth_protocols),
                   ConditionalField(StrLenField("data", '', length_from=lambda p:p.len-4),
                                    lambda p:p.auth_protocol != 0xc223 and p.len > 4),
                   ConditionalField(ByteEnumField("algorithm", 5, _PPP_LCP_CHAP_algorithms),
                                    lambda p:p.auth_protocol == 0xc223)]


_PPP_LCP_quality_protocols = {0xc025: "Link Quality Report"}

class PPP_LCP_Quality_Protocol_Option(PPP_LCP_Option):
    fields_desc = [ByteEnumField("type", 4, _PPP_lcp_optiontypes),
                   FieldLenField("len", None, fmt="B", length_of="data",
                                 adjust=lambda p,x:x+4),
                   ShortEnumField("quality_protocol", None, _PPP_LCP_quality_protocols),
                   StrLenField("data", None, length_from=lambda p:p.len-4)]

class PPP_LCP_Magic_Number_Option(PPP_LCP_Option):
    fields_desc = [ByteEnumField("type", 5, _PPP_lcp_optiontypes),
                   FieldLenField("len", 6, fmt="B", adjust = lambda p,x:6),
                   IntField("magic_number", None)]


class PPP_LCP_Configure(PPP_LCP):
    fields_desc = [ByteEnumField("code", 1, _PPP_lcptypes),
                   XByteField("id", 0),
                   FieldLenField("len", None, fmt="H", length_of="options",
                                 adjust=lambda p,x:x+4),
                   PacketListField("options", [], PPP_LCP_Option,
                                   length_from=lambda p:p.len-4)]

    def answers(self, other):
        if isinstance(other, PPP_LCP_Configure)\
           and self.code in [2, 3, 4]\
           and other.code == 1\
           and other.id == self.id:
            return 1;
        return 0

class PPP_LCP_Code_Reject(PPP_LCP):
    fields_desc = [ByteEnumField("code", 7, _PPP_lcptypes),
                   XByteField("id", 0),
                   FieldLenField("len", None, fmt="H", length_of="rejected_packet",
                                 adjust=lambda p,x:x+4),
                   PacketField("rejected_packet", None, PPP_LCP)]

class PPP_LCP_Protocol_Reject(PPP_LCP):
    fields_desc = [ByteEnumField("code", 8, _PPP_lcptypes),
                   XByteField("id", 0),
                   FieldLenField("len", None, fmt="H", length_of="rejected_information",
                                 adjust=lambda p,x:x+6),
                   ShortEnumField("rejected_protocol", None, _PPP_proto),
                   PacketField("rejected_information", None, Packet)]

class PPP_LCP_Echo(PPP_LCP):
     fields_desc = [ByteEnumField("code", 9, _PPP_lcptypes),
                    XByteField("id", 0),
                    FieldLenField("len", None, fmt="H", length_of="data",
                                 adjust=lambda p,x:x+8),
                    IntField("magic_number", None),
                    StrLenField("data", "", length_from=lambda p:p.len-8)]

class PPP_LCP_Discard_Request(PPP_LCP):
    fields_desc = [ByteEnumField("code", 9, _PPP_lcptypes),
                   XByteField("id", 0),
                   FieldLenField("len", None, fmt="H", length_of="data",
                                 adjust=lambda p,x:x+8),
                   IntField("magic_number", None),
                   StrLenField("data", None, length_from=lambda p:p.len-8)]


bind_layers( GREPPTP, PPP, proto=0x880b)
bind_layers( PPP, PPP_LCP, proto=0xc021)
bind_layers( PPP, EAP, proto=0xc227)
