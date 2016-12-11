from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import GRE, ETHER_TYPES
from scapy.fields import BitField, XShortEnumField, ShortField, ConditionalField, XIntField
import struct


class GREEnhanced(GRE):

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt and struct.unpack("!H", _pkt[2:4])[0] == 0x880b:
            return GREPPTP
        return cls


class GREPPTP(Packet):
    name = "GRE Enhanced"
    fields_desc = [BitField("chksum_present", 0, 1),
                   BitField("routing_present", 0, 1),
                   BitField("key_present", 1, 1),
                   BitField("seqnum_present", 0, 1),
                   BitField("strict_route_source", 0, 1),
                   BitField("recursion_control", 0, 3),
                   BitField("acknum_present", 0, 1),
                   BitField("flags", 0, 4),
                   BitField("version", 1, 3),
                   XShortEnumField("proto", 0x880b, ETHER_TYPES),
                   ShortField("payload_len", None),
                   ShortField("call_id", None),
                   ConditionalField(XIntField("seqence_number", None), lambda pkt:pkt.seqnum_present==1),
                   ConditionalField(XIntField("ack_number", None), lambda pkt:pkt.acknum_present==1)]


# This function is a nasty hack to swap guessed
# GRE class from scapy to custom GRE class supporting
# Enhanced GRE version used with PPTP
def swap_gre_hack():
    for i in xrange(len(IP.payload_guess)):
        if IP.payload_guess[i][1] == GRE:
            IP.payload_guess[i] = (IP.payload_guess[i][0], GREEnhanced)


#bind_layers(IP, GREEnhanced, frag=0, proto=47)
swap_gre_hack()
