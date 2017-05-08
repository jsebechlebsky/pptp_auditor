from scapy.layers.inet import IP
from scapy.layers.l2 import GRE_PPTP
from scapy.automaton import Automaton, ATMT
from scapy.packet import NoPayload
from scapy.config import conf


class GREPPTPConnection(Automaton):

    def __init__(self, *args, **kargs):
        self.last_seq_received = None
        Automaton.__init__(self, *args, **kargs)

    def parse_args(self, peer_ip, call_id, peer_call_id, debug=0, store=1, **kargs):
        Automaton.parse_args(self,debug=5,store=1,**kargs)
        self.peer_ip = peer_ip
        self.call_id = call_id
        self.peer_call_id = peer_call_id
        self.gre_layer = IP(dst=peer_ip) / GRE_PPTP(call_id=call_id,seqence_number=0)

    def master_filter(self, pkt):
        return (IP in pkt and
                pkt[IP].src == self.peer_ip and
                GRE_PPTP in pkt and
                pkt[GRE_PPTP].call_id == self.peer_call_id and
                pkt[GRE_PPTP].seqnum_present == 1 and
                (pkt[GRE_PPTP].seqence_number > self.last_seq_received or self.last_seq_received is None))

    @ATMT.state(initial=1)
    def START(self):
        pass

    @ATMT.state()
    def ESTABLISHED(self):
        pass

    @ATMT.state(final=1)
    def END(self):
        pass

    @ATMT.condition(START)
    def initialize(self):
        raise self.ESTABLISHED()

    @ATMT.receive_condition(ESTABLISHED)
    def receive_incoming_data(self, pkt):
        if not (isinstance(pkt[GRE_PPTP].payload, NoPayload) or isinstance(pkt[GRE_PPTP], conf.padding_layer)):
            raise self.ESTABLISHED().action_parameters(pkt)

    @ATMT.action(receive_incoming_data)
    def receive_data(self, pkt):
        #print 'Received:'
        #pkt.show()
        self.last_seq_received = pkt[GRE_PPTP].seqence_number
        self.oi.gre.send(str(pkt[GRE_PPTP].payload))

    @ATMT.ioevent(ESTABLISHED, name='gre', as_supersocket='grelink')
    def outgoing_data_received(self, fd):
        #print 'io event'
        raise self.ESTABLISHED().action_parameters(fd.recv())

    @ATMT.action(outgoing_data_received)
    def send_data(self, pkt):
        self.gre_layer[GRE_PPTP].seqnum_present = 1
        self.gre_layer[GRE_PPTP].call_id = self.call_id
        if self.last_seq_received is None:
            self.gre_layer[GRE_PPTP].ack_number = None
            self.gre_layer[GRE_PPTP].acknum_present = 0
        else:
            self.gre_layer[GRE_PPTP].acknum_present = 1
            self.gre_layer[GRE_PPTP].ack_number = self.last_seq_received
        self.send(self.gre_layer / pkt)
        pkt = self.gre_layer / pkt
        #print 'sent:'
        #pkt.show2()
        self.gre_layer[GRE_PPTP].seqence_number += 1

    @ATMT.timeout(ESTABLISHED,timeout=2.0)
    def established_timeout(self):
        raise self.ESTABLISHED()

    @ATMT.action(established_timeout)
    def send_ack(self):
        if self.last_seq_received is not None:
            self.gre_layer[GRE_PPTP].call_id = self.call_id
            self.gre_layer[GRE_PPTP].seqnum_present = 0
            self.gre_layer[GRE_PPTP].ack_number = self.last_seq_received
            self.gre_layer[GRE_PPTP].acknum_present = 1
            self.send(self.gre_layer)


