from scapy.automaton import Automaton, ATMT
from scapy.supersocket import StreamSocket
from scapy.layers.pptp import *
from ppp import LCPEnumAuthMethodAutomaton, EAPNegotiateAutomaton
from .logger import write_log_info, write_log_debug, write_log_error, write_log_warning
from .authmethods import EAP
import socket
import sys
import string


def filter_printable(s):
    return filter(lambda x: x in set(string.printable), s)


class PPTPInfo:

    def __init__(self):
        self.protocol_version = None
        self.maximum_channels = None
        self.firmware_revision = None
        self.host_name = None
        self.vendor_string = None
        self.ppp_info = None

    @classmethod
    def _unknown_if_none(cls, obj):
        return obj if obj is not None else 'Unknown'

    def get_protocol_version_str(self):
        if self.protocol_version is None:
            return 'Unknown'
        else:
            return '{0}.{1}'.format(self.protocol_version >> 8, self.protocol_version & 0xff)

    def get_maximum_channels(self):
        return self._unknown_if_none(self.maximum_channels)

    def get_firmware_revision(self):
        return self._unknown_if_none(self.firmware_revision)

    def get_host_name(self):
        return filter_printable(self.host_name) if self.host_name is not None else 'Unknown'

    def get_vendor_string(self):
        return filter_printable(self.vendor_string) if self.vendor_string is not None else 'Unknown'

    def __str__(self):
        return 'protol_version={0}, maximum_channels={1}, firmware_revision={2}, host_name=\'{3}\', vendor_string=\'{4}\''\
               .format(self.protocol_version, self.maximum_channels, self.firmware_revision,
                       filter_printable(self.host_name), filter_printable(self.vendor_string))


def set_pptp_info_from_scc_reply(pptp_info, pkt_reply):
    assert(isinstance(pptp_info, PPTPInfo))
    assert(isinstance(pkt_reply, PPTPStartControlConnectionReply))

    pptp_info.protocol_version = pkt_reply.protocol_version
    pptp_info.maximum_channels = pkt_reply.maximum_channels
    pptp_info.firmware_revision = pkt_reply.firmware_revision
    pptp_info.host_name = pkt_reply.host_name
    pptp_info.vendor_string = pkt_reply.vendor_string


class PPTPCallInfo:

    def __init__(self):
        self.call_id = None
        self.peer_call_id = None

    def __str__(self):
        return 'call_id={0}, peer_call_id={1}'.format(self.call_id, self.peer_call_id)


def set_pptp_call_info_from_call_reply(call_info, pkt_reply):
    assert(isinstance(call_info, PPTPCallInfo))
    assert(isinstance(pkt_reply, PPTPOutgoingCallReply))

    call_info.call_id = pkt_reply.call_id
    call_info.peer_call_id = pkt_reply.peer_call_id


class PPTPAutomaton(Automaton):

    def __init__(self, *args, **kargs):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ss = StreamSocket(s)
        self.ppp_automaton = None
        Automaton.__init__(self, *args, ll=lambda: ss, recvsock=lambda: ss,  **kargs)

    def parse_args(self, target_ip, ppp_automaton, port=1723, send_call_clear=False, **kargs):
        Automaton.parse_args(self, **kargs)
        self.target_ip = target_ip
        self.port = port
        self.pptp_info = None
        self.call_info = PPTPCallInfo()
        self.ppp_automaton = ppp_automaton
        self._send_call_clear = False
        self.log_tag = 'ControlConnection'

    @ATMT.state(initial=1)
    def state_connect(self):

        assert(self.ppp_automaton is not None)
        # Connect socket to target server
        print 'Connecting to {0}:{1} ...'.format(self.target_ip, self.port),
        try:
            write_log_info(self.log_tag,
                           'Establishing TCP connection to {0}:{1}'.format(self.target_ip, self.port))
            self.send_sock.ins.settimeout(2.0)
            self.send_sock.ins.connect((self.target_ip, self.port))
        except socket.error as sock_error:
            print 'Failed'
            err_msg = 'Unable to connect to {0}:{1}: {2}'.format(self.target_ip, self.port, sock_error)
            write_log_error('ControlConnection', err_msg)
            print >> sys.stderr, err_msg
            raise self.end()
        print 'Connected'
        self.pptp_info = PPTPInfo()

        # Send PPTP Start-Control-Connection-Request
        write_log_info(self.log_tag, 'Sending StartControlConnection message to server')
        pkt = PPTPStartControlConnectionRequest(host_name='test', vendor_string='test')
        self.send(pkt)
        raise self.state_start_control_connection_wait()

    @ATMT.state()
    def state_start_control_connection_wait(self):
        # Wait for PPTP Start-Control-Connection-Reply
        pass

    @ATMT.receive_condition(state_start_control_connection_wait, prio=1)
    def start_control_connection_receive(self, pkt):
        pkt_pptp = PPTP(str(pkt))
        if PPTPStartControlConnectionReply in pkt_pptp:
            if pkt_pptp.result_code == 1:  # OK
                log_msg = 'Received StartControlConnectionReply - OK'
                write_log_info(self.log_tag, log_msg)

                set_pptp_info_from_scc_reply(self.pptp_info, pkt_pptp)
                write_log_info(self.log_tag, self.pptp_info)
                raise self.state_start_call()
            else:
                err_msg = 'Received StartControlConnectionReply - Fail, result_code = {0}, error_code = {1}'\
                                     .format(pkt_pptp.result_code, pkt_pptp.error_code)
                print >> sys.stderr, err_msg
                write_log_error(self.log_tag, err_msg)
                raise self.state_stop_control_connection()
        else:
            err_msg = sys.stderr, 'Unexpected reply received to Start-Control-Connection request: {0}'\
                                 .format(pkt_pptp.summary())
            print >> sys.stderr, err_msg
            write_log_error(self.log_tag, err_msg)
            raise self.end()

    @ATMT.timeout(state_start_control_connection_wait, timeout=2)
    def start_control_connection_timeout(self):
        err_msg = sys.stderr, 'Server did not respond to Start-Control-Connection in time'
        print >> sys.stderr, err_msg
        write_log_error(err_msg)
        raise self.end()


    @ATMT.state()
    def state_start_call(self):
        write_log_info(self.log_tag, 'Sending OutgoingCallRequest message to server')
        self.send(PPTPOutgoingCallRequest())
        raise self.state_start_call_wait()

    @ATMT.state()
    def state_start_call_wait(self):
        pass

    @ATMT.receive_condition(state_start_call_wait, prio=1)
    def start_call_receive(self, pkt):
        pkt_pptp = PPTP(str(pkt))
        if PPTPOutgoingCallReply in pkt_pptp:
            if pkt_pptp.result_code == 1:  # OK
                write_log_info(self.log_tag, 'Received OutgoingCallReply - OK')
                set_pptp_call_info_from_call_reply(self.call_info, pkt_pptp)
                write_log_info(self.log_tag, self.call_info)
                raise self.state_call_established()
            else:
                err_msg = 'Received OutgoingCallReply - Fail, result code = {0}, error_code = {1}, cause_code = {2}'\
                          .format(pkt_pptp.result_code, pkt_pptp.error_code, pkt_pptp.cause_code)
                print >> sys.stderr, err_msg
                write_log_error(self.log_tag, err_msg)
                raise self.state_stop_control_connection()
        else:
            err_msg = 'Unexpected reply received to Outgoing-Call request: {0}'\
                                 .format(pkt_pptp.summary())
            print >> sys.stderr, err_msg
            write_log_error(self.log_tag, err_msg)
            raise self.state_stop_control_connection()

    @ATMT.timeout(state_start_call_wait, timeout=2)
    def start_call_timeout(self):
        err_msg = 'Server did not respond to Outgoing-Call-Request in time'
        print >> sys.stderr, err_msg
        write_log_error(self.log_tag, err_msg)
        raise self.state_stop_control_connection()

    @ATMT.state()
    def state_call_established(self):
        #self.ppp_automaton = self.ppp_automaton_class(self.target_ip, self.call_info.call_id,
        #                                              arg=self.ppp_automaton_arg)
        self.ppp_automaton.set_call_id(self.call_info.call_id)
        ppp_info = self.ppp_automaton.run()  # TODO this should be running on background
        self.pptp_info.ppp_info = ppp_info

        raise self.state_call_clear()

    @ATMT.receive_condition(state_call_established, prio=1)
    def call_established_receive(self, pkt):
        pkt_pptp = PPTP(str(pkt))
        if PPTPEchoRequest in pkt_pptp:
            reply = PPTPEchoReply(identifier=pkt_pptp.identifier)
            self.send(reply)

    @ATMT.state()
    def state_call_clear(self):
        if self._send_call_clear:
            log_msg = 'Sending CallClearRequest to server'
            write_log_info(self.log_tag, log_msg)
            self.send(PPTPCallClearRequest(call_id=self.call_info.call_id))
            raise self.state_call_clear_wait()
        else:
            raise self.state_stop_control_connection()

    @ATMT.state()
    def state_call_clear_wait(self):
        pass

    @ATMT.receive_condition(state_call_clear_wait, prio=1)
    def call_clear_receive(self, pkt):
        pkt_pptp = PPTP(str(pkt))
        if PPTPCallDisconnectNotify in pkt_pptp:
            log_msg = 'Received CallDisconnectNotify'
            write_log_info(self.log_tag, log_msg)
        else:
            err_msg = 'Unexpected reply received to Call-Clear request: {0}'\
                      .format(pkt_pptp.summary())
            write_log_error(self.log_tag, err_msg)
            print >> sys.stderr, err_msg
        raise self.state_stop_control_connection()

    @ATMT.timeout(state_call_clear, timeout=2)
    def call_clear_timeout(self):
        err_msg = 'Server did not respond to Call-Clear request in time'
        print >> sys.stderr, err_msg
        write_log_error(self.log_tag, err_msg)
        raise self.state_stop_control_connection()

    @ATMT.state()
    def state_stop_control_connection(self):
        log_msg = 'Sending StopControlConnectionRequest to server'
        write_log_info(self.log_tag, log_msg)
        self.send(PPTPStopControlConnectionRequest())
        raise self.state_stop_control_connection_wait()

    @ATMT.state()
    def state_stop_control_connection_wait(self):
        pass

    @ATMT.receive_condition(state_stop_control_connection_wait, prio=1)
    def stop_control_connection_receive(self, pkt):
        pptp_pkt = PPTP(str(pkt))
        if PPTPStopControlConnectionReply in pptp_pkt:
            log_msg = 'Received StopControlConnectionReply'
            write_log_info(self.log_tag, log_msg)
        else:
            err_msg = 'Unexpected reply to Stop-Control-Connection request: {0}'\
                                 .format(pptp_pkt.summary())
            print >> sys.stderr, err_msg
        raise self.end()

    @ATMT.timeout(state_stop_control_connection_wait, timeout=2)
    def stop_control_connection_timeout(self):
        err_msg = 'Server did not respond to Stop-Control-Connection in time'
        print >> sys.stderr, err_msg
        write_log_error(self.log_tag, err_msg)
        raise self.end()

    @ATMT.state(final=1)
    def end(self):
        return self.pptp_info

    def get_ppp_automaton(self):
        return self.ppp_automaton