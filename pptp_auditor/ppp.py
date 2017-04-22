from scapy.automaton import Automaton, ATMT
from scapy.layers.ppp import HDLC, PPP, PPP_LCP_ACCM_Option, PPP_LCP_MRU_Option, PPP_LCP_Magic_Number_Option,\
                             PPP_LCP_Configure, PPP_LCP_Echo
from scapy_pptp.gre import GREPPTPConnection
from authmethods import AuthMethodSet
from .logger import write_log_info, write_log_error, write_log_warning, write_log_debug
import random
import copy
from threading import Event

class PPPState:

    def __init__(self):
        self.protocol_compression = False
        self.address_control_compression = False
        self.auth_method = None
        self.magic_number = None
        self.peer_magic_number = None
        self.client_async_control_map = 0
        self.server_async_control_map = 0


class LCPAutomaton(Automaton):

    def __init__(self, target, call_id, peer_call_id,*args, **kargs):
        if kargs.has_key('from_automaton') and kargs.get('from_automaton') is not None:
            self.ss = kargs.get('from_automaton').ss
        else:
            self.ss = GREPPTPConnection.grelink(PPP, target, call_id, peer_call_id)
        Automaton.__init__(self, target, *args, ll=lambda *a, **ka: self.ss, recvsock=lambda *a, **ka: self.ss, **kargs)

    def parse_args(self, target, debug=0, store=1, from_automaton=None, **kargs):
        Automaton.parse_args(self, debug,store, **kargs)
        if from_automaton is None:
            self.sent_requests = {}
            self.next_conf_request_id = 0
            self.ppp_state = PPPState()
        else:
            self.sent_requests = from_automaton.sent_requests
            self.next_conf_request_id = from_automaton.next_conf_request_id
            self.ppp_state = from_automaton.ppp_state
        self.event_finished = Event()
        self.result = None
        self.log_tag = 'PPP-LCP'

    def set_call_id(self, call_id):
        self.ss.call_id = call_id

    def set_peer_call_id(self, peer_call_id):
        self.ss.peer_call_id = peer_call_id

    def send_ppp(self, pkt, proto):
        payload = PPP(proto=proto) / pkt if self.ppp_state.address_control_compression else \
            HDLC() / PPP(proto=proto) / pkt
        self.send(payload)
        return payload

    def send_lcp(self, pkt):
        return self.send_ppp(pkt, 0xc021)

    def send_eap(self, pkt):
        return self.send_ppp(pkt, 0xc227)

    @ATMT.state(initial=1)
    def state_begin(self):
        # Send request regarding accm and magic number
        accm_option = PPP_LCP_ACCM_Option()
        magic_number_option = PPP_LCP_Magic_Number_Option(magic_number=random.randint(0, (2 << 16) - 1))
        mru_option = PPP_LCP_MRU_Option(max_recv_unit=1000)
        lcp_conf_request = PPP_LCP_Configure(id=self.next_conf_request_id, options=[accm_option, magic_number_option, mru_option])
        log_msg = 'Sending LCP Configure request, id {0}, requesting ACCM={1}, magic_number={2}'\
                  .format(lcp_conf_request.id, accm_option.accm, magic_number_option.magic_number)
        write_log_info(self.log_tag, log_msg)
        self.sent_requests[self.next_conf_request_id] = self.send_lcp(lcp_conf_request)
        self.next_conf_request_id += 1
        raise self.state_negotiate()

    @ATMT.state()
    def state_negotiate(self):
        pass

    def respond_to_lcp_echo(self, pkt):
        assert(PPP_LCP_Echo in pkt)
        if pkt[PPP_LCP_Echo].code == 9:  # Echo request
            log_msg = 'Received LCP Echo request with id {0}, magic number {1}'\
                      .format(pkt[PPP_LCP_Echo].id, pkt[PPP_LCP_Echo].magic_number)
            write_log_info(self.log_tag, log_msg)
            lcp_echo_reply = PPP_LCP_Echo(id=pkt[PPP_LCP_Echo].id, code=10,
                                          magic_number=self.ppp_state.magic_number)
            log_msg = 'Sending LCP Echo reply with id {0}, magic number {1}'\
                      .format(pkt[PPP_LCP_Echo].id, self.ppp_state.magic_number)
            write_log_info(self.log_tag, log_msg)
            self.send_lcp(lcp_echo_reply)


    @ATMT.receive_condition(state_negotiate, prio=1)
    def negotiate_receive(self, pkt):
        if PPP_LCP_Configure in pkt:
            if pkt[PPP_LCP_Configure].code == 1:  # LCP Configure-Request
                self.process_configure_request(pkt[PPP_LCP_Configure])
            elif pkt[PPP_LCP_Configure].code == 2:  # LCP Configure-Ack
                self.process_configure_ack(pkt[PPP_LCP_Configure])
            elif pkt[PPP_LCP_Configure].code == 3:  # LCP Configure-Nak
                self.process_configure_nak(pkt[PPP_LCP_Configure])
            elif pkt[PPP_LCP_Configure].code == 4:  # LCP Configure-Reject
                self.process_configure_reject(pkt[PPP_LCP_Configure])
        elif PPP_LCP_Echo in pkt:
            self.respond_to_lcp_echo(pkt)

    def process_configure_request(self, pkt):
        raise NotImplementedError

    def process_configure_ack(self, pkt):
        raise NotImplementedError

    def process_configure_nak(self, pkt):
        raise NotImplementedError

    def process_configure_reject(self, pkt):
        raise NotImplementedError

    @ATMT.timeout(state_negotiate, timeout=0.5)
    def negotiate_timeout(self):
        pass

    def is_finished(self):
        return self.event_finished.isSet()

    def get_result(self):
        return self.result

    @ATMT.state(final=1)
    def state_end(self):
        #print 'Done'
        self.ss.atmt.stop()
        self.ss.close()
        self.event_finished.set()
        self.result = self.automaton_done()


class LCPEnumAuthMethodAutomaton(LCPAutomaton):

    def __init__(self, *args, **kargs):
        LCPAutomaton.__init__(self, *args, **kargs)

    def parse_args(self, target, lcp_auth_methods=AuthMethodSet(), debug=5, store=1, from_automaton=None, **kargs):
        LCPAutomaton.parse_args(self, target, debug, store, from_automaton, **kargs)
        self.authmethods = lcp_auth_methods

    def send_auth_request(self):
        suggested_method = self.authmethods.get_next_to_try()
        if suggested_method is None:
            raise self.state_end()
        suggested_option = suggested_method.get_lcp_option()
        request = PPP_LCP_Configure(id=self.next_conf_request_id, options=[suggested_option])
        log_msg = 'Sending LCP Configure request, id {0}, requesting auth method {1}'\
                  .format(request.id, suggested_method)
        write_log_info(self.log_tag, log_msg)
        self.sent_requests[request.id] = self.send_lcp(request)
        self.next_conf_request_id += 1

    def process_configure_request(self, req):
        rejected_options = []
        naked_options = []
        new_conf = copy.deepcopy(self.ppp_state)
        log_msg = 'Received LCP Configure request from server, id {0}'.format(req.id)
        write_log_info(self.log_tag, log_msg)
        for option in req.options:
            if option.type == 1:  # MRU
                pass  # TODO process MRU setting
            elif option.type == 2:  # Async Control Character Map
                pass  # TODO process Async control character map
            elif option.type == 3:  # Authentication protocol
                self.authmethods.enable_method_from_option(option)
                suggested_method = self.authmethods.get_next_to_try()
                if suggested_method is None:
                    self.send_gre_ack()
                    raise self.state_end()
                suggested_option = suggested_method.get_lcp_option()
                log_msg = 'Received LCP Configure request id {0} is requesting auth method {1}, will Nak with {2}'\
                          .format(req.id, self.authmethods.get_method_for_option(option), suggested_method)
                write_log_info(self.log_tag, log_msg)
                naked_options.append(suggested_option)
            elif option.type == 5:  # Magic number
                new_conf.peer_magic_number = option.magic_number
                log_msg = 'Received LCP Configure request id {0} is requesting magic_number={1}'\
                          .format(req.id, option.magic_number)
                write_log_info(self.log_tag, log_msg)
            elif option.type == 7:  # Protocol field compression
                new_conf.protocol_compression = True
                log_msg = 'Received LCP Configure request id {0} is requesting protocol field compression'\
                          .format(req.id)
                write_log_info(self.log_tag, log_msg)
                pass  # TODO process protocol field compression
            elif option.type == 8:  # Address and control field compression
                new_conf.address_control_compression = True
                log_msg = 'Received LCP Configure request id {0} is requesting address and control field compression'\
                          .format(req.id)
                write_log_info(self.log_tag, log_msg)
                pass  # TODO process address and control field compression
            else:
                rejected_options.append(option)

        if len(rejected_options) > 0:
            log_msg = 'Sending Configure-Reject to request with id {0}'.format(req.id)
            write_log_info(self.log_tag, log_msg)
            lcp_reject = PPP_LCP_Configure(code=4, id=req.id, options=rejected_options)
            self.send_lcp(lcp_reject)
        elif len(naked_options) > 0:
            log_msg = 'Sending Configure-Nak to request with id {0}'.format(req.id)
            write_log_info(self.log_tag, log_msg)
            lcp_nak = PPP_LCP_Configure(code=3, id=req.id, options=naked_options)
            self.send_lcp(lcp_nak)
        else:
            log_msg = 'Sending Configure-Ack to request with id {0}'.format(req.id)
            write_log_info(self.log_tag, log_msg)
            lcp_ack = PPP_LCP_Configure(code=2, id=req.id, options=req.options)
            self.send_lcp(lcp_ack)
            self.ppp_state = new_conf
        self.send_auth_request()

    def process_configure_ack(self, resp):
        log_msg = 'Received Configure-Ack to request with id {0}'.format(resp.id)
        write_log_info(self.log_tag, log_msg)
        for option in resp.options:
            if option.type == 2:  # Async Control Character Map
                pass
            elif option.type == 5:  # Magic number
                self.ppp_state.magic_number = option.magic_number
                log_msg = 'Setting magic number to {0}'.format(option.magic_number)
                write_log_info(self.log_tag, log_msg)
            elif option.type == 3:  # Authentication protocol
                log_msg = 'Server Ack-ed auth method {0} in response to request with id {1}'\
                          .format(self.authmethods.get_method_for_option(option), resp.id)
                write_log_info(self.log_tag, log_msg)
                self.authmethods.enable_method_from_option(option)
                self.send_auth_request()

    @classmethod
    def get_auth_option_from_lcp_conf_req(cls, pkt):
        lcp_conf_req = pkt[PPP_LCP_Configure]
        for option in lcp_conf_req.options:
            if option.type == 3:
                return option
        return None

    def process_configure_nak(self, resp):
        log_msg = 'Received Configure-Nak to request with id {0}'.format(resp.id)
        write_log_info(self.log_tag, log_msg)
        for option in resp.options:
            if option.type == 3:
                self.authmethods.enable_method_from_option(option)
                requested_option = self.get_auth_option_from_lcp_conf_req(self.sent_requests[resp.id])
                self.authmethods.disable_method_from_option(requested_option)
                log_msg = 'Server Nak-ed auth method {0} in response to request with id {1} and suggested {2}'\
                          .format(self.authmethods.get_method_for_option(requested_option), resp.id,
                                  self.authmethods.get_method_for_option(option))
                write_log_info(self.log_tag, log_msg)
        self.send_auth_request()

    def process_configure_reject(self, resp):
        log_msg = 'Received Configure-Rejet to request with id {0}'.format(resp.id)
        write_log_info(self.log_tag, log_msg)
        for option in resp.options:
            if option.type == 3:
                self.authmethods.disable_method_from_option(option)
                log_msg = 'Server rejected auth method {0} in response to request with id {1}'\
                          .format(self.authmethods.get_method_for_option(option), resp.id)
                write_log_info(self.log_tag, log_msg)

    def automaton_done(self):
        return self.authmethods

