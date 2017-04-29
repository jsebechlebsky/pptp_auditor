from scapy.layers.ppp import PPP_LCP_Configure, PPP_CHAP_ChallengeResponse
from scapy.automaton import ATMT
from .authmethods import AuthMethodSet
from .ppp import LCPAutomaton
from .logger import write_log_info
import copy


class CHAPAutomaton(LCPAutomaton):

    def __init__(self, *args, **kargs):
        LCPAutomaton.__init__(self, *args, **kargs)

    def parse_args(self, target, chap_method=None, lcp_auth_methods=AuthMethodSet(), **kargs):
        assert chap_method is not None
        LCPAutomaton.parse_args(self, target, **kargs)
        self.chap_method = chap_method
        self.authmethods = lcp_auth_methods

    def send_request(self):
        request = PPP_LCP_Configure(id=self.next_conf_request_id, options=[self.chap_method.get_lcp_option()])
        log_msg = 'Sending LCP Configure request, id {0}, requesting auth method {1}' \
            .format(request.id, self.chap_method)
        write_log_info(self.log_tag, log_msg)
        self.sent_requests[request.id] = self.send_lcp(request)
        self.next_conf_request_id += 1

    #def debug(self, lvl, msg):
    #    print msg

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
                if not self.chap_method.is_lcp_option(option):
                    naked_options.append(self.chap_method.get_lcp_option())
                    log_msg = 'Received LCP Configure request id {0} is requesting auth method {1}, will Nak with {2}' \
                    .format(req.id, self.authmethods.get_method_for_option(option), self.chap_method)
                    write_log_info(self.log_tag, log_msg)
            elif option.type == 5:  # Magic number
                new_conf.peer_magic_number = option.magic_number
                log_msg = 'Received LCP Configure request id {0} is requesting magic_number={1}' \
                    .format(req.id, option.magic_number)
                write_log_info(self.log_tag, log_msg)
            elif option.type == 7:  # Protocol field compression
                new_conf.protocol_compression = True
                log_msg = 'Received LCP Configure request id {0} is requesting protocol field compression' \
                    .format(req.id)
                write_log_info(self.log_tag, log_msg)
                pass  # TODO process protocol field compression
            elif option.type == 8:  # Address and control field compression
                new_conf.address_control_compression = True
                log_msg = 'Received LCP Configure request id {0} is requesting address and control field compression' \
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
            self.send_request()
        elif len(naked_options) > 0:
            log_msg = 'Sending Configure-Nak to request with id {0}'.format(req.id)
            write_log_info(self.log_tag, log_msg)
            lcp_nak = PPP_LCP_Configure(code=3, id=req.id, options=naked_options)
            self.send_lcp(lcp_nak)
            self.send_request()
        else:
            log_msg = 'Sending Configure-Ack to request with id {0}'.format(req.id)
            write_log_info(self.log_tag, log_msg)
            lcp_ack = PPP_LCP_Configure(code=2, id=req.id, options=req.options)
            self.send_lcp(lcp_ack)
            self.ppp_state = new_conf
            raise self.state_chap_negotiated()

    def process_configure_reject(self, pkt):
        pass

    def process_configure_nak(self, pkt):
        for option in pkt.options:
            if option.type == 3:
                # if aunthetication option was naked we have nothing to do
                raise self.state_end()

    def process_configure_ack(self, pkt):
        log_msg = 'Received Configure-Ack to request with id {0}'.format(pkt.id)
        write_log_info(self.log_tag, log_msg)
        chap_negotiated = False
        for option in pkt.options:
            if option.type == 2:  # Async Control Character Map
                pass
            elif option.type == 5:  # Magic number
                self.ppp_state.magic_number = option.magic_number
                log_msg = 'Setting magic number to {0}'.format(option.magic_number)
                write_log_info(self.log_tag, log_msg)
            elif option.type == 3:  # Authentication protocol
                log_msg = 'Server Ack-ed auth method {0} in response to request with id {1}' \
                    .format(self.authmethods.get_method_for_option(option), pkt.id)
                write_log_info(self.log_tag, log_msg)
                if self.chap_method.is_lcp_option(option):
                    chap_negotiated = True

        if chap_negotiated:
            raise self.state_chap_negotiated()

    @ATMT.state()
    def state_chap_negotiated(self):
        pass

    @ATMT.receive_condition(state_chap_negotiated)
    def chap_negotiated_receive(self, pkt):
        if PPP_LCP_Configure in pkt:
            self.process_configure_request(pkt)
        if PPP_CHAP_ChallengeResponse in pkt:
            self.chap_method.add_extra("Name", pkt[PPP_CHAP_ChallengeResponse].optional_name)
            raise self.state_end()

    @ATMT.timeout(state_chap_negotiated, timeout=1)
    def chap_negotiated_timeout(self):
        raise self.state_end()