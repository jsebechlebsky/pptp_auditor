from scapy.automaton import Automaton, ATMT
from scapy.layers.inet import IP
from scapy.layers.ppp import HDLC
from scapy_pptp.eap_tls import EAP, EAP_TLS
from scapy_ssl_tls.ssl_tls import TLSHandshake, TLSClientHello, TLSRecord, TLS, TLSCertificateList, TLSServerHello
from scapy_pptp.ppp_lcp import *
from authmethods import AuthMethodSet, EAPAuthMethodSet
from .logger import write_log_info, write_log_error, write_log_warning, write_log_debug
import random
import copy
import base64
import sys


class PPPState:

    def __init__(self):
        self.protocol_compression = False
        self.address_control_compression = False
        self.auth_method = None
        self.magic_number = None
        self.client_async_control_map = 0
        self.server_async_control_map = 0


class LCPAutomaton(Automaton):

    def parse_args(self, target, debug=0, store=1, from_automaton=None, **kargs):
        Automaton.parse_args(self, debug, store, **kargs)
        if from_automaton is None:
            self.target = target
            self.call_id = None
            self.ip = IP(dst=target, proto='gre')
            self.gre_seq = 0
            self.gre_ack = None
            self.sent_requests = {}
            self.next_conf_request_id = 0
            self.ppp_state = PPPState()
        else:
            self.target = from_automaton.target
            self.call_id= from_automaton.call_id
            self.ip = from_automaton.ip
            self.gre_seq = from_automaton.gre_seq
            self.gre_ack = from_automaton.gre_ack
            self.sent_requests = from_automaton.sent_requests
            self.next_conf_request_id = from_automaton.next_conf_request_id
            self.ppp_state = from_automaton.ppp_state
        self.log_tag = 'PPP-LCP'


    def master_filter(self, pkt):
        #if IP in pkt and pkt[IP].src == self.target and GREPPTP in pkt:
        #    pkt.show2()
        return IP in pkt and pkt[IP].src == self.target and GREPPTP in pkt

    def set_call_id(self, call_id):
        self.call_id = call_id

    def send_ppp(self, pkt, proto):
        payload = PPP(proto=proto) / pkt if self.ppp_state.address_control_compression else \
            HDLC() / PPP(proto=proto) / pkt
        gre = GREPPTP(seqnum_present=1,
                       acknum_present=1 if self.gre_ack is not None else 0,
                       seqence_number=self.gre_seq,
                       ack_number=self.gre_ack,
                       call_id=self.call_id,
                       payload_len=len(str(payload)))
        pkt_to_send = self.ip / gre / payload
        #pkt_to_send.show2()
        self.send(pkt_to_send)
        self.gre_seq += 1
        return pkt_to_send

    def send_lcp(self, pkt):
        return self.send_ppp(pkt, 0xc021)

    def send_eap(self, pkt):
        return self.send_ppp(pkt, 0xc227)

    def send_gre_ack(self):
        if self.gre_ack is not None:
            gre_ack = GREPPTP(seqnum_present=0,
                               acknum_present=1,
                               ack_number=self.gre_ack,
                               call_id=self.call_id,
                               payload_len=0)
            #gre_ack.show2()
            pkt_to_send = self.ip / gre_ack
            self.send(pkt_to_send)
            return pkt_to_send

    def register_gre_reception(self, pkt):
        if GREPPTP in pkt:
            if pkt[GREPPTP].seqnum_present:
                self.gre_ack = max(pkt[GREPPTP].seqence_number, self.gre_ack) if self.gre_ack is not None else\
                               pkt[GREPPTP].seqence_number
            if pkt[GREPPTP].acknum_present:
                #TODO acknowledge reception
                pass

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
        #raise self.state_end()

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
        elif pkt[PPP_LCP_Echo].code == 10:  # Echo reply
            self.send_gre_ack(pkt)


    @ATMT.receive_condition(state_negotiate, prio=1)
    def negotiate_receive(self, pkt):
        self.register_gre_reception(pkt)
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
        else:
            self.send_gre_ack()

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

    @ATMT.state(final=1)
    def state_end(self):
        #print 'Done'
        self.automaton_done()
        pass


class LCPEnumAuthMethodAutomaton(LCPAutomaton):

    def parse_args(self, target, lcp_auth_methods=AuthMethodSet(), debug=5, store=1, from_automaton=None, **kargs):
        LCPAutomaton.parse_args(self, target, debug, store, from_automaton, **kargs)
        self.authmethods = lcp_auth_methods

    def send_auth_request(self):
        suggested_method = self.authmethods.get_next_to_try()
        if suggested_method is None:
            raise self.state_end()
        #print 'Requesting ', suggested_method
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
                new_conf.magic_number = option.magic_number
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
        self.send_gre_ack()

    def automaton_done(self):
        return self.authmethods

    @ATMT.state(final=1)
    def state_end(self):
        return self.automaton_done()


class EAPNegotiateAutomaton(LCPAutomaton):

    def parse_args(self, target, cert_file=None, eap_auth_methods=None,
                   identity='user', debug=0, store=1, **kargs):
        LCPAutomaton.parse_args(self, target, debug, store, **kargs)
        self.lcp_authmethods = AuthMethodSet()
        self.eap_log_tag = 'EAP'
        self.eap_tls_log_tag = 'EAP-TLS'
        self.eap_authmethods = EAPAuthMethodSet() if eap_auth_methods is None else eap_auth_methods
        self.eap_last_requested_method = None
        self.identity = identity
        self.cert_file = cert_file
        self.eap_tls_data = None

    def request_eap(self):
        eap_option = PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc227)
        lcp_conf_req = PPP_LCP_Configure(id=self.next_conf_request_id, options=[eap_option])
        self.next_conf_request_id += 1
        self.sent_requests[lcp_conf_req.id] = lcp_conf_req
        log_msg = 'Sending LCP Configure request id {0}, requesting EAP'.format(lcp_conf_req.id)
        write_log_info(self.log_tag, log_msg)
        self.send_lcp(lcp_conf_req)

    def process_configure_request(self, req):
        rejected_options = []
        naked_options = []
        new_conf = copy.deepcopy(self.ppp_state)
        log_msg = 'Received LCP Configure request from server, id {0}'.format(req.id)
        write_log_info(self.log_tag, log_msg)
        eap_negotiated = False
        for option in req.options:
            if option.type == 1:  # MRU
                pass  # TODO process MRU setting
            elif option.type == 2:  # Async Control Character Map
                pass  # TODO process Async control character map
            elif option.type == 3:  # Authentication protocol
                #TODO check for EAP, request EAP
                if option.auth_protocol == 0xc227: #EAP
                    eap_negotiated = True
                    log_msg = 'Received LCP Configure request id {0} is requesting auth protocol EAP'\
                              .format(req.id)
                    write_log_info(self.log_tag, log_msg)
                else:
                    naked_options.append(PPP_LCP_Auth_Protocol_Option(auth_protocol=0x227))
                    log_msg = 'Received LCP Configure request id {0} is requesting auth protocol {0}'\
                              .format(req.id, self.lcp_authmethods.get_method_for_option(option))
                    write_log_info(self.log_tag, log_msg)
            elif option.type == 5:  # Magic number
                new_conf.magic_number = option.magic_number
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
            self.request_eap()
        elif len(naked_options) > 0:
            log_msg = 'Sending Configure-Nak to request with id {0}'.format(req.id)
            write_log_info(self.log_tag, log_msg)
            lcp_nak = PPP_LCP_Configure(code=3, id=req.id, options=naked_options)
            self.send_lcp(lcp_nak)
            self.request_eap()
        else:
            log_msg = 'Sending Configure-Ack to request with id {0}'.format(req.id)
            write_log_info(self.log_tag, log_msg)
            lcp_ack = PPP_LCP_Configure(code=2, id=req.id, options=req.options)
            self.send_lcp(lcp_ack)
            self.ppp_state = new_conf
            if eap_negotiated:
                raise self.state_eap_negotiated()

    def process_configure_ack(self, resp):
        acked_eap = False
        for option in resp.options:
            if option.type == 1:
                # TODO
                pass
            elif option.type == 2:
                # TODO
                pass
            elif option.type == 3: # Auth option
                acked_eap = True
                log_msg = 'Server Ack-ed EAP auth method from request {0}'\
                          .format(resp.id)
                write_log_info(self.log_tag, log_msg)
        self.send_gre_ack()
        if acked_eap:
            raise self.state_eap_negotiated()

    def process_configure_nak(self, resp):
        naked_eap_auth = False
        for option in resp.options:
            if option.type == 3:
                log_msg = 'Server Nak-ed auth method {0} from request id {1}, suggesting {2}'\
                          .format('EAP', resp.id, self.lcp_authmethods.get_method_for_option(option))
                write_log_info(self.log_tag, log_msg)
                naked_eap_auth = True
            else:
                log_msg = 'Server Nak-ed LCP option type {0}, in request id {1}'\
                          .format(option.type, resp.id)
                write_log_info(self.log_tag, log_msg)
        self.send_gre_ack()
        if naked_eap_auth:
            raise self.state_end()

    def process_configure_reject(self, resp):
        rejected_eap_auth = False
        for option in resp.options:
            if option.type == 3:
                rejected_method = self.lcp_authmethods.get_method_for_option(option)
                log_msg = 'Server rejected auth method {0} from request id {1}'\
                          .format(rejected_method, resp.id)
                write_log_info(self.log_tag, log_msg)
                rejected_eap_auth = True
            else:
                log_msg = 'Server rejected LCP option type {0}, in request id {1}'\
                          .format(option.type, resp.id)
                write_log_info(self.log_tag, log_msg)
        self.send_gre_ack()
        if rejected_eap_auth:
            raise self.state_end()

    @ATMT.state()
    def state_eap_negotiated(self):
        pass

    def eap_process_request(self, pkt):
        if EAP in pkt:
            requested_method = self.eap_authmethods.get_eap_method_for_method_type(pkt[EAP].type)
        elif EAP_TLS in pkt:
            requested_method = self.eap_authmethods.get_eap_method_for_method_type(pkt[EAP_TLS].type)
        else:
            requested_method = None
        if requested_method:
            requested_method.set_enabled()
        else:
            # TODO Warning about uknown EAP type
            pass
        log_msg = 'Received {0} request id {1}'.format(requested_method if requested_method is not None else 'Unknown',
                                                       pkt[EAP].id if EAP in pkt else pkt[EAP_TLS].id)
        write_log_info(self.eap_log_tag, log_msg)
        suggested_method = self.eap_authmethods.get_next_to_try()
        self.eap_last_requested_method = suggested_method
        if suggested_method is None:
            raise self.state_end()
        log_msg = 'Sending Legacy-Nak to EAP-TLS request id {0}, suggesting {1}' \
                  .format(pkt[EAP].id if EAP in pkt else pkt[EAP_TLS].id, suggested_method)
        eap_nak = suggested_method.get_eap_nak_response(pkt[EAP].id if EAP in pkt else pkt[EAP_TLS].id)
        write_log_info(self.eap_log_tag, log_msg)
        self.send_eap(eap_nak)

    def eap_handle_tls_request(self, pkt):
        log_msg = 'Received EAP-TLS request id {0}'.format(pkt[EAP_TLS].id)
        write_log_info(self.eap_tls_log_tag, log_msg)

        tls_client_hello = TLSRecord() / TLSHandshake() / TLSClientHello(compression_methods=range(0xff)[::-1],
                                                                         cipher_suites=range(0xff))
        eap_tls_client_hello = EAP_TLS(code=2, id=pkt[EAP_TLS].id, L=1,
                                       tls_message_len=len(tls_client_hello), tls_data=str(tls_client_hello))
        self.send_eap(eap_tls_client_hello)
        log_msg = 'Sending TLS ClientHello message in EAP response id {0}'.format(pkt[EAP_TLS].id)
        write_log_info(self.eap_tls_log_tag, log_msg)
        raise self.state_receive_eap_tls_server_hello()

    @ATMT.receive_condition(state_eap_negotiated, prio=1)
    def eap_negotiated_receive(self, pkt):
        self.register_gre_reception(pkt)

        if PPP_LCP_Configure in pkt:
            pass # TODO handle this
        elif PPP_LCP_Echo in pkt:
            self.respond_to_lcp_echo(pkt)
        elif EAP_TLS in pkt:
            eap_method = self.eap_authmethods.get_eap_method_for_method_type(13)
            if eap_method.is_state_known():
                self.eap_process_request(pkt)
            else:
                eap_method.set_enabled()
                #pkt.show2()
                self.eap_handle_tls_request(pkt)
        elif EAP in pkt:
            #pkt.show2()
            if pkt[EAP].type == 1:  # Indetity
                if pkt[EAP].code == 1:  # Request
                    log_msg = 'Received EAP-Identity request id {0}, identity \'{1}\''\
                              .format(pkt[EAP].id, pkt[EAP].identity)
                    write_log_info(self.eap_log_tag, log_msg)
                    eap_identity_response = EAP(code=2, id=pkt[EAP].id, type='Identity', identity=self.identity)
                    log_msg = 'Sending EAP-Identity response id {0}, identity \'{1}\''\
                              .format(pkt[EAP].id, self.identity)
                    write_log_info(self.eap_log_tag, log_msg)
                    self.send_eap(eap_identity_response)
                elif pkt[EAP].code == 2:  # Reply
                    pass  # TODO respond to identity response
                else:
                    pass  # TODO Warn
            elif pkt[EAP].type == 3:  # Legacy-Nak
                pass  # TODO handle this
            elif pkt[EAP].type >= 4:
                self.eap_process_request(pkt)
            else:
                # TODO this is weird
                raise self.state_end()

    @ATMT.timeout(state_eap_negotiated, timeout=1)
    def eap_negotiated_timeout(self):
        if self.eap_last_requested_method is not None:
            self.eap_last_requested_method.set_disabled()
        eap_failure = EAP(code='Failure')
        self.send_eap(eap_failure)
        # TODO we might want to wait for LCP Terminate messages ...
        raise self.state_end()

    @ATMT.state()
    def state_receive_eap_tls_server_hello(self):
        pass

    def dump_certificates(self, pkt):
        assert (TLSCertificateList in pkt)
        if self.cert_file is not None:
            certificates = []
            for cert in pkt[TLSCertificateList].certificates:
                certificates.append(cert.data)
            try:
                with open(self.cert_file, 'w') as f:
                    for certificate in certificates:
                        f.write(der2pem(str(certificate)))
            except IOError as e:
                err_msg = 'Error writing server certificate to {0}'.format(self.cert_file)
                print >> sys.stderr, err_msg
                write_log_error('pptp_auditor', err_msg)
                raise self.state_end()

    @ATMT.receive_condition(state=state_receive_eap_tls_server_hello, prio=1)
    def receive_eap_tls_server_hello_receive(self, pkt):
        if PPP_LCP_Configure in pkt:
            pass
        elif PPP_LCP_Echo in pkt:
            self.respond_to_lcp_echo(pkt)
        elif EAP_TLS in pkt:
            if pkt[EAP_TLS].code == 1:  # Request
                log_msg = 'Received EAP-TLS request id {0}, containing {1}B fragment of tls data'\
                         .format(pkt[EAP_TLS].id, len(pkt[EAP_TLS].tls_data))
                write_log_info(self.eap_tls_log_tag, log_msg)

                #print 'TLS data len = {0}'.format(len(pkt[EAP_TLS].tls_data))
                if self.eap_tls_data is None:
                    self.eap_tls_data = pkt[EAP_TLS].tls_data
                else:
                    self.eap_tls_data += pkt[EAP_TLS].tls_data
                if pkt[EAP_TLS].M == 0:
                    #print 'Composed_len = {0}'.format(len(self.eap_tls_data))
                    tls_pkt = TLS(self.eap_tls_data)
                    #print 'Reassembled {0}B of tls_data'.format(len(self.eap_tls_data))
                    if TLSServerHello in tls_pkt and TLSCertificateList in tls_pkt:
                        log_msg = 'Reassembled ServerHello contains certificate chain of {0} certificate(s)'\
                                  .format(len(tls_pkt[TLSCertificateList].certificates))
                        write_log_info(self.eap_tls_log_tag, log_msg)
                        if self.cert_file is not None:
                            print 'Dumping TLS Certificate chain to {0}'.format(self.cert_file)
                            self.dump_certificates(tls_pkt)
                    raise self.state_end()
                else:
                    log_msg = 'Sending EAP-TLS Ack response id {0}'.format(pkt[EAP_TLS].id)
                    write_log_info(self.eap_tls_log_tag, log_msg)
                    eap_tls_ack = EAP_TLS(code=2, id=pkt[EAP_TLS].id, type=13)
                    self.send_eap(eap_tls_ack)
            else:
                pass
        else:
            # TODO log this
            raise self.state_end()

    @ATMT.timeout(state=state_receive_eap_tls_server_hello, timeout=1)
    def receive_eap_tls_server_hello_timeout(self):
        raise self.state_end()

    def automaton_done(self):
        return self.eap_authmethods


def der2pem(der_string, obj='CERTIFICATE'):
    pem_string = '-----BEGIN {0}-----\n'.format(obj)
    base64_string = base64.b64encode(der_string)
    chunks = [base64_string[i:i+64] for i in range(0, len(base64_string), 64)]
    pem_string += '\n'.join(chunks)
    pem_string += '\n-----END {0}-----\n'.format(obj)
    return pem_string