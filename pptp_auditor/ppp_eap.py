from scapy.layers.ppp import PPP_LCP_Auth_Protocol_Option
from scapy.layers.ppp import PPP_LCP_Configure, PPP_LCP_Echo
from scapy.layers.l2 import EAP, EAP_TLS
from scapy.layers.tls.handshake import TLSClientHello, TLSCertificate
from scapy.layers.tls.record import TLS
from scapy.layers.tls.crypto.suites import _tls_cipher_suites
from scapy.automaton import ATMT
from scapy_pptp.peap import PEAP
from scapy_pptp.mseap import EAP_MSCHAPv2Challenge
from .logger import write_log_info, write_log_error
from .ppp import LCPAutomaton
from .authmethods import AuthMethodSet, EAPAuthMethodSet
import sys, copy


class EAPNegotiateAutomaton(LCPAutomaton):

    def __init__(self, *args, **kargs):
        LCPAutomaton.__init__(self, *args, **kargs)

    def parse_args(self, target, cert_file=None, eap_auth_methods=None,
                   identity='user', debug=0, store=1, **kargs):
        LCPAutomaton.parse_args(self, target, debug, store, **kargs)
        self.lcp_authmethods = AuthMethodSet()
        self.eap_log_tag = 'EAP'
        self.eap_tls_log_tag = 'EAP-TLS'
        self.peap_log_tag = 'PEAP'
        self.eap_authmethods = EAPAuthMethodSet() if eap_auth_methods is None else eap_auth_methods
        self.eap_last_requested_method = None
        self.identity = identity
        self.cert_file = cert_file
        self.eap_tls_data = None
        # We want to track if we received at least some EAP request after providing Identity,
        # if not, EAP is disabled for the provided Identity and we want to detect that
        self.eap_received_some_request = False

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
        log_msg = 'Received Configure-Ack to request with id {0}'.format(resp.id)
        write_log_info(self.log_tag, log_msg)
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
            elif option.type == 5:  # Magic number
                self.ppp_state.magic_number = option.magic_number
                log_msg = 'Setting magic number to {0}'.format(option.magic_number)
                write_log_info(self.log_tag, log_msg)
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
        if rejected_eap_auth:
            raise self.state_end()

    @ATMT.state()
    def state_eap_negotiated(self):
        pass

    def get_id_from_eap_pkt(self, pkt):
        if EAP in pkt:
            return pkt[EAP].id
        elif EAP_TLS in pkt:
            return pkt[EAP_TLS].id
        elif PEAP in pkt:
            return pkt[PEAP].id
        elif EAP_MSCHAPv2Challenge in pkt:
            return pkt[EAP_MSCHAPv2Challenge].id
        else:
            return None

    def eap_process_request(self, pkt):
        self.eap_received_some_request = True
        if EAP in pkt:
            requested_method = self.eap_authmethods.get_eap_method_for_method_type(pkt[EAP].type)
        elif EAP_TLS in pkt:
            requested_method = self.eap_authmethods.get_eap_method_for_method_type(pkt[EAP_TLS].type)
        elif PEAP in pkt:
            requested_method = self.eap_authmethods.get_eap_method_for_method_type(pkt[PEAP].type)
        elif EAP_MSCHAPv2Challenge in pkt:
            requested_method = self.eap_authmethods.get_eap_method_for_method_type(pkt[EAP_MSCHAPv2].type)
        else:
            requested_method = None
        if requested_method:
            requested_method.set_enabled()
        else:
            # TODO Warning about uknown EAP type
            pass

        if self.eap_last_requested_method is not None and requested_method is not None and\
           self.eap_last_requested_method.eap_type != requested_method.eap_type:
            self.eap_last_requested_method.set_disabled()

        log_msg = 'Received {0} request id {1}'.format(requested_method if requested_method is not None else 'Unknown',
                                                       self.get_id_from_eap_pkt(pkt))
        write_log_info(self.eap_log_tag, log_msg)
        suggested_method = self.eap_authmethods.get_next_to_try()
        self.eap_last_requested_method = suggested_method
        if suggested_method is None:
            raise self.state_end()
        log_msg = 'Sending Legacy-Nak to EAP-TLS request id {0}, suggesting {1}' \
                  .format(self.get_id_from_eap_pkt(pkt), suggested_method)
        eap_nak = suggested_method.get_eap_nak_response(pkt[EAP].id if EAP in pkt else pkt[EAP_TLS].id)
        write_log_info(self.eap_log_tag, log_msg)
        self.send_eap(eap_nak)

    #def debug(self, lvl, msg):
    #    print msg

    def eap_handle_tls_request(self, pkt):
        log_msg = 'Received EAP-TLS request id {0}'.format(pkt[EAP_TLS].id)
        write_log_info(self.eap_tls_log_tag, log_msg)

        tls_client_hello = TLS(msg=TLSClientHello(ciphers=[x for x in _tls_cipher_suites.values()], version='TLS 1.0'))
        eap_tls_client_hello = EAP_TLS(code=2, id=pkt[EAP_TLS].id, L=1,
                                       tls_message_len=len(tls_client_hello), tls_data=str(tls_client_hello))
        self.send_eap(eap_tls_client_hello)
        log_msg = 'Sending TLS ClientHello message in EAP response id {0}'.format(pkt[EAP_TLS].id)
        write_log_info(self.eap_tls_log_tag, log_msg)
        raise self.state_receive_eap_tls_server_hello()

    def eap_handle_peap_request(self, pkt):
        log_msg = 'Received PEAP request id {0}'.format(pkt[PEAP].id)
        write_log_info(self.peap_log_tag, log_msg)

        tls_client_hello = TLS(msg=TLSClientHello(ciphers=[x for x in _tls_cipher_suites.values()], version='TLS 1.0'))
        peap_client_hello = PEAP(code=2, id=pkt[PEAP].id, L=1, V=pkt[PEAP].V,
                                 tls_message_len=len(tls_client_hello), tls_data=str(tls_client_hello))
        self.send_eap(peap_client_hello)
        log_msg = 'Sending TLS ClientHello in PEAP response id {0}'.format(pkt[PEAP].id)
        write_log_info(self.peap_log_tag, log_msg)
        raise self.state_receive_peap_server_hello()

    @ATMT.receive_condition(state_eap_negotiated, prio=1)
    def eap_negotiated_receive(self, pkt):
        if PPP_LCP_Configure in pkt:
            if pkt[PPP_LCP_Configure].code == 1:  # LCP Configure-Request
                self.process_configure_request(pkt[PPP_LCP_Configure])
            elif pkt[PPP_LCP_Configure].code == 2:  # LCP Configure-Ack
                self.process_configure_ack(pkt[PPP_LCP_Configure])
            elif pkt[PPP_LCP_Configure].code == 3:  # LCP Configure-Nak
                self.process_configure_nak(pkt[PPP_LCP_Configure])
            elif pkt[PPP_LCP_Configure].code == 4:  # LCP Configure-Reject
                self.process_configure_reject(pkt[PPP_LCP_Configure])
            # TODO this might need some modification, we don't want auth method to change here
        elif PPP_LCP_Echo in pkt:
            self.respond_to_lcp_echo(pkt)
        elif EAP_TLS in pkt:
            eap_method = self.eap_authmethods.get_eap_method_for_method_type(13)
            if eap_method.is_state_known():
                self.eap_process_request(pkt)
            else:
                eap_method.set_enabled()
                self.eap_handle_tls_request(pkt)
        elif PEAP in pkt:
            eap_method = self.eap_authmethods.get_eap_method_for_method_type(25)
            if eap_method.is_state_known():
                self.eap_process_request(pkt)
            else:
                eap_method.set_enabled()
                self.eap_handle_peap_request(pkt)
        elif EAP_MSCHAPv2Challenge in pkt:
            eap_method = self.eap_authmethods.get_eap_method_for_method_type(26)
            if not eap_method.is_state_known():
                eap_method.set_enabled()
                eap_method.add_extra("Name", pkt[EAP_MSCHAPv2Challenge].optional_name)
            self.eap_process_request(pkt)
        elif EAP in pkt:
            if pkt[EAP].code == 1: # Request
                if pkt[EAP].type == 1:  # Identity
                    log_msg = 'Received EAP-Identity request id {0}, identity \'{1}\''\
                              .format(pkt[EAP].id, pkt[EAP].identity)
                    write_log_info(self.eap_log_tag, log_msg)
                    eap_identity_response = EAP(code=2, id=pkt[EAP].id, type='Identity', identity=self.identity)
                    log_msg = 'Sending EAP-Identity response id {0}, identity \'{1}\''\
                              .format(pkt[EAP].id, self.identity)
                    write_log_info(self.eap_log_tag, log_msg)
                    self.send_eap(eap_identity_response)
                elif pkt[EAP].type == 2: # Notification
                    pass # TODO log this
                elif pkt[EAP].type == 3: # Legacy-Nak
                    pass # TODO process this
                elif pkt[EAP].type >= 4:  # Reply
                    self.eap_process_request(pkt)
                else:
                    pass  # TODO Warn
            elif pkt[EAP].code == 2:  # Response
                if pkt[EAP].type == 1:  # Identity
                    pass # No reason for server to send identity response
                elif pkt[EAP].type == 2:  # Notification
                    pass # TODO log this
                elif pkt[EAP].type >= 4:
                    pass  # No reason to receive response when logging is not actually used
            elif pkt[EAP].code == 3:  # Success
                pass
            elif pkt[EAP].code == 4:  # Failure
                log_msg = 'Received EAP-Failure id {0}'.format(pkt[EAP].id)
                write_log_info(self.eap_log_tag, log_msg)
                # If we received failure before receiving any requests, we can assume
                # EAP is disabled for the provided Identity
                if not self.eap_received_some_request:
                    #TODO log this
                    eap_methods = self.eap_authmethods.get_methods()
                    for eap_method in eap_methods:
                        eap_method.set_disabled()
                else:
                    self.eap_last_requested_method.set_disabled()
                raise self.state_end()
            else:
                # TODO this is weird
                raise self.state_end()

    @ATMT.timeout(state_eap_negotiated, timeout=3)
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
        assert (TLSCertificate in pkt)
        if self.cert_file is not None:
            certificates = []
            for cert in pkt[TLSCertificate].certs:
                print cert
                certificates.append(cert[1].pem)
            try:
                with open(self.cert_file, 'w') as f:
                    for certificate in certificates:
                        f.write(certificate)
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

                if self.eap_tls_data is None:
                    self.eap_tls_data = pkt[EAP_TLS].tls_data
                else:
                    self.eap_tls_data += pkt[EAP_TLS].tls_data
                if pkt[EAP_TLS].M == 0:
                    tls_pkt = TLS(self.eap_tls_data)
                    if TLSCertificate in tls_pkt:
                        log_msg = 'Reassembled ServerHello contains certificate chain of {0} certificate(s)'\
                                  .format(tls_pkt[TLSCertificate].certslen)
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

    @ATMT.state()
    def state_receive_peap_server_hello(self):
        pass

    @ATMT.receive_condition(state=state_receive_peap_server_hello, prio=1)
    def receive_peap_server_hello_receive(self, pkt):
        if PPP_LCP_Configure in pkt:
            pass
        elif PPP_LCP_Echo in pkt:
            self.respond_to_lcp_echo(pkt)
        elif PEAP in pkt:
            if pkt[PEAP].code == 1:  # Request
                log_msg = 'Received PEAP request id {0}, containing {1}B fragment of tls data' \
                    .format(pkt[PEAP].id, len(pkt[PEAP].tls_data))
                write_log_info(self.eap_tls_log_tag, log_msg)

                if self.eap_tls_data is None:
                    self.eap_tls_data = pkt[PEAP].tls_data
                else:
                    self.eap_tls_data += pkt[PEAP].tls_data
                if pkt[PEAP].M == 0:
                    tls_pkt = TLS(self.eap_tls_data)
                    if TLSCertificate in tls_pkt:
                        log_msg = 'Reassembled ServerHello contains certificate chain of {0} certificate(s)' \
                            .format(tls_pkt[TLSCertificate].certslen)
                        write_log_info(self.eap_tls_log_tag, log_msg)
                        if self.cert_file is not None:
                            print 'Dumping TLS Certificate chain to {0}'.format(self.cert_file)
                            self.dump_certificates(tls_pkt)
                    raise self.state_end()
                else:
                    log_msg = 'Sending PEAP Ack response id {0}'.format(pkt[EAP_TLS].id)
                    write_log_info(self.eap_tls_log_tag, log_msg)
                    eap_tls_ack = PEAP(code=2, id=pkt[PEAP].id, type=25)
                    self.send_eap(eap_tls_ack)
            else:
                pass
        else:
            # TODO log this
            raise self.state_end()

    @ATMT.timeout(state=state_receive_peap_server_hello, timeout=1)
    def receive_peap_server_hello_timeout(self):
        raise self.state_end()

    def automaton_done(self):
        return self.eap_authmethods
