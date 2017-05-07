import argparse
import logging
import sys
import socket
import subprocess
import time
from .logger import setup_logger
from .pptp import PPTPAutomaton, PPTPInfo
from .ppp import LCPEnumAuthMethodAutomaton
from .ppp_eap import EAPNegotiateAutomaton
from .ppp_chap import CHAPAutomaton
from .capture import PacketRecorder
from .authmethods import EAPAuthMethodSet, AuthMethodSet, PAP, CHAP_MD5, CHAP_SHA1, MSCHAP, MSCHAPv2, EAP,\
                         get_all_eap_authmethods, EAPTLS, EAPPEAP, EAPCHAP, EAPMSEAP


def check_raw_sock_perm():
    """
    Check if user has permissions to create RAW sockets
    :return:
        bool: True if raw socket can be succesfully created, False otherwise
    """
    from scapy.config import conf
    try:
        sck = conf.L3socket()
    except:
        return False
    sck.close()
    return True


def enabled_state_to_string(state):
    """
    Translate state to string
    :param state: bool or None
    :return:
        basestring:
    """
    if state is None:
        return 'Unknown'
    else:
        return 'Enabled' if state else 'Disabled'


def set_iptables_drop_icmp_protocol_unreachable():
    """
    Setup iptables firewall rule to drop ICMP protocol-unreachable packets
    """
    cmd = 'iptables -I OUTPUT -p icmp --icmp-type protocol-unreachable -j DROP 2>&1 1>/dev/null &&'\
          'iptables -I FORWARD -p icmp --icmp-type protocol-unreachable -j DROP 2>&1 1>/dev/null'
    ret_val = subprocess.call(cmd, shell=True)
    if ret_val != 0:
        print >> sys.stderr, 'Failed to add iptables ICMP protocol-unreachable dropping rule'


def restore_iptables_drop_icmp_protocol_unreachable():
    """
    Remove iptables rule to drop ICMP protocol-unreachable packets
    :return:
    """
    cmd = 'iptables -D OUTPUT -p icmp --icmp-type protocol-unreachable -j DROP 2>&1 1>/dev/null &&' \
          'iptables -D FORWARD -p icmp --icmp-type protocol-unreachable -j DROP 2>&1 1>/dev/null'
    ret_val = subprocess.call(cmd, shell=True)
    if ret_val != 0:
        print >> sys.stderr, 'Failed to restore iptables rules'


def get_target_address_info(target):
    """
    Return hostname, alias list and ip address for ip address or domain
    :param target: ip address or domain
    :return:
        (hostname, alias list, ip)
    """
    target_hostname = None
    target_alias_list = None
    target_ip = None
    try:
        (target_hostname, target_alias_list, target_ip) = socket.gethostbyaddr(target)
    except socket.herror:
        target_ip = [target]
        # TODO check that target IP is proper IP address
    return target_hostname, target_alias_list, target_ip


def print_header(str):
    """
    Print simple header/title
    :param str: text of title
    """
    print '{0}\n{1:^50}\n{0}'.format('='*50, str)


def print_property(property_name, value):
    """
    Simple wrapper to print named property
    :param property_name:   name of property
    :param value:           value of property
    """
    print '{0:25} {1}'.format(property_name, value)


def print_cert_str(cert_str):
    """
    Parse and print info from certificate
    :param cert_str: info from certificate formatted like PROPERTY1=VALUE1/PROPERTY2=VALUE2
    :return:
    """
    for s in cert_str.split('/'):
        if '=' not in s:
            continue
        kv = s.split('=')
        print_property(kv[0]+':', kv[1])


def print_cert_info(method):
    """
    Print certificate info of EAP method
    :param method: EAPAuthMethod instance
    """
    if method is not None and method.get_enabled_state():
        print_header(str(method) + ' Certificate')
        if method.cert is not None:
            print_property('Serial:', str(method.cert.serial))
            print 'Issuer'
            print_cert_str(method.cert.issuer_str)
            print 'Subject'
            print_cert_str(method.cert.subject_str)
            print_property('Validity:', '%s to %s' % (method.cert.notBefore_str, method.cert.notAfter_str))


def print_results(target_hostname, alias_list, target_ip, lcp_auth_methods, eap_auth_methods, pptp_info, args):
    """
    Print formated test results
    :param target_hostname:     hostname of target server
    :param alias_list:          alias list of target server
    :param target_ip:           ip of target server
    :param lcp_auth_methods:    LCPAuthMethodSet instance with states of PPP auth methods
    :param eap_auth_methods:    EAPAuthMethodSet instance with states of EAP auth methods
    :param pptp_info:           PPTPInfo instance with info from control connection
    :param args:                command line arguments from ArgumentParser
    """
    print_header('PPTP info')
    print_property('PPTP server domain:', target_hostname if target_hostname is not None else 'Unknown')
    aliases = alias_list if alias_list is not None and len(alias_list) > 0 else ['Unknown']
    print_property('PPTP server aliases:', aliases[0])
    for alias in aliases[1:]:
        print_property('', alias)
    print_property('PPTP server IP:', target_ip[0] if target_ip[0] is not None else 'Unknown')
    print_property('PPTP server port:', args.port)
    if pptp_info is not None:
        assert isinstance(pptp_info, PPTPInfo)
        print_property('Protocol version:', pptp_info.get_protocol_version_str())
        print_property('Maximum_channels:', pptp_info.get_maximum_channels())
        print_property('Firmware revision:', pptp_info.get_firmware_revision())
        print_property('Framing capabilities:', pptp_info.get_framing_capabilities())
        print_property('Bearer capabilities:', pptp_info.get_bearer_capabilities())
        print_property('Host name:', pptp_info.get_host_name())
        print_property('Vendor string:', pptp_info.get_vendor_string())
        print_property('Connection speed:', pptp_info.get_connection_speed())
        print_property('GRE window size:', pptp_info.get_window_size())
        print_property('Packet processing delay:', pptp_info.get_window_size())
        print_property('Physical channel id:', pptp_info.get_physical_channel_id())


    if lcp_auth_methods is not None:
        print_header('PPP Authentication')
        ppp_methods = [PAP, CHAP_MD5, CHAP_SHA1, MSCHAP, MSCHAPv2, EAP]
        for ppp_method in ppp_methods:
            method_state = lcp_auth_methods.get_method_enabled_state(ppp_method)
            extra = lcp_auth_methods.get_method(ppp_method).get_extra_as_string()
            if extra:
                print_property(str(ppp_method()), enabled_state_to_string(method_state) + ',' +
                               lcp_auth_methods.get_method(ppp_method).get_extra_as_string())
            else:
                print_property(str(ppp_method()), enabled_state_to_string(method_state))

    if eap_auth_methods is not None:
        print_header('EAP Authentication (Identity \'{0}\')'.format(args.identity))
        if eap_auth_methods.is_disabled_for_identity():
            print 'EAP is disabled for identity \'{0}\''.format(args.identity)
        else:
            for eap_method in eap_auth_methods.get_methods():
                if isinstance(eap_method, EAPTLS) or isinstance(eap_method, EAPPEAP):
                    print_property(eap_method, enabled_state_to_string(eap_method.get_enabled_state()))
                else:
                    extra = eap_method.get_extra_as_string()
                    if extra == '':
                        print_property(eap_method, enabled_state_to_string(eap_method.get_enabled_state()))
                    else:
                        print_property(eap_method, enabled_state_to_string(eap_method.get_enabled_state()) + ',' + extra)

        print_cert_info(eap_auth_methods.get_method(EAPTLS))
        print_cert_info(eap_auth_methods.get_method(EAPPEAP))

    print_header('Warning')

    if lcp_auth_methods is not None:
        if lcp_auth_methods.get_method_enabled_state(PAP):
            print 'PAP Authentication is enabled. User credentials are sent in plaintext, no encryption is used.'
        if lcp_auth_methods.get_method_enabled_state(CHAP_MD5) or lcp_auth_methods.get_method_enabled_state(CHAP_SHA1):
            print 'CHAP Authentication is enabled. Connection is vulnerable to MitM attacks, no encryption is used.'
        if lcp_auth_methods.get_method_enabled_state(MSCHAP) or lcp_auth_methods.get_method_enabled_state(MSCHAPv2):
            print 'MSCHAP/MSCHAPv2 Authentication is enabled. NTHash of user password can be recovered by sniffing' \
                  'network traffic.'
    if eap_auth_methods is not None:
        if eap_auth_methods.get_method_enabled_state(EAPPEAP):
            print 'PEAP Authentication is enabled. Make sure all clients are validating server certificate.'
        if eap_auth_methods.get_method_enabled_state(EAPCHAP):
            print 'EAP-MD5 Authentication is enabled. Connection is vulnerable to MitM attacks, no encryption si used.'
        if eap_auth_methods.get_method_enabled_state(EAPMSEAP):
            print 'MS-EAP (MSCHAPv2) Authentication is enabld. NTHash of user password can be recovered by sniffing'\
                  'network traffic'
    print 'You are using PPTP. The PPTP protocol is not considered to be really secure, even when configured properly.'


def main():
    parser = argparse.ArgumentParser('PPTP Auditing tool')
    parser.add_argument('target', help='Adress of PPTP server')
    parser.add_argument('-p', '--port', help='PPTP port', type=int, default=1723, dest='port')
    parser.add_argument('-l', '--log', help='Filename for log', default='log.txt',
                        dest='logfile')
    parser.add_argument('-i', '--identity', help='Identity to use with EAP', default='user',
                        dest='identity')
    parser.add_argument('-c', '--dump_cert_file', help='File to dump server TLS certificate to', default=None,
                        dest='cert_file')
    parser.add_argument('-e', '--test_all_eap_methods', help='Test all EAP auth methods', default=False,
                        action='store_true')
    parser.add_argument('-r','--record_pcap', help='Record communication with target to pcap file', default=None,
                        dest='pcap_file')
    parser.add_argument('-di', '--dont_drop_icmp', help='Dont drop ICMP protocol-unreachable packets', default=True,
                        dest='drop_icmp', action='store_false')
    parser.add_argument('-d', '--log-debug', help='Log debug information',
                        action='store_const', dest='loglevel',
                        const=logging.DEBUG, default=logging.INFO)
    parser.add_argument('-a', '--log-append', help='Append output to logfile instead of truncating it',
                        action='store_const', dest='logfile_mode',
                        const='a', default='w')
    args = parser.parse_args()

    setup_logger(args)

    print 'PPTP Auditor'

    if not check_raw_sock_perm():
        print >> sys.stderr, 'You don\'t have sufficient permission to create raw sockets.\n'\
                             'Try running pptp_auditor as root.'
        sys.exit(-1)

    if args.drop_icmp:
        set_iptables_drop_icmp_protocol_unreachable()

    (target_hostname, alias_list, target_ip) = get_target_address_info(args.target)

    pkt_recorder = None
    if args.pcap_file is not None:
        pkt_recorder = PacketRecorder(args.target, args.pcap_file)
        pkt_recorder.start()
        time.sleep(0.5)

    print 'Probing enabled LCP authentication methods'
    lcp_auth_methods = AuthMethodSet()
    pptp_automaton = PPTPAutomaton(args.target, LCPEnumAuthMethodAutomaton,
                                   ppp_automaton_kwargs={'lcp_auth_methods':lcp_auth_methods},
                                   port=args.port)

    pptp_info = None
    eap_auth_methods = None
    try:
        pptp_info = pptp_automaton.run()

        for chap_method in [CHAP_MD5, CHAP_SHA1, MSCHAP, MSCHAPv2]:
            if pptp_info is not None and pptp_info.ppp_info.get_method_enabled_state(chap_method):
                pptp_automaton = PPTPAutomaton(args.target, CHAPAutomaton,
                                               ppp_automaton_kwargs={'chap_method': pptp_info.ppp_info.get_method(chap_method),
                                                                     'lcp_auth_methods': lcp_auth_methods},
                                               port=args.port)
                pptp_automaton.run()

        if pptp_info is not None and pptp_info.ppp_info.get_method_enabled_state(EAP):
            if args.test_all_eap_methods:
                eap_auth_methods = EAPAuthMethodSet(methods=get_all_eap_authmethods())
            else:
                eap_auth_methods = EAPAuthMethodSet()

            while not eap_auth_methods.is_state_of_all_methods_known():
                assert (isinstance(eap_auth_methods, EAPAuthMethodSet))
                print 'Probing enabled EAP authentication methods {0}/{1}' \
                      .format(eap_auth_methods.get_number_of_known_methods(), len(eap_auth_methods.get_methods()))
                pptp_automaton = PPTPAutomaton(args.target, EAPNegotiateAutomaton,
                                               ppp_automaton_kwargs={'cert_file': args.cert_file,
                                                                     'identity': args.identity,
                                                                     'eap_auth_methods': eap_auth_methods},
                                               port=args.port)
                pptp_automaton.run()
    except socket.error as sock_err:
        print >> sys.stderr, 'Unexpected connection error: {0}'.format(sock_err)
    except Exception as error:
        print >> sys.stderr, 'Unexpected error: {0}'.format(error)
    finally:
        if pkt_recorder is not None:
            pkt_recorder.stop()
        if args.drop_icmp:
            restore_iptables_drop_icmp_protocol_unreachable()

    print_results(target_hostname, alias_list, target_ip, lcp_auth_methods, eap_auth_methods, pptp_info, args)