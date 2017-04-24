import argparse
import logging
import sys
import texttable
import socket
import subprocess
import time
from .logger import setup_logger
from .pptp import PPTPAutomaton
from .ppp import LCPEnumAuthMethodAutomaton
from .ppp_eap import EAPNegotiateAutomaton
from .ppp_chap import CHAPAutomaton
from .capture import PacketRecorder
from .authmethods import EAPAuthMethodSet, AuthMethodSet, PAP, CHAP_MD5, CHAP_SHA1, MSCHAP, MSCHAPv2, EAP,\
                         get_all_eap_authmethods


def check_raw_sock_perm():
    from scapy.config import conf
    try:
        sck = conf.L3socket()
    except:
        return False
    sck.close()
    return True


def enabled_state_to_string(state):
    if state is None:
        return 'Unknown'
    else:
        return 'Enabled' if state else 'Disabled'


def print_table_with_title(title, table):
    table_str = table.draw()
    top_part_len = table_str.find('\n')
    top_part = table_str[:top_part_len]
    print top_part
    stuffing_len = (top_part_len - 2 - len(title))
    left_stuffing_len = stuffing_len / 2
    right_stuffing_len = stuffing_len / 2 + stuffing_len % 2
    title_part = '|' + (' ' * left_stuffing_len) + title + (' ' * right_stuffing_len) + '|'
    print title_part
    print table_str + '\n'


def set_iptables_drop_icmp_protocol_unreachable():
    cmd = 'iptables -I OUTPUT -p icmp --icmp-type protocol-unreachable -j DROP 2>&1 1>/dev/null &&'\
          'iptables -I FORWARD -p icmp --icmp-type protocol-unreachable -j DROP 2>&1 1>/dev/null'
    ret_val = subprocess.call(cmd, shell=True)
    if ret_val != 0:
        print >> sys.stderr, 'Failed to add iptables ICMP protocol-unreachable dropping rule'


def restore_iptables_drop_icmp_protocol_unreachable():
    cmd = 'iptables -D OUTPUT -p icmp --icmp-type protocol-unreachable -j DROP 2>&1 1>/dev/null &&' \
          'iptables -D FORWARD -p icmp --icmp-type protocol-unreachable -j DROP 2>&1 1>/dev/null'
    ret_val = subprocess.call(cmd, shell=True)
    if ret_val != 0:
        print >> sys.stderr, 'Failed to restore iptables rules'


def get_target_address_info(target):
    target_hostname = None
    target_alias_list = None
    target_ip = None
    try:
        (target_hostname, target_alias_list, target_ip) = socket.gethostbyaddr(target)
    except socket.herror:
        target_ip = [target]
        # TODO check that target IP is proper IP address
    return target_hostname, target_alias_list, target_ip


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

    # Print PPTP connection info
    table = texttable.Texttable()
    table.set_cols_align(['l', 'c'])
    table.add_row(['PPTP server domain', target_hostname if target_hostname is not None else 'Unknown'])
    table.add_row(['PPTP server aliases', '\n'.join(alias_list) if alias_list is not None and len(alias_list) > 0 else 'Unknown'])
    table.add_row(['PPTP server IP', target_ip[0] if target_ip[0] is not None else 'Unknown'])
    table.add_row(['PPTP port', args.port])
    if pptp_info is not None:
        table.add_row(['Protocol version', pptp_info.get_protocol_version_str()])
        table.add_row(['Maximum channels', pptp_info.get_maximum_channels()])
        table.add_row(['Firmware revision', pptp_info.get_firmware_revision()])
        table.add_row(['Host name', '\'{0}\''.format(pptp_info.get_host_name())])
        table.add_row(['Vendor string', '\'{0}\''.format(pptp_info.get_vendor_string())])
    print_table_with_title('PPTP Info', table)

    if lcp_auth_methods is not None:
        #  Print LCP Authmethods state
        table = texttable.Texttable(max_width=100)
        table.set_cols_align(['c'] * len(lcp_auth_methods.get_methods()))
        lcp_methods = [PAP, CHAP_MD5, CHAP_SHA1, MSCHAP, MSCHAPv2, EAP]
        table.add_row([str(x()) for x in lcp_methods])
        lcp_states = [lcp_auth_methods.get_method_enabled_state(x) for x in lcp_methods]
        table.add_row([enabled_state_to_string(x) for x in lcp_states])
        lcp_extras = [lcp_auth_methods.get_method(x).get_extra_as_string() for x in lcp_methods]
        table.add_row(lcp_extras)
        print_table_with_title('State of LCP Authentication methods', table)

    if eap_auth_methods is not None:
        table = texttable.Texttable()
        table.set_cols_align(['l', 'c','l'])
        for eap_method in eap_auth_methods.get_methods():
            table.add_row([eap_method, eap_method.get_enabled_state_str(), eap_method.get_extra_as_string()])
        print table.draw() + '\n'
