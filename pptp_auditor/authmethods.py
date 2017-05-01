from scapy.layers.l2 import EAP as EAP_pkt, eap_types
from scapy.layers.ppp import PPP_LCP_Auth_Protocol_Option


class AuthMethod:

    def __init__(self):
        self.enabled_state = None
        self.extra = {}

    def set_enabled(self):
        self.enabled_state = True

    def set_disabled(self):
        self.enabled_state = False

    def is_state_known(self):
        return self.enabled_state is not None

    def get_enabled_state(self):
        return self.enabled_state

    def get_enabled_state_str(self):
        if self.enabled_state is None:
            return "Unknown"
        elif self.enabled_state:
            return "Enabled"
        else:
            return "Disabled"

    def add_extra(self, key, value):
        self.extra[key]=value

    def get_extra_as_string(self):
        return "\n".join(["{0}: {1}".format(x,y) for (x,y) in self.extra.items()])

    def __str__(self):
        raise NotImplementedError


class LCPAuthMethod(AuthMethod):

    def is_lcp_option(self, option):
        raise NotImplementedError

    def get_lcp_option(self):
        return self.pkt

    def is_lcp_option(self, option):
        if option.auth_protocol == self.pkt.auth_protocol:
            if option.auth_protocol == 0xc223:
                return option.algorithm == self.pkt.algorithm
            else:
                return True
        else:
            return False


class PAP(LCPAuthMethod):

    def __init__(self):
        LCPAuthMethod.__init__(self)
        self.pkt = PPP_LCP_Auth_Protocol_Option()

    @classmethod
    def __str__(self):
        return "PAP"

    def is_lcp_option(self, option):
        return option.auth_protocol == 0xc023


class CHAP_MD5(LCPAuthMethod):

    def __init__(self):
        LCPAuthMethod.__init__(self)
        self.pkt = PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc223, algorithm='MD5')

    @classmethod
    def __str__(self):
        return "CHAP+MD5"


class CHAP_SHA1(LCPAuthMethod):

    def __init__(self):
        LCPAuthMethod.__init__(self)
        self.pkt = PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc223, algorithm='SHA1')

    @classmethod
    def __str__(self):
        return "CHAP+SHA1"


class MSCHAP(LCPAuthMethod):

    def __init__(self):
        LCPAuthMethod.__init__(self)
        self.pkt = PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc223, algorithm='MS-CHAP')

    @classmethod
    def __str__(self):
        return "MS-CHAP"


class MSCHAPv2(LCPAuthMethod):

    def __init__(self):
        LCPAuthMethod.__init__(self)
        self.pkt = PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc223, algorithm="MS-CHAP-v2")

    @classmethod
    def __str__(self):
        return "MS-CHAP-v2"


class EAP(LCPAuthMethod):

    def __init__(self):
        LCPAuthMethod.__init__(self)
        self.pkt = PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc227)

    @classmethod
    def __str__(self):
        return "EAP"


class AuthMethodSet:

    MAX_TRIES = 5

    def __init__(self, methods = [PAP(), CHAP_MD5(), CHAP_SHA1(), MSCHAP(), MSCHAPv2(), EAP()]):
        self.methods = {method:0 for method in methods}

    def get_next_to_try(self):
        unknown_methods = sorted([method for method in self.methods.keys() if not method.is_state_known()
                                  and self.methods[method] < self.MAX_TRIES],
                                 key=lambda x: self.methods[x])
        if len(unknown_methods) <= 0:
            return None
        method_to_try = unknown_methods[0]
        self.methods[method_to_try] += 1
        return unknown_methods[0]

    def get_method(self, cls):
        for method in self.methods.keys():
            if isinstance(method, cls):
                return method
        return None

    def set_method_state_from_option(self, option, state):
        for method in self.methods.keys():
            if method.is_lcp_option(option):
                if state:
                    #print 'Enabling', method
                    method.set_enabled()
                else:
                    #print 'Disabling', method
                    method.set_disabled()

    def get_method_for_option(self, option):
        for method in self.methods.keys():
            if method.is_lcp_option(option):
                return method
        return None

    def enable_method_from_option(self, option):
        self.set_method_state_from_option(option, True)

    def disable_method_from_option(self, option):
        self.set_method_state_from_option(option, False)

    def get_methods(self):
        return [method for method in self.methods.keys()]

    def get_method_enabled_state(self, method):
        for m in self.methods.keys():
            if isinstance(m, method):
                return m.get_enabled_state()
        return None

    def get_number_of_known_methods(self):
        known_methods_nr = 0
        for m in self.methods.keys():
            if m.is_state_known():
                known_methods_nr += 1
        return known_methods_nr

    def is_state_of_all_methods_known(self):
        return self.get_number_of_known_methods() == len(self.methods.keys())

    def __str__(self):
            return ','.join(['{0}: {1}'.format(method, method.get_enabled_state_str()) for method in self.methods.keys()])


class EAPAuthMethod(AuthMethod):

    def __init__(self, eap_type=None):
        AuthMethod.__init__(self)
        self.eap_type = eap_type

    def is_eap_option(self, eap_type):
        return self.eap_type == eap_type

    def get_eap_nak_response(self, id):
        return EAP_pkt(code='Response', id=id, type='Legacy Nak', desired_auth_type=self.eap_type)

    def is_eap_request(self, request):
        return EAP_pkt in request and request[EAP_pkt].type == self.eap_type

    def __str__(self):
        if self.eap_type in eap_types.keys():
            return eap_types[self.eap_type]
        else:
            return 'Unknown EAP auth method({0})'.format(self.eap_type)


def get_all_eap_authmethods():
    all_authmethods = []
    for eap_type in eap_types.keys():
        if eap_type == 4:
            all_authmethods.append(EAPCHAP())
        elif eap_type == 13:
            all_authmethods.append(EAPTLS())
        elif eap_type == 25:
            all_authmethods.append(EAPPEAP())
        elif eap_type == 29:
            all_authmethods.append(EAPMSCHAPv2())
        elif eap_type >= 4:
            all_authmethods.append(EAPAuthMethod(eap_type))
    return all_authmethods


class EAPCHAP(EAPAuthMethod):
    def __init__(self):
        EAPAuthMethod.__init__(self, 4)


class EAPTLS(EAPAuthMethod):

    def __init__(self):
        EAPAuthMethod.__init__(self, 13)


class EAPPEAP(EAPAuthMethod):

    def __init__(self):
        EAPAuthMethod.__init__(self, 25)


class EAPMSCHAPv2(EAPAuthMethod):

    def __init__(self):
        EAPAuthMethod.__init__(self, 29)


class EAPMSEAP(EAPAuthMethod):

    def __init__(self):
        EAPAuthMethod.__init__(self, 26)


class EAPAuthMethodSet(AuthMethodSet):

    def __init__(self, methods=[EAPTLS(), EAPPEAP(), EAPCHAP(), EAPMSEAP()]):
        AuthMethodSet.__init__(self, methods)
        self.disabled_for_identity = False


    def set_disabled_for_identity(self):
        self.disabled_for_identity = True

    def is_disabled_for_identity(self):
        return self.disabled_for_identity

    def get_eap_method_for_request(self, request):
        for method in self.methods.keys():
            if method.is_eap_request(request):
                return method
        return None

    def get_eap_method_for_method_type(self, type):
        for method in self.methods.keys():
            if method.eap_type == type:
                return method
        return None

    def set_method_state_from_request(self, request, state):
        if EAP not in request:
            return
        for method in self.methods.keys():
            if method.is_eap_request(request):
                if state:
                    method.set_enabled()
                else:
                    method.set_disabled()

    def enable_option_from_request(self, request):
        self.set_method_state_from_request(request, True)

    def disable_method_from_request(self, request):
        self.set_method_state_from_request(request, False)
