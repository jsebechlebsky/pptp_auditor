from scapy.layers.l2 import EAP as EAP_pkt, eap_types
from scapy.layers.ppp import PPP_LCP_Auth_Protocol_Option


class AuthMethod:
    """
    Base class for holding authentication method info and state
    """

    def __init__(self):
        self.enabled_state = None
        self.extra = {}
        self.cert = None

    def set_enabled(self):
        """Mark authentication method as enabled"""
        self.enabled_state = True

    def set_disabled(self):
        """Mark authentication method as disabled"""
        self.enabled_state = False

    def is_state_known(self):
        """
        Returns value based on whether the state of authentication
        method is known
        :return:
            True if authentication method is known
            False if authentication method is not known
        """
        return self.enabled_state is not None

    def get_enabled_state(self):
        """
        Returns value based on authentication method
        known state
        :return:
            True if authentication method is enabled
            False if authentication method is disabled
            None if state of authentication method is not known
        """
        return self.enabled_state

    def get_enabled_state_str(self):
        """
        Returns string describing authentication method
        known state
        :return:
            "Unknown"
            "Enabled"
            "Disabled"
        """
        if self.enabled_state is None:
            return "Unknown"
        elif self.enabled_state:
            return "Enabled"
        else:
            return "Disabled"

    def add_extra(self, key, value):
        """
        Sets extra information for the authentication method
        :param key:     name of the information, i.e. user_name
        :param value:   extra information about the method
        """
        self.extra[key]=value

    def get_extra_as_string(self):
        """
        Returns extra information string
        :return:
            String containing extra information, each line formatted as 'key: value'
        """
        return "\n".join(["{0}: {1}".format(x,y) for (x,y) in self.extra.items()])

    def __str__(self):
        raise NotImplementedError


class LCPAuthMethod(AuthMethod):
    """ Base class for holding PPP Authentication option state"""

    def get_lcp_option(self):
        """
        Get LCP option for the method
        :return:
            LCPOption: LCPOption instance containing request for the method
        """
        return self.pkt

    def is_lcp_option(self, option):
        """
        Check if option is requesting the method
        :param option: LCPOption instance
        :return:
            bool:
        """
        if option.auth_protocol == self.pkt.auth_protocol:
            if option.auth_protocol == 0xc223:
                return option.algorithm == self.pkt.algorithm
            else:
                return True
        else:
            return False

    def __str__(self):
        raise NotImplementedError


class PAP(LCPAuthMethod):
    """Password authentication protocol"""
    def __init__(self):
        LCPAuthMethod.__init__(self)
        self.pkt = PPP_LCP_Auth_Protocol_Option()

    @classmethod
    def __str__(cls):
        return "PAP"

    def is_lcp_option(self, option):
        return option.auth_protocol == 0xc023


class CHAP_MD5(LCPAuthMethod):
    """Challenge-Handshake authentication protocol + MD5"""
    def __init__(self):
        LCPAuthMethod.__init__(self)
        self.pkt = PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc223, algorithm='MD5')

    @classmethod
    def __str__(cls):
        return "CHAP+MD5"


class CHAP_SHA1(LCPAuthMethod):
    """Challenge-Handshake authentication protocol + SHA1"""
    def __init__(self):
        LCPAuthMethod.__init__(self)
        self.pkt = PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc223, algorithm='SHA1')

    @classmethod
    def __str__(self):
        return "CHAP+SHA1"


class MSCHAP(LCPAuthMethod):
    """Microsoft Challenge-Handshake authentication protocol"""
    def __init__(self):
        LCPAuthMethod.__init__(self)
        self.pkt = PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc223, algorithm='MS-CHAP')

    @classmethod
    def __str__(cls):
        return "MS-CHAP"


class MSCHAPv2(LCPAuthMethod):
    """Microsoft Challenge-Handshake authentication protocol v2"""
    def __init__(self):
        LCPAuthMethod.__init__(self)
        self.pkt = PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc223, algorithm="MS-CHAP-v2")

    @classmethod
    def __str__(cls):
        return "MS-CHAP-v2"


class EAP(LCPAuthMethod):
    """Extensible authentication protocol"""
    def __init__(self):
        LCPAuthMethod.__init__(self)
        self.pkt = PPP_LCP_Auth_Protocol_Option(auth_protocol=0xc227)

    @classmethod
    def __str__(cls):
        return "EAP"


class AuthMethodSet:
    """
    Helper class to hold state of all check authentication methods
    """
    MAX_TRIES = 5

    def __init__(self, methods=[PAP(), CHAP_MD5(), CHAP_SHA1(), MSCHAP(), MSCHAPv2(), EAP()]):
        """Initialize authentication method set with given method instances"""
        self.methods = {method:0 for method in methods}

    def get_next_to_try(self):
        """

        :return:
            LCPAuthMethod: LCPAuthMethod instance of next authentication method state of which is not known,
                           if state of all methods is known, it returns None
        """
        unknown_methods = sorted([method for method in self.methods.keys() if not method.is_state_known()
                                  and self.methods[method] < self.MAX_TRIES],
                                 key=lambda x: self.methods[x])
        if len(unknown_methods) <= 0:
            return None
        method_to_try = unknown_methods[0]
        self.methods[method_to_try] += 1
        return unknown_methods[0]

    def get_method(self, cls):
        """
        Returns method state instance for authentication method specified by its class
        :param cls: LCPAuthMethod subclass
        :return:
            LCPAuthMethod: Instance of LCPAuthMethod from the set, None if there is no such method
        """
        for method in self.methods.keys():
            if isinstance(method, cls):
                return method
        return None

    def set_method_state_from_option(self, option, state):
        """
        Sets state of method requested by LCPOption to provided state
        :param option: (LCPOption) LCPOption instance
        :param state: (bool) true if method should be enabled, false otherwise
        """
        for method in self.methods.keys():
            if method.is_lcp_option(option):
                if state:
                    method.set_enabled()
                else:
                    method.set_disabled()

    def get_method_for_option(self, option):
        """
        Returns method state instance for authentication method from provided LCPOption
        :param option: (LCPOption) LCPOption instance with authentication method
        :return:
            LCPAuthMethod instance from set, or None if there is no such method
        """
        for method in self.methods.keys():
            if method.is_lcp_option(option):
                return method
        return None

    def enable_method_from_option(self, option):
        """
        Mark method in provided LCPOption as enabled
        :param option: (LCPOption) LCPOption instance with authentication method
        """
        self.set_method_state_from_option(option, True)

    def disable_method_from_option(self, option):
        """
        Mark method in provided LCPOption as disabled
        :param option: (LCPOption) LCPOption instance with authentication method
        """
        self.set_method_state_from_option(option, False)

    def get_methods(self):
        """
        Get list of all method state instances from set
        :return:
            list of LCPAuthMethod instances
        """
        return [method for method in self.methods.keys()]

    def get_method_enabled_state(self, method):
        """
        Get state of method specified by LCPAuthMethod subclass
        :param method: LCPAuthMethod subclass
        :return:
            True if method is enabled
            False is method is disabled
            None if state of the method is not known
        """
        for m in self.methods.keys():
            if isinstance(m, method):
                return m.get_enabled_state()
        return None

    def get_number_of_known_methods(self):
        """
        Returns number of methods from the state state of whose is already known
        """
        known_methods_nr = 0
        for m in self.methods.keys():
            if m.is_state_known():
                known_methods_nr += 1
        return known_methods_nr

    def is_state_of_all_methods_known(self):
        """
        Whether state of all methods in set is known
        :return:
            bool:
        """
        return self.get_number_of_known_methods() == len(self.methods.keys())

    def __str__(self):
        """
        Get string representation of state of all methods
        """
        return ','.join(['{0}: {1}'.format(method, method.get_enabled_state_str()) for method in self.methods.keys()])


class EAPAuthMethod(AuthMethod):
    """ Base class for EAP authentication method state """
    def __init__(self, eap_type=None):
        """
        Initialize EAPAuthMethod for provided eap type number
        :param eap_type: (int) eap type number according to IANA
        """
        AuthMethod.__init__(self)
        self.eap_type = eap_type

    def is_eap_option(self, eap_type):
        """Compare eap type to eap type of the method"""
        return self.eap_type == eap_type

    def get_eap_nak_response(self, id):
        """
        Get EAP-Legacy-Nak response packet requesting the method
        :param id: (int) response id
        :return:
            Instance of Scapy EAP-Legacy-Nak packet
        """
        return EAP_pkt(code='Response', id=id, type='Legacy Nak', desired_auth_type=self.eap_type)

    def is_eap_request(self, request):
        """
        Check whether packet contains EAP request for the method
        :param request: Scapy packet to check
        :return:
            bool:
        """
        return EAP_pkt in request and request[EAP_pkt].type == self.eap_type

    def __str__(self):
        """
        Returns name of the EAP method according to eap type number
        """
        if self.eap_type in eap_types.keys():
            return eap_types[self.eap_type]
        else:
            return 'Unknown EAP auth method({0})'.format(self.eap_type)


def get_all_eap_authmethods():
    """
    Get method state objects for all EAP method types defined in Scapy
    :return:
        list of EAPAuthMethod instances
    """
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
    """EAP-MD5"""
    def __init__(self):
        EAPAuthMethod.__init__(self, 4)


class EAPTLS(EAPAuthMethod):
    """EAP-TLS"""
    def __init__(self):
        EAPAuthMethod.__init__(self, 13)


class EAPPEAP(EAPAuthMethod):
    """PEAP"""
    def __init__(self):
        EAPAuthMethod.__init__(self, 25)


class EAPMSCHAPv2(EAPAuthMethod):
    """MSCHAPv2"""
    def __init__(self):
        EAPAuthMethod.__init__(self, 29)


class EAPMSEAP(EAPAuthMethod):
    """MSCHAP"""
    def __init__(self):
        EAPAuthMethod.__init__(self, 26)


class EAPAuthMethodSet(AuthMethodSet):
    """Helper class to hold states of set of EAP authentication methods"""
    def __init__(self, methods=[EAPTLS(), EAPPEAP(), EAPCHAP(), EAPMSEAP()]):
        """
        Initiliaze set with EAPAuthMethod instances
        :param methods: list of EAPAuthMethod instances
        """
        AuthMethodSet.__init__(self, methods)
        self.disabled_for_identity = False

    def set_disabled_for_identity(self):
        """
        Note that all EAP methods seems to be disabled for the identity
        """
        self.disabled_for_identity = True

    def is_disabled_for_identity(self):
        """
        Check whether all EAP methods are disabled for identity
        """
        return self.disabled_for_identity

    def get_eap_method_for_request(self, request):
        """
        Returns EAPAuthMethod instance for method requested in Packet
        :param request: Scapy Packet instance
        :return:
            EAPAuthMethod instance for requested EAP method, or None
        """
        for method in self.methods.keys():
            if method.is_eap_request(request):
                return method
        return None

    def get_eap_method_for_method_type(self, eap_type):
        """
        Returns EAPAuthMethod instance for given method type number
        :param eap_type: (int) type number of EAP method
        :return:
            EAPAuthMethod instance or None
        """
        for method in self.methods.keys():
            if method.eap_type == eap_type:
                return method
        return None

    def set_method_state_from_request(self, request, state):
        """
        Set state of method from EAP-Request
        :param request: Scapy packet containing EAP
        :param state: bool
        """
        if EAP not in request:
            return
        for method in self.methods.keys():
            if method.is_eap_request(request):
                if state:
                    method.set_enabled()
                else:
                    method.set_disabled()

    def enable_option_from_request(self, request):
        """
        Enables method from EAP request
        :param request: Scapy packet containing EAP
        """
        self.set_method_state_from_request(request, True)

    def disable_method_from_request(self, request):
        """
        Disables method from EAP request
        :param request: Scapy packet containing EAP
        """
        self.set_method_state_from_request(request, False)
