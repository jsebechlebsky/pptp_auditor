# PPTP Auditor

Simple security auditing tool for PPTP VPN, allowing to discover enabled
authentication methods.


## Installation

### Automatic installation

Utility requires Python2.7, pip and virtualenv installed on target system.
When these requirements are satisfied, utility will be installed to
virtual environment `.env` together with all dependecies during
first execution of `pptp_auditor.sh` wrapper script.

### Manual installation

Utility can be installed to your Python2.7 environment by running
```
python setup.py install
```

## Running utility

Utility can be run using wrapper script `pptp_auditor.sh`, which will
also install and invoke it from dedicated virtualenv directory `.env`.

If you have installed utility manually to your (virtual) environment
you can run it by invoking `pptp_auditor` command.

To get list of all available options run
```
pptp_auditor --help
```
or
```
pptp_auditor.sh --help
```

## Examples

* Perform simple test of PPTP server running at IP `192.168.56.101`
```
pptp_auditor.sh 192.168.56.101
```
* Perform simple test of PPTP server running at domain `testdomain.com`
at non-standard port `2173`.
```
pptp_auditor.sh --port 2173 testdomain.com
```
* Perform test of PPTP server running at IP `192.168.56.101`, write log
to `log.txt`, capture communication with server to `capture.pcap`, dump
TLS certificate of server to file `certificate.pem`, test for most of EAP
authentication methods (not only those usually used with PPTP).
```
pptp_auditor.sh 192.168.56.101 --log log.txt --record_pcap capture.pcap
--dump_cert_file certificate.pem --test_all_eap_methods
```
