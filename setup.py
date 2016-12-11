#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name='pptp_auditor',
    version='0.0.1.dev1',
    description='Security auditing tool for PPTP VPN',
    author='Ján Sebechlebský',
    author_email='sebechlebskyjan@gmail.com',
    keywords='pptp,vpn,security,audit,pap,chap,mschap,eap',
    license='GPLv3',
    url='https://github.com/jsebechlebsky/pptp_auditor',
    packages=['pptp_auditor', 'scapy_pptp'],
    entry_points={
        'console_scripts': [
            'pptp_auditor=pptp_auditor.pptp_auditor:main',
        ],
    },
    dependency_links=['http://github.com/jsebechlebsky/scapy-ssl_tls/tarball/scapy233_compat#egg=scapy-ssl_tls-1.3.0'],
    install_requires=['scapy-ssl_tls==1.3.0', 'texttable'],
)

