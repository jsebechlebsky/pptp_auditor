#!/bin/sh

if python --version 2>&1 | grep -q '^Python 2'; then
    PYTHON=python
else
    PYTHON=python2
fi

create_virtual_env() {
    if which virtualenv > /dev/null; then
        echo "Creating virtual environment in ./.env directory"
	virtualenv .env
	if $?; then
	    echo "Failed to create virtual environment"
	    exit -1
	fi
	. .env/bin/activate
	$PYTHON ./setup.py install
	if $?; then
           echo "pptp_auditor installation into virtualenv failed"
	   rm -r .env
	   deactivate
	   exit -1
        fi
	deactivate
    else
        echo "virtualenv seems not to be available. Please install virtualenv"
	exit -1
    fi
}

if [ ! -d ".env" ]; then
     create_virtual_env	
fi

. .env/bin/activate
pptp_auditor "$@"
deactivate
