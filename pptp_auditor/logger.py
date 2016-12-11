import logging

_LOGGER_NAME = 'pptp_auditor_logger'
_LOGGER = logging.getLogger(_LOGGER_NAME)


def get_logger():
    return _LOGGER


def setup_logger(args):
    _LOGGER.setLevel(args.loglevel)
    ch = logging.FileHandler(args.logfile, args.logfile_mode)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s')
    ch.setFormatter(formatter)

    _LOGGER.addHandler(ch)


def write_log(level, category, message):
    msg = '{0}: {1}'.format(category, message)
    _LOGGER.log(level, msg)


def write_log_debug(category, message):
    write_log(logging.DEBUG, category, message)


def write_log_info(category, message):
    write_log(logging.INFO, category, message)


def write_log_warning(category, message):
    write_log(logging.WARNING, category, message)


def write_log_error(category, message):
    write_log(logging.ERROR, category, message)