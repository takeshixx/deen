import logging

import deen.constants


def getLogger(name='', level=0, log_format=None):
    if not log_format:
        log_format = deen.constants.verbose_log_format
    formatter = logging.Formatter(log_format)
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger = logging.getLogger(name)
    levels = [logging.WARN, logging.DEBUG]
    logger.setLevel(levels[min(level, len(levels) - 1)])
    logger.addHandler(ch)
    return logger


DEEN_LOG = getLogger('deen')
