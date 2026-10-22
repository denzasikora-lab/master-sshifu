"""Короткие цветные статусы без управляющих кодов в журналах."""

import os
import sys

from . import PROJECT_NAME

COLORS = {'info': '36', 'success': '32', 'warning': '33', 'error': '31', 'muted': '90'}


def show(message, tone='info', stream=None):
    stream = stream if stream is not None else sys.stdout
    text = PROJECT_NAME + ': ' + message
    if stream.isatty() and 'NO_COLOR' not in os.environ and os.environ.get('TERM') != 'dumb':
        text = '\033[' + COLORS[tone] + 'm' + text + '\033[0m'
    print(text, file=stream, flush=True)
