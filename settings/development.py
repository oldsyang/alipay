# -*- coding: utf-8 -*-
# @Author  : oldsyang

from .common import *

if os.path.isfile(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'private.py')):
    from .private import *  # pylint: disable=import-error,wildcard-import
