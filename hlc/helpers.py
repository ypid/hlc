# -*- coding: utf-8 -*-

"""
Helper functions of the host list converter.
"""

import re


# https://stackoverflow.com/questions/5286541/how-can-i-flatten-lists-without-splitting-strings/5286571#5286571
def flatten(foo):
    for x in foo:
        if hasattr(x, '__iter__') and not isinstance(x, str):
            for y in flatten(x):
                yield y
        else:
            yield x


def parse_kv(vars_string):
    extra_vars = {}
    if vars_string:
        for kv in re.split(r'[,;]\s*', vars_string):
            k, v = kv.split('=')
            extra_vars[k] = v
    return extra_vars
