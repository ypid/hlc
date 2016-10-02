import os
import sre_constants
from nose.tools import raises

from hlc import Hostlist


test_data_dir = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    'data',
)


def test_valid_ignore_fqdn_re():
    Hostlist(
        ignore_fqdn_re=r'(:?phone|android|privat)',
    )


@raises(sre_constants.error)
def test_invalid_ignore_fqdn_re():
    Hostlist(
        ignore_fqdn_re=r':?phone|android|privat)',
    )


# Formats are tested from the Makefile
def test_read_ms_dhcp_file():
    hostlist = Hostlist()
    hostlist.read_file(os.path.join(test_data_dir, 'ms_dhcp_original.csv'), 'ms_dhcp')
