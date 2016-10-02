# -*- coding: utf-8 -*-

"""
Command line interface of the host list converter.
"""

import logging
import textwrap
import argparse

from ._meta import __version__
from .hostlist import Hostlist
from .helpers import parse_kv


def main():
    hostlist = Hostlist()

    args_parser = argparse.ArgumentParser(
        description=textwrap.dedent("""
            The host list converter (hlc).
        """),
        # epilog=__doc__,
    )
    args_parser.add_argument(
        '-V', '--version',
        action='version',
        version=__version__,
    )
    args_parser.add_argument(
        '-d', '--debug',
        help="Write debugging and higher to STDOUT|STDERR.",
        action="store_const",
        dest="loglevel",
        const=logging.DEBUG,
        default=logging.WARNING,
    )
    args_parser.add_argument(
        '-v', '--verbose',
        help="Write information and higher to STDOUT|STDERR.",
        action="store_const",
        dest="loglevel",
        const=logging.INFO,
    )
    args_parser.add_argument(
        '-q', '--quiet', '--silent',
        help="Only write errors and higher to STDOUT|STDERR.",
        action="store_const",
        dest="loglevel",
        const=logging.ERROR,
    )
    args_parser.add_argument(
        'input_file',
        help="File path to the input file to process."
        " '-' will read from STDIN.",
        #  type=argparse.FileType('r'),
        nargs='+',
    )
    args_parser.add_argument(
        '-f', '--input-format', '--from',
        help="Format of the input file."
        " Default: %(default)s.",
        default='json',
        choices=hostlist._readers.keys(),
    )
    args_parser.add_argument(
        '-o', '--output-file',
        help="Where to write the output file."
        " '-' will read from STDIN."
        " If not given, no final output will be produced.",
    )
    args_parser.add_argument(
        '-t', '--output-format', '--to',
        help="Format of the output file."
        " Default: %(default)s.",
        default='json',
        choices=hostlist._writers.keys(),
    )
    args_parser.add_argument(
        '-e', '--extra-vars',
        help="Set additional variables as key=value to change the behavior of"
        " how different input/output formats are processed.",
        action='append',
    )
    args_parser.add_argument(
        '-I', '--ignore-fqdn-regex',
        help="Regular expression checked against the input FQDNs."
        " If the regular expression matches, the FQDN will not be exported.",
    )
    args_parser.add_argument(
        '-r', '--rename-csv-file',
        help="Allows you to do mass rename via a provided CSV file."
        " It is based on substation using regular expressions."
        " The first column is a case insensitive search pattern,"
        " the second one the replacement string.",
    )
    args = args_parser.parse_args()
    logging.basicConfig(
        format='%(levelname)s: %(message)s',
        level=args.loglevel,
    )

    hostlist = Hostlist(
        ignore_fqdn_re=args.ignore_fqdn_regex,
        kv=parse_kv(', '.join(args.extra_vars)) if args.extra_vars else {},
    )
    if args.rename_csv_file:
        hostlist.read_rename_csv_file(args.rename_csv_file)

    for input_file in args.input_file:
        hostlist.read_file(input_file, args.input_format)

    hostlist.consistency_check()

    if args.output_file:
        hostlist.write_file(args.output_file, args.output_format)
