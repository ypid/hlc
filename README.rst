hlc
===

|Build Status| |Version| |License| |Python versions| |dev status| |pypi monthly downloads|

.. |Build Status| image:: https://travis-ci.org/ypid/hlc.svg
   :target: https://travis-ci.org/ypid/hlc

.. |Version| image:: https://img.shields.io/pypi/v/hlc.svg
   :target: https://pypi.python.org/pypi/hlc

.. |License| image:: https://img.shields.io/pypi/l/hlc.svg
   :target: https://pypi.python.org/pypi/hlc

.. |Python versions| image:: https://img.shields.io/pypi/pyversions/hlc.svg
   :target: https://pypi.python.org/pypi/hlc

.. |dev status| image:: https://img.shields.io/pypi/status/hlc.svg
   :target: https://pypi.python.org/pypi/hlc

.. |pypi monthly downloads| image:: https://img.shields.io/pypi/dm/hlc.svg
   :target: https://pypi.python.org/pypi/hlc

| **h**\ ost **l**\ ist **c**\ onveter supporting hosts(5), ethers(5) and other formats.

Python script which can convert different types of host or workstation lists. Refer
to the Synopsis_ for currently supported input and output formats.

If you need support for another input/output format it should be pretty
straight forward to add it.

Refer to the Makefile_ and the test_data_ for usage examples.

Synopsis
--------

.. code-block:: text

   usage: hlc [-h] [-V] [-d] [-v] [-q]
              [-f {paedml_linux,json,ms_dhcp,linuxmuster_net}] [-o OUTPUT_FILE]
              [-t {paedml_linux,json,ethers,hosts}] [-e EXTRA_VARS]
              [-I IGNORE_FQDN_REGEX] [-r RENAME_CSV_FILE]
              input_file [input_file ...]

   The host list converter (hlc).

   positional arguments:
     input_file            File path to the input file to process. '-' will read
                           from STDIN.

   optional arguments:
     -h, --help            show this help message and exit
     -V, --version         show program's version number and exit
     -d, --debug           Write debugging and higher to STDOUT|STDERR.
     -v, --verbose         Write information and higher to STDOUT|STDERR.
     -q, --quiet, --silent
                           Only write errors and higher to STDOUT|STDERR.
     -f {paedml_linux,json,ms_dhcp,linuxmuster_net}, --input-format {paedml_linux,json,ms_dhcp,linuxmuster_net}, --from {paedml_linux,json,ms_dhcp,linuxmuster_net}
                           Format of the input file. Default: json.
     -o OUTPUT_FILE, --output-file OUTPUT_FILE
                           Where to write the output file. '-' will read from
                           STDIN. If not given, no final output will be produced.
     -t {paedml_linux,json,ethers,hosts}, --output-format {paedml_linux,json,ethers,hosts}, --to {paedml_linux,json,ethers,hosts}
                           Format of the output file. Default: json.
     -e EXTRA_VARS, --extra-vars EXTRA_VARS
                           Set additional variables as key=value to change the
                           behavior of how different input/output formats are
                           processed.
     -I IGNORE_FQDN_REGEX, --ignore-fqdn-regex IGNORE_FQDN_REGEX
                           Regular expression checked against the input FQDNs. If
                           the regular expression matches, the FQDN will not be
                           exported.
     -r RENAME_CSV_FILE, --rename-csv-file RENAME_CSV_FILE
                           Allows you to do mass rename via a provided CSV file.
                           It is based on substation using regular expressions.
                           The first column is a case insensitive search pattern,
                           the second one the replacement string.

Install
-------

You can install hlc by invoking the following commands:

.. code-block:: bash

   gpg --recv-keys 'C505 B5C9 3B0D B3D3 38A1  B600 5FE9 2C12 EE88 E1F0'
   mkdir --parent /tmp/hlc && cd /tmp/hlc
   wget -r -nd -l 1 https://pypi.python.org/pypi/hlc --accept-regex '^https://(test)?pypi.python.org/packages/.*\.whl.*'
   current_release="$(find . -type f -name '*.whl' | sort | tail -n 1)"
   gpg -v "${current_release}.asc" && pip3 install "${current_release}"

Refer to `Verifying PyPI and Conda Packages`_ for more details.

Or if you feel lazy and agree that `pip/issues/1035 <https://github.com/pypa/pip/issues/1035>`_
should be fixed you can also install hlc like this:

.. code-block:: bash

   pip3 install hlc

Supersedes
----------

* parse_windows_dhcp_leases_csv_

Authors
-------

* `Robin Schneider <https://me.ypid.de/>`_

License
-------

`GNU Affero General Public License v3 (AGPL-3.0)`_

.. _GNU Affero General Public License v3 (AGPL-3.0): https://tldrlegal.com/license/gnu-affero-general-public-license-v3-%28agpl-3.0%29
.. _parse_windows_dhcp_leases_csv: https://github.com/hamcos/deployment-scripts/tree/master/parse_windows_dhcp_leases_csv
.. _Makefile: https://github.com/ypid/hlc/blob/master/Makefile
.. _test_data: https://github.com/ypid/hlc/tree/master/tests/data
.. _Verifying PyPI and Conda Packages: stuartmumford.uk/blog/verifying-pypi-and-conda-packages.html
