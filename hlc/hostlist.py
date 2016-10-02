# -*- coding: utf-8 -*-

"""
The core of the host list converter.
"""

import sys
import logging
import re
import csv
import json
from operator import itemgetter
import collections

from netaddr import IPAddress, EUI, valid_mac, mac_unix_expanded

from .helpers import flatten, parse_kv


class Hostlist:

    _CSV_FIELD_NOT_USED = ''

    # Key: Tag to add to the host if one of the regex patterns matches the hostname.
    # Value: List of regex objects.
    _HOSTNAME_TAGS_RE_DICT = {
    }

    # Additionally supported: 'domain'
    _DEFAULT_KV = {
        'write.paedml_linux.ldap_ou': 'schule',
        'write.paedml_linux.subnetwork_id': '10.1.0.0/24',
        # BIOS: 0; UEFI: 1
        'write.paedml_linux.system_fw': 0,
        'write.paedml_linux.type': 'ipmanagedclient',
        'write.paedml_linux.delimiter': '\t',
        'read.paedml_linux.delimiter': '\t',
        'hosts.include_hostname': 'true',
        'hosts.description': 'false',
        'ethers.description': 'true',
        # E: LAN, Ethernet
        # W: WLAN
        # WA: WAN, DSL
        # B: Bluetooth
        'ethers.0_mac_address_name_prefix': 'E_',
        'ethers.1_mac_address_name_prefix': 'W_',
        # https://tools.ietf.org/html/rfc4343
        # Domain Name System (DNS) Case Insensitivity Clarification
        'sanitize.hostname': 'true',
        'sanitize.fqdn': 'true',
    }

    # Key: LMZ paedML Linux host type to add if one of the regex patterns matches the hostname.
    # Value: List of regex objects.
    _HOSTNAME_LMZ_PAEDML_LINUX_TYPE_RE_DICT = {
        # Univention Corporate Client (Linux, UCC)
        #  'ucc': re.compile()
        #
        # Windows-System managed via OPSI
        'windows': [
            re.compile(
                r'''
                (:?
                    (:?
                        pc|
                        nb|
                        computer
                    )[0-9]+
                    |
                    teacher|
                    lehrer
                )
                ''',
                re.IGNORECASE | re.VERBOSE
            )
        ],
        # Device with IP address (printer, AP)
        'ipmanagedclient': [
            re.compile(
                r'''
                (:?
                    (:?
                        ap|
                        printer
                    )[0-9]+
                )
                ''',
                re.IGNORECASE | re.VERBOSE
            )
        ],
    }

    def __init__(
        self,
        readers=None,
        writers=None,
        ignore_fqdn_re=None,
        kv={},
    ):

        self._hosts = []
        self._host_rename_spec = []
        self._ignore_fqdn_re = None
        self._readers = {
            'paedml_linux': self._read_paedml_linux_file,
            'linuxmuster_net': self._read_linuxmuster_net_file,
            'ms_dhcp': self._read_ms_dhcp_file,
            'json': self._read_json_file,
        }
        self._writers = {
            'paedml_linux': self._write_paedml_linux_file,
            'json': self._write_json_file,
            'ethers': self._write_ethers_file,
            'hosts': self._write_hosts_file,
            #  'linuxmuster.net': None,
        }
        self._kv = self._DEFAULT_KV
        self._kv.update(kv)

        if readers:
            self._readers = readers
        if writers:
            self._writers = writers
        if ignore_fqdn_re:
            self._ignore_fqdn_re = re.compile(ignore_fqdn_re)

    def read_rename_csv_file(self, csv_file):
        with open(csv_file, newline='') as csvfile:
            csv_reader = csv.reader(csvfile, delimiter=',', quotechar='|')
            for item in csv_reader:
                if len(item) < 2:
                    logging.debug(
                        "Line has less than two cells "
                        " in file: {}".format(
                            csv_file,
                        )
                    )
                    continue

                kv = {}
                if len(item) > 2:
                    kv = parse_kv(', '.join(item[2:]))
                self._host_rename_spec.append({
                    'pattern': item[0],
                    'repl': item[1],
                    'kv': kv,
                })

    def _get_sanitized_hostname(self, raw_hostname):
        return re.sub(r'[^\w_-]', '_', raw_hostname, re.IGNORECASE)

    def add_host(self, host_data):
        if not host_data:
            return False

        if not self._check_host_data(host_data):
            return False

        self._sanitize_host_data(host_data)

        self._complement_host_data(host_data)
        self._user_sanitize_host_data(host_data)
        self._sanitize_host_data(host_data)
        self._user_complement_host_data(host_data)
        self._sanitize_host_data(host_data)
        self._complement_host_data(host_data)

        self._hosts.append(host_data)

    def consistency_check(self):
        self._check_for_duplicate('fqdn', severity='warning')
        self._check_for_duplicate('mac_addresses', severity='fatal')

    def _check_for_duplicate(self, entry, additional_list=[], severity='fatal'):
        check_list = [k[entry] for k in self._hosts if entry in k]
        check_list.extend(additional_list)
        flattened_check_list = list(flatten(check_list))

        duplicate_items = [e for e, count in collections.Counter(flattened_check_list).items()
                           if count > 1]
        if len(duplicate_items) > 0:
            msg = "Duplicate {} detected: {}".format(
                entry,
                ', '.join(duplicate_items),
            )
            if severity == 'fatal':
                raise Exception(msg)
            else:
                logging.warning(msg)
        return True

    def _check_host_data(self, host_data):
        if self._ignore_fqdn_re and self._ignore_fqdn_re.search(host_data['fqdn']):
            logging.warning(
                "Ignoring line: {}"
                "FQDN ({}) matched ignore FQDN regex.".format(
                    host_data['_raw_input'],
                    host_data['fqdn'],
                )
            )
            return False

        for ip_address in host_data.get('ip_addresses', []):
            try:
                IPAddress(ip_address)
            except:
                logging.warning(
                    "Ignoring line with invalid IP address ({}): {}".format(
                        ip_address,
                        host_data['_raw_input'],
                    )
                )
                return False

        for mac_address in host_data.get('mac_addresses', []):
            if not valid_mac(mac_address):
                logging.warning(
                    "Ignoring line with invalid MAC address ({}): {}".format(
                        mac_address,
                        host_data['_raw_input'],
                    )
                )
                return False

        return True

    def _sanitize_host_data(self, host_data):
        if 'hostname' in host_data and self._kv['sanitize.hostname'] == 'true':
            host_data['hostname'] = host_data['hostname'].lower()

        if 'fqdn' in host_data and self._kv['sanitize.fqdn'] == 'true':
            host_data['fqdn'] = host_data['fqdn'].lower()

        if 'mac_addresses' in host_data:
            mac_addresses = []
            for mac_address in host_data['mac_addresses']:
                mac = EUI(mac_address)
                mac.dialect = mac_unix_expanded
                mac_addresses.append(str(mac))
            host_data['mac_addresses'] = mac_addresses

        if not host_data.get('description', True):
            del host_data['description']

    def _user_sanitize_host_data(self, host_data):
        if len(self._host_rename_spec) == 0:
            return

        done_entries = []
        for e in self._host_rename_spec:
            kv = e.get('kv', {})
            entries = kv.get('entries', 'fqdn hostname').split(' ')
            flush_entries = kv.get('flush_entries', 'fqdn hostname').split(' ')
            control = kv.get('control', '').split(' ')

            for entry in entries:
                if entry not in host_data or entry in done_entries:
                    continue

                repl = re.sub(
                    e['pattern'],
                    e['repl'].format(
                        description=self._get_sanitized_hostname(
                            host_data.get('description', '')),
                        fqdn=host_data.get('fqdn', ''),
                    ),
                    host_data[entry],
                    0,
                    re.IGNORECASE,
                )
                if host_data[entry] != repl:
                    host_data[entry] = repl
                    if 'last' in control:
                        done_entries.append(entry)
                    if entry in host_data['_complemented_entries'] and entry in flush_entries:
                        del host_data[entry]

    def _get_tags_for_re_dict(self, entry_to_check, re_dict, max_tags=1):
        tags = []
        for tag, re_list in re_dict.items():
            for re_obj in re_list:
                if re_obj.search(entry_to_check):
                    tags.append(tag)
                    break
            if len(tags) > max_tags:
                logging.warning(
                    "Added more tags then expected for '{}'."
                    " Expected: {}."
                    " Got: {} ({}).".format(
                        entry_to_check,
                        max_tags,
                        len(tags),
                        ', '.join(tags),
                    )
                )
        return tags

    def _get_desc_for_entry(self, host_data, entry):
        attr_list = []
        if entry in host_data:
            if isinstance(host_data[entry], str):
                attr_list.append(host_data[entry])
            elif isinstance(host_data[entry], dict):
                attr_list.extend(list(host_data[entry].values()))
        return ', '.join(attr_list)

    def _complement_host_data(self, host_data):
        host_data.setdefault('_complemented_entries', [])

        if 'fqdn' in host_data and 'hostname' not in host_data:
            host_data['hostname'] = '{}.'.format(host_data['fqdn']).split('.', 1)[0]
            host_data['_complemented_entries'].append('hostname')

        if 'fqdn' not in host_data and 'hostname' in host_data and 'domain' in self._kv:
            host_data['fqdn'] = '.'.join([host_data['hostname'], self._kv['domain']])
            host_data['_complemented_entries'].append('fqdn')

        if 'description' not in host_data:
            entries = ('location', 'group')
            description = []
            for entry in entries:
                attr_str = self._get_desc_for_entry(host_data, entry)
                if attr_str:
                    description.append('{}: {}'.format(entry, attr_str))
            if description:
                host_data['description'] = '; '.join(description)
                host_data['_complemented_entries'].append('description')

    def _user_complement_host_data(self, host_data):

        if 'paedml_linux_type' not in host_data and 'hostname' in host_data:
            paedml_linux_type = self._get_tags_for_re_dict(
                host_data['hostname'],
                self._HOSTNAME_LMZ_PAEDML_LINUX_TYPE_RE_DICT,
            )
            if len(paedml_linux_type) >= 1:
                host_data['paedml_linux_type'] = paedml_linux_type[0]

    def _get_delimiter(self, delimiter_key):
        raw_delimiter = self._kv[delimiter_key]
        delimiter_map = {
            'comma': ',',
            'tab': '\t',
        }
        return delimiter_map.get(raw_delimiter, raw_delimiter)

    def read_file(self, input_file, input_format):
        if input_file == '-':
            self._readers[input_format](sys.stdin, input_format)
        else:
            with open(input_file, newline='') as input_fh:
                self._readers[input_format](input_fh, input_format)

    def _read_json_file(self, input_fh, input_format):
        self._hosts.extend(json.load(input_fh))

    def _read_ms_dhcp_file(self, input_fh, input_format):
        csv_reader = csv.reader(input_fh, delimiter=',', quotechar='|')
        for item in csv_reader:
            _raw_input = ', '.join(item)
            try:
                host_data = {
                    'ip_addresses': [item[0]],
                    'fqdn': item[1],
                    'description': item[5],
                    '_raw_input': _raw_input,
                    '_input_format': input_format,
                }
            except:
                logging.warning(
                    "Caught exception for line: {}".format(
                        _raw_input,
                    )
                )
                continue

            mac_address = item[4]
            if not valid_mac(mac_address):
                # I have seen a MAC address with a tailing '00000' behind.
                # But in this case, a second entry with the same, valid MAC
                # address followed.
                # Not sure what that says about the quality of the Windows DHCP
                # Server …
                logging.info(
                    "Invalid MAC address ({}), ignoring line: {}".format(
                        mac_address,
                        host_data['_raw_input'],
                    )
                )
                continue

            host_data.setdefault('mac_addresses', [])
            host_data['mac_addresses'].append(mac_address)
            self.add_host(host_data)

    def _read_linuxmuster_net_file(self, input_fh, input_format):
        """
        Raum;Hostname;Gruppe;MAC;IP;1;1;1;1;1;PXE;Optionen
        Refer to `man workstations(5)` on a linuxmuster.net Server for details.
        TODO: In my actual workstations file group and hostname seem to be
        flipped? And there is a subnetmask.
        """
        csv_reader = csv.reader(input_fh, delimiter=';', quotechar='|')
        for item in csv_reader:
            _raw_input = ', '.join(item)
            try:
                host_data = {
                    'location': {
                        'room': item[0],
                    },
                    'group': item[2],
                    'hostname': item[1],
                    'mac_addresses': [item[3]],
                    'ip_addresses': [item[4]],
                    '_raw_input': _raw_input,
                    '_input_format': input_format,
                }
            except:
                logging.warning(
                    "Caught exception for line: {}".format(
                        _raw_input,
                    )
                )
                continue

            self.add_host(host_data)

    def _read_paedml_linux_file(self, input_fh, input_format):
        csv_reader = csv.reader(
            input_fh,
            delimiter=self._get_delimiter('read.paedml_linux.delimiter'),
            quotechar='"',
        )
        for item in csv_reader:
            _raw_input = ', '.join(item)
            try:
                mac_addresses = []
                mac_addresses.append(item[2])
                try:
                    if item[11]:
                        mac_addresses.extend(item[11].split(','))
                except IndexError:
                    pass

                host_data = {
                    'paedml_linux_type': item[0],
                    'hostname': item[1],
                    'mac_addresses': mac_addresses,
                    'paedml_linux_ldap_ou': item[3],
                    'paedml_linux_subnetwork_id': item[4],
                    'description': item[5],
                    'paedml_linux_system_fw': item[10],
                    '_raw_input': _raw_input,
                    '_input_format': input_format,
                }
            except:
                logging.warning(
                    "Caught exception for line: {}".format(
                        _raw_input,
                    )
                )
                continue

            if host_data.get('hostname', False) and mac_addresses:
                self.add_host(host_data)

    def write_file(self, output_file, output_format):
        # Make output deterministic.
        self._hosts = sorted(
            self._hosts,
            key=itemgetter('hostname'),
        )
        if output_file == '-':
            self._writers[output_format](sys.stdout, output_format)
        else:
            with open(output_file, 'w', newline='', encoding='utf-8') as output_fh:
                if output_format in ['ethers', 'hosts']:
                    output_fh.write('# Generated by the host list converter (hlc)\n')
                self._writers[output_format](output_fh, output_format)

    def _write_json_file(self, output_fh, output_format):
        json.dump(
            self._hosts,
            output_fh,
            sort_keys=True,
            indent=2,
        )
        output_fh.write('\n')

    def _write_paedml_linux_file(self, output_fh, output_format):
        csv_writer = csv.writer(
            output_fh,
            delimiter=self._get_delimiter('write.paedml_linux.delimiter'),
            # https://stackoverflow.com/a/17725590
            lineterminator='\n',
            quotechar='|',
            quoting=csv.QUOTE_MINIMAL,
        )
        for host_data in self._hosts:
            csv_writer.writerow([
                host_data.get('paedml_linux_type', self._kv['write.paedml_linux.type']),
                host_data['hostname'],
                host_data['mac_addresses'][0],
                host_data.get('paedml_linux_ldap_ou', self._kv['write.paedml_linux.ldap_ou']),
                host_data.get(
                    'paedml_linux_subnetwork_id',
                    self._kv['write.paedml_linux.subnetwork_id']),
                host_data.get('description', self._CSV_FIELD_NOT_USED),  # Inventory ID
                self._CSV_FIELD_NOT_USED,
                self._CSV_FIELD_NOT_USED,
                self._CSV_FIELD_NOT_USED,
                self._CSV_FIELD_NOT_USED,
                host_data.get('paedml_linux_system_fw', self._kv['write.paedml_linux.system_fw']),
                ','.join(host_data['mac_addresses'][1:]),
            ])

    def _write_ethers_file(self, output_fh, output_format):
        for host_data in self._hosts:
            if 'mac_addresses' not in host_data:
                continue

            if 'description' in host_data and self._kv['ethers.description'] == 'true':
                output_fh.write('# {}:\n'.format(host_data['description']))

            for ind, mac_address in enumerate(host_data['mac_addresses']):
                ethers_hostname = host_data['fqdn']
                if not re.match(r'(:?E|WA?|B)_', ethers_hostname, re.IGNORECASE):
                    if ind == 0 and self._kv['ethers.0_mac_address_name_prefix'] != 'none':
                        ethers_hostname = self._kv['ethers.0_mac_address_name_prefix'] \
                            + ethers_hostname
                    if ind == 1 and self._kv['ethers.1_mac_address_name_prefix'] != 'none':
                        ethers_hostname = self._kv['ethers.1_mac_address_name_prefix'] \
                            + ethers_hostname
                output_fh.write('{} {}\n'.format(
                    mac_address,
                    ethers_hostname,
                ))

    def _write_hosts_file(self, output_fh, output_format):
        for host_data in self._hosts:
            if 'ip_addresses' not in host_data:
                continue

            if 'description' in host_data and self._kv['hosts.description'] == 'true':
                output_fh.write('# {}:\n'.format(host_data['description']))

            names = [host_data['fqdn']]
            if self._kv['hosts.include_hostname'] == 'true':
                names.append(host_data['hostname'])
            for ip_address in host_data['ip_addresses']:
                output_fh.write('{:20} {}\n'.format(
                    ip_address,
                    ' '.join(names),
                ))
