#!/usr/bin/python

# (C) Copyright [2018] Hewlett Packard Enterprise Development LP
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of version 3 or later of the GNU General Public License
# as published by the Free Software Foundation.  Alternatively, at your
# choice, you may also redistribute it and/or modify it under the terms
# of the Apache License, version 2.0, available at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <https://www.gnu.org/licenses/>

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = r'''
---
short_description: Manage HPE 3PAR CPG
author:
  - Farhan Nomani (@farhan7500)
  - Gautham P Hegde (@gautamphegde)
description:
  - Create and delete CPG on HPE 3PAR.
module: hpe3par_cpg
options:
  cpg_name:
    description:
      - Name of the CPG.
    required: true
  disk_type:
    choices:
      - FC
      - NL
      - SSD
    description:
      - Specifies that physical disks must have the specified device type.
  domain:
    description:
      - Specifies the name of the domain in which the object will reside.
  growth_increment:
    default: -1.0
    description:
      - Specifies the growth increment the amount of logical disk storage
       created on each auto-grow operation.
  growth_increment_unit:
    choices:
      - MiB
      - GiB
      - TiB
    default: GiB
    description:
      - Unit of growth increment.
  growth_limit:
    default: -1.0
    description:
      - Specifies that the autogrow operation is limited to the specified
       storage amount that sets the growth limit.
  growth_limit_unit:
    choices:
      - MiB
      - GiB
      - TiB
    default: GiB
    description:
      - Unit of growth limit.
  growth_warning:
    default: -1.0
    description:
      - Specifies that the threshold of used logical disk space when exceeded
       results in a warning alert.
  growth_warning_unit:
    choices:
      - MiB
      - GiB
      - TiB
    default: GiB
    description:
      - Unit of growth warning.
  high_availability:
    choices:
      - PORT
      - CAGE
      - MAG
    description:
      - Specifies that the layout must support the failure of one port pair,
       one cage, or one magazine.
  raid_type:
    choices:
      - R0
      - R1
      - R5
      - R6
    description:
      - Specifies the RAID type for the logical disk.
  set_size:
    default: -1
    description:
      - Specifies the set size in the number of chunklets.
  state:
    choices:
      - present
      - absent
    description:
      - Whether the specified CPG should exist or not.
    required: true
  secure:
    description:
      - Specifies whether cerificate need to be installed while communicating
    type: bool
    default: false
extends_documentation_fragment: hpe3par
version_added: 2.7
'''


EXAMPLES = r'''
    - name: Create CPG sample_cpg
      hpe3par_cpg:
        storage_system_ip: 10.10.10.1
        storage_system_username: username
        storage_system_password: password
        state: present
        cpg_name: sample_cpg
        domain: sample_domain
        growth_increment: 32000
        growth_increment_unit: MiB
        growth_limit: 64000
        growth_limit_unit: MiB
        growth_warning: 48000
        growth_warning_unit: MiB
        raid_type: R6
        set_size: 8
        high_availability: MAG
        disk_type: FC
        secure: false

    - name: Delete CPG sample_cpg
      hpe3par_cpg:
        storage_system_ip: 10.10.10.1
        storage_system_username: username
        storage_system_password: password
        state: absent
        cpg_name: sample_cpg
        secure: false
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils import hpe3par, basic
try:
    from hpe3par_sdk import client
    from hpe3parclient import exceptions
    HAS_3PARCLIENT = True
except ImportError:
    HAS_3PARCLIENT = False


def convert_to_binary_multiple(size, size_unit):
    if size_unit == 'GiB':
        suffix = 'G'
    if size_unit == 'MiB':
        suffix = 'M'
    if size_unit == 'TiB':
        suffix = 'T'

    size_kib = basic.human_to_bytes(str(size) + suffix)
    return int(size_kib / (1024 * 1024))


def validate_set_size(raid_type, set_size):
    if raid_type is not None or set_size is not None:
        set_size_array = client.HPE3ParClient.RAID_MAP[raid_type]['set_sizes']
        if set_size in set_size_array:
            return True
    return False


def cpg_ldlayout_map(ldlayout_dict):
    if ldlayout_dict['RAIDType'] is not None and ldlayout_dict['RAIDType']:
        ldlayout_dict['RAIDType'] = client.HPE3ParClient.RAID_MAP[
            ldlayout_dict['RAIDType']]['raid_value']
    if ldlayout_dict['HA'] is not None and ldlayout_dict['HA']:
        ldlayout_dict['HA'] = getattr(
            client.HPE3ParClient, ldlayout_dict['HA'])
    return ldlayout_dict


def create_cpg(
        client_obj,
        cpg_name,
        domain,
        growth_increment,
        growth_increment_unit,
        growth_limit,
        growth_limit_unit,
        growth_warning,
        growth_warning_unit,
        raid_type,
        set_size,
        high_availability,
        disk_type):
    try:
        if not validate_set_size(raid_type, set_size):
            return (False, False, "Set size not part of RAID set", {})
        if not client_obj.cpgExists(cpg_name):
            ld_layout = dict()
            disk_patterns = []
            if disk_type is not None and disk_type:
                disk_type = getattr(client.HPE3ParClient, disk_type)
                disk_patterns = [{'diskType': disk_type}]
            ld_layout = {
                'RAIDType': raid_type,
                'setSize': set_size,
                'HA': high_availability,
                'diskPatterns': disk_patterns}
            ld_layout = cpg_ldlayout_map(ld_layout)
            if growth_increment is not None:
                growth_increment = convert_to_binary_multiple(
                    growth_increment, growth_increment_unit)
            if growth_limit is not None:
                growth_limit = convert_to_binary_multiple(
                    growth_limit, growth_limit_unit)
            if growth_warning is not None:
                growth_warning = convert_to_binary_multiple(
                    growth_warning, growth_warning_unit)
            optional = {
                'domain': domain,
                'growthIncrementMiB': growth_increment,
                'growthLimitMiB': growth_limit,
                'usedLDWarningAlertMiB': growth_warning,
                'LDLayout': ld_layout}
            client_obj.createCPG(cpg_name, optional)
        else:
            return (True, False, "CPG already present")
    except exceptions.ClientException as e:
        return (False, False, "CPG creation failed | %s" % (e))
    return (True, True, "Created CPG %s successfully." % cpg_name)


def delete_cpg(
        client_obj,
        cpg_name):
    try:
        if client_obj.cpgExists(cpg_name):
            client_obj.deleteCPG(cpg_name)
        else:
            return (True, False, "CPG does not exist")
    except exceptions.ClientException as e:
        return (False, False, "CPG delete failed | %s" % e)
    return (True, True, "Deleted CPG %s successfully." % cpg_name)


def main():

    module = AnsibleModule(argument_spec=hpe3par.cpg_argument_spec())
    if not HAS_3PARCLIENT:
        module.fail_json(msg='the python hpe3par_sdk library is required (https://pypi.org/project/hpe3par_sdk)')

    if len(module.params["cpg_name"]) < 1 or len(module.params["cpg_name"]) > 31:
        module.fail_json(msg="CPG name must be atleast 1 character and not more than 31 characters")

    storage_system_ip = module.params["storage_system_ip"]
    storage_system_username = module.params["storage_system_username"]
    storage_system_password = module.params["storage_system_password"]
    cpg_name = module.params["cpg_name"]
    domain = module.params["domain"]
    growth_increment = module.params["growth_increment"]
    growth_increment_unit = module.params["growth_increment_unit"]
    growth_limit = module.params["growth_limit"]
    growth_limit_unit = module.params["growth_limit_unit"]
    growth_warning = module.params["growth_warning"]
    growth_warning_unit = module.params["growth_warning_unit"]
    raid_type = module.params["raid_type"]
    set_size = module.params["set_size"]
    high_availability = module.params["high_availability"]
    disk_type = module.params["disk_type"]
    secure = module.params["secure"]

    wsapi_url = 'https://%s:8080/api/v1' % storage_system_ip
    client_obj = client.HPE3ParClient(wsapi_url, secure)

    # States
    if module.params["state"] == "present":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = create_cpg(
                client_obj,
                cpg_name,
                domain,
                growth_increment,
                growth_increment_unit,
                growth_limit,
                growth_limit_unit,
                growth_warning,
                growth_warning_unit,
                raid_type,
                set_size,
                high_availability,
                disk_type
            )
        except Exception as e:
            module.fail_json(msg="CPG create failed | %s" % e)
        finally:
            client_obj.logout()

    elif module.params["state"] == "absent":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = delete_cpg(
                client_obj,
                cpg_name
            )
        except Exception as e:
            module.fail_json(msg="CPG create failed | %s" % e)
        finally:
            client_obj.logout()

    if return_status:
        module.exit_json(changed=changed, msg=msg)
    else:
        module.fail_json(msg=msg)


if __name__ == '__main__':
    main()
