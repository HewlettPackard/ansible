#!/usr/bin/python
# Copyright: (c) 2018, Hewlett Packard Enterprise Development LP
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


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
  - Create, modify and delete CPG on HPE 3PAR.
module: cpg_3par
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
    description:
      - Specifies the growth increment the amount of logical disk storage
       created on each auto-grow operation.
  growth_limit:
    description:
      - Specifies that the autogrow operation is limited to the specified
       storage amount that sets the growth limit.
  growth_warning:
    description:
      - Specifies that the threshold of used logical disk space when exceeded
       results in a warning alert.
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
      - Specifies whether certificate need to be validated while communicating
    type: bool
    default: no
  new_name:
    description:
      - Specifies the name of the CPG to update.
  disable_auto_grow:
    description:
      - Enables (false) or disables (true) CPG auto grow.
    type: bool
    default: false
  rm_growth_limit:
    description:
      - Enables (false) or disables (true) auto grow limit enforcement.
    type: bool
    default: false
  rm_warning_alert:
    description:
      - Enables (false) or disables (true) warning limit enforcement.
    type: bool
    default: false
extends_documentation_fragment: hpe3par
version_added: 2.8
'''


EXAMPLES = r'''
    - name: Create CPG sample_cpg
      cpg_3par:
        storage_system_ip: 10.10.10.1
        storage_system_username: username
        storage_system_password: password
        state: present
        cpg_name: sample_cpg
        domain: sample_domain
        growth_increment: 32000 MiB
        growth_limit: 64000 MiB
        growth_warning: 48000 MiB
        raid_type: R6
        set_size: 8
        high_availability: MAG
        disk_type: FC
        secure: no

    - name: Modify CPG sample_cpg
      cpg_3par:
        storage_system_ip: 10.10.10.1
        storage_system_username: username
        storage_system_password: password
        state: present
        cpg_name: sample_cpg
        growth_increment: 36000 MiB
        growth_limit: 65002 MiB
        growth_warning: 45000 MiB
        raid_type: R6
        set_size: 8
        high_availability: MAG
        disk_type: FC
        secure: no
        new_name: new_sample_cpg
        disable_auto_grow: false
        rm_growth_limit: false
        rm_warning_alert: false

    - name: Delete CPG sample_cpg
      cpg_3par:
        storage_system_ip: 10.10.10.1
        storage_system_username: username
        storage_system_password: password
        state: absent
        cpg_name: sample_cpg
        secure: no
'''

RETURN = r'''
'''

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.storage.hpe3par import hpe3par
try:
    from hpe3par_sdk import client
    from hpe3parclient import exceptions
    HAS_3PARCLIENT = True
except ImportError:
    HAS_3PARCLIENT = False


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
        growth_limit,
        growth_warning,
        raid_type,
        set_size,
        high_availability,
        disk_type,
        new_name,
        disable_auto_grow,
        rm_growth_limit,
        rm_warning_alert):
    try:
        ld_layout = dict()
        ld_layout_modify = dict()
        modify_only_param = dict()
        cpg_object_dict = dict()
        modify_param_dict = dict()
        optional = dict()
        disk_patterns = list()
        if disk_type:
            disk_type = getattr(client.HPE3ParClient, disk_type)
            disk_patterns.append({'diskType': disk_type})
        ld_layout.update({
            'RAIDType': raid_type,
            'setSize': set_size,
            'HA': high_availability,
            'diskPatterns': disk_patterns})
        modify_only_param.update({
            'newName': new_name,
            'disableAutoGrow': disable_auto_grow,
            'rmGrowthLimit': rm_growth_limit,
            'rmWarningAlert': rm_warning_alert})
        ld_layout = cpg_ldlayout_map(ld_layout)
        if growth_increment is not None:
            growth_increment = hpe3par.convert_to_binary_multiple(
                growth_increment)
        if growth_limit is not None:
            growth_limit = hpe3par.convert_to_binary_multiple(
                growth_limit)
        if growth_warning is not None:
            growth_warning = hpe3par.convert_to_binary_multiple(
                growth_warning)
        optional.update({
            'growthIncrementMiB': growth_increment,
            'growthLimitMiB': growth_limit,
            'usedLDWarningAlertMiB': growth_warning,
            'LDLayout': ld_layout})
        if not client_obj.cpgExists(cpg_name):
            optional.update({'domain': domain})
            client_obj.createCPG(cpg_name, optional)
        else:
            if domain is not None:
                return (False, False, "CPG domain name can not be modified")
            if new_name is not None and len(new_name) > 31:
                return (False, False, "CPG new_name should not be more than 31 characters")
            cpg_object = client_obj.getCPG(cpg_name)
            optional.update(modify_only_param)

            if optional['growthLimitMiB'] is not None and optional['rmGrowthLimit'] == True:
                return (False, False, "rmGrowthLimit can't be set to true while setting growthLimitMiB")
            if optional['growthIncrementMiB'] is not None and optional['disableAutoGrow'] == True:
                return (False, False, "disableAutoGrow can't be set to true while setting growthIncrementMiB")
            if optional['usedLDWarningAlertMiB'] is not None and optional['rmWarningAlert'] == True:
                return (False, False, "rmWarningAlert can't be set to true while setting usedLDWarningAlertMiB")
            #Creating a dictionary modify_parameter_dict by comparing the
            #parameter values of optional dictionary with cpg_object elements.
            #If entered parameter value is different from cpg_object elements
            #then we are adding such parameters in modify_parameter_dict.
            modify_parameter_dict = dict()
            if optional['growthIncrementMiB'] is not None and optional['growthIncrementMiB']:
                if optional['growthIncrementMiB'] != cpg_object.sdgrowth.increment_MiB:
                    modify_parameter_dict['growthIncrementMiB'] = optional['growthIncrementMiB']
            if optional['growthLimitMiB'] is not None and optional['growthLimitMiB']:
                if optional['growthLimitMiB'] != cpg_object.sdgrowth.limit_MiB:
                    modify_parameter_dict['growthLimitMiB'] = optional['growthLimitMiB']
            if optional['usedLDWarningAlertMiB'] is not None and optional['usedLDWarningAlertMiB']:
                if optional['usedLDWarningAlertMiB'] != cpg_object.sdgrowth.warning_MiB:
                    modify_parameter_dict['usedLDWarningAlertMiB'] = optional['usedLDWarningAlertMiB']
            if raid_type is not None:
                if optional['LDLayout']['RAIDType'] != cpg_object.sdgrowth.ld_layout.raidtype:
                    ld_layout_modify['RAIDType'] = optional['LDLayout']['RAIDType']
            if set_size is not None:
                if optional['LDLayout']['setSize'] != cpg_object.sdgrowth.ld_layout.set_size:
                    ld_layout_modify['setSize'] = optional['LDLayout']['setSize']
            if high_availability is not None:
                if optional['LDLayout']['HA'] != cpg_object.sdgrowth.ld_layout.ha:
                    ld_layout_modify['HA'] = optional['LDLayout']['HA']
            if disk_type is not None:
                if optional['LDLayout']['diskPatterns'][0]['diskType'] != cpg_object.sdgrowth.ld_layout.disk_patterns[0].disk_type:
                    ld_layout_modify['diskPatterns'] = optional['LDLayout']['diskPatterns']
            if ld_layout_modify:
                modify_parameter_dict['LDLayout'] = ld_layout_modify
            if cpg_object.sdgrowth.limit_MiB and optional['rmGrowthLimit'] == True:
                modify_parameter_dict['rmGrowthLimit'] = optional['rmGrowthLimit']
            if cpg_object.sdgrowth.increment_MiB and optional['disableAutoGrow'] == True:
                modify_parameter_dict['disableAutoGrow'] = optional['disableAutoGrow']
            if cpg_object.sdgrowth.warning_MiB and optional['rmWarningAlert'] == True:
                modify_parameter_dict['rmWarningAlert'] = optional['rmWarningAlert']
            if optional['newName'] is not None:
                modify_parameter_dict['newName'] = optional['newName']

            if not modify_parameter_dict:
                return (True, False, "CPG %s is already configured with entered parameters values" % cpg_name)
            client_obj.modifyCPG(cpg_name, modify_parameter_dict)
            
    except exceptions.ClientException as e:
        return (False, False, "CPG configuration failed | %s" % (e))
    return (True, True, "CPG %s configuration is successful." % cpg_name)


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
    growth_limit = module.params["growth_limit"]
    growth_warning = module.params["growth_warning"]
    raid_type = module.params["raid_type"]
    set_size = module.params["set_size"]
    high_availability = module.params["high_availability"]
    disk_type = module.params["disk_type"]
    secure = module.params["secure"]
    new_name = module.params["new_name"]
    disable_auto_grow = module.params["disable_auto_grow"]
    rm_growth_limit = module.params["rm_growth_limit"]
    rm_warning_alert = module.params["rm_warning_alert"]

    wsapi_url = 'https://%s:8080/api/v1' % storage_system_ip
    try:
        client_obj = client.HPE3ParClient(wsapi_url, secure)
    except exceptions.SSLCertFailed:
        module.fail_json(msg="SSL Certificate Failed")
    except exceptions.ConnectionError:
        module.fail_json(msg="Connection Error")
    except exceptions.UnsupportedVersion:
        module.fail_json(msg="Unsupported WSAPI version")
    except Exception as e:
        module.fail_json(msg="Initializing client failed. %s" % e)

    if storage_system_username is None or storage_system_password is None:
        module.fail_json(msg="Storage system username or password is None")
    if cpg_name is None:
        module.fail_json(msg="CPG Name is None")

    # States
    if module.params["state"] == "present":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = create_cpg(
                client_obj,
                cpg_name,
                domain,
                growth_increment,
                growth_limit,
                growth_warning,
                raid_type,
                set_size,
                high_availability,
                disk_type,
                new_name,
                disable_auto_grow,
                rm_growth_limit,
                rm_warning_alert
            )
        except Exception as e:
            module.fail_json(msg="CPG configuration failed | %s" % e)
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
            module.fail_json(msg="CPG delete failed | %s" % e)
        finally:
            client_obj.logout()

    if return_status:
        module.exit_json(changed=changed, msg=msg)
    else:
        module.fail_json(msg=msg)


if __name__ == '__main__':
    main()
