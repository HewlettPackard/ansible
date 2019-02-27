# Copyright: (c) 2018, Hewlett Packard Enterprise Development LP
# Simplified BSD License (see licenses/simplified_bsd.txt or https://opensource.org/licenses/BSD-2-Clause)

from ansible.module_utils import basic


def convert_to_binary_multiple(size_with_unit):
    if size_with_unit is None:
        return -1
    valid_units = ['MiB', 'GiB', 'TiB']
    valid_unit = False
    for unit in valid_units:
        if size_with_unit.strip().endswith(unit):
            valid_unit = True
            size = size_with_unit.split(unit)[0]
            if float(size) < 0:
                return -1
    if not valid_unit:
        raise ValueError("%s does not have a valid unit. The unit must be one of %s" % (size_with_unit, valid_units))

    size = size_with_unit.replace(" ", "").split('iB')[0]
    size_kib = basic.human_to_bytes(size)
    return int(size_kib / (1024 * 1024))


storage_system_spec = {
    "storage_system_ip": {
        "required": True,
        "type": "str"
    },
    "storage_system_username": {
        "required": True,
        "type": "str",
        "no_log": True
    },
    "storage_system_password": {
        "required": True,
        "type": "str",
        "no_log": True
    },
    "secure": {
        "type": "bool",
        "default": False
    }
}


def cpg_argument_spec():
    spec = {
        "state": {
            "required": True,
            "choices": ['present', 'absent'],
            "type": 'str'
        },
        "cpg_name": {
            "required": True,
            "type": "str"
        },
        "domain": {
            "type": "str"
        },
        "growth_increment": {
            "type": "str",
        },
        "growth_limit": {
            "type": "str",
        },
        "growth_warning": {
            "type": "str",
        },
        "raid_type": {
            "required": False,
            "type": "str",
            "choices": ['R0', 'R1', 'R5', 'R6']
        },
        "set_size": {
            "required": False,
            "type": "int"
        },
        "high_availability": {
            "type": "str",
            "choices": ['PORT', 'CAGE', 'MAG']
        },
        "disk_type": {
            "type": "str",
            "choices": ['FC', 'NL', 'SSD']
        }
    }
    spec.update(storage_system_spec)
    return spec


def host_argument_spec():
    spec = {
        "state": {
            "required": True,
            "choices": [
                'present',
                'absent',
                'modify',
                'add_initiator_chap',
                'remove_initiator_chap',
                'add_target_chap',
                'remove_target_chap',
                'add_fc_path_to_host',
                'remove_fc_path_from_host',
                'add_iscsi_path_to_host',
                'remove_iscsi_path_from_host'],
            "type": 'str'},
        "host_name": {
            "type": "str"},
        "host_domain": {
            "type": "str"},
        "host_new_name": {
            "type": "str"},
        "host_fc_wwns": {
            "type": "list"},
        "host_iscsi_names": {
            "type": "list"},
        "host_persona": {
            "required": False,
            "type": "str",
            "choices": [
                "GENERIC",
                "GENERIC_ALUA",
                "GENERIC_LEGACY",
                "HPUX_LEGACY",
                "AIX_LEGACY",
                "EGENERA",
                "ONTAP_LEGACY",
                "VMWARE",
                "OPENVMS",
                "HPUX",
                "WINDOWS_SERVER"]},
        "force_path_removal": {
            "type": "bool"},
        "chap_name": {
            "type": "str"},
        "chap_secret": {
            "type": "str"},
        "chap_secret_hex": {
            "type": "bool"}
    }
    spec.update(storage_system_spec)
    return spec
