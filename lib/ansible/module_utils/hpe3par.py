# (C) Copyright 2018 Hewlett Packard Enterprise Development LP
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of version 3 or later of the GNU General Public License as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program.  If not, see <https://www.gnu.org/licenses/>

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
            "type": "float",
            "default": -1.0
        },
        "growth_increment_unit": {
            "type": "str",
            "choices": ['TiB', 'GiB', 'MiB'],
            "default": 'GiB'
        },
        "growth_limit": {
            "type": "float",
            "default": -1.0
        },
        "growth_limit_unit": {
            "type": "str",
            "choices": ['TiB', 'GiB', 'MiB'],
            "default": 'GiB'
        },
        "growth_warning": {
            "type": "float",
            "default": -1.0
        },
        "growth_warning_unit": {
            "type": "str",
            "choices": ['TiB', 'GiB', 'MiB'],
            "default": 'GiB'
        },
        "raid_type": {
            "required": False,
            "type": "str",
            "choices": ['R0', 'R1', 'R5', 'R6']
        },
        "set_size": {
            "required": False,
            "type": "int",
            "default": -1
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
