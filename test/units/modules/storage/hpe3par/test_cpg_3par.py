# Copyright: (c) 2018, Hewlett Packard Enterprise Development LP
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


import mock
import pytest
import sys
sys.modules['hpe3par_sdk'] = mock.Mock()
sys.modules['hpe3par_sdk.client'] = mock.Mock()
sys.modules['hpe3parclient'] = mock.Mock()
sys.modules['hpe3parclient.exceptions'] = mock.Mock()
from ansible.modules.storage.hpe3par import cpg_3par
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.storage.hpe3par import hpe3par


@mock.patch('ansible.modules.storage.hpe3par.cpg_3par.client')
@mock.patch('ansible.modules.storage.hpe3par.cpg_3par.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.cpg_3par.create_cpg')
def test_module_args(mock_create_cpg, mock_module, mock_client):
    """
    hpe3par CPG - test module arguments
    """

    PARAMS_FOR_PRESENT = {
        'storage_system_ip': '192.168.0.1',
        'storage_system_username': 'USER',
        'storage_system_password': 'PASS',
        'cpg_name': 'test_cpg',
        'domain': 'test_domain',
        'growth_increment': 32768,
        'growth_increment_unit': 'MiB',
        'growth_limit': 32768,
        'growth_limit_unit': 'MiB',
        'growth_warning': 32768,
        'growth_warning_unit': 'MiB',
        'raid_type': 'R6',
        'set_size': 8,
        'high_availability': 'MAG',
        'disk_type': 'FC',
        'state': 'present',
        'secure': False,
        'new_name': 'xyz', 
        'disable_auto_grow': False,
        'rm_growth_limit': False,
        'rm_warning_alert': False
    }
    mock_module.params = PARAMS_FOR_PRESENT
    mock_module.return_value = mock_module
    mock_client.HPE3ParClient.login.return_value = True
    mock_create_cpg.return_value = (True, True, "Created CPG successfully.")
    cpg_3par.main()
    mock_module.assert_called_with(
        argument_spec=hpe3par.cpg_argument_spec())


@mock.patch('ansible.modules.storage.hpe3par.cpg_3par.client')
@mock.patch('ansible.modules.storage.hpe3par.cpg_3par.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.cpg_3par.create_cpg')
def test_main_exit_functionality_present_success_without_issue_attr_dict(mock_create_cpg, mock_module, mock_client):
    """
    hpe3par flash cache - success check
    """
    PARAMS_FOR_PRESENT = {
        'storage_system_ip': '192.168.0.1',
        'storage_system_name': '3PAR',
        'storage_system_username': 'USER',
        'storage_system_password': 'PASS',
        'cpg_name': 'test_cpg',
        'domain': 'test_domain',
        'growth_increment': 32768,
        'growth_increment_unit': 'MiB',
        'growth_limit': 32768,
        'growth_limit_unit': 'MiB',
        'growth_warning': 32768,
        'growth_warning_unit': 'MiB',
        'raid_type': 'R6',
        'set_size': 8,
        'high_availability': 'MAG',
        'disk_type': 'FC',
        'state': 'present',
        'secure': False,
        'new_name': 'xyz', 
        'disable_auto_grow': False,
        'rm_growth_limit': False,
        'rm_warning_alert': False
    }
    # This creates a instance of the AnsibleModule mock.
    mock_module.params = PARAMS_FOR_PRESENT
    mock_module.return_value = mock_module
    instance = mock_module.return_value
    mock_client.HPE3ParClient.login.return_value = True
    mock_create_cpg.return_value = (
        True, True, "Created CPG successfully.")
    cpg_3par.main()
    # AnsibleModule.exit_json should be called
    instance.exit_json.assert_called_with(
        changed=True, msg="Created CPG successfully.")
    # AnsibleModule.fail_json should not be called
    assert instance.fail_json.call_count == 0


@mock.patch('ansible.modules.storage.hpe3par.cpg_3par.client')
@mock.patch('ansible.modules.storage.hpe3par.cpg_3par.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.cpg_3par.delete_cpg')
def test_main_exit_functionality_absent_success_without_issue_attr_dict(mock_delete_cpg, mock_module, mock_client):
    """
    hpe3par flash cache - success check
    """
    PARAMS_FOR_DELETE = {
        'storage_system_ip': '192.168.0.1',
        'storage_system_name': '3PAR',
        'storage_system_username': 'USER',
        'storage_system_password': 'PASS',
        'cpg_name': 'test_cpg',
        'domain': None,
        'growth_increment': None,
        'growth_increment_unit': None,
        'growth_limit': None,
        'growth_limit_unit': None,
        'growth_warning': None,
        'growth_warning_unit': None,
        'raid_type': None,
        'set_size': None,
        'high_availability': None,
        'disk_type': None,
        'state': 'absent',
        'secure': False,
        'new_name': 'xyz', 
        'disable_auto_grow': False,
        'rm_growth_limit': False,
        'rm_warning_alert': False
    }
    # This creates a instance of the AnsibleModule mock.
    mock_module.params = PARAMS_FOR_DELETE
    mock_module.return_value = mock_module
    instance = mock_module.return_value
    mock_delete_cpg.return_value = (
        True, True, "Deleted CPG test_cpg successfully.")
    mock_client.HPE3ParClient.login.return_value = True
    cpg_3par.main()
    # AnsibleModule.exit_json should be called
    instance.exit_json.assert_called_with(
        changed=True, msg="Deleted CPG test_cpg successfully.")
    # AnsibleModule.fail_json should not be called
    assert instance.fail_json.call_count == 0


def test_convert_to_binary_multiple():
    assert hpe3par.convert_to_binary_multiple(None) == -1
    assert hpe3par.convert_to_binary_multiple('-1.0 MiB') == -1
    assert hpe3par.convert_to_binary_multiple('-1.0GiB') == -1
    assert hpe3par.convert_to_binary_multiple('1.0   MiB') == 1
    assert hpe3par.convert_to_binary_multiple('1.5GiB') == 1.5 * 1024
    assert hpe3par.convert_to_binary_multiple('1.5 TiB') == 1.5 * 1024 * 1024
    assert hpe3par.convert_to_binary_multiple(' 1.5 TiB ') == 1.5 * 1024 * 1024


@mock.patch('ansible.modules.storage.hpe3par.cpg_3par.client')
def test_validate_set_size(mock_client):
    mock_client.HPE3ParClient.RAID_MAP = {'R0': {'raid_value': 1, 'set_sizes': [1]},
                                          'R1': {'raid_value': 2, 'set_sizes': [2, 3, 4]},
                                          'R5': {'raid_value': 3, 'set_sizes': [3, 4, 5, 6, 7, 8, 9]},
                                          'R6': {'raid_value': 4, 'set_sizes': [6, 8, 10, 12, 16]}
                                          }
    raid_type = 'R0'
    set_size = 1
    assert cpg_3par.validate_set_size(raid_type, set_size)

    set_size = 2
    assert not cpg_3par.validate_set_size(raid_type, set_size)

    raid_type = None
    assert not cpg_3par.validate_set_size(raid_type, set_size)


@mock.patch('ansible.modules.storage.hpe3par.cpg_3par.client')
def test_cpg_ldlayout_map(mock_client):
    mock_client.HPE3ParClient.PORT = 1
    mock_client.HPE3ParClient.RAID_MAP = {'R0': {'raid_value': 1, 'set_sizes': [1]},
                                          'R1': {'raid_value': 2, 'set_sizes': [2, 3, 4]},
                                          'R5': {'raid_value': 3, 'set_sizes': [3, 4, 5, 6, 7, 8, 9]},
                                          'R6': {'raid_value': 4, 'set_sizes': [6, 8, 10, 12, 16]}
                                          }
    ldlayout_dict = {'RAIDType': 'R6', 'HA': 'PORT'}
    assert cpg_3par.cpg_ldlayout_map(ldlayout_dict) == {
        'RAIDType': 4, 'HA': 1}


@mock.patch('ansible.modules.storage.hpe3par.cpg_3par.client')
def test_create_cpg(mock_client):
    cpg_3par.validate_set_size = mock.Mock(return_value=True)
    cpg_3par.cpg_ldlayout_map = mock.Mock(
        return_value={'RAIDType': 4, 'HA': 1})

    mock_client.HPE3ParClient.login.return_value = True
    mock_client.HPE3ParClient.cpgExists.return_value = False
    mock_client.HPE3ParClient.FC = 1
    mock_client.HPE3ParClient.createCPG.return_value = True

    assert cpg_3par.create_cpg(mock_client.HPE3ParClient,
                               'test_cpg',
                               'test_domain',
                               '32768 MiB',
                               '32768 MiB',
                               '32768 MiB',
                               'R6',
                               8,
                               'MAG',
                               'FC',
                               None,
                               False,
                               False,
                               False
                               ) == (True, True, "CPG %s configuration is successful." % 'test_cpg')

    mock_client.HPE3ParClient.cpgExists.return_value = True
    assert cpg_3par.create_cpg(mock_client.HPE3ParClient,
                               'test_cpg',
                               None,
                               '32768.0 MiB',
                               '32768.0 MiB',
                               '32768.0 MiB',
                               'R6',
                               8,
                               'MAG',
                               'FC',
                               None,
                               True,
                               False,
                               False
                               ) == (False, False, "disableAutoGrow can't be set to true while setting growthIncrementMiB")
    assert cpg_3par.create_cpg(mock_client.HPE3ParClient,
                               'test_cpg',
                               None,
                               '32768.0 MiB',
                               '32768.0 MiB',
                               '32768.0 MiB',
                               'R6',
                               8,
                               'MAG',
                               'FC',
                               None,
                               False,
                               True,
                               False
                               ) == (False, False, "rmGrowthLimit can't be set to true while setting growthLimitMiB")
    assert cpg_3par.create_cpg(mock_client.HPE3ParClient,
                               'test_cpg',
                               None,
                               '32768.0 MiB',
                               '32768.0 MiB',
                               '32768.0 MiB',
                               'R6',
                               8,
                               'MAG',
                               'FC',
                               None,
                               False,
                               False,
                               True
                               ) == (False, False, "rmWarningAlert can't be set to true while setting usedLDWarningAlertMiB")
    assert cpg_3par.create_cpg(mock_client.HPE3ParClient,
                               'test_cpg',
                               'test_domain',
                               '32768.0 MiB',
                               '32768.0 MiB',
                               '32768.0 MiB',
                               'R6',
                               8,
                               'MAG',
                               'FC',
                               None,
                               False,
                               False,
                               False
                               ) == (False, False, "CPG domain name can not be modified")
    assert cpg_3par.create_cpg(mock_client.HPE3ParClient,
                               'test_cpg',
                               None,
                               '32768.0 MiB',
                               '32768.0 MiB',
                               '32768.0 MiB',
                               'R6',
                               8,
                               'MAG',
                               'FC',
                               'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                               False,
                               False,
                               False
                               ) == (False, False, "CPG new_name should not be more than 31 characters")



@mock.patch('ansible.modules.storage.hpe3par.cpg_3par.client')
def test_delete_cpg(mock_client):
    mock_client.HPE3ParClient.login.return_value = True
    mock_client.HPE3ParClient.cpgExists.return_value = True
    mock_client.HPE3ParClient.FC = 1
    mock_client.HPE3ParClient.deleteCPG.return_value = True

    assert cpg_3par.delete_cpg(mock_client.HPE3ParClient,
                               'test_cpg'
                               ) == (True, True, "Deleted CPG %s successfully." % 'test_cpg')

    mock_client.HPE3ParClient.cpgExists.return_value = False

    assert cpg_3par.delete_cpg(mock_client.HPE3ParClient,
                               'test_cpg'
                               ) == (True, False, "CPG does not exist")
    assert cpg_3par.delete_cpg(mock_client.HPE3ParClient,
                               None
                               ) == (True, False, "CPG does not exist")
