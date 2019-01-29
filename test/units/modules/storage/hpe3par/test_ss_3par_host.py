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
from ansible.modules.storage.hpe3par import ss_3par_host
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.storage.hpe3par import hpe3par


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.create_host')
def test_module_args(mock_create_host, mock_module, mock_client):
    """
    hpe3par CPG - test module arguments
    """
    PARAMS_FOR_PRESENT = {
        'state': 'present',
        'storage_system_ip': '192.168.0.1',
        'storage_system_username': 'USER',
        'storage_system_password': 'PASS',
        'host_name': 'host',
        'host_domain': 'domain',
        'host_new_name': 'new',
        'host_fc_wwns': ['PASS'],
        'host_iscsi_names': ['host'],
        'host_persona': 'GENERIC',
        'force_path_removal': 'true',
        'chap_name': 'chap',
        'chap_secret': 'secret',
        'chap_secret_hex': 'true',
        'secure': False}

    mock_module.params = PARAMS_FOR_PRESENT
    mock_module.return_value = mock_module
    mock_client.HPE3ParClient.login.return_value = True
    mock_create_host.return_value = (True, True, "Created host successfully.")
    ss_3par_host.main()
    mock_module.assert_called_with(
        argument_spec=hpe3par.host_argument_spec())

@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.create_host')
def test_main_exit_functionality_success_without_issue_attr_dict(mock_create_host, mock_module, mock_client):
    """
    hpe3par host - success check
    """
    PARAMS_FOR_PRESENT = {
        'state': 'present',
        'storage_system_ip': '192.168.0.1',
        'storage_system_username': 'USER',
        'storage_system_password': 'PASS',
        'host_name': 'host',
        'host_domain': 'domain',
        'host_new_name': 'new',
        'host_fc_wwns': ['PASS'],
        'host_iscsi_names': ['host'],
        'host_persona': 'GENERIC',
        'force_path_removal': 'true',
        'chap_name': 'chap',
        'chap_secret': 'secret',
        'chap_secret_hex': 'true',
        'secure': False}

        # This creates a instance of the AnsibleModule mock.
    mock_module.params = PARAMS_FOR_PRESENT
    mock_module.return_value = mock_module
    instance = mock_module.return_value
    mock_client.HPE3ParClient.login.return_value = True
    mock_create_host.return_value = (
        True, True, "Created host host successfully.")
    ss_3par_host.main()
        # AnsibleModule.exit_json should be called
    instance.exit_json.assert_called_with(
        changed=True, msg="Created host host successfully.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_create_host_create_already_present(mock_client):
    """
    hpe3par host - create a host
    """
    assert ss_3par_host.create_host(
            mock_client.HPE3ParClient, "host", None, None, None, None) == (True, False, "Host already present")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_delete_host_create_sucess_login(mock_client):
    """
    hpe3par host - delete a host
    """
    assert ss_3par_host.delete_host(
        mock_client.HPE3ParClient, "host") == (True, True, "Deleted host host successfully.")

@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_delete_host_that_doest_not_exist(mock_client):
    """
    hpe3par host - delete a host
    """
    mock_client.HPE3ParClient.hostExists.return_value = False
    assert ss_3par_host.delete_host(
        mock_client.HPE3ParClient, "host") == (True, False, "Host does not exist")

@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_modify_host_success(mock_client):
    """
    hpe3par host - Modify host
    """
    assert ss_3par_host.modify_host(
        mock_client.HPE3ParClient, "host_name", None, None) == (True, True, "Modified host host_name successfully.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_initiator_chap_chapname_empty(mock_client):
    """
    hpe3par host - Add initiator chap
    """
    assert ss_3par_host.add_initiator_chap(
        mock_client.HPE3ParClient, "host_name", None, None, None) == (False, False, "Host modification failed. Chap name is null")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_initiator_chap_chapsecret_empty(mock_client):
    """
    hpe3par host - Add initiator chap
    """
    assert ss_3par_host.add_initiator_chap(
        mock_client.HPE3ParClient, "host", "chap", None, None) == (False, False, "Host modification failed. chap_secret is null")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_initiator_chap_chaphex_true(mock_client):
    """
    hpe3par host - Add initiator chap
    """
    assert ss_3par_host.add_initiator_chap(
        mock_client.HPE3ParClient, "host", "chap", "secret", True) == (False, False, "Add initiator chap failed. Chap secret hex is false and chap secret less than 32 characters")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_initiator_chap_chaphex_false(mock_client):
    """
    hpe3par host - Add initiator chap
    """
    assert ss_3par_host.add_initiator_chap(
        mock_client.HPE3ParClient, "host", "chap", "secret", False) == (False, False, "Add initiator chap failed. Chap secret hex is false and chap secret less than 12 characters or more than 16 characters")
