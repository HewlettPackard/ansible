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


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_initiator_chap_success(mock_client):
    """
    hpe3par host - Add initiator chap
    """
    mock_client.HPE3ParClient.CHAP_INITIATOR = 1
    assert ss_3par_host.add_initiator_chap(
        mock_client.HPE3ParClient, "host", "chap", "secretsecretsecretsecretsecret12", True) == (True, True, "Added initiator chap.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_target_chap_chapname_empty(mock_client):
    """
    hpe3par host - Add target chap
    """
    assert ss_3par_host.add_target_chap(
        mock_client.HPE3ParClient, "host", None, None, None) == (False, False, "Host modification failed. Chap name is null")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_target_chap_chapsecret_empty(mock_client):
    """
    hpe3par host - Add target chap
    """
    assert ss_3par_host.add_target_chap(
        mock_client.HPE3ParClient, "host", "chap", None, None) == (False, False, "Host modification failed. chap_secret is null")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_target_chap_chaphex_true(mock_client):
    """
    hpe3par host - Add target chap
    """
    assert ss_3par_host.add_target_chap(
        mock_client.HPE3ParClient, "host", "chap", "secret", True) == (False, False, "Attribute chap_secret must be 32 hexadecimal characters if chap_secret_hex is true")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_target_chap_chaphex_false(mock_client):
    """
    hpe3par host - Add target chap
    """
    assert ss_3par_host.add_target_chap(
        mock_client.HPE3ParClient, "host", "chap", "secret", False) == (False, False, "Attribute chap_secret must be 12 to 16 character if chap_secret_hex is false")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.initiator_chap_exists')
def test_add_target_chap_exists(mock_initiator_chap_exists, mock_client):
    """
    hpe3par host - Add target chap
    """
    mock_initiator_chap_exists.return_value = False
    assert ss_3par_host.add_target_chap(
        mock_client.HPE3ParClient, "host", "chap", "secretsecretsecretsecretsecret12", True) == (True, False, "Initiator chap does not exist")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_target_chap_success(mock_client):
    """
    hpe3par host - Add target chap
    """
    mock_client.HPE3ParClient.CHAP_TARGET = 1
    assert ss_3par_host.add_target_chap(
        mock_client.HPE3ParClient, "host", "chap", "secretsecretsecretsecretsecret12", True) == (True, True, "Added target chap.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_remove_initiator_chap_sucess(mock_client):
    """
    hpe3par host - Add target chap
    """
    mock_client.HPE3ParClient.HOST_EDIT_REMOVE = 1
    assert ss_3par_host.remove_initiator_chap(
        mock_client.HPE3ParClient, "host") == (True, True, "Removed initiator chap.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_remove_target_chap_success(mock_client):
    """
    hpe3par host - Add target chap
    """
    mock_client.HPE3ParClient.HOST_EDIT_REMOVE = 1
    assert ss_3par_host.remove_target_chap(
        mock_client.HPE3ParClient, "host") == (True, True, "Removed target chap.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_FC_empty(mock_client):
    """
    hpe3par host - Add target chap
    """
    assert ss_3par_host.add_fc_path_to_host(
        mock_client.HPE3ParClient, "host", None) == (False, False, "Host modification failed. host_fc_wwns is null")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_FC_success(mock_client):
    """
    hpe3par host - Add target chap
    """
    mock_client.HPE3ParClient.HOST_EDIT_ADD = 1
    assert ss_3par_host.add_fc_path_to_host(
        mock_client.HPE3ParClient, "host", "iscsi") == (True, True, "Added FC path to host successfully.")



@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_remove_fc_fcwwns_empty(mock_client):
    """
    hpe3par host - Add target chap
    """
    assert ss_3par_host.remove_fc_path_from_host(
        mock_client.HPE3ParClient, "host", None, None) == (False, False, "Host modification failed. host_fc_wwns is null")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_remove_fc_sucess(mock_client):
    """
    hpe3par host - Add target chap
    """
    mock_client.HPE3ParClient.HOST_EDIT_REMOVE = 1
    assert ss_3par_host.remove_fc_path_from_host(
        mock_client.HPE3ParClient, "host", "fcwwns", None) == (True, True, "Removed FC path from host successfully.")



@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_iscsi_empty(mock_client):
    """
    hpe3par host - Add target chap
    """
    assert ss_3par_host.add_iscsi_path_to_host(
        mock_client.HPE3ParClient, "host", None) == (False, False, "Host modification failed. host_iscsi_names is null")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_add_iscsi_sucess(mock_client):
    """
    hpe3par host - Add target chap
    """
    assert ss_3par_host.add_iscsi_path_to_host(
        mock_client.HPE3ParClient, "host", "iscsi") == (True, True, "Added ISCSI path to host successfully.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_remove_iscsi_empty(mock_client):
    """
    hpe3par host - Add target chap
    """
    assert ss_3par_host.remove_iscsi_path_from_host(
        mock_client.HPE3ParClient, "host", None, None) == (False, False, "Host modification failed. host_iscsi_names is null")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
def test_remove_iscsi_sucess(mock_client):
    """
    hpe3par host - Add target chap
    """
    assert ss_3par_host.remove_iscsi_path_from_host(
        mock_client.HPE3ParClient, "host", "iscsi", None) == (True, True, "Removed ISCSI path from host successfully.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.create_host')
def test_main_exit_functionality_success_without_issue_attr_dict_present(mock_create_host, mock_module, mock_client):
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
    mock_module.params["state"] = "present"
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
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.delete_host')
def test_main_exit_functionality_success_without_issue_attr_dict_absent(mock_delete_host, mock_module, mock_client):
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
    mock_module.params["state"] = "absent"
    mock_module.return_value = mock_module
    instance = mock_module.return_value
    mock_client.HPE3ParClient.login.return_value = True
    mock_delete_host.return_value = (
        True, True, "Deleted host host successfully.")
    ss_3par_host.main()
        # AnsibleModule.exit_json should be called
    instance.exit_json.assert_called_with(
        changed=True, msg="Deleted host host successfully.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.modify_host')
def test_main_exit_functionality_success_without_issue_attr_dict_modify(mock_modify_host, mock_module, mock_client):
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
    mock_module.params["state"] = "modify"
    mock_module.return_value = mock_module
    instance = mock_module.return_value
    mock_client.HPE3ParClient.login.return_value = True
    mock_modify_host.return_value = (
        True, True, "Modified host host successfully.")
    ss_3par_host.main()
        # AnsibleModule.exit_json should be called
    instance.exit_json.assert_called_with(
        changed=True, msg="Modified host host successfully.")



@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.add_initiator_chap')
def test_main_exit_functionality_success_without_issue_attr_dict_add_initiator_chap(mock_add_initiator_chap, mock_module, mock_client):
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
    mock_module.params["state"] = "add_initiator_chap"
    mock_module.return_value = mock_module
    instance = mock_module.return_value
    mock_client.HPE3ParClient.login.return_value = True
    mock_add_initiator_chap.return_value = (
        True, True, "Add_initiator_chap successfully.")
    ss_3par_host.main()
        # AnsibleModule.exit_json should be called
    instance.exit_json.assert_called_with(
        changed=True, msg="Add_initiator_chap successfully.")



@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.remove_initiator_chap')
def test_main_exit_functionality_success_without_issue_attr_dict_remove_initiator_chap(mock_remove_initiator_chap, mock_module, mock_client):
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
    mock_module.params["state"] = "remove_initiator_chap"
    mock_module.return_value = mock_module
    instance = mock_module.return_value
    mock_client.HPE3ParClient.login.return_value = True
    mock_remove_initiator_chap.return_value = (
        True, True, "Remove initiator chap successfully.")
    ss_3par_host.main()
        # AnsibleModule.exit_json should be called
    instance.exit_json.assert_called_with(
        changed=True, msg="Remove initiator chap successfully.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.add_target_chap')
def test_main_exit_functionality_success_without_issue_attr_dict_add_target_chap(mock_add_target_chap, mock_module, mock_client):
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
    mock_module.params["state"] = "add_target_chap"
    mock_module.return_value = mock_module
    instance = mock_module.return_value
    mock_client.HPE3ParClient.login.return_value = True
    mock_add_target_chap.return_value = (
        True, True, "Add target chap successfully.")
    ss_3par_host.main()
        # AnsibleModule.exit_json should be called
    instance.exit_json.assert_called_with(
        changed=True, msg="Add target chap successfully.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.remove_target_chap')
def test_main_exit_functionality_success_without_issue_attr_dict_remove_target_chap(mock_remove_target_chap, mock_module, mock_client):
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
    mock_module.params["state"] = "remove_target_chap"
    mock_module.return_value = mock_module
    instance = mock_module.return_value
    mock_client.HPE3ParClient.login.return_value = True
    mock_remove_target_chap.return_value = (
        True, True, "Remove target chap successfully.")
    ss_3par_host.main()
        # AnsibleModule.exit_json should be called
    instance.exit_json.assert_called_with(
        changed=True, msg="Remove target chap successfully.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.add_fc_path_to_host')
def test_main_exit_functionality_success_without_issue_attr_dict_add_fc_path_to_host(mock_add_fc_path_to_host, mock_module, mock_client):
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
    mock_module.params["state"] = "add_fc_path_to_host"
    mock_module.return_value = mock_module
    instance = mock_module.return_value
    mock_client.HPE3ParClient.login.return_value = True
    mock_add_fc_path_to_host.return_value = (
        True, True, "Add fc path to host successfully.")
    ss_3par_host.main()
        # AnsibleModule.exit_json should be called
    instance.exit_json.assert_called_with(
        changed=True, msg="Add fc path to host successfully.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.remove_fc_path_from_host')
def test_main_exit_functionality_success_without_issue_attr_dict_remove_fc_path_from_host(mock_remove_fc_path_from_host, mock_module, mock_client):
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
    mock_module.params["state"] = "remove_fc_path_from_host"
    mock_module.return_value = mock_module
    instance = mock_module.return_value
    mock_client.HPE3ParClient.login.return_value = True
    mock_remove_fc_path_from_host.return_value = (
        True, True, "Removed fc path from host successfully.")
    ss_3par_host.main()
        # AnsibleModule.exit_json should be called
    instance.exit_json.assert_called_with(
        changed=True, msg="Removed fc path from host successfully.")



@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.add_iscsi_path_to_host')
def test_main_exit_functionality_success_without_issue_attr_dict_add_iscsi_path_to_host(mock_add_iscsi_path_to_host, mock_module, mock_client):
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
    mock_module.params["state"] = "add_iscsi_path_to_host"
    mock_module.return_value = mock_module
    instance = mock_module.return_value
    mock_client.HPE3ParClient.login.return_value = True
    mock_add_iscsi_path_to_host.return_value = (
        True, True, "Add iscsi path to host successfully.")
    ss_3par_host.main()
        # AnsibleModule.exit_json should be called
    instance.exit_json.assert_called_with(
        changed=True, msg="Add iscsi path to host successfully.")


@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.client')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.AnsibleModule')
@mock.patch('ansible.modules.storage.hpe3par.ss_3par_host.remove_iscsi_path_from_host')
def test_main_exit_functionality_success_without_issue_attr_dict_remove_iscsi_path_from_host(mock_remove_iscsi_path_from_host, mock_module, mock_client):
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
    mock_module.params["state"] = "remove_iscsi_path_from_host"
    mock_module.return_value = mock_module
    instance = mock_module.return_value
    mock_client.HPE3ParClient.login.return_value = True
    mock_remove_iscsi_path_from_host.return_value = (
        True, True, "Remove iscsi path from host successfully.")
    ss_3par_host.main()
        # AnsibleModule.exit_json should be called
    instance.exit_json.assert_called_with(
        changed=True, msg="Remove iscsi path from host successfully.")
