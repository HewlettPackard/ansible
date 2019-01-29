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
short_description: Manage HPE StoreServ 3PAR HOST
author:
  - Arshad Ansari (@ansarars)
description:
 - On HPE 3PAR  Create and Delete Host. 
 - Add Initiator Chap.
 - Remove Initiator Chap. 
 - Add Target Chap. 
 - Remove Target Chap.
 - Add FC Path to Host 
 - Remove FC Path from Host 
 - Add ISCSI Path to Host
 - Remove ISCSI Path from Host
module: ss_3par_host
options:
  chap_name:
    description:
      - The chap name. Required with actions add_initiator_chap,
       add_target_chap.
    required: false
  chap_secret:
    description:
      - The chap secret for the host or the target Required with actions
       add_initiator_chap, add_target_chap.
    required: false
  chap_secret_hex:
    description:
      - If true, then chapSecret is treated as Hex.
    required: false
    type: bool
  force_path_removal:
    description:
      - If true, remove WWN(s) or iSCSI(s) even if there are VLUNs that are
       exported to the host.
    required: false
    type: bool
  host_domain:
    description:
      - Create the host in the specified domain, or in the default domain,
       if unspecified.
    required: false
  host_fc_wwns:
    description:
      - Set one or more WWNs for the host. Required with action
       add_fc_path_to_host, remove_fc_path_from_host.
    required: false
  host_iscsi_names:
    description:
      - Set one or more iSCSI names for the host. Required with action
       add_iscsi_path_to_host, remove_iscsi_path_from_host.
    required: false
  host_name:
    description:
      - Name of the Host.
    required: true
  host_new_name:
    description:
      - New name of the Host.
    required: true
  host_persona:
    choices:
      - GENERIC
      - GENERIC_ALUA
      - GENERIC_LEGACY
      - HPUX_LEGACY
      - AIX_LEGACY
      - EGENERA
      - ONTAP_LEGACY
      - VMWARE
      - OPENVMS
      - HPUX
      - WINDOWS_SERVER
    description:
      - ID of the persona to assign to the host. Uses the default persona
       unless you specify the host persona.
    required: false
  state:
    choices:
      - present
      - absent
      - modify
      - add_initiator_chap
      - remove_initiator_chap
      - add_target_chap
      - remove_target_chap
      - add_fc_path_to_host
      - remove_fc_path_from_host
      - add_iscsi_path_to_host
      - remove_iscsi_path_from_host
    description:
      - Whether the specified Host should exist or not. State also provides
       actions to add and remove initiator and target chap, add fc/iscsi path
       to host.
    required: true
  secure:
    description:
      - Specifies whether the certificate needs to be validated while communicating.
    type: bool
    default: no
extends_documentation_fragment: hpe3par
version_added: 2.8
'''


EXAMPLES = r'''
    - name: Create Host "{{ host_name }}"
      hpe3par_host:
        storage_system_ip="{{ storage_system_ip }}"
        storage_system_username="{{ storage_system_username }}"
        storage_system_password="{{ storage_system_password }}"
        state=present
        host_name="{{ host_name }}"

    - name: Modify Host "{{ host_name }}"
      hpe3par_host:
        storage_system_ip="{{ storage_system_ip }}"
        storage_system_username="{{ storage_system_username }}"
        storage_system_password="{{ storage_system_password }}"
        state=modify
        host_name="{{ host_name }}"
        host_new_name="{{ host_new_name }}"

    - name: Delete Host "{{ new_name }}"
      hpe3par_host:
        storage_system_ip="{{ storage_system_ip }}"
        storage_system_username="{{ storage_system_username }}"
        storage_system_password="{{ storage_system_password }}"
        state=absent
        host_name="{{ host_new_name }}"
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


def create_host(
        client_obj,
        host_name,
        host_iscsi_names,
        host_fc_wwns,
        host_domain,
        host_persona):
    try:
        if not client_obj.hostExists(host_name):
            optional = dict()
            if host_domain is not None:
                optional['domain'] = host_domain

            if host_persona is not None:
                optional['persona'] = getattr(
                    client.HPE3ParClient, host_persona)

            client_obj.createHost(
                host_name,
                host_iscsi_names,
                host_fc_wwns,
                optional)
        else:
            return (True, False, "Host already present")
    except exceptions.ClientException as e:
        return (False, False, "Host creation failed | %s" % (e))
    finally:
        client_obj.logout()
    return (True, True, "Created host %s successfully." % host_name )


def modify_host(
        client_obj,
        host_name,
        host_new_name,
        host_persona):
    try:
        if host_persona is not None:
            host_persona = getattr(
                client.HPE3ParClient, host_persona)

        client_obj.modifyHost(
            host_name, {
                "newName": host_new_name, "persona": host_persona})
    except exceptions.ClientException as e:
        return (False, False, "Host modification failed | %s" % (e))
    finally:
        client_obj.logout()
    return (True, True, "Modified host %s successfully." % host_name )


def delete_host(
        client_obj,
        host_name):
    try:
        if client_obj.hostExists(host_name):
            client_obj.deleteHost(host_name)
        else:
            return (True, False, "Host does not exist")
    except exceptions.ClientException as e:
        return (False, False, "Host deletion failed | %s" % (e))
    finally:
        client_obj.logout()
    return (True, True, "Deleted host %s successfully." % host_name )


def add_initiator_chap(
        client_obj,
        host_name,
        chap_name,
        chap_secret,
        chap_secret_hex):
    if chap_name is None:
        return (
            False,
            False,
            "Host modification failed. Chap name is null"
            )
    if chap_secret is None:
        return (
            False,
            False,
            "Host modification failed. chap_secret is null"
            )
    try:
        if chap_secret_hex and len(chap_secret) != 32:
            return (
                False,
                False,
                "Add initiator chap failed. Chap secret hex is false and chap \
secret less than 32 characters"
                )
        if not chap_secret_hex and (
                len(chap_secret) < 12 or len(chap_secret) > 16):
            return (
                False,
                False,
                "Add initiator chap failed. Chap secret hex is false and chap \
secret less than 12 characters or more than 16 characters"
                )
        client_obj.modifyHost(host_name,
                              {'chapOperationMode':
                               HPE3ParClient.CHAP_INITIATOR,
                               'chapOperation':
                               HPE3ParClient.HOST_EDIT_ADD,
                               'chapName': chap_name,
                               'chapSecret': chap_secret,
                               'chapSecretHex': chap_secret_hex})
    except exceptions.ClientException as e:
        return (False, False, "Add initiator chap failed | %s" % (e))
    finally:
        client_obj.logout()
    return (True, True, "Added initiator chap.")


def remove_initiator_chap(
        client_obj,
        host_name):
    try:
        client_obj.modifyHost(
            host_name, {
                'chapOperation': HPE3ParClient.HOST_EDIT_REMOVE})
    except exceptions.ClientException as e:
        return (False, False, "Remove initiator chap failed | %s" % (e))
    finally:
        client_obj.logout()
    return (True, True, "Removed initiator chap.")


def initiator_chap_exists(
        client_obj,
        host_name):
    try:
        return client_obj.getHost(host_name).initiator_chap_enabled
    finally:
        client_obj.logout()


def add_target_chap(
        client_obj,
        host_name,
        chap_name,
        chap_secret,
        chap_secret_hex):
    if chap_name is None:
        return (
            False,
            False,
            "Host modification failed. Chap name is null"
            )
    if chap_secret is None:
        return (
            False,
            False,
            "Host modification failed. chap_secret is null"
            )
    if chap_secret_hex and len(chap_secret) != 32:
        return (
            False,
            False,
            'Attribute chap_secret must be 32 hexadecimal characters if \
chap_secret_hex is true'
            )
    if not chap_secret_hex and (
            len(chap_secret) < 12 or len(chap_secret) > 16):
        return (
            False,
            False,
            'Attribute chap_secret must be 12 to 16 character if \
chap_secret_hex is false'
            )
    try:
        if initiator_chap_exists(
                client_obj,
                storage_system_username,
                storage_system_password,
                host_name):
            client_obj.login(storage_system_username, storage_system_password)
            mod_request = {
                'chapOperationMode': HPE3ParClient.CHAP_TARGET,
                'chapOperation': HPE3ParClient.HOST_EDIT_ADD,
                'chapName': chap_name,
                'chapSecret': chap_secret,
                'chapSecretHex': chap_secret_hex}
            client_obj.modifyHost(host_name, mod_request)
        else:
            return (True, False, "Initiator chap does not exist")
    except exceptions.ClientException as e:
        return (False, False, "Add target chap failed | %s" % (e))
    finally:
        client_obj.logout()
    return (True, True, "Added target chap.")


def remove_target_chap(
        client_obj,
        host_name):
    try:
        mod_request = {
            'chapOperation': HPE3ParClient.HOST_EDIT_REMOVE,
            'chapRemoveTargetOnly': True}
        client_obj.modifyHost(host_name, mod_request)
    except exceptions.ClientException as e:
        return (False, False, "Remove target chap failed | %s" % (e))
    finally:
        client_obj.logout()
    return (True, True, "Removed target chap.")


def add_fc_path_to_host(
        client_obj,
        host_name,
        host_fc_wwns):
    if host_fc_wwns is None:
        return (
            False,
            False,
            "Host modification failed. host_fc_wwns is null"
            )
    try:
        client_obj.login(storage_system_username, storage_system_password)
        mod_request = {
            'pathOperation': HPE3ParClient.HOST_EDIT_ADD,
            'FCWWNs': host_fc_wwns}
        client_obj.modifyHost(host_name, mod_request)
    except exceptions.ClientException as e:
        return (False, False, "Add FC path to host failed | %s" % (e))
    finally:
        client_obj.logout()
    return (True, True, "Added FC path to host successfully.")


def remove_fc_path_from_host(
        client_obj,
        host_name,
        host_fc_wwns,
        force_path_removal):
    if host_fc_wwns is None:
        return (
            False,
            False,
            "Host modification failed. host_fc_wwns is null"
            )
    try:
        mod_request = {
            'pathOperation': HPE3ParClient.HOST_EDIT_REMOVE,
            'FCWWNs': host_fc_wwns,
            'forcePathRemoval': force_path_removal}
        client_obj.modifyHost(host_name, mod_request)
    except exceptions.ClientException as e:
        return (False, False, "Remove FC path from host failed | %s" % (e))
    finally:
        client_obj.logout()
    return (True, True, "Removed FC path from host successfully.")


def add_iscsi_path_to_host(
        client_obj,
        host_name,
        host_iscsi_names):
    if host_iscsi_names is None:
        return (
            False,
            False,
            "Host modification failed. host_iscsi_names is null"
            )
    try:
        mod_request = {
            'pathOperation': HPE3ParClient.HOST_EDIT_ADD,
            'iSCSINames': host_iscsi_names}
        client_obj.modifyHost(host_name, mod_request)
    except exceptions.ClientException as e:
        return (False, False, "Add ISCSI path to host failed | %s" % (e))
    finally:
        client_obj.logout()
    return (True, True, "Added ISCSI path to host successfully.")


def remove_iscsi_path_from_host(
        client_obj,
        host_name,
        host_iscsi_names,
        force_path_removal):
    if host_iscsi_names is None:
        return (
            False,
            False,
            "Host modification failed. host_iscsi_names is null"
            )
    try:
        mod_request = {
            'pathOperation': HPE3ParClient.HOST_EDIT_REMOVE,
            'iSCSINames': host_iscsi_names,
            'forcePathRemoval': force_path_removal}
        client_obj.modifyHost(host_name, mod_request)
    except exceptions.ClientException as e:
        return (
            False,
            False,
            "Remove ISCSI path from host failed | %s" %
            (e)
            )
    finally:
        client_obj.logout()
    return (True, True, "Removed ISCSI path from host successfully.")


def main():
    module = AnsibleModule(argument_spec=hpe3par.host_argument_spec())
    if not HAS_3PARCLIENT:
        module.fail_json(msg='the python hpe3par_sdk library is required (https://pypi.org/project/hpe3par_sdk)')

    if module.params["host_name"] is None:
        module.fail_json(msg="Host creation failed. Host name is null")
    if len(module.params["host_name"]) < 1 or len(module.params["host_name"]) > 31:
        module.fail_json(msg="Host create failed. Host name must be atleast 1 character and not more than 31 characters")

    storage_system_ip = module.params["storage_system_ip"]
    storage_system_username = module.params["storage_system_username"]
    storage_system_password = module.params["storage_system_password"]

    host_name = module.params["host_name"]
    host_new_name = module.params["host_new_name"]
    host_domain = module.params["host_domain"]
    host_fc_wwns = module.params["host_fc_wwns"]
    host_iscsi_names = module.params["host_iscsi_names"]
    host_persona = module.params["host_persona"]
    chap_name = module.params["chap_name"]
    chap_secret = module.params["chap_secret"]
    chap_secret_hex = module.params["chap_secret_hex"]
    force_path_removal = module.params["force_path_removal"]
    secure = module.params["secure"]

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

    # States
    if module.params["state"] == "present":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = create_host(
                client_obj,
                host_name,
                host_iscsi_names,
                host_fc_wwns,
                host_domain,
                host_persona
            )
        except Exception as e:
            module.fail_json(msg="Host create failed | %s" % e)
        finally:
            client_obj.logout()

    if module.params["state"] == "modify":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = modify_host(
                client_obj,
                host_name,
                host_new_name,
                host_persona
            )
        except Exception as e:
            module.fail_json(msg="Host modify failed | %s" % e)
        finally:
            client_obj.logout()

    elif module.params["state"] == "absent":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = delete_host(
                client_obj,
                host_name
            )
        except Exception as e:
            module.fail_json(msg="Host delete failed | %s" % e)
        finally:
            client_obj.logout()

    elif module.params["state"] == "add_initiator_chap":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = add_initiator_chap(
                client_obj,
                host_name,
                chap_name,
                chap_secret,
                chap_secret_hex
            )
        except Exception as e:
            module.fail_json(msg="Add initiator chap failed | %s" % e)
        finally:
            client_obj.logout()

    elif module.params["state"] == "remove_initiator_chap":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = remove_initiator_chap(
                client_obj,
                host_name
            )
        except Exception as e:
            module.fail_json(msg="Remove initiator chap failed | %s" % e)
        finally:
            client_obj.logout()

    elif module.params["state"] == "add_target_chap":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = add_target_chap(
                client_obj,
                host_name,
                chap_name,
                chap_secret,
                chap_secret_hex
            )
        except Exception as e:
            module.fail_json(msg="Add target chap failed | %s" % e)
        finally:
            client_obj.logout()

    elif module.params["state"] == "remove_target_chap":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = remove_target_chap(
                client_obj,
                host_name
            )
        except Exception as e:
            module.fail_json(msg="Remove target chap failed | %s" % e)
        finally:
            client_obj.logout()

    elif module.params["state"] == "add_fc_path_to_host":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = add_fc_path_to_host(
                client_obj,
                host_name,
                host_fc_wwns
            )
        except Exception as e:
            module.fail_json(msg="Add FC path to host failed | %s" % e)
        finally:
            client_obj.logout()

    elif module.params["state"] == "remove_fc_path_from_host":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = remove_fc_path_from_host(
                client_obj,
                host_name,
                host_fc_wwns,
                force_path_removal
            )
        except Exception as e:
            module.fail_json(msg="Remove FC path to host failed | %s" % e)
        finally:
            client_obj.logout()            

    elif module.params["state"] == "add_iscsi_path_to_host":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = add_iscsi_path_to_host(
                client_obj,
                host_name,
                host_iscsi_names
            )
        except Exception as e:
            module.fail_json(msg="Add iscsi path to host failed | %s" % e)
        finally:
            client_obj.logout() 

    elif module.params["state"] == "remove_iscsi_path_from_host":
        try:
            client_obj.login(storage_system_username, storage_system_password)
            return_status, changed, msg = remove_iscsi_path_from_host(
                client_obj,
                host_name,
                host_iscsi_names,
                force_path_removal
            )
        except Exception as e:
            module.fail_json(msg="Remove iscsi path to host failed | %s" % e)
        finally:
            client_obj.logout()

    if return_status:
        module.exit_json(changed=changed, msg=msg)
    else:
        module.fail_json(msg=msg)


if __name__ == '__main__':
    main()
