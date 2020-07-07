#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Zainab Alsaffar <zalsaffa@redhat.com>

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: zabbix_user
short_description: Manage a user account on Zabbix Server
description:
    - This is a custom module built to manage the creation of a user account on Zabbix when state is defined as present. 
    - And the removal of a user account when state is defined as absent.
version_added: '1.0'
author: 'Zainab Alsaffar (@zanssa)'
requirments:
    - 'python >= 2.6'
    - 'zabbix-api >= 0.5.4'
options:
    user_name:
        description:
            - Name of the user in Zabbix.
            - I(user_name) is the unique identifier used and cannot be updated using this module.
        required: true
        type: str
    user_groups:
        description:
            - List of user groups the user is a member of.
        type: list
        elements: str
    user_passwd:
        description:
            - User's password.
        type: str
    state:
        description:
            - State of the user.
            - On C(present), it will create a user if the user doesn't exist or update the user if the associated data is different.
            - On C(absent), will remove a user if the account exists.
        choices: ['present', 'absent']
        default: 'present'
        type: str
    force:
        description:
            - Overwrite the user configuration, even if already present.
        type: bool
        default: 'yes'
        choices: ['yes', 'no']
    server_url:
        description:
            - URL of a zabbix server.
        required: true
        type: str
    login_user:
        description:
            - A user account with admin privilages to authenticate with zabbix server.
        required: true
        type: str
    login_password:
        description:
            - User's password with admin privilages to authenticate with zabbix server.
        required: true
        type: str
    name:
        description:
            - Name of the user.
        type: str
    surname:
        description: 
            - Surname of the user.
        type: str
    lang:
        description:
            - Language code of the user's language.
        type: str
        default: 'en_GB'
        choices: ['en_GB', 'en_US', 'zh_CN', 'cs_CZ','fr_FR', 'it_IT', 'ko_KR', 'ja_JP', 'nb_NO', 'pl_PL', 'pt_BR', 'ru_RU', 'sk_SK', 'tr_TR', 'uk_UA']
    autologin:
        description:
            - Whether to enable auto-login.
            - Numerical values are accepted for this parameter.
            - Auto-login disabled (0) default, Auto-login enabled (1).
        type: int
        default: 0
    autologout:
        description:
            - User session life time.
            - Accepts second and time unit with suffix.
            - If set to 0s, the session will never expire.
        type: str
        default: '15m'
    refresh:
        description:
            - Automatic refersh period.
            - Accepts second and time unit with suffix.
        type: str
        default: '30s'
    rows_per_page:
        description:
            - Amount of object rows to show per page.
        type: int
        default: 50
    theme:
        description:
            - Users's theme.
        type: str
        default: 'default'
        choices: ['default', 'blue-theme', 'dark-theme']
    zabbix_user_type:
        description:
            - Type of the user.
        type: str
        default: 'Zabbix user'
        choices: ['Zabbix user', 'Zabbix admin', 'Zabbix super admin']
    url:
        description:
            - URL of the page to redirect the user to after logging in.
        type: str
    medias:
        description:
            - User's media used for sending notifications.
        type: list
        elements: dict
        default: []
        suboptions:
            mediatype:
                description:
                    - Media type name.
                    - Required if I(active=0), user's media is set to be enabled.
                type: str
                default: 'Email'
                choices: ['Discord', 'Email', 'Mattermost', 'Opsgenie', 'PagerDuty', 'Pushover', 'Slack', 'SMS']
            sendto:
                description:
                    - Address, user name or other identifier of the recipient.
                    - Required if I(active=0), user's media is set to be enabled.
                type: str
            period:
                description:
                    - Time when the notifications can be sent as a time period or user macros separated by a semicolon.
                type: str
                default: '1-7,00:00-24:00'
            severity:
                description:
                    - Trigger severities to send notifications about.
                type: dict
                suboptions:
                    not_classified:
                        description:
                            - Use to set if severity not_classified enabled or disabled.
                        type: bool
                        default: true
                    information:
                        description:
                            - Use to set if severity information enabled or disabled.
                        type: bool
                        default: true
                    warning:
                        description:
                            - Use to set if severity warning enabled or disabled.
                        type: bool
                        default: true
                    average:
                        description:
                            - Use to set if severity average enabled or disabled.
                        type: bool
                        default: true
                    high:
                        description:
                            - Use to set if severity high enabled or disabled.
                        type: bool
                        default: true
                    disaster:
                        description:
                            - Use to set if severity disaster enabled or disabled.
                        type: bool
                        default: true
                default:
                    not_classified: true
                    information: true
                    warning: true
                    average: true
                    high: true
                    disaster: true    
            active:
                description:
                    - Wether the media is enabled.
                    - 0 (enabled, default), 1 (disabled)
                type: int
                default: 0
                choices: [0,1]
    new_passwd:
        description:
            - An updated user's password.
        type: str
notes: supports_check_mode is allowed in this module 
'''
EXAMPLES = '''
- name: Create a new user or update an existing user's info
  zabbix_user:
    server_url: http://monitor.zabbix.com
    login_user: Admin
    login_passwd: Admin's passwd
    user_name: username
    name: Example
    surname: User
    user_passwd: password
    user_groups:
        - Example group1
        - Example group2
    lang: en_US
    autologin: 0
    autologout: '15m'
    refresh: '30s'
    rows_per_page: 50
    theme: 'dark-theme'
    url: http://url.after.login.to.monitor.zabbix.com
    medias:
        - mediatype: Email
          sendto: username@example.com
          period: '1-7,00:00-24:00'
          severity:
            not_classified: yes
            information: no
            warning: yes
            average: no
            high: yes
            disaster: yes
          active: 0
    zabbix_user_type: Zabbix user
    state: present

- Update an existing user's groups setting
  module: zabbix_user
    server_url: http://monitor.zabbix.com
    login_user: Admin
    login_passwd: Admin's passwd
    user_name: username
    name: Example
    user_groups:
        - Example group1
        - Example group2
        - Example group3
    force: no

- name: Delete a user account
  module: zabbix_user
    server_url: http://monitor.zabbix.com
    login_user: Admin
    login_passwd: Admin's passwd
    user_name: username
    state: absent
'''

RETURN = '''
'''

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
import traceback, atexit, copy

try:
    from zabbix_api import ZabbixAPI
    HAS_ZABBIX_API = True
except ImportError:
    ZBX_IMP_ERR = traceback.format_exc()
    HAS_ZABBIX_API = False

class User(object):
    def __init__(self, module, zbx):
        self._module= module
        self._zapi= zbx

    def does_user_exist(self, user_name):
        result = self._zapi.user.get({'output': 'extend', 'filter': {'alias': user_name},
                                    'SelectUsgrps': 'extend', 'selectMedias': 'extend', 'getAccess': True})
        return result

    def check_user_groups_exist(self, user_groups):
        groups = []
        for user_group in user_groups:
            result = self._zapi.usergroup.get({'output': 'extend', 'filter': {'name': user_group}})
            if not result:
                self._module.fail_json(msg="User group not found: %s" % user_group)
            else:
                groups.append({'usrgrpid': result[0]['usrgrpid'], 'name': result[0]['name']})
            return groups
    
    def get_usergid_by_groupname(self, user_groups):
        user_group_ids = []
        for user_group in user_groups:
            user_group_name = self._zapi.usergroup.get({'output': 'extend', 'filter': {'name': user_group}})
            if user_group_name:
                user_group_ids.append({'usrgrpid': user_group_name[0]['usrgrpid']})
            else:
                self._module.fail_json(msg="Usergroup not found: %s" % user_group_name)
        return user_group_ids

    def convert_user_medias_parameters(self, medias):
        result = copy.deepcopy(medias)
        for user_media in result:
            media_types = self._zapi.mediatype.get({'output': 'extend'})
            for media_type in media_types:
                if media_type['name'] == user_media['mediatype']:
                    user_media['mediatypeid'] = media_type['mediatypeid']
                    break
            
            if 'mediatypeid' not in user_media:
                self._module.fail_json(msg="Media type not found: %s" % user_media['mediatype'])
            else:
                del user_media['mediatype']

            severity_binary_num = ''
            for severity_key in 'not_classified','information','warning','average','high','disaster':
                if user_media['severity'][severity_key]:
                    severity_binary_num = severity_binary_num + '1'
                else:
                    severity_binary_num = severity_binary_num + '0'
            user_media['severity'] = str(int(severity_binary_num, 2))
        return result

    def add_user(self, user_name, name, surname, user_group_ids, user_passwd, lang, theme, autologin, autologout, refresh, rows_per_page, url, medias,
                zabbix_user_type):    
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)

            medias = self.convert_user_medias_parameters(medias)
            parameters = {'alias': user_name, 'name': name, 'surname': surname, 'usrgrps': user_group_ids, 'passwd': user_passwd,'lang': lang,
                            'theme': theme, 'autologin': autologin, 'autologout': autologout, 'refresh': refresh, 'rows_per_page': rows_per_page,
                            'url': url, 'user_medias': medias, 'type': zabbix_user_type}
            
            user_list = self._zapi.user.create(parameters)
            if len(user_list) >= 1:
                return user_list['userids'][0]
        except Exception as e:
            self._module.fail_json(msg="Failed to create user %s: %s" % (user_name, e))

    def update_user(self, user_id, user_name, name, surname, user_group_ids, lang, theme, autologin, autologout, refresh, rows_per_page, 
                    url, medias, zabbix_user_type, new_passwd):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            
            medias = self.convert_user_medias_parameters(medias)

            parameters = {'userid': user_id, 'alias': user_name, 'name': name, 'surname': surname, 'usrgrps': user_group_ids, 'lang': lang,
                            'theme': theme, 'autologin': autologin, 'autologout': autologout, 'refresh': refresh, 'rows_per_page': rows_per_page,
                            'url': url, 'user_medias': medias, 'type': zabbix_user_type}
            if new_passwd:
                parameters['passwd'] = new_passwd
            
            updated_user_account = self._zapi.user.update(parameters)
            if len(updated_user_account) >=1:
                return updated_user_account['userids'][0]
        except Exception as e:
            self._module.fail_json(msg="Failed to update user %s: %s" %(user_name, e))

    def delete_user(self, user_id, user_name):
        try:
            if self._module.check_mode:
                self._module.exit_json(changed=True)
            self._zapi.user.delete([user_id])
        except Exception as e:
            self._module.fail_json(msg="Failed to delete user %s: %s" %(user_name, e))

    def check_medias_properties(self, existing_medias, medias):
        existing_medias_ids = []
        if len(existing_medias) >= 1:
            for existing_media in existing_medias:
                existing_medias_ids.append(int(existing_media['mediatypeid']))

        medias_ids = []
        medias= self.convert_user_medias_parameters(medias)
        if len(medias) >= 1:
            for media in medias:
                medias_ids.append(int(media['mediatypeid']))

        if set(medias_ids) != set(existing_medias_ids):
            return True
        else:
            return False

    def get_user_groups_by_user_id(self, user_id):
        result = []
        result = self._zapi.usergroup.get({'output': 'extend', 'userids': user_id})
        return result

    def get_user_medias_by_username(self, user_name):
        result = []
        result = self._zapi.user.get({'output': 'extend', 'filter': {'alias' : user_name}, 'selectMedias': 'extend'})
        result = result[0]['medias']
        return result

    def check_all_params(self, zbx_user , user_id, user_name, name, surname, user_groups, lang, theme, autologin, autologout, refresh, rows_per_page, 
                        url, medias, exist_medias, zabbix_user_type):
        #get the existing user's groups
        exist_group_name = []
        exist_user_groups = self.get_user_groups_by_user_id(user_id)
        for exist_user_group in exist_user_groups:
            exist_group_name.append(exist_user_group['name'])
        if set(user_groups) != set(exist_group_name):
            return True
        # check whether the existing media type id/s is/are equal to the ids of medias type passed to the module
        if self.check_medias_properties(exist_medias,medias):
            return True
        # check whether the name has changed
        if name:
            if zbx_user[0]['name'] != name:
                return True
        # check whether the surname has changed
        if surname:
            if zbx_user[0]['surname'] != surname:
                return True
        # check whether the lang has changed
        if lang:
            if zbx_user[0]['lang'] != lang:
                return True
        # check whether the autologin has changed
        if autologin:
            if zbx_user[0]['autologin'] != autologin:
                return True
        # check whether the autologout has changed
        if autologout:
            if zbx_user[0]['autologout'] != autologout:
                return True
        # check whether the refresh has changed
        if refresh:
            if zbx_user[0]['refresh'] != refresh:
                return True
        # check whether the rows_per_page has changed
        if rows_per_page:
            if zbx_user[0]['rows_per_page'] != rows_per_page:
                return True
         # check whether the theme has changed
        if theme:
            if zbx_user[0]['theme'] != theme:
                return True
         # check whether the url has changed
        if theme:
            if zbx_user[0]['url'] != url:
                return True
        return False

def main():    
    module = AnsibleModule(
        argument_spec=dict(
            server_url=dict(type='str', required=True),
            login_user=dict(type='str', required=True),
            login_password=dict(type='str', required=True, no_log=True),
            validate_certs=dict(type='bool', required=False, default=True),
            user_name=dict(type='str', required=True),
            name=dict(type='str', required=False, default=''),
            surname=dict(type='str', required=False, default=''),
            user_groups=dict(type='list', required=False),
            user_passwd=dict(type='str', required=False, no_log=True),
            new_passwd=dict(type='str', required=False, no_log=True),
            lang=dict(type='str', default='en_GB', choices=['en_GB', 'en_US', 'zh_CN', 'cs_CZ','fr_FR', 'it_IT', 'ko_KR', 
                                                            'ja_JP', 'nb_NO', 'pl_PL', 'pt_BR', 'ru_RU', 'sk_SK', 'tr_TR', 'uk_UA']),
            theme=dict(type='str', default='default', choices=['default', 'blue-theme', 'dark-theme']),
            autologin=dict(type='int', default=0),
            autologout=dict(type='str', default='15m'),
            refresh=dict(type='str', default= '30s'),
            rows_per_page=dict(type='int', default=50),
            url=dict(type='str', default=''),
            medias=dict(type='list', default=[], elements='dict', options=dict(
                                                                    mediatype=dict(type='str', default='Email', choices=['Discord', 'Email', 'Mattermost', 'Opsgenie', 
                                                                                                                            'PagerDuty', 'Pushover', 'Slack', 'SMS']),
                                                                    sendto=dict(type='str', required=True),
                                                                    period=dict(type='str', default='1-7,00:00-24:00'),
                                                                    severity=dict(type='dict', 
                                                                                options=dict(
                                                                                    not_classified=dict(type='bool', default=True),
                                                                                    information=dict(type='bool', default=True),
                                                                                    warning=dict(type='bool', default=True),
                                                                                    average=dict(type='bool', default=True),
                                                                                    high=dict(type='bool', default=True),
                                                                                    disaster=dict(type='bool', default=True)),
                                                                                default=dict(
                                                                                    not_classified=True,
                                                                                    information=True,
                                                                                    warning=True,
                                                                                    average=True,
                                                                                    high=True,
                                                                                    disaster=True)),
                                                                    active=dict(type='int', default=0, choices=[0,1]))),
            zabbix_user_type=dict(type='str', default='Zabbix user', choices=['Zabbix user', 'Zabbix admin', 'Zabbix super admin']),
            state=dict(type='str', default='present', choices=['present', 'absent']),
            force=dict(type='bool', default=True),
            timeout=dict(type='int', default=10)
        ),        
        supports_check_mode=True
        )

    if not HAS_ZABBIX_API:
        module.fail_json(msg=missing_required_lib('zabbix-api', url='https://pypi.org/project/zabbix-api'), exception=ZBX_IMP_ERR)
    
    server_url = module.params['server_url']
    login_user = module.params['login_user']
    login_password = module.params['login_password']
    validate_certs= module.params['validate_certs']
    user_name = module.params['user_name']
    name = module.params['name']
    surname = module.params['surname']
    user_groups = module.params['user_groups']
    user_passwd = module.params['user_passwd']
    new_passwd = module.params['new_passwd']
    lang = module.params['lang']
    theme = module.params['theme']
    autologin = module.params['autologin']
    autologout = module.params['autologout']
    refresh = module.params['refresh']
    rows_per_page = module.params['rows_per_page']
    url = module.params['url']
    medias = module.params['medias']
    zabbix_user_type = module.params['zabbix_user_type'] 
    state = module.params['state']
    force = module.params['force']
    timeout = module.params['timeout']

    # convert Zabbix user to 1; Zabbix admin to 2; Zabbix super admin to 3
    user_types = {
        'Zabbix user': 1,
        'Zabbix admin': 2,
        'Zabbix super admin': 3
    }
    zabbix_user_type = user_types[zabbix_user_type]
    
    zbx = None
    # login to Zabbix
    try:
        zbx = ZabbixAPI(server_url, timeout=timeout, user=login_user, passwd=login_password, validate_cert=validate_certs)
        zbx.login(login_user, login_password)
        atexit.register(zbx.logout)
    except Exception as e:
        module.fail_json(msg="Failed to connect to Zabbix Server: %s: %s" % (e, module.params['server_url']))
        
    user = User(module, zbx)
    
    user_group_ids = []

    if user_groups:
        user_group_ids = user.get_usergid_by_groupname(user_groups)

    # check if user exists
    does_user_exist = user.does_user_exist(user_name)
    
    if does_user_exist:
        # get user id by user name
        user_id = does_user_exist[0]['userid']
    
        if state == "absent":
            # remove user
            user.delete_user(user_id, user_name)
            module.exit_json(changed=True, result="Successfully delete user %s" % user_name)
        else:
            if not user_groups:
                # if user_groups have not been specified when updating an existing user, just get the groups ids
                # from an the existing user without updating them.
                user_groups = user.get_user_groups_by_user_id(user_id)
                user_group_ids = user.get_usergid_by_groupname(user_groups)

            # get existing user's medias
            exist_medias = user.get_user_medias_by_username(user_name)

            # if no medias were specified with the module, start with an empty list
            if not medias:
                medias = []
        
            # when force=no is specified, append exisiting medias to medias to update.
            # when no medias have been specified, copy exisiting media as specified from API
            if not force or not medias:
                for media in copy.deepcopy(exist_medias):
                # remove values not used during add/update
                    for del_key in ['mediaid','userid']:
                        del media[del_key]

                    if media not in medias:
                        medias.append(media)

            if not force:
                for group_id in user.get_usergid_by_groupname(user.get_user_groups_by_user_id(user_id)):
                    if group_id not in user_group_ids:
                        user_group_ids.append(group_id)

            # update user
            if user.check_all_params(does_user_exist, user_id, user_name, name, surname, user_groups, lang, theme, autologin, autologout, refresh,
                                        rows_per_page, url, medias, exist_medias, zabbix_user_type):

                user.update_user(user_id, user_name, name, surname, user_group_ids, lang, theme, autologin, autologout, refresh, rows_per_page,
                                    url, medias, zabbix_user_type, new_passwd)

                module.exit_json(changed=True, result="Successfully update user %s " % user_name)
                
            else:
                module.exit_json(changed=False)
    else:
        if state == "absent":
            # the user is already deleted or not exist
            module.exit_json(changed=False)

        if not user_groups:
            module.fail_json(msg="Specify at least one group for creating user '%s'." % user_name)

        if not user_passwd:
            module.fail_json(msg="A password must be entered for creating user '%s'." % user_name)

        # create user
        user.add_user(user_name,name, surname, user_group_ids, user_passwd, lang, theme, autologin, autologout, refresh, rows_per_page, 
                        url, medias, zabbix_user_type)
        module.exit_json(changed=True, result="Successfully added user '%s'." % user_name)

if __name__ == '__main__':
    main()