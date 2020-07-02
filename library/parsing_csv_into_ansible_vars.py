#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Zainab Alsaffar <zalsaffa@redhat.com>

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: parsing_csv_into_ansible_vars:
short_description: Create a variable file for ansible playbook
description:
    - This is a custom module built to create a yml varible file. 
version_added: "1.0"
author: "Zainab Alsaffar (@zanssa)"
requirments:
    - "python >= 2.6"
options:
    csv_file:
        description:
            - A CSV file name.
        required: true
        type: str
    yaml_file:
        description:
            - A yml file name.
        required: true
        type: str
notes: supports_check_mode is allowed in this module
'''
EXAMPLES = '''
- name: Parsing a CSV file into an Ansible varible file
  parsing_csv_into_ansible_vars:
  csv_file: example.csv
  yaml_file: example.yml
'''

from ansible.module_utils.basic import AnsibleModule
import csv, yaml, os.path
from os import path

def check_csv_file_exists(csv_file):
    does_file_exists = path.exists(csv_file)
    if does_file_exists:
        return True

def main():
    module = AnsibleModule(argument_spec=dict(
        csv_file=dict(type='str', required=True),
        yaml_file=dict(type='str', required=False)
    ),
    supports_check_mode=True)

    csv_file = module.params['csv_file']
    yaml_file = module.params['yaml_file']

    file_exists = check_csv_file_exists(csv_file)

    if file_exists:
        csv_data = []
        with open(csv_file) as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                csv_data.append(row)
 
        with open(yaml_file, 'w') as outfile:
            outfile.write(yaml.dump({'csv_data': csv_data}))

        module.exit_json(changed=True, result="A yml Variabe file for Ansible has been successfully created: %s" % yaml_file)
    else:
        module.fail_json(changed=False, msg="CSV file not found %s" % csv_file)

if __name__=="__main__":
    main()