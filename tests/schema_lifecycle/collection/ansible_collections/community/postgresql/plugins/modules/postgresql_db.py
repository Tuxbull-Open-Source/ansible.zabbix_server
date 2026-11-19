#!/usr/bin/python
from ansible.module_utils.basic import AnsibleModule
import json
import os

module = AnsibleModule(argument_spec=dict(name=dict(required=True), login_user=dict(no_log=True), login_password=dict(no_log=True), login_host=dict(), login_port=dict(type='int'), state=dict(required=True), target=dict()))
path = os.environ['LIFECYCLE_STATE']
with open(path, encoding='utf-8') as stream:
    data = json.load(stream)
data['events'].append('import')
if data.get('import_failure'):
    with open(path, 'w', encoding='utf-8') as stream:
        json.dump(data, stream, sort_keys=True)
    module.fail_json(msg='synthetic import failure')
data['schema_rows'] = 1
with open(path, 'w', encoding='utf-8') as stream:
    json.dump(data, stream, sort_keys=True)
module.exit_json(changed=True)
