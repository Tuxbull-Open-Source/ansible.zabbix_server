#!/usr/bin/python
from ansible.module_utils.basic import AnsibleModule
import json
import os

module = AnsibleModule(argument_spec=dict(name=dict(required=True), state=dict(required=True)))
state_path = os.environ['LIFECYCLE_STATE']
with open(state_path, encoding='utf-8') as stream:
    state = json.load(stream)
state['events'].append('package')
schema_ready = (state.get('schema_rows') == 1 and
                isinstance(state.get('mandatory', 8000000), (int, float)) and
                not isinstance(state.get('mandatory', 8000000), bool))
if not schema_ready and not state.get('masked'):
    module.fail_json(msg='package transaction was not protected by preinstall mask')
state['unit_exists'] = True
state['database_exists'] = True
with open(state_path, 'w', encoding='utf-8') as stream:
    json.dump(state, stream, sort_keys=True)
module.exit_json(changed=not state.get('package_installed_before', False))
