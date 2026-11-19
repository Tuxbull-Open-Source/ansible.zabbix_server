#!/usr/bin/python
from ansible.module_utils.basic import AnsibleModule
import json
import os

module = AnsibleModule(argument_spec=dict(login_db=dict(), query=dict(required=True), positional_args=dict(type='list'), login_user=dict(no_log=True), login_password=dict(no_log=True), login_host=dict(), login_port=dict(type='int')))
path = os.environ['LIFECYCLE_STATE']
with open(path, encoding='utf-8') as stream:
    state = json.load(stream)
query = module.params['query']
state['events'].append('query:' + query)
if 'pg_database' in query:
    result, rowcount = [{'exists': state['database_exists']}], 1
elif 'to_regclass' in query:
    result, rowcount = [{'dbversion': 'dbversion' if state['schema_rows'] is not None else None}], 1
elif 'count(*)' in query:
    result, rowcount = [{'rows': state['schema_rows']}], 1
elif 'SELECT mandatory' in query:
    if state.get('verify_failure'):
        result, rowcount = [], 0
    else:
        result, rowcount = [{'mandatory': state.get('mandatory', 8000000)}], 1
else:
    module.fail_json(msg='unexpected query')
with open(path, 'w', encoding='utf-8') as stream:
    json.dump(state, stream, sort_keys=True)
module.exit_json(changed=False, query_result=result, rowcount=rowcount)
