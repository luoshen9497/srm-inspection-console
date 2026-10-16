import copy
import base64
import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from app import ConfigRepository, InspectionState, run_inspection, validate_config, import_metersphere
from api_auth import redact_auth_evidence


class CasFixture(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body=b'', **headers):
        self.send_response(status)
        for key, value in headers.items():
            self.send_header(key.replace('_', '-'), value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path)
        if path.path == '/login':
            self.server.logins += 1
            self.reply(200, b'<input name="lt" value="fresh-lt">', Content_Type='text/html', Set_Cookie='sid=fresh-session; Path=/')
        elif path.path == '/callback':
            valid = parse_qs(path.query).get('ticket') == ['ST-fresh'] and self.headers.get('Cookie') == 'sid=fresh-session'
            self.reply(302 if valid else 403, Location=f'/landing?ticket=access-{self.server.logins}')
        elif path.path in ('/user', '/business', '/detail'):
            valid = self.headers.get('Authorization') == f'Bearer access-{self.server.logins}'
            if path.path == '/detail':
                valid = valid and parse_qs(path.query).get('user') == ['42']
            self.reply(200 if valid else 401, json.dumps({'ok': valid, 'userId':42, 'accessToken':f'access-{self.server.logins}'}).encode(), Content_Type='application/json')
        elif path.path == '/public':
            self.reply(200, b'{"ok":true}', Content_Type='application/json')
        else:
            self.reply(404)

    def do_POST(self):
        body = parse_qs(self.rfile.read(int(self.headers.get('Content-Length', 0))).decode())
        valid = not self.server.fail_login and body.get('lt') == ['fresh-lt'] and body.get('username') == ['fixture-user'] and body.get('password') == ['fixture-password'] and self.headers.get('Cookie') == 'sid=fresh-session'
        if valid:
            self.reply(302, Location='/callback?ticket=ST-fresh')
        else:
            self.reply(200, b'<html>login failed</html>', Content_Type='text/html')


def fixture_config(base, enabled=False):
    assertion = [{'path':'$.ok','op':'equals','value':True}]
    checks = [
        {'id':'login-page','name':'获取登录页','method':'GET','path':'/login','response_type':'text','expected_status':200,
         'extract':[{'variable':'lt','source':'body','pattern':'name="lt" value="([^"]+)"'}], 'assertions':[]},
        {'id':'submit-login','name':'提交登录','method':'POST','path':'/login','response_type':'text','expected_status':302,'follow_redirects':False,
         'body_encoding':'form','body':{'lt':'${lt}','username':'${SRM_USERNAME}','password':'${SRM_PASSWORD}'},
         'extract':[{'variable':'ticket','source':'headers','pattern':r'[?&]ticket=([^&\s]+)'}], 'assertions':[]},
        {'id':'exchange-token','name':'兑换 token','method':'GET','path':'/callback?ticket=${ticket}', 'response_type':'text','expected_status':302,'follow_redirects':False,
         'extract':[{'variable':'suposTicket','source':'headers','pattern':r'[?&]ticket=([^&\s]+)'}], 'assertions':[]},
        {'id':'verify-user','name':'验证用户','method':'GET','path':'/user','headers':{'Authorization':'Bearer ${suposTicket}'},
         'extract':[{'variable':'userId','path':'$.userId'}],'assertions':copy.deepcopy(assertion),'login_precheck':True},
    ]
    for check in checks:
        check.update(enabled=enabled, session_setup=True)
    ids=[check['id'] for check in checks]
    checks.extend([
        {'id':'business-query','name':'业务查询','method':'GET','path':'/business','enabled':enabled,'auth_flow_id':'fixture-login',
         'headers':{'Authorization':'Bearer ${token}'},'assertions':copy.deepcopy(assertion)},
        {'id':'business-detail','name':'业务详情','method':'GET','path':'/detail?user=${userId}','enabled':enabled,'auth_flow_id':'fixture-login',
         'headers':{'Authorization':'Bearer ${token}'},'assertions':copy.deepcopy(assertion)},
        {'id':'public-query','name':'公共查询','method':'GET','path':'/public','enabled':True,'assertions':copy.deepcopy(assertion)},
    ])
    return {'system_id':'fixture-system','environment':'test','base_url':base,'adapter':'cas-session-v1','allowed_origins':[base],
            'variables':{'SRM_USERNAME':'fixture-user','SRM_PASSWORD':'fixture-password'},'checks':checks,
            'api_auth_flows':[{'id':'fixture-login','name':'模拟登录流程','enabled':enabled,'step_ids':ids,'outputs':{'token':'suposTicket','userId':'userId'}}]}


class AuthFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=ThreadingHTTPServer(('127.0.0.1',0), CasFixture)
        cls.server.logins=0
        cls.server.fail_login=False
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True)
        cls.thread.start()
        cls.base=f'http://127.0.0.1:{cls.server.server_port}'

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.server.fail_login=False

    def state(self, root):
        path=root/'fixture-system.json'
        path.write_text(json.dumps(fixture_config(self.base)))
        ConfigRepository(path).migrate()
        return InspectionState(path, root/'runs',use_environment_fallback=False)

    def draft(self, state):
        config,_=state.repository.load()
        flow=config['api_auth_flows'][0]
        by_id={c['id']:c for c in config['checks']}
        return {'flow':flow,'steps':[by_id[sid] for sid in flow['step_ids']]}

    def test_whole_chain_cookies_redirects_export_once_per_run(self):
        config=fixture_config(self.base,True)
        validate_config(config)
        before=self.server.logins
        for _ in range(2):
            report=run_inspection(config,'fixture',targets=['api'])
            self.assertEqual(report['status'],'passed',report)
            self.assertEqual(len(report['checks']),7)
            self.assertNotIn('access-',json.dumps(report))
            self.assertNotIn('ST-fresh',json.dumps(report))
        self.assertEqual(self.server.logins,before+2)

    def test_assertions_cannot_persist_the_runtime_token(self):
        config=fixture_config(self.base,True)
        config['checks'][3]['assertions'].append({'path':'$.accessToken','op':'nonempty','record_actual':True})
        config['checks'][4]['assertions'].append({'path':'$.accessToken','op':'equals','value':'${token}','record_actual':True})
        report=run_inspection(config,'fixture',targets=['api'])
        self.assertEqual(report['status'],'passed')
        self.assertNotIn('access-',json.dumps(report))
        business=next(c for c in report['checks'] if c['id']=='business-query')
        self.assertEqual(business['assertions'][-1]['actual'],'***')
        self.assertEqual(business['assertions'][-1]['expected'],'***')

    def test_failed_step_blocks_outputs_and_dependents_only(self):
        config=fixture_config(self.base,True)
        config['variables']['suposTicket']='stale-credential'
        self.server.fail_login=True
        report=run_inspection(config,'fixture',targets=['api'])
        statuses={c['id']:c['status'] for c in report['checks']}
        self.assertEqual(statuses['submit-login'],'failed')
        for sid in ['exchange-token','verify-user','business-query','business-detail']:
            self.assertEqual(statuses[sid],'skipped')
        self.assertEqual(statuses['public-query'],'passed')

    def test_test_then_enable_is_atomic_and_does_not_store_tokens(self):
        with tempfile.TemporaryDirectory() as temp:
            state=self.state(Path(temp))
            document=state.api_checks_document()
            for item in document['items']:
                item['enabled']=True
            document['auth_flows'][0]['enabled']=True
            with self.assertRaisesRegex(ValueError,'完整测试'):
                state.update_api_checks(document)
            result=state.test_auth_flow(self.draft(state))
            self.assertTrue(result['verified'])
            self.assertTrue(all(output['present'] for output in result['outputs']))
            self.assertNotIn('access-',json.dumps(result))
            saved=state.update_api_checks(document)
            self.assertTrue(saved['verification']['fixture-login']['verified'])
            # The verification store contains a hash, never the exported token.
            record=state.runtime.get_metadata('api-auth-verification:fixture-login',{})
            self.assertEqual(set(record),{'flow_hash','verified_at'})
            self.assertNotIn('access-',json.dumps(state.repository.load()))
            self.assertEqual(state.preflight()['status'],'passed')
            business=next(c for c in saved['items'] if c['id']=='business-query')
            self.assertEqual(state.test_check({'check':business})['status'],'passed')

    def test_contract_change_or_failed_retest_requires_new_success(self):
        with tempfile.TemporaryDirectory() as temp:
            state=self.state(Path(temp))
            draft=self.draft(state)
            state.test_auth_flow(draft)
            document=state.api_checks_document()
            document['auth_flows'][0]['enabled']=True
            for item in document['items'][:4]: item['enabled']=True
            document['items'][0]['path']='/login?changed=true'
            with self.assertRaisesRegex(ValueError,'完整测试'):
                state.update_api_checks(document)
            self.server.fail_login=True
            result=state.test_auth_flow(draft)
            self.assertFalse(result['verified'])
            self.assertTrue(all(not output['present'] for output in result['outputs']))
            document['items'][0]['path']='/login'
            with self.assertRaisesRegex(ValueError,'完整测试'):
                state.update_api_checks(document)

    def test_order_missing_dependency_and_partial_enable_rejected(self):
        config=fixture_config(self.base,True)
        config['api_auth_flows'][0]['step_ids'][0:2]=reversed(config['api_auth_flows'][0]['step_ids'][0:2])
        with self.assertRaisesRegex(ValueError,'尚未提取'):
            validate_config(config)
        config=fixture_config(self.base,True)
        config['checks'][0]['headers']={'X-Ticket':'${ticket|base64}'}
        with self.assertRaisesRegex(ValueError,'尚未提取'):
            validate_config(config)
        config=fixture_config(self.base)
        config['checks'][0]['enabled']=True
        with self.assertRaisesRegex(ValueError,'整体启用'):
            validate_config(config)
        config=fixture_config(self.base)
        config['checks'][4]['enabled']=True
        with self.assertRaisesRegex(ValueError,'先验证并启用'):
            validate_config(config)
        config['checks'][4]['auth_flow_id']='missing-flow'
        with self.assertRaisesRegex(ValueError,'不存在'):
            validate_config(config)

    def test_encoded_credentials_are_redacted_from_authentication_evidence(self):
        secret='fixture-password'
        encoded=base64.b64encode(secret.encode()).decode()
        result={'reason':encoded,'evidence':{'server_message':secret},'assertions':[]}
        redact_auth_evidence(result,[secret])
        self.assertEqual(result['reason'],'***')
        self.assertEqual(result['evidence']['server_message'],'***')

    def test_settings_api_ui_updates_preserve_flow_domain(self):
        with tempfile.TemporaryDirectory() as temp:
            state=self.state(Path(temp))
            before=state.api_checks_document()
            settings=state.settings_document()
            settings['settings']['display_name']='New name'
            settings['credentials']={}
            state.update_settings(settings)
            self.assertEqual(state.api_checks_document()['auth_flows'],before['auth_flows'])
            self.assertEqual(state.api_checks_document()['version'],before['version'])
            state.update_ui_scenes(state.ui_scenes_document())
            self.assertEqual(state.api_checks_document()['auth_flows'],before['auth_flows'])
            document=state.api_checks_document()
            document.pop('auth_flows')
            state.update_api_checks(document)
            self.assertEqual(state.api_checks_document()['auth_flows'],before['auth_flows'])
            with self.assertRaises(ValueError):
                state.delete_collection_item('api','login-page',{'version':state.api_checks_document()['version']})


    def test_draft_can_be_incomplete_but_test_and_enable_validate_it(self):
        with tempfile.TemporaryDirectory() as temp:
            state=self.state(Path(temp))
            document=state.api_checks_document()
            document['items'][3]['assertions']=[]
            document['auth_flows'][0]['outputs']['token']='not_extracted'
            state.update_api_checks(document)
            with self.assertRaisesRegex(ValueError,'输出变量|最后一步'):
                state.test_auth_flow(self.draft(state))

    def test_credentials_changed_after_test_cannot_enable_old_verification(self):
        with tempfile.TemporaryDirectory() as temp:
            state=self.state(Path(temp))
            state.test_auth_flow(self.draft(state))
            state.credentials.update({'password':'different-fixture-password'})
            document=state.api_checks_document()
            document['auth_flows'][0]['enabled']=True
            for item in document['items'][:4]: item['enabled']=True
            self.assertFalse(document['verification']['fixture-login']['verified'])
            with self.assertRaisesRegex(ValueError,'完整测试'):
                state.update_api_checks(document)

    def test_migration_is_idempotent_and_links_token_consumers(self):
        from migrate_api_auth_flows import prepare
        config=fixture_config(self.base,True)
        config.pop('api_auth_flows')
        for check,name in zip(config['checks'][:4],['/cas/login','登录-step1','登录-step2','获取用户信息']): check['name']=name
        for check in config['checks'][4:6]:
            check.pop('auth_flow_id')
            check['headers']['Authorization']='Bearer ${suposTicket}'
        migrated,changed=prepare(config)
        self.assertTrue(changed)
        validate_config(migrated)
        self.assertEqual(migrated['api_auth_flows'][0]['outputs']['token'],'suposTicket')
        self.assertEqual(migrated['checks'][4]['auth_flow_id'],'ubd-login')
        self.assertFalse(any(c['enabled'] for c in migrated['checks'][:6]))
        again,changed=prepare(migrated)
        self.assertFalse(changed)
        self.assertEqual(again,migrated)

    def test_reimport_disables_whole_flow_and_retains_token_mapping(self):
        config=fixture_config(self.base,True)
        steps=[{'type':'HTTPSamplerProxy','name':c['name'],'method':c['method'],'url':self.base+c['path'],
                'headers':[{'name':'Authorization','value':'Bearer ${suposTicket}'}] if c.get('auth_flow_id') else []}
               for c in config['checks']]
        result=import_metersphere(json.dumps({'data':[{'scenarioDefinition':{'hashTree':steps}}]}),config)
        self.assertFalse(result['api_auth_flows'][0]['enabled'])
        self.assertTrue(all(not c['enabled'] for c in result['checks']))
        business=next(c for c in result['checks'] if c['id']=='business-query')
        self.assertEqual(business['auth_flow_id'],'fixture-login')
        self.assertEqual(business['headers']['Authorization'],'Bearer ${token}')
        validate_config(result)


if __name__=='__main__':
    unittest.main()
