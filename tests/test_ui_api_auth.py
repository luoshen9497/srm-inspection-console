"""Real CAS fixture + browser adapter tests for API-authenticated UI runs."""
import copy
import http.cookiejar
import json
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch
from urllib.request import HTTPCookieProcessor, build_opener

from app import InspectionState, inspection_timeout_budget, run_inspection, validate_config
from api_auth import auth_flow_hash, browser_cookies
from browser_executor import run_ui_checks
import test_api_auth_flows as auth_fixture
from test_ui_inspection import FakeBrowser, FakeContext, FakePage, FakeRuntime


class CookieContext(FakeContext):
    def add_cookies(self, cookies):
        self.cookies = copy.deepcopy(cookies)


class UiApiAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        auth_fixture.AuthFlowTests.setUpClass()
        cls.server = auth_fixture.AuthFlowTests.server
        cls.base = auth_fixture.AuthFlowTests.base

    @classmethod
    def tearDownClass(cls):
        auth_fixture.AuthFlowTests.tearDownClass()

    def setUp(self):
        self.server.fail_login = False
        self.contexts = []
        self.entry_urls = []

    def config(self):
        config = auth_fixture.fixture_config(self.base, True)
        config['ui'] = {'base_url': self.base, 'default_timeout_seconds': 1}
        config['checks'].append({
            'id': 'ui-home', 'name': 'UI 首页', 'type': 'ui', 'enabled': True,
            'auth_dependency': {'api_flow_id': 'fixture-login', 'entry_url': self.base + '/landing?ticket=${token}'},
            'steps': [
                {'id': 'open-home', 'description': '打开首页', 'action': 'goto', 'path': '/'},
                {'id': 'verify-home', 'description': '验证首页', 'action': 'assert_visible', 'locator': {'test_id': 'workbench'}},
            ],
        })
        return config

    def runner(self, checks, config, variables, store, **kwargs):
        page = FakePage()
        context = CookieContext(page)
        self.contexts.append(context)
        browser = FakeBrowser(context)

        @contextmanager
        def runtime_factory():
            yield FakeRuntime(browser)

        result = run_ui_checks(checks, config, variables, store, runtime_factory=runtime_factory, **kwargs)
        self.entry_urls.extend(action[1] for action in page.actions if action[0] == 'goto' and '/landing?' in action[1])
        return result

    def test_ui_only_gets_fresh_auth_each_scheduled_run_without_running_business_apis(self):
        config = self.config()
        validate_config(config)
        before = self.server.logins
        with tempfile.TemporaryDirectory() as temp, patch('app.run_ui_checks', side_effect=self.runner):
            for index in range(2):
                report = run_inspection(config, 'fixture', targets=['ui'], trigger='scheduled',
                                        artifact_root=Path(temp), run_id=f'run-{index}')
                self.assertEqual(report['status'], 'passed', report)
                self.assertEqual({r['id'] for r in report['checks']}, {'api-auth-fixture-login', 'ui-home'})
                self.assertTrue(all(r['type'] == 'ui' for r in report['checks']))
                self.assertNotIn('access-', json.dumps(report))
                self.assertNotIn('fresh-session', json.dumps(report))
        self.assertEqual(self.server.logins, before + 2)
        self.assertEqual(len(set(self.entry_urls)), 2)
        self.assertTrue(all(context.cookies[0]['name'] == 'sid' and context.closed for context in self.contexts))

    def test_combined_run_shares_one_api_login_with_multiple_ui_scenes(self):
        config = self.config()
        second = copy.deepcopy(config['checks'][-1])
        second['id'] = 'ui-second'
        config['checks'].append(second)
        before = self.server.logins
        with tempfile.TemporaryDirectory() as temp, patch('app.run_ui_checks', side_effect=self.runner):
            report = run_inspection(config, 'fixture', targets=['api', 'ui'], artifact_root=Path(temp))
        self.assertEqual(report['status'], 'passed', report)
        self.assertEqual(self.server.logins, before + 1)
        self.assertEqual(len(self.contexts), 1)
        self.assertEqual(len(self.entry_urls), 1)

    def test_api_failure_blocks_browser_and_business_scene(self):
        self.server.fail_login = True
        with tempfile.TemporaryDirectory() as temp, patch('app.run_ui_checks', side_effect=self.runner), patch('browser_executor._launch_browser') as launch:
            report = run_inspection(self.config(), 'fixture', targets=['ui'], artifact_root=Path(temp))
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(report['checks'][0]['classification'], 'authentication_failed')
        self.assertEqual(report['checks'][1]['status'], 'skipped')
        launch.assert_not_called()

    def test_editor_full_and_partial_tests_execute_api_dependency(self):
        with tempfile.TemporaryDirectory() as temp, patch('app.run_ui_checks', side_effect=self.runner):
            root = Path(temp)
            path = root / 'fixture-system.json'
            path.write_text(json.dumps(self.config()))
            state = InspectionState(path, root / 'runs', use_environment_fallback=False)
            scene = self.config()['checks'][-1]
            for partial in (False, True):
                result = state.test_ui_check({'check': scene, 'through_step_id': 'open-home'}, through_step=partial)
                self.assertEqual(result['status'], 'passed', result)
                self.assertEqual(result['session_checks'][0]['id'], 'api-auth-fixture-login')
                self.assertEqual(len(result['check']['steps']), 1 if partial else 2)
                self.assertNotIn('access-', json.dumps(result))

    def test_invalid_cross_origin_missing_disabled_and_conflicting_dependencies_rejected(self):
        for mutation, message in [
            ({'entry_url': 'https://unapproved.example/?ticket=${token}'}, '允许来源'),
            ({'entry_url': self.base + '/?ticket=${missing}'}, '输出变量'),
            ({'api_flow_id': 'missing'}, '不存在'),
            ({'scene_id': 'ui-login'}, '只能选择一个'),
            ({'entry_url': self.base + '/?ticket=${token|base64}'}, '格式无效'),
        ]:
            config = self.config()
            config['checks'][-1]['auth_dependency'].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, message):
                validate_config(config)
        config = self.config()
        config['api_auth_flows'][0]['enabled'] = False
        for check in config['checks'][:4]:
            check['enabled'] = False
        with self.assertRaisesRegex(ValueError, '先启用 API'):
            validate_config(config)

    def test_cookie_export_preserves_scope_flags_and_session_expiry(self):
        jar = http.cookiejar.CookieJar()
        jar.set_cookie(http.cookiejar.Cookie(
            0, 'sid', 'private-cookie', None, False, '.example.test', True, True,
            '/cas', True, True, None, True, None, None, {'HttpOnly': None, 'SameSite': 'none'}, False,
        ))
        opener = build_opener(HTTPCookieProcessor(jar))
        cookie = browser_cookies((opener, opener))[0]
        self.assertEqual(cookie['domain'], '.example.test')
        self.assertEqual(cookie['path'], '/cas')
        self.assertTrue(cookie['secure'])
        self.assertTrue(cookie['httpOnly'])
        self.assertEqual(cookie['sameSite'], 'None')
        self.assertNotIn('expires', cookie)

    def test_browser_bootstrap_failure_blocks_scenes_and_redacts_credentials(self):
        def failed_runner(checks, config, variables, store, **kwargs):
            auth = kwargs['api_auth_context']
            page = FakePage()
            page.render_wait_error = TimeoutError('callback failed ' + auth['variables']['token'] + ' fresh-session')
            context = CookieContext(page)
            @contextmanager
            def runtime_factory():
                yield FakeRuntime(FakeBrowser(context))
            results = run_ui_checks(checks, config, variables, store, runtime_factory=runtime_factory, **kwargs)
            self.assertTrue(context.closed)
            return results
        with tempfile.TemporaryDirectory() as temp, patch('app.run_ui_checks', side_effect=failed_runner):
            report = run_inspection(self.config(), 'fixture', targets=['ui'], artifact_root=Path(temp))
        self.assertEqual(report['checks'][0]['status'], 'failed')
        self.assertEqual(report['checks'][1]['status'], 'skipped')
        self.assertNotIn('access-', json.dumps(report))
        self.assertNotIn('fresh-session', json.dumps(report))

    def test_distinct_flows_use_isolated_browser_contexts(self):
        config = self.config()
        second_flow = copy.deepcopy(config['api_auth_flows'][0])
        second_flow['id'] = 'second-login'
        second_flow['step_ids'] = ['second-' + sid for sid in second_flow['step_ids']]
        for step in copy.deepcopy(config['checks'][:4]):
            step['id'] = 'second-' + step['id']
            config['checks'].append(step)
        config['api_auth_flows'].append(second_flow)
        second_scene = copy.deepcopy(next(c for c in config['checks'] if c['id'] == 'ui-home'))
        second_scene['id'] = 'ui-other'
        second_scene['auth_dependency']['api_flow_id'] = 'second-login'
        config['checks'].append(second_scene)
        validate_config(config)
        with tempfile.TemporaryDirectory() as temp, patch('app.run_ui_checks', side_effect=self.runner):
            report = run_inspection(config, 'fixture', targets=['ui'], artifact_root=Path(temp))
        self.assertEqual(report['status'], 'passed', report)
        self.assertEqual(len(self.contexts), 2)
        self.assertIsNot(self.contexts[0], self.contexts[1])
        self.assertEqual(len(set(self.entry_urls)), 2)

    def test_lease_budget_counts_implicit_auth_once_and_bootstrap(self):
        config = self.config()
        ui = config['checks'][-1]
        # Two 1-second UI steps, four default 10-second API login steps,
        # and a 4-second browser bootstrap budget.
        self.assertEqual(inspection_timeout_budget(config, [ui]), 46)
        second = copy.deepcopy(ui)
        second['id'] = 'ui-more'
        self.assertEqual(inspection_timeout_budget(config, [ui, second]), 48)
        self.assertEqual(inspection_timeout_budget(config, config['checks'][:4] + [ui]), 46)

    def test_runtime_token_in_entry_path_is_redacted_from_browser_evidence(self):
        config = self.config()
        config['checks'][-1]['auth_dependency']['entry_url'] = self.base + '/bootstrap/${token}/'
        with tempfile.TemporaryDirectory() as temp, patch('app.run_ui_checks', side_effect=self.runner):
            report = run_inspection(config, 'fixture', targets=['ui'], artifact_root=Path(temp))
        self.assertEqual(report['status'], 'passed', report)
        self.assertNotIn('access-', json.dumps(report))
        self.assertIn('***', report['checks'][0]['evidence']['page_url'])

    def test_empty_scene_entry_uses_flow_default_for_auth_and_lease(self):
        config = self.config()
        config['api_auth_flows'][0]['browser_entry_url'] = config['checks'][-1]['auth_dependency']['entry_url']
        config['checks'][-1]['auth_dependency']['entry_url'] = ''
        self.assertEqual(inspection_timeout_budget(config, [config['checks'][-1]]), 46)
        with tempfile.TemporaryDirectory() as temp, patch('app.run_ui_checks', side_effect=self.runner):
            report = run_inspection(config, 'fixture', targets=['ui'], artifact_root=Path(temp))
        self.assertEqual(report['status'], 'passed', report)
        self.assertEqual(len(self.entry_urls), 1)
        self.assertTrue(report['checks'][0]['evidence']['browser_entry_completed'])

    def test_redirect_to_login_cannot_pass_a_goto_only_authenticated_scene(self):
        def redirected_runner(checks, config, variables, store, **kwargs):
            page = FakePage()
            original_goto = page.goto
            def redirected_goto(url, wait_until, timeout):
                response = original_goto(url, wait_until, timeout)
                if '/landing?' not in url:
                    page.url = self.base + '/cas-web/login'
                return response
            page.goto = redirected_goto
            context = CookieContext(page)
            @contextmanager
            def runtime_factory():
                yield FakeRuntime(FakeBrowser(context))
            return run_ui_checks(checks, config, variables, store, runtime_factory=runtime_factory, **kwargs)
        config = self.config()
        config['checks'][-1]['steps'] = config['checks'][-1]['steps'][:1]
        with tempfile.TemporaryDirectory() as temp, patch('app.run_ui_checks', side_effect=redirected_runner):
            report = run_inspection(config, 'fixture', targets=['ui'], artifact_root=Path(temp))
        self.assertEqual(report['status'], 'failed')
        scene = report['checks'][-1]
        self.assertEqual(scene['classification'], 'authentication_failed')
        self.assertIn('跳回登录页', scene['reason'])
        self.assertIn('failure_screenshot', scene['steps'][0])

    def test_default_flow_entry_must_be_trusted_and_use_exported_variables(self):
        for entry, message in [('https://evil.example/?ticket=${token}', '允许来源'),
                               (self.base + '/?ticket=${missing}', '输出变量')]:
            config = self.config()
            config['api_auth_flows'][0]['browser_entry_url'] = entry
            with self.subTest(entry=entry), self.assertRaisesRegex(ValueError, message):
                validate_config(config)

    def test_browser_default_does_not_change_api_request_contract_hash(self):
        config = self.config()
        flow = config['api_auth_flows'][0]
        original = auth_flow_hash(config, flow)
        flow['browser_entry_url'] = self.base + '/landing?ticket=${token}'
        self.assertEqual(auth_flow_hash(config, flow), original)
        config['checks'][0]['path'] = '/different-login'
        self.assertNotEqual(auth_flow_hash(config, flow), original)


if __name__ == '__main__':
    unittest.main()
