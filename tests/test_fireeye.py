import io
import unittest
try:
    from unittest.mock import patch, ANY as MOCK_ANY
except ImportError:
    from mock import patch, ANY as MOCK_ANY
import responses
import sandboxapi.fireeye
from . import read_resource


class TestFireEye(unittest.TestCase):

    def setUp(self):
        self.sandbox = sandboxapi.fireeye.FireEyeAPI('username', 'password', 'http://fireeye.mock', 'profile')
        self.legacy_sandbox = sandboxapi.fireeye.FireEyeAPI('username', 'password',
                                                            'http://fireeye.mock', 'profile',
                                                            legacy_api=True)

    @responses.activate
    def test_analyze(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.2.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.2.0/submissions',
                      json=read_resource('fireeye_submissions'))
        self.assertEquals(self.sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'), 1)

    @responses.activate
    def test_check(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.2.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.2.0/submissions/status/1',
                      json=read_resource('fireeye_submissions_status'))
        self.assertEquals(self.sandbox.check('1'), True)

    @responses.activate
    def test_is_available(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.2.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.2.0/config',
                      json=read_resource('fireeye_config'))
        self.assertTrue(self.sandbox.is_available())

    @responses.activate
    def test_not_is_available(self):
        self.assertFalse(self.sandbox.is_available())
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.2.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.2.0/config',
                      status=500)
        self.assertFalse(self.sandbox.is_available())

    @responses.activate
    def test_report(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.2.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.2.0/submissions/results/1',
                      json=read_resource('fireeye_submissions_results'))
        self.assertEquals(self.sandbox.report(1)['msg'], 'concise')

    @responses.activate
    def test_score(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.2.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.2.0/submissions/results/1',
                      json=read_resource('fireeye_submissions_results'))
        self.assertEquals(self.sandbox.score(self.sandbox.report(1)), 8)

    # Legacy API support.
    @responses.activate
    def test_analyze(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/submissions',
                      json=read_resource('fireeye_submissions'))
        self.assertEquals(self.legacy_sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'), 1)

    @responses.activate
    def test_check(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.1.0/submissions/status/1',
                      json=read_resource('fireeye_submissions_status'))
        self.assertEquals(self.legacy_sandbox.check('1'), True)

    @responses.activate
    def test_is_available(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.1.0/config',
                      json=read_resource('fireeye_config'))
        self.assertTrue(self.legacy_sandbox.is_available())

    @responses.activate
    def test_not_is_available(self):
        self.assertFalse(self.legacy_sandbox.is_available())
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.1.0/config',
                      status=500)
        self.assertFalse(self.legacy_sandbox.is_available())

    @responses.activate
    def test_report(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.1.0/submissions/results/1',
                      json=read_resource('fireeye_submissions_results'))
        self.assertEquals(self.legacy_sandbox.report(1)['msg'], 'concise')

    @responses.activate
    def test_score(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.1.0/submissions/results/1',
                      json=read_resource('fireeye_submissions_results'))
        self.assertEquals(self.legacy_sandbox.score(self.legacy_sandbox.report(1)), 8)

    # Core functionality.
    @patch('requests.post')
    @patch('requests.get')
    def test_proxies_is_passed_to_requests(self, m_get, m_post):

        m_get.return_value.status_code = 200
        m_get.return_value.content = b''
        m_post.return_value.status_code = 200
        m_post.return_value.content = b''

        proxies = {
            'http': 'http://10.10.1.10:3128',
            'https': 'http://10.10.1.10:1080',
        }

        api = sandboxapi.fireeye.FireEyeAPI('username', 'password',
                                            self.sandbox.api_url, 'profile',
                                            proxies=proxies)
        api._request('/test')

        m_get.assert_called_once_with(api.api_url + '/test', auth=MOCK_ANY,
                                      headers=MOCK_ANY, params=MOCK_ANY,
                                      proxies=proxies, verify=MOCK_ANY)

        api._request('/test', method='POST')

        m_post.assert_called_with(api.api_url + '/test', auth=MOCK_ANY,
                                  headers=MOCK_ANY, data=MOCK_ANY,
                                  files=None, proxies=proxies,
                                  verify=MOCK_ANY)

    @responses.activate
    def test_reauthenticates_if_logged_out_http_401(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.2.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.2.0/submissions/status/1',
                      status=401)
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.2.0/submissions/status/1',
                      json=read_resource('fireeye_submissions_status'))
        self.assertEquals(self.sandbox.check('1'), True)

    @responses.activate
    def test_reauthenticates_if_logged_out_json_401(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.2.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.2.0/submissions/status/1',
                      json=read_resource('fireeye_unauthorized'))
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.2.0/submissions/status/1',
                      json=read_resource('fireeye_submissions_status'))
        self.assertEquals(self.sandbox.check('1'), True)
