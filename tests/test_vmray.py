import io
from unittest import TestCase

try:
    from unittest.mock import patch, ANY as MOCK_ANY
except ImportError:
    from mock import patch, ANY as MOCK_ANY

import responses
import sandboxapi.vmray
from . import read_resource

class TestVMRay(TestCase):

    def setUp(self):
        self.sandbox = sandboxapi.vmray.VMRayAPI('key', 'http://vmray.mock')

    @responses.activate
    def test_analyze(self):
        responses.add(responses.POST, 'http://vmray.mock/rest/sample/submit',
                      json=read_resource('vmray_sample_submit'))
        self.assertEqual(self.sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'), 1169850)

    @responses.activate
    def test_analyze_with_errors(self):
        responses.add(responses.POST, 'http://vmray.mock/rest/sample/submit',
                      json=read_resource('vmray_sample_submit_errors'))
        with self.assertRaises(sandboxapi.SandboxError):
            self.assertEqual(self.sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'))

    @responses.activate
    def test_check(self):
        responses.add(responses.GET, 'http://vmray.mock/rest/submission/sample/1',
                      json=read_resource('vmray_submission_sample'))
        self.assertEqual(self.sandbox.check('1'), True)

    @responses.activate
    def test_is_available(self):
        responses.add(responses.GET, 'http://vmray.mock/rest/system_info',
                      json=read_resource('vmray_system_info'))
        self.assertTrue(self.sandbox.is_available())

    @responses.activate
    def test_not_is_available(self):
        self.assertFalse(self.sandbox.is_available())
        responses.add(responses.GET, 'http://vmray.mock/rest/system_info',
                      status=500)
        self.assertFalse(self.sandbox.is_available())

    @responses.activate
    def test_report(self):
        responses.add(responses.GET, 'http://vmray.mock/rest/analysis/sample/1',
                      json=read_resource('vmray_analysis_sample'))
        responses.add(responses.GET, 'http://vmray.mock/rest/analysis/1097123/archive/logs/summary.json',
                      json=read_resource('vmray_analysis_archive_logs_summary'))
        self.assertEqual(self.sandbox.report(1)['version'], 1)

    @responses.activate
    def test_score(self):
        responses.add(responses.GET, 'http://vmray.mock/rest/analysis/sample/1',
                      json=read_resource('vmray_analysis_sample'))
        responses.add(responses.GET, 'http://vmray.mock/rest/analysis/1097123/archive/logs/summary.json',
                      json=read_resource('vmray_analysis_archive_logs_summary'))
        self.assertEqual(self.sandbox.score(self.sandbox.report(1)), 20)

    @patch('requests.post')
    @patch('requests.get')
    def test_proxies_is_passed_to_requests(self, m_get, m_post):

        m_get.return_value.status_code = 200
        m_post.return_value.status_code = 200

        proxies = {
            'http': 'http://10.10.1.10:3128',
            'https': 'http://10.10.1.10:1080',
        }

        api = sandboxapi.vmray.VMRayAPI('key', self.sandbox.api_url,
                                        proxies=proxies)
        api._request('/test')

        m_get.assert_called_once_with(api.api_url + '/test', auth=MOCK_ANY,
                                      headers=MOCK_ANY, params=MOCK_ANY,
                                      proxies=proxies, verify=MOCK_ANY)

        api._request('/test', method='POST')

        m_post.assert_called_once_with(api.api_url + '/test', auth=MOCK_ANY,
                                       headers=MOCK_ANY, data=MOCK_ANY,
                                       files=None, proxies=proxies,
                                       verify=MOCK_ANY)
