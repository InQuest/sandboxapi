import io
import os
import json
import unittest
try:
    from unittest.mock import patch, ANY as MOCK_ANY
except ImportError:
    from mock import patch, ANY as MOCK_ANY
import responses
import sandboxapi.falcon
from . import read_resource


class TestFalcon(unittest.TestCase):

    def setUp(self):
        self.sandbox = sandboxapi.falcon.FalconAPI('key', 'http://falcon.mock/api/v2')

    @responses.activate
    def test_analyze(self):
        responses.add(responses.POST, 'http://falcon.mock/api/v2/submit/file',
                      json=read_resource('falcon_submit_file'), status=201)
        self.assertEqual(self.sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'), '1')

    @responses.activate
    def test_check(self):
        responses.add(responses.GET, 'http://falcon.mock/api/v2/report/1/state',
                      json=read_resource('falcon_report_state'))
        self.assertEqual(self.sandbox.check('1'), True)

    @responses.activate
    def test_is_available(self):
        responses.add(responses.GET, 'http://falcon.mock/api/v2/system/heartbeat',
                      json=read_resource('falcon_system_heartbeat'))
        self.assertTrue(self.sandbox.is_available())

    @responses.activate
    def test_not_is_available(self):
        self.assertFalse(self.sandbox.is_available())
        responses.add(responses.GET, 'http://falcon.mock/api/v2/system/heartbeat',
                      status=500)
        self.assertFalse(self.sandbox.is_available())

    @responses.activate
    def test_report(self):
        responses.add(responses.GET, 'http://falcon.mock/api/v2/report/1/summary',
                      json=read_resource('falcon_report_summary'))
        self.assertEqual(self.sandbox.report(1)['job_id'], '1')

    @responses.activate
    def test_score(self):
        responses.add(responses.GET, 'http://falcon.mock/api/v2/report/1/summary',
                      json=read_resource('falcon_report_summary'))
        self.assertEqual(self.sandbox.score(self.sandbox.report(1)), 5)

    @patch('requests.post')
    @patch('requests.get')
    def test_proxies_is_passed_to_requests(self, m_get, m_post):

        m_get.return_value.status_code = 200
        m_post.return_value.status_code = 200

        proxies = {
            'http': 'http://10.10.1.10:3128',
            'https': 'http://10.10.1.10:1080',
        }

        api = sandboxapi.falcon.FalconAPI('key', self.sandbox.api_url,
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
