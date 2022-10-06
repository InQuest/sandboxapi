import io
import unittest
try:
    from unittest.mock import patch
except ImportError:
    from mock import patch
import responses
import sandboxapi.joe
import jbxapi
from . import read_resource


class TestJoe(unittest.TestCase):

    def setUp(self):
        self.sandbox = sandboxapi.joe.JoeAPI('key', 'http://joe.mock/api', True)

    @responses.activate
    def test_analyze(self):
        if not jbxapi.__version__.startswith("2"):
            responses.add(responses.POST, 'http://joe.mock/api/v2/submission/new',
                        json=read_resource('joe_submission_new'))
        else:
            responses.add(responses.POST, 'http://joe.mock/api/v2/analysis/submit',
                        json=read_resource('joe_analysis_submit'))
        self.assertEqual(self.sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'), '100001')

    @responses.activate
    def test_check(self):
        if not jbxapi.__version__.startswith("2"):
            responses.add(responses.POST, 'http://joe.mock/api/v2/analysis/info',
                        json=read_resource('joe_analysis_info'))
        else:
            responses.add(responses.POST, 'http://joe.mock/api/v2/analysis/info',
                        json=read_resource('joe_analysis_info'))
        self.assertEqual(self.sandbox.check('1'), True)

    @responses.activate
    def test_is_available(self):
        responses.add(responses.POST, 'http://joe.mock/api/v2/server/online',
                      json=read_resource('joe_server_online'))
        self.assertTrue(self.sandbox.is_available())

    @responses.activate
    def test_not_is_available(self):
        self.assertFalse(self.sandbox.is_available())
        responses.add(responses.POST, 'http://joe.mock/api/v2/server/online',
                      status=500)
        self.assertFalse(self.sandbox.is_available())

    @responses.activate
    def test_report(self):
        responses.add(responses.POST, 'http://joe.mock/api/v2/analysis/download',
                      json=read_resource('joe_analysis_download'))
        self.assertEqual(self.sandbox.report(8)['analysis']['signaturedetections']['strategy'][1]['score'], 1)

    @responses.activate
    def test_score(self):
        responses.add(responses.POST, 'http://joe.mock/api/v2/analysis/download',
                      json=read_resource('joe_analysis_download'))
        self.assertEqual(self.sandbox.score(self.sandbox.report(1)), 1)

    @patch('requests.post')
    @patch('requests.get')
    def test_proxies_is_passed_to_requests(self, m_get, m_post):

        m_get.return_value.status_code = 200
        m_post.return_value.status_code = 200

        proxies = {
            'http': 'http://10.10.1.10:3128',
            'https': 'http://10.10.1.10:1080',
        }

        api = sandboxapi.joe.JoeAPI('key', self.sandbox.jbx.apiurl, True,
                                    proxies=proxies)
        self.assertEqual(api.jbx.session.proxies, proxies)
