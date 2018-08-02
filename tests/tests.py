import io
import os
import json
import unittest
try:
    from unittest.mock import patch, ANY as MOCK_ANY
except ImportError:
    from mock import patch, ANY as MOCK_ANY

import responses

import sandboxapi.cuckoo
import sandboxapi.fireeye
import sandboxapi.joe
import sandboxapi.vmray
import sandboxapi.falcon

def read_resource(resource):
    with open(os.path.join('tests', 'resources', '{r}.json'.format(r=resource)), 'r') as f:
        return json.loads(f.read())


class TestCuckoo(unittest.TestCase):

    def setUp(self):
        self.sandbox = sandboxapi.cuckoo.CuckooAPI('http://cuckoo.mock:8090/')

    @responses.activate
    def test_analyses(self):
        responses.add(responses.GET, 'http://cuckoo.mock:8090/tasks/list',
                      json=read_resource('cuckoo_tasks_list'))
        self.assertEquals(len(self.sandbox.analyses()), 2)

    @responses.activate
    def test_analyze(self):
        responses.add(responses.POST, 'http://cuckoo.mock:8090/tasks/create/file',
                      json=read_resource('cuckoo_tasks_create_file'))
        self.assertEquals(self.sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'), '1')

    @responses.activate
    def test_check(self):
        responses.add(responses.GET, 'http://cuckoo.mock:8090/tasks/view/1',
                      json=read_resource('cuckoo_tasks_view'))
        self.assertEquals(self.sandbox.check('1'), True)

    @responses.activate
    def test_is_available(self):
        responses.add(responses.GET, 'http://cuckoo.mock:8090/cuckoo/status',
                      json=read_resource('cuckoo_status'))
        self.assertTrue(self.sandbox.is_available())

    @responses.activate
    def test_not_is_available(self):
        self.assertFalse(self.sandbox.is_available())
        responses.add(responses.GET, 'http://cuckoo.mock:8090/cuckoo/status',
                      status=500)
        self.assertFalse(self.sandbox.is_available())

    @responses.activate
    def test_report(self):
        responses.add(responses.GET, 'http://cuckoo.mock:8090/tasks/report/8/json',
                      json=read_resource('cuckoo_tasks_report'))
        self.assertEquals(self.sandbox.report(8)['info']['id'], 8)

    @responses.activate
    def test_score(self):
        responses.add(responses.GET, 'http://cuckoo.mock:8090/tasks/report/8/json',
                      json=read_resource('cuckoo_tasks_report'))
        self.assertEquals(self.sandbox.score(self.sandbox.report(8)), 5)

    @patch('requests.post')
    @patch('requests.get')
    def test_proxies_is_passed_to_requests(self, m_get, m_post):

        m_get.return_value.status_code = 200
        m_post.return_value.status_code = 200

        proxies = {
            'http': 'http://10.10.1.10:3128',
            'https': 'http://10.10.1.10:1080',
        }

        api = sandboxapi.cuckoo.CuckooAPI('cuckoo.mock',
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

    @responses.activate
    def test_cuckoo_old_style_host_port_path(self):
        sandbox = sandboxapi.cuckoo.CuckooAPI('cuckoo.mock')
        responses.add(responses.GET, 'http://cuckoo.mock:8090/tasks/list',
                      json=read_resource('cuckoo_tasks_list'))
        self.assertEquals(len(self.sandbox.analyses()), 2)

        sandbox = sandboxapi.cuckoo.CuckooAPI('cuckoo.mock', 9090, '/test')
        responses.add(responses.GET, 'http://cuckoo.mock:9090/test/tasks/list',
                      json=read_resource('cuckoo_tasks_list'))
        self.assertEquals(len(self.sandbox.analyses()), 2)



class TestJoe(unittest.TestCase):

    def setUp(self):
        self.sandbox = sandboxapi.joe.JoeAPI('key', 'http://joe.mock/api', True)

    @responses.activate
    def test_analyze(self):
        responses.add(responses.POST, 'http://joe.mock/api/v2/analysis/submit',
                      json=read_resource('joe_analysis_submit'))
        self.assertEquals(self.sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'), '100001')

    @responses.activate
    def test_check(self):
        responses.add(responses.POST, 'http://joe.mock/api/v2/analysis/info',
                      json=read_resource('joe_analysis_info'))
        self.assertEquals(self.sandbox.check('1'), True)

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
        self.assertEquals(self.sandbox.report(8)['analysis']['signaturedetections']['strategy'][1]['score'], 1)

    @responses.activate
    def test_score(self):
        responses.add(responses.POST, 'http://joe.mock/api/v2/analysis/download',
                      json=read_resource('joe_analysis_download'))
        self.assertEquals(self.sandbox.score(self.sandbox.report(1)), 1)

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
        self.assertEquals(api.jbx.session.proxies, proxies)


class TestFireEye(unittest.TestCase):

    def setUp(self):
        self.sandbox = sandboxapi.fireeye.FireEyeAPI('username', 'password', 'http://fireeye.mock', 'profile')

    @responses.activate
    def test_analyze(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/submissions',
                      json=read_resource('fireeye_submissions'))
        self.assertEquals(self.sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'), 1)

    @responses.activate
    def test_check(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.1.0/submissions/status/1',
                      json=read_resource('fireeye_submissions_status'))
        self.assertEquals(self.sandbox.check('1'), True)

    @responses.activate
    def test_is_available(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.1.0/config',
                      json=read_resource('fireeye_config'))
        self.assertTrue(self.sandbox.is_available())

    @responses.activate
    def test_not_is_available(self):
        self.assertFalse(self.sandbox.is_available())
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.1.0/config',
                      status=500)
        self.assertFalse(self.sandbox.is_available())

    @responses.activate
    def test_report(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.1.0/submissions/results/1',
                      json=read_resource('fireeye_submissions_results'))
        self.assertEquals(self.sandbox.report(1)['msg'], 'concise')

    @responses.activate
    def test_score(self):
        responses.add(responses.POST, 'http://fireeye.mock/wsapis/v1.1.0/auth/login',
                      headers={'X-FeApi-Token': 'MOCK'})
        responses.add(responses.GET, 'http://fireeye.mock/wsapis/v1.1.0/submissions/results/1',
                      json=read_resource('fireeye_submissions_results'))
        self.assertEquals(self.sandbox.score(self.sandbox.report(1)), 8)

    @patch('requests.post')
    @patch('requests.get')
    def test_proxies_is_passed_to_requests(self, m_get, m_post):

        m_get.return_value.status_code = 200
        m_post.return_value.status_code = 200

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


class TestVMRay(unittest.TestCase):

    def setUp(self):
        self.sandbox = sandboxapi.vmray.VMRayAPI('key', 'http://vmray.mock')

    @responses.activate
    def test_analyze(self):
        responses.add(responses.POST, 'http://vmray.mock/rest/sample/submit',
                      json=read_resource('vmray_sample_submit'))
        self.assertEquals(self.sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'), 1169850)

    @responses.activate
    def test_analyze_with_errors(self):
        responses.add(responses.POST, 'http://vmray.mock/rest/sample/submit',
                      json=read_resource('vmray_sample_submit_errors'))
        with self.assertRaises(sandboxapi.SandboxError):
            self.assertEquals(self.sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'))

    @responses.activate
    def test_check(self):
        responses.add(responses.GET, 'http://vmray.mock/rest/submission/sample/1',
                      json=read_resource('vmray_submission_sample'))
        self.assertEquals(self.sandbox.check('1'), True)

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
        self.assertEquals(self.sandbox.report(1)['version'], 1)

    @responses.activate
    def test_score(self):
        responses.add(responses.GET, 'http://vmray.mock/rest/analysis/sample/1',
                      json=read_resource('vmray_analysis_sample'))
        responses.add(responses.GET, 'http://vmray.mock/rest/analysis/1097123/archive/logs/summary.json',
                      json=read_resource('vmray_analysis_archive_logs_summary'))
        self.assertEquals(self.sandbox.score(self.sandbox.report(1)), 20)

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


class TestFalcon(unittest.TestCase):

    def setUp(self):
        self.sandbox = sandboxapi.falcon.FalconAPI('key', 'http://falcon.mock/api/v2')

    @responses.activate
    def test_analyze(self):
        responses.add(responses.POST, 'http://falcon.mock/api/v2/submit/file',
                      json=read_resource('falcon_submit_file'), status=201)
        self.assertEquals(self.sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'), '1')

    @responses.activate
    def test_check(self):
        responses.add(responses.GET, 'http://falcon.mock/api/v2/report/1/state',
                      json=read_resource('falcon_report_state'))
        self.assertEquals(self.sandbox.check('1'), True)

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
        self.assertEquals(self.sandbox.report(1)['job_id'], '1')

    @responses.activate
    def test_score(self):
        responses.add(responses.GET, 'http://falcon.mock/api/v2/report/1/summary',
                      json=read_resource('falcon_report_summary'))
        self.assertEquals(self.sandbox.score(self.sandbox.report(1)), 5)

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


class TestSandboxAPI(unittest.TestCase):

    @patch('requests.post')
    @patch('requests.get')
    def test_proxies_is_passed_to_requests(self, m_get, m_post):
        m_get.return_value.status_code = 200
        m_post.return_value.status_code = 200

        proxies = {
            'http': 'http://10.10.1.10:3128',
            'https': 'http://10.10.1.10:1080',
        }

        api = sandboxapi.SandboxAPI(proxies=proxies)
        api.api_url = 'http://sandbox.mock'
        api._request('/test')

        m_get.assert_called_once_with('http://sandbox.mock/test', auth=None,
                                      headers=None, params=None, proxies=proxies,
                                      verify=True)

        api._request('/test', method='POST')

        m_post.assert_called_once_with('http://sandbox.mock/test', auth=None,
                                       headers=None, data=None, files=None,
                                       proxies=proxies, verify=True)
