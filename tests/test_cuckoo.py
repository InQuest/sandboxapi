import io
import unittest
try:
    from unittest.mock import patch, ANY as MOCK_ANY
except ImportError:
    from mock import patch, ANY as MOCK_ANY
import responses
import sandboxapi.cuckoo
from . import read_resource


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
