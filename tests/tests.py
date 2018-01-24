import io
import os
import json
import unittest

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
        self.sandbox = sandboxapi.cuckoo.CuckooAPI('cuckoo.mock')

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


class TestVMRay(unittest.TestCase):

    def setUp(self):
        self.sandbox = sandboxapi.vmray.VMRayAPI('key', 'http://vmray.mock')

    @responses.activate
    def test_analyze(self):
        responses.add(responses.POST, 'http://vmray.mock/rest/sample/submit',
                      json=read_resource('vmray_sample_submit'))
        self.assertEquals(self.sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'), 1169850)

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


class TestFalcon(unittest.TestCase):

    def setUp(self):
        self.sandbox = sandboxapi.falcon.FalconAPI('key', 'secret', 'http://falcon.mock')

    @responses.activate
    def test_analyze(self):
        responses.add(responses.POST, 'http://falcon.mock/api/submit',
                      json=read_resource('falcon_submit'))
        self.assertEquals(self.sandbox.analyze(io.BytesIO('test'.encode('ascii')), 'filename'), '040c0111aef474d8b7bfa9a7caa0e06b4f1049c7ae8c66611a53fc2599f0b90f')

    @responses.activate
    def test_check(self):
        responses.add(responses.GET, 'http://falcon.mock/api/state/1',
                      json=read_resource('falcon_state'))
        self.assertEquals(self.sandbox.check('1'), True)

    @responses.activate
    def test_is_available(self):
        responses.add(responses.GET, 'http://falcon.mock/api/quota',
                      json=read_resource('falcon_quota'))
        self.assertTrue(self.sandbox.is_available())

    @responses.activate
    def test_not_is_available(self):
        self.assertFalse(self.sandbox.is_available())
        responses.add(responses.GET, 'http://falcon.mock/api/quota',
                      status=500)
        self.assertFalse(self.sandbox.is_available())

    @responses.activate
    def test_report(self):
        responses.add(responses.GET, 'http://falcon.mock/api/scan/1',
                      json=read_resource('falcon_scan'))
        self.assertEquals(self.sandbox.report(1)['response_code'], 0)
