import io
import os
import json
import unittest

import responses

import sandboxapi.cuckoo
import sandboxapi.fireeye
import sandboxapi.joe
import sandboxapi.vmray
import sandboxapi.vxstream

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
        self.assertEquals(self.sandbox.analyze(io.BytesIO('test'), 'filename'), '1')

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

    @responses.activate
    def test_report(self):
        responses.add(responses.GET, 'http://cuckoo.mock:8090/tasks/report/8/json',
                      json=read_resource('cuckoo_tasks_report'))
        print self.sandbox.report(8)
        self.assertEquals(self.sandbox.report(8)['info']['id'], 8)
