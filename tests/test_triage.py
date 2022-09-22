import io
import os
import json
import unittest
try:
    from unittest.mock import patch, ANY as MOCK_ANY
except ImportError:
    from mock import patch, ANY as MOCK_ANY
import responses
import sandboxapi.triage
from . import read_resource


class TestTriage(unittest.TestCase):
    def setUp(self):
        self.sandbox = sandboxapi.triage.TriageAPI("key",
                                                   "http://api.triage.mock")

    @responses.activate
    def test_analyze(self):
        responses.add(responses.POST,
                      'http://api.triage.mock/v0/samples',
                      json=read_resource('triage_analyze'), status=200)
        triage_id = self.sandbox.analyze(io.BytesIO('test'.encode('ascii')),
                                         "testfile")
        self.assertEquals(triage_id, "200707-pht1cwk3ls")

    @responses.activate
    def test_check(self):
        responses.add(responses.GET,
                      'http://api.triage.mock/v0/samples/test/status',
                      json=read_resource('triage_check'), status=200)
        self.assertTrue(self.sandbox.check("test"))

    @responses.activate
    def test_is_available(self):
        responses.add(responses.GET, 'http://api.triage.mock/v0/samples',
                      json=read_resource('triage_available'), status=200)
        self.assertTrue(self.sandbox.is_available())

    @responses.activate
    def test_report(self):
        responses.add(responses.GET,
                      'http://api.triage.mock/v0/samples/test/summary',
                      json=read_resource('triage_report'), status=200)
        data = self.sandbox.report("test")
        self.assertEquals(
            10, data["tasks"]["200615-8jbndpgg9n-behavioral1"]["score"])

    @responses.activate
    def test_score(self):
        responses.add(responses.GET,
                      'http://api.triage.mock/v0/samples/test/summary',
                      json=read_resource('triage_report'), status=200)
        score = self.sandbox.score("test")
        self.assertEquals(10, score)

    @responses.activate
    def test_full_report(self):
        responses.add(responses.GET,
                      'http://api.triage.mock/v0/samples/200615-8jbndpgg9n/summary',
                      json=read_resource('triage_report'), status=200)
        responses.add(responses.GET,
                      'http://api.triage.mock/v0/samples/200615-8jbndpgg9n/behavioral1/report_triage.json',
                      json=read_resource('triage_behavioral1'), status=200)
        responses.add(responses.GET,
                      'http://api.triage.mock/v0/samples/200615-8jbndpgg9n/behavioral2/report_triage.json',
                      json=read_resource('triage_behavioral2'), status=200)

        full_report = self.sandbox.full_report("200615-8jbndpgg9n")
        self.assertTrue(full_report["tasks"]["behavioral1"]["sample"]["score"],
                        10)
        self.assertTrue(full_report["tasks"]["behavioral2"]["sample"]["score"],
                        10)
