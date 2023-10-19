import io
from unittest import TestCase

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

import responses
import sandboxapi.opswat
from . import read_resource


URL = "http://filescanio.mock"


class TestJoe(TestCase):
    def setUp(self):
        self.sandbox = sandboxapi.opswat.OPSWATFilescanSandboxAPI("key", URL, True)

    @responses.activate
    def test_score_malicious(self):
        id = 1
        target_score = 100
        responses.add(
            responses.GET,
            f"{URL}/api/scan/{id}/report?filter=general&filter=finalVerdict&filter=allTags&filter=overallState&filter=taskReference&filter=subtaskReferences&filter=allSignalGroups",
            json=read_resource("opswat_submissions_result_malicious"),
        )
        self.assertEqual(self.sandbox.score(self.sandbox.report(id)), target_score)

    @responses.activate
    def test_score_suspicious(self):
        id = 1
        target_score = 50
        responses.add(
            responses.GET,
            f"{URL}/api/scan/{id}/report?filter=general&filter=finalVerdict&filter=allTags&filter=overallState&filter=taskReference&filter=subtaskReferences&filter=allSignalGroups",
            json=read_resource("opswat_submissions_result_suspicious"),
        )
        self.assertEqual(self.sandbox.score(self.sandbox.report(id)), target_score)

    @responses.activate
    def test_score_benign(self):
        id = 1
        target_score = 0
        responses.add(
            responses.GET,
            f"{URL}/api/scan/{id}/report?filter=general&filter=finalVerdict&filter=allTags&filter=overallState&filter=taskReference&filter=subtaskReferences&filter=allSignalGroups",
            json=read_resource("opswat_submissions_result_benign"),
        )
        self.assertEqual(self.sandbox.score(self.sandbox.report(id)), target_score)
