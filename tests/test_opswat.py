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


class TestOPSWAT(TestCase):
    def setUp(self):
        self.sandbox = sandboxapi.opswat.OPSWATFilescanSandboxAPI("key", URL, True)

    # analyze
    @responses.activate
    def test_analyze(self):
        sent_file_response = {"flow_id": "1234"}

        responses.add(responses.POST, f"{URL}/api/scan/file", json=sent_file_response)
        self.assertEqual(
            self.sandbox.analyze(io.BytesIO("test".encode("ascii")), "filename"), "1234"
        )

    # check
    @responses.activate
    def test_check(self):
        flow_id = 1
        finished = [
            ("opswat_submissions_result_malicious", True),
            ("opswat_submissions_result_not_finished", False),
        ]
        for report in finished:
            responses.add(
                responses.GET,
                f"{URL}/api/scan/{flow_id}/report",
                json=read_resource(report[0]),
            )
            self.assertEqual(self.sandbox.check("1"), report[1])

    # is available
    @responses.activate
    def test_is_available(self):
        response = {
            "accountId": "1234",
        }
        responses.add(responses.GET, f"{URL}/api/users/me", json=response)
        self.assertTrue(self.sandbox.is_available())

    @responses.activate
    def test_not_available(self):
        response = {
            "accountId": "1234",
        }
        responses.add(responses.GET, f"{URL}/api/users/me", json=response, status=404)
        self.assertFalse(self.sandbox.is_available())

    # report
    @responses.activate
    def test_report(self):
        id = 1
        url = f"{URL}/api/scan/{id}/report?filter=general&filter=finalVerdict&filter=allTags&filter=overallState&filter=taskReference&filter=subtaskReferences&filter=allSignalGroups"

        responses.add(
            responses.GET,
            url,
            json=read_resource("opswat_submissions_result_malicious"),
        )

        response = self.sandbox.report(id)
        self.assertEqual(
            response,
            read_resource("opswat_submissions_result_malicious"),
        )

        self.assertEqual(
            response["reports"]["f7977db1-6a99-46c3-8567-de1c88c93aa4"]["finalVerdict"][
                "verdict"
            ],
            "MALICIOUS",
        )

    # score
    @responses.activate
    def test_score(self):
        id = 1
        files_and_score = [
            ("opswat_submissions_result_malicious", 100),
            ("opswat_submissions_result_suspicious", 50),
            ("opswat_submissions_result_benign", 0),
            ("opswat_submissions_result_likely_malicious", 75),
        ]

        for file_and_score in files_and_score:
            responses.add(
                responses.GET,
                f"{URL}/api/scan/{id}/report?filter=general&filter=finalVerdict&filter=allTags&filter=overallState&filter=taskReference&filter=subtaskReferences&filter=allSignalGroups",
                json=read_resource(file_and_score[0]),
            )
            self.assertEqual(
                self.sandbox.score(self.sandbox.report(id)), file_and_score[1]
            )
