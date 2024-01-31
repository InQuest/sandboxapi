from __future__ import print_function

import sandboxapi
import sys
import time


class MetaDefenderSandboxAPI(sandboxapi.SandboxAPI):
    """MetaDefender Sandbox API wrapper."""

    def __init__(
        self, api_key, url="https://www.filescan.io", verify_ssl=True, **kwargs
    ):
        """Initialize the interface to MetaDefender Sandbox API.
        :type   api_key:    str
        :param  api_key:    MetaDefender Sandbox API key

        :type   url         str
        :param  url         The url (including the port) of the MetaDefender Sandbox
                            instance defaults to https://www.filescan.io
        """
        sandboxapi.SandboxAPI.__init__(self, **kwargs)
        self.api_key = api_key
        self.api_url = url
        self.headers = {"X-Api-Key": self.api_key}
        self.verify_ssl = verify_ssl

    def analyze(self, handle, filename, password=None, is_private=False):
        """Submit a file for analysis.

        :type  handle:   File handle
        :param handle:   Handle to file to upload for analysis.
        :type  filename: str
        :param filename: File name.
        :type  password: str
        :param password: Custom password, in case uploaded archive is protected.
        :type  is_private: boolean
        :param is_private: If file should not be available for download by other users.

        :rtype:  str
        :return: flow_id as a string
        """

        if not self.api_key:
            raise sandboxapi.SandboxError("Missing API key")

        # multipart post files.
        files = {"file": (filename, handle)}

        # ensure the handle is at offset 0.
        handle.seek(0)

        try:
            params = {"password": password, "is_private": is_private}

            response = self._request(
                "/api/scan/file",
                method="POST",
                params=params,
                headers=self.headers,
                files=files,
            )

            if response.status_code == 200 and response and response.json():
                # send file, get flow_id
                if "flow_id" in response.json():
                    return response.json()["flow_id"]

            raise sandboxapi.SandboxError(
                "api error in analyze ({u}): {r}".format(
                    u=response.url, r=response.content
                )
            )
        except (ValueError, KeyError) as e:
            raise sandboxapi.SandboxError("error in analyze: {e}".format(e=e))

    def check(self, item_id):
        """Check if an analysis is complete.

        :type  item_id: str
        :param item_id: flow_id to check.

        :rtype:  bool
        :return: Boolean indicating if a report is done or not.
        """
        response = self._request(
            "/api/scan/{flow_id}/report".format(flow_id=item_id), headers=self.headers
        )

        if response.status_code == 404:
            # unknown id
            return False

        try:
            if "allFinished" in response.json() and response.json()["allFinished"]:
                return True
            elif "allFinished" not in response.json():
                raise sandboxapi.SandboxError(
                    "api error in check ({u}): {r}".format(
                        u=response.url, r=response.content
                    )
                )

        except ValueError as e:
            raise sandboxapi.SandboxError(e)

        return False

    def is_available(self):
        """Determine if the MetaDefender Sandbox API server is alive.

        :rtype:  bool
        :return: True if service is available, False otherwise.
        """
        # if the availability flag is raised, return True immediately.
        # NOTE: subsequent API failures will lower this flag. we do this here
        # to ensure we don't keep hitting Opswat with requests while
        # availability is there.
        if self.server_available:
            return True

        # otherwise, we have to check with the cloud.
        else:
            try:
                response = self._request("/api/users/me", headers=self.headers)

                # we've got opswat.
                if response.status_code == 200 and "accountId" in response.json():
                    self.server_available = True
                    return True
            except sandboxapi.SandboxError:
                pass

        self.server_available = False
        return False

    def report(self, item_id, report_format="json"):
        """Retrieves the specified report for the analyzed item, referenced by item_id.

        Available formats include: json.

        :type  item_id:       str
        :param item_id:       flow_id number
        :type  report_format: str
        :param report_format: Return format

        :rtype:  dict
        :return: Dictionary representing the JSON parsed data or raw, for other
                 formats / JSON parsing failure.
        """
        if report_format == "html":
            return "Report Unavailable"

        filters = [
            "filter=general",
            "filter=finalVerdict",
            "filter=allTags",
            "filter=overallState",
            "filter=taskReference",
            "filter=subtaskReferences",
            "filter=allSignalGroups",
            "filter=iocs",
        ]

        postfix = "&".join(filters)
        url_suffix = "/api/scan/{flow_id}/report?{postfix}".format(
            flow_id=item_id, postfix=postfix
        )

        response = self._request(url_suffix, headers=self.headers)

        try:
            return response.json()
        except ValueError:
            pass

        # otherwise, return the raw content.
        return response.content.decode("utf-8")

    def score(self, report):
        """Pass in the report from self.report(), get back an int."""
        report_scores = [0]
        reports = report.get("reports", {})
        for report_value in reports.values():
            score = 0
            threat_level = report_value.get("finalVerdict", {}).get("threatLevel", 0)
            report_scores.append(max(0, threat_level) * 100)

        score = max(report_scores)
        return score


def md_sandbox_loop(md_sandbox, filename):
    # test run
    with open(arg, "rb") as handle:
        flow_id = md_sandbox.analyze(handle, filename)
        print("file {f} submitted for analysis, id {i}".format(f=filename, i=flow_id))

    while not md_sandbox.check(flow_id):
        print("not done yet, sleeping 10 seconds...")
        time.sleep(10)

    print("Analysis complete. fetching report...")
    print(md_sandbox.report(flow_id))


if __name__ == "__main__":

    def usage():
        msg = "%s: <sandbox_url> <api_key> <submit <file_path> | available | report <flow_id> | score <report> | analyze <file_path>"
        print(msg % sys.argv[0])
        sys.exit(1)

    cmd = None
    api_key = None
    url = None

    if len(sys.argv) == 4:
        cmd = sys.argv.pop().lower()
        api_key = sys.argv.pop()
        url = sys.argv.pop()
        arg = None

    elif len(sys.argv) == 5:
        arg = sys.argv.pop()
        cmd = sys.argv.pop().lower()
        api_key = sys.argv.pop()
        url = sys.argv.pop()

    else:
        usage()

    md_sandbox = MetaDefenderSandboxAPI(api_key, url)

    if arg is None and "available" not in cmd:
        usage()

    # process command line arguments.
    if "submit" in cmd:
        with open(arg, "rb") as handle:
            print(md_sandbox.analyze(handle, arg))

    elif "available" in cmd:
        print(md_sandbox.is_available())

    elif "report" in cmd:
        print(md_sandbox.report(arg))

    elif "analyze" in cmd:
        md_sandbox_loop(md_sandbox, arg)

    elif "score" in cmd:
        score = md_sandbox.score(arg)
        print(score)

    else:
        usage()
