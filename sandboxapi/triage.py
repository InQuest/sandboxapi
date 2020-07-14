from __future__ import print_function

import os
import sys
import json

import sandboxapi

class TriageAPI(sandboxapi.SandboxAPI):

    def __init__(self, api_key, url=None, api_path=None, verify_ssl=True,
                 **kwargs):
        """
        :type   api_key:    str
        :param  api_key:    The API key which can be found on the /account page
                            on the Triage web interface

        :type   url         str
        :param  url         The url (including the port) of the Triage instance
                            defaults to https://api.tria.ge

        :type   api_path    str
        :param  api_path    The path to the API on the Triage instance
                            defaults to /v0
        """
        sandboxapi.SandboxAPI.__init__(self, **kwargs)

        self.api_key = api_key
        self.base_url = url or "https://api.tria.ge"

        self.api_url = self.base_url + (api_path or "/v0")

        self.headers = {'Authorization': 'Bearer {:s}'.format(api_key)}

        self.verify_ssl = verify_ssl

    def request(self, uri, method='GET', params=None, files=None, auth=None):

        response = self._request(
            uri, method, params, files, self.headers, auth)

        # Try parsing the response as JSON to see if we got a valid object
        try:
            data = response.json()
        except ValueError as e:
            raise sandboxapi.SandboxError(
                "Triage returned a non JSON response {:s}", e)

        # If we got a normal object check whether we didn't receive an error
        # object
        if "error" in data.keys():
            raise sandboxapi.SandboxError(
                "Triage raised an error: {:s} - {:s}".format(
                    data["error"], data["message"]))

        # Everything is good to go
        return data

    def analyze(self, handle, filename):
        """Submit a file for analysis.

        :type  handle:   File handle
        :param handle:   Handle to file to upload for analysis.
        :type  filename: str
        :param filename: File name.

        :rtype:  str
        :return: File ID as a string
        """
        files = {"file": (filename, handle)}
        params = {"_json": json.dumps({
            "kind": "file",
            "interactive": False
        })}

        # Ensure the handle is at offset 0.
        handle.seek(0)

        # Make the request to Triage
        data = self.request("/samples", method='POST', files=files,
                            params=params)

        if "id" in data.keys():
            return data["id"]
        else:
            raise sandboxapi.SandboxError("Triage returned no ID")

    def check(self, item_id):
        """Check if an analysis is complete.

        :type  item_id: str
        :param item_id: Analysis ID to check.

        :rtype:  bool
        :return: Boolean indicating if a report is done or not.
        """

        data = self.request("/samples/{:s}/status".format(item_id))

        if "status" in data.keys():
            return data["status"] == "reported"
        else:
            raise sandboxapi.SandboxError("Triage didn't return a status")

    def is_available(self):
        """Determine if the Triage server is alive.

        :rtype:  bool
        :return: True if service is available, False otherwise.
        """

        try:
            self.request("/samples")
        except sandboxapi.SandboxError:
            return False

        return True

    def report(self, item_id, report_format="json"):
        """Retrieves the specified report for the analyzed item,
        referenced by item_id. Note that the summary is returned and more
        detailed information is available.

        :param str item_id: The id of the submitted file.
        :param str report_format:   In here for compatibility though Triage
                                    only supports the JSON format

        :rtype: dic
        :return: Dictionary representing the JSON parsed data.
        """

        if report_format != "json":
            raise sandboxapi.SandboxError(
                "Triage api only supports the json report format")

        data = self.request("/samples/{:s}/summary".format(item_id))

        return data

    def score(self, item_id):
        """Gives back the highest score choosing from all the analyses

        :param str item_id: The id of the submitted file.

        :rtype: int
        :return: int on a scale from 1 til 10
        """
        report = self.report(item_id)
        # 1 Is the Triage base score
        score = 1

        # Loop over the available reports to pick the highest score
        for task_id, task in report["tasks"].items():
            if "score" in task:
                if task["score"] > score:
                    score = task["score"]

        return score

    def full_report(self, item_id):
        """Retrieves the summary report and the full report of each task for
        the analyzed item, referenced by item_id.

        :param str item_id: The id of the submitted file.

        :rtype: dic
        :return: Dictionary representing the JSON parsed data.
        """
        report = self.report(item_id)
        full_report = {
            'summary': report,
            'tasks': {}
        }

        # Loop over all the tasks in the summary
        for task_id in report["tasks"]:
            # Remove the sample ID to get the task names
            task_name = task_id.replace("{:s}-".format(item_id), "")

            try:
                # Try to retrieve each full report
                triage_report = self.request(
                    "/samples/{:s}/{:s}/report_triage.json".format(
                        item_id, task_name))
                full_report["tasks"][task_name] = triage_report
            except sandboxapi.SandboxError:
                continue

        return full_report


if __name__ == "__main__":

    def usage():
        msg = "%s: <key> <submit <file> | <report <id> | <score <id> | <full_report <id>"
        print(msg % sys.argv[0])
        sys.exit(1)

    if len(sys.argv) == 4:
        arg = sys.argv.pop()
        cmd = sys.argv.pop().lower()
        api_key = sys.argv.pop()

    else:
        usage()

    triage = TriageAPI(api_key)

    try:
        if "submit" in cmd:
            with open(arg, "r") as f:
                sample_id = triage.analyze(f, os.path.basename(f.name))
                print("Sample ID: {:s}".format(sample_id))

        elif "check" in cmd:
            if triage.check(arg):
                print("Report done")
            else:
                print("Report is not done yet")

        elif "full_report" in cmd:
            sample = triage.full_report(arg)
            print(sample)

        elif "report" in cmd:
            sample = triage.report(arg)
            print(sample)

        elif "score" in cmd:
            score = triage.score(arg)
            print(score)

    except sandboxapi.SandboxError as e:
        print("Unable to complete the action: {:s}".format(str(e)))
