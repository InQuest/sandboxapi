from __future__ import print_function

import sys
import time

import sandboxapi

class VMRayAPI(sandboxapi.SandboxAPI):
    """VMRay Sandbox API wrapper."""

    def __init__(self, api_key, url=None, verify_ssl=True, **kwargs):
        """Initialize the interface to VMRay Sandbox API."""
        sandboxapi.SandboxAPI.__init__(self, **kwargs)

        self.base_url = url or 'https://cloud.vmray.com'
        self.api_url = self.base_url + '/rest'
        self.api_key = api_key
        self.verify_ssl = verify_ssl

        # define once and use later
        self.headers = {'Authorization': 'api_key {a}'.format(a=api_key)}

    def analyze(self, handle, filename):
        """Submit a file for analysis.

        :type  handle:   File handle
        :param handle:   Handle to file to upload for analysis.
        :type  filename: str
        :param filename: File name.

        :rtype:  str
        :return: File ID as a string
        """
        # multipart post files.
        files = {"sample_file": (filename, handle)}

        # ensure the handle is at offset 0.
        handle.seek(0)

        response = self._request("/sample/submit", method='POST', files=files, headers=self.headers)

        try:
            if response.status_code == 200 and not response.json()['data']['errors']:
                # only support single-file submissions; just grab the first one.
                return response.json()['data']['samples'][0]['sample_id']
            else:
                raise sandboxapi.SandboxError("api error in analyze ({u}): {r}".format(u=response.url, r=response.content))
        except (ValueError, KeyError, IndexError) as e:
            raise sandboxapi.SandboxError("error in analyze: {e}".format(e=e))

    def check(self, item_id):
        """Check if an analysis is complete.

        :type  item_id: str
        :param item_id: File ID to check.

        :rtype:  bool
        :return: Boolean indicating if a report is done or not.
        """
        response = self._request("/submission/sample/{sample_id}".format(sample_id=item_id), headers=self.headers)

        if response.status_code == 404:
            # unknown id
            return False

        try:
            finished = False
            for submission in response.json()['data']:
                finished = finished or submission['submission_finished']
            if finished:
                return True

        except (ValueError, KeyError) as e:
            raise sandboxapi.SandboxError(e)

        return False

    def is_available(self):
        """Determine if the VMRay API server is alive.

        :rtype:  bool
        :return: True if service is available, False otherwise.
        """
        # if the availability flag is raised, return True immediately.
        # NOTE: subsequent API failures will lower this flag. we do this here
        # to ensure we don't keep hitting VMRay with requests while
        # availability is there.
        if self.server_available:
            return True

        # otherwise, we have to check with the cloud.
        else:
            try:
                response = self._request("/system_info", headers=self.headers)

                # we've got vmray.
                if response.status_code == 200:
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
        :param item_id:       File ID number
        :type  report_format: str
        :param report_format: Return format

        :rtype:  dict
        :return: Dictionary representing the JSON parsed data or raw, for other
                 formats / JSON parsing failure.
        """
        if report_format == "html":
            return "Report Unavailable"

        # grab an analysis id from the submission id.
        response = self._request("/analysis/sample/{sample_id}".format(sample_id=item_id),
                headers=self.headers)

        try:
            # the highest score is probably the most interesting.
            # vmray uses this internally with sample_highest_vti_score so this seems like a safe assumption.
            analysis_id = 0
            top_score = -1
            for analysis in response.json()['data']:
                if analysis['analysis_vti_score'] > top_score:
                    top_score = analysis['analysis_vti_score']
                    analysis_id = analysis['analysis_id']

        except (ValueError, KeyError) as e:
            raise sandboxapi.SandboxError(e)

        # assume report format json.
        response = self._request("/analysis/{analysis_id}/archive/logs/summary.json".format(analysis_id=analysis_id),
                headers=self.headers)

        # if response is JSON, return it as an object.
        try:
            return response.json()
        except ValueError:
            pass

        # otherwise, return the raw content.
        return response.content

    def score(self, report):
        """Pass in the report from self.report(), get back an int 0-100"""
        try:
            return report['vti']['vti_score']
        except KeyError:
            return 0


def vmray_loop(vmray, filename):
    # test run
    with open(arg, "rb") as handle:
        fileid = vmray.analyze(handle, filename)
        print("file {f} submitted for analysis, id {i}".format(f=filename, i=fileid))

    while not vmray.check(fileid):
        print("not done yet, sleeping 10 seconds...")
        time.sleep(10)

    print("analysis complete. fetching report...")
    print(vmray.report(fileid))


if __name__ == "__main__":

    def usage():
        msg = "%s: <url> <api_key> <submit <fh> | available | report <id> | analyze <fh>"
        print(msg % sys.argv[0])
        sys.exit(1)

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

    # instantiate VMRay Sandbox API interface.
    vmray = VMRayAPI(api_key)

    # process command line arguments.
    if "submit" in cmd:
        if arg is None:
            usage()
        else:
            with open(arg, "rb") as handle:
                print(vmray.analyze(handle, arg))

    elif "available" in cmd:
        print(vmray.is_available())

    elif "report" in cmd:
        if arg is None:
            usage()
        else:
            print(vmray.report(arg))

    elif "analyze" in cmd:
        if arg is None:
            usage()
        else:
            vmray_loop(vmray, arg)

    else:
        usage()
