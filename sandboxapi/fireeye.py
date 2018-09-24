from __future__ import print_function

import sys
import time
import json

from requests.auth import HTTPBasicAuth

import sandboxapi

class FireEyeAPI(sandboxapi.SandboxAPI):
    """FireEye Sandbox API wrapper."""

    def __init__(self, username, password, url, profile, legacy_api=False, verify_ssl=True, **kwargs):
        """Initialize the interface to FireEye Sandbox API."""
        sandboxapi.SandboxAPI.__init__(self, **kwargs)

        self.base_url = url
        self.username = username
        self.password = password
        self.profile = profile or 'winxp-sp3'
        self.api_token = None
        self.verify_ssl = verify_ssl

        if legacy_api:
            # Use v1.1.0 endpoints for v7.x appliances.
            self.api_url = url + '/wsapis/v1.1.0'
        else:
            self.api_url = url + '/wsapis/v1.2.0'

    def _request(self, uri, method='GET', params=None, files=None, headers=None, auth=None):
        """Override the parent _request method.

        We have to do this here because FireEye requires some extra
        authentication steps. On each request we pass the auth headers, and
        if the session has expired, we automatically reauthenticate.
        """
        if headers:
            headers['Accept'] = 'application/json'
        else:
            headers = {
                'Accept': 'application/json',
            }

        if not self.api_token:
            # need to log in
            response = sandboxapi.SandboxAPI._request(self, '/auth/login', 'POST', headers=headers,
                                                      auth=HTTPBasicAuth(self.username, self.password))
            if response.status_code != 200:
                raise sandboxapi.SandboxError("Can't log in, HTTP Error {e}".format(e=response.status_code))
            # we are now logged in, save the token
            self.api_token = response.headers.get('X-FeApi-Token')

        headers['X-FeApi-Token'] = self.api_token

        response = sandboxapi.SandboxAPI._request(self, uri, method, params, files, headers)

        # handle session timeout
        unauthorized = False
        try:
            if json.loads(response.content.decode('utf-8'))['fireeyeapis']['httpStatus'] == 401:
                unauthorized = True
        except (ValueError, KeyError):
            # non-JSON response, or no such keys.
            pass

        if response.status_code == 401 or unauthorized:
            self.api_token = None
            try:
                headers.pop('X-FeApi-Token')
            except KeyError:
                pass

            # recurse
            return self._request(uri, method, params, files, headers)

        return response

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
        files = {"file": (filename, handle)}

        # ensure the handle is at offset 0.
        handle.seek(0)

        # add submission options
        data = {
            #FIXME: These may need to change, see docs page 36
            'options': '{"application":"0","timeout":"500","priority":"0","profiles":["%s"],"analysistype":"0","force":"true","prefetch":"1"}' % self.profile,
        }

        response = self._request("/submissions", method='POST', params=data, files=files)

        try:
            if response.status_code == 200:
                # good response
                try:
                    return response.json()['ID']
                except TypeError:
                    return response.json()[0]['ID']
            else:
                raise sandboxapi.SandboxError("api error in analyze ({u}): {r}".format(u=response.url, r=response.content))
        except (ValueError, KeyError) as e:
            raise sandboxapi.SandboxError("error in analyze: {e}".format(e=e))

    def check(self, item_id):
        """Check if an analysis is complete.

        :type  item_id: str
        :param item_id: File ID to check.

        :rtype:  bool
        :return: Boolean indicating if a report is done or not.
        """
        response = self._request("/submissions/status/{file_id}".format(file_id=item_id))

        if response.status_code == 404:
            # unknown id
            return False

        try:
            status = response.json()['submissionStatus']
            if status == 'Done':
                return True

        except ValueError as e:
            raise sandboxapi.SandboxError(e)

        return False

    def is_available(self):
        """Determine if the FireEye API server is alive.

        :rtype:  bool
        :return: True if service is available, False otherwise.
        """
        # if the availability flag is raised, return True immediately.
        # NOTE: subsequent API failures will lower this flag. we do this here
        # to ensure we don't keep hitting FireEye with requests while
        # availability is there.
        if self.server_available:
            return True

        # otherwise, we have to check with the cloud.
        else:
            try:
                response = self._request("/config")

                # we've got fireeye.
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

        # else we try JSON
        response = self._request("/submissions/results/{file_id}?info_level=extended".format(file_id=item_id))

        # if response is JSON, return it as an object
        try:
            return response.json()
        except ValueError:
            pass

        # otherwise, return the raw content.
        return response.content


    def score(self, report):
        """Pass in the report from self.report(), get back an int."""
        score = 0
        if report['alert'][0]['severity'] == 'MAJR':
            score = 8

        return score


def fireeye_loop(fireeye, filename):
    # test run
    with open(arg, "rb") as handle:
        fileid = fireeye.analyze(handle, filename)
        print("file {f} submitted for analysis, id {i}".format(f=filename, i=fileid))

    while not fireeye.check(fileid):
        print("not done yet, sleeping 10 seconds...")
        time.sleep(10)

    print("analysis complete. fetching report...")
    print(fireeye.report(fileid))


if __name__ == "__main__":

    def usage():
        msg = "%s: <url> <username> <password> <submit <fh> | available | report <id> | analyze <fh>"
        print(msg % sys.argv[0])
        sys.exit(1)

    if len(sys.argv) == 5:
        cmd = sys.argv.pop().lower()
        password = sys.argv.pop()
        username = sys.argv.pop()
        url = sys.argv.pop()
        arg = None

    elif len(sys.argv) == 6:
        arg = sys.argv.pop()
        cmd = sys.argv.pop().lower()
        password = sys.argv.pop()
        username = sys.argv.pop()
        url = sys.argv.pop()

    else:
        usage()

    # instantiate FireEye Sandbox API interface.
    fireeye = FireEyeAPI(username, password, url, 'winxp-sp3')

    # process command line arguments.
    if "submit" in cmd:
        if arg is None:
            usage()
        else:
            with open(arg, "rb") as handle:
                print(fireeye.analyze(handle, arg))

    elif "available" in cmd:
        print(fireeye.is_available())

    elif "report" in cmd:
        if arg is None:
            usage()
        else:
            print(fireeye.report(arg))

    elif "analyze" in cmd:
        if arg is None:
            usage()
        else:
            fireeye_loop(fireeye, arg)

    else:
        usage()
