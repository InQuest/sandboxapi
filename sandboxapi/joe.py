import json

import jbxapi

import sandboxapi

class JoeAPI(sandboxapi.SandboxAPI):
    """Joe Sandbox API wrapper.

    This class is actually just a convenience wrapper around jbxapi.JoeSandbox.
    """

    def __init__(self, apikey, apiurl, accept_tac, timeout=None, verify_ssl=True, retries=3, **kwargs):
        """Initialize the interface to Joe Sandbox API."""
        sandboxapi.SandboxAPI.__init__(self)
        self.jbx = jbxapi.JoeSandbox(apikey, apiurl or jbxapi.API_URL, accept_tac, timeout, verify_ssl, retries, **kwargs)

    def analyze(self, handle, filename):
        """Submit a file for analysis.

        :type  handle:   File handle
        :param handle:   Handle to file to upload for analysis.
        :type  filename: str
        :param filename: File name.

        :rtype:  str
        :return: Task ID as a string
        """
        # ensure the handle is at offset 0.
        handle.seek(0)

        try:
            return self.jbx.submit_sample(handle)['webids'][0]
        except (jbxapi.JoeException, KeyError, IndexError) as e:
            raise sandboxapi.SandboxError("error in analyze: {e}".format(e=e))

    def check(self, item_id):
        """Check if an analysis is complete.

        :type  item_id: str
        :param item_id: File ID to check.

        :rtype:  bool
        :return: Boolean indicating if a report is done or not.
        """
        try:
            return self.jbx.info(item_id).get('status').lower() == 'finished'
        except jbxapi.JoeException:
            return False

        return False

    def is_available(self):
        """Determine if the Joe Sandbox API server is alive.

        :rtype:  bool
        :return: True if service is available, False otherwise.
        """
        # if the availability flag is raised, return True immediately.
        # NOTE: subsequent API failures will lower this flag. we do this here
        # to ensure we don't keep hitting Joe with requests while availability
        # is there.
        if self.server_available:
            return True

        # otherwise, we have to check with the cloud.
        else:

            try:
                self.server_available = self.jbx.server_online()
                return self.server_available
            except jbxapi.JoeException:
                pass

        self.server_available = False
        return False

    def report(self, item_id, report_format="json"):
        """Retrieves the specified report for the analyzed item, referenced by item_id.

        For available report formats, see online Joe Sandbox documentation.

        :type  item_id:       str
        :param item_id:       File ID number
        :type  report_format: str
        :param report_format: Return format

        :rtype:  dict
        :return: Dictionary representing the JSON parsed data or raw, for other
                 formats / JSON parsing failure.
        """
        if report_format == "json":
            report_format = "jsonfixed"

        try:
            return json.loads(self.jbx.download(item_id, report_format)[1].decode('utf-8'))
        except (jbxapi.JoeException, ValueError, IndexError) as e:
            raise sandboxapi.SandboxError("error in report fetch: {e}".format(e=e))

    def score(self, report):
        """Pass in the report from self.report(), get back an int."""
        try:
            return report['analysis']['signaturedetections']['strategy'][1]['score']
        except (KeyError, IndexError):
            return 0


if __name__ == "__main__":
    print("use jbxapi.py instead")
