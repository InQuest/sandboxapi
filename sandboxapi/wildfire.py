from __future__ import print_function

import json
import sys

import xmltodict

import sandboxapi


BENIGN = 0
MALWARE = 1
GRAYWARE = 2
PHISHING = 4


class WildFireAPI(sandboxapi.SandboxAPI):
    """WildFire Sandbox API wrapper."""

    def __init__(self, api_key='', url='', verify_ssl=True, **kwargs):
        """Initialize the interface to the WildFire Sandbox API.

        :param str api_key: The customer API key.
        :param str url: The WildFire API URL.
        """
        super(WildFireAPI, self).__init__(**kwargs)
        self.base_url = url or 'https://wildfire.paloaltonetworks.com'
        self.api_url = self.base_url + '/publicapi'
        self._api_key = api_key
        self._score = BENIGN
        self.verify_ssl = verify_ssl

    def analyze(self, handle, filename):
        """Submit a file for analysis.

        :param BytesIO handle: File handle
        :param str filename: File name
        :rtype: str
        :return: File ID as a string
        """
        # multipart post files.
        files = {"file": (filename, handle)}

        # ensure the handle is at offset 0.
        handle.seek(0)

        data = {'apikey': self._api_key}

        response = self._request('/submit/file', method='POST', files=files, params=data)

        try:
            if response.status_code == 200:
                output = self.decode(response)
                return output['wildfire']['upload-file-info']['sha256']
            else:
                raise sandboxapi.SandboxError("api error in analyze ({}): {}".format(response.url, response.content))
        except (ValueError, KeyError, IndexError) as e:
            raise sandboxapi.SandboxError("error in analyze {}".format(e))

    def decode(self, response):
        """Convert a xml response to a python dictionary.

        :param requests.Response response: A Response object with xml content.
        :rtype: dict
        :return: The xml content converted to a dictionary.
        """
        # This weird conversion to and from JSON is because the XML is being parsed as an Ordereddict.
        # TODO: See if there's a better way to do this without having to convert to JSON.
        output = json.loads(json.dumps(xmltodict.parse(response.content.decode('utf-8'))))
        if 'error' in output:
            raise sandboxapi.SandboxError(output['error']['error-message'])
        return output

    def check(self, item_id):
        """Check if an analysis is complete.

        :param str item_id: The hash of the file to check.
        :rtype: bool
        :return: True if the report is ready, otherwise False.
        """
        data = {
            'apikey': self._api_key,
            'hash': item_id,
        }
        response = self._request('/get/verdict', method='POST', params=data)

        if not response.ok:
            raise sandboxapi.SandboxError("{}: {}".format(response.status_code, response.content))

        output = self.decode(response)
        try:
            status = int(output['wildfire']['get-verdict-info']['verdict'])
            if status >= 0:
                self._score = status
                return True
            elif status == -100:
                return False
            elif status == -101:
                raise sandboxapi.SandboxError('An error occurred while processing the sample.')
            elif status == -102:
                raise sandboxapi.SandboxError('Unknown sample in the Wildfire database.')
            elif status == -103:
                raise sandboxapi.SandboxError('Invalid hash value.')
            else:
                raise sandboxapi.SandboxError('Unknown status.')
        except (ValueError, IndexError) as e:
            raise sandboxapi.SandboxError(e)

    def is_available(self):
        """Checks to see if the WildFire sandbox is up and running.

        :rtype: bool
        :return: True if the WildFire sandbox is responding, otherwise False.

        WildFire doesn't have an explicit endpoint for checking the sandbox status, so this is kind of a hack.
        """
        try:
            # Making a GET request to the API should always give a code 405 if the service is running.
            # Relying on this fact to get a reliable 405 if the service is up.
            response = self._request('/get/sample', params={'apikey': self._api_key})
            if response.status_code == 405:
                return True
            else:
                return False
        except sandboxapi.SandboxError:
            return False

    def report(self, item_id, report_format='json'):
        """Retrieves the specified report for the analyzed item, referenced by item_id.

        :param str item_id: The hash of the file.
        :param str report_format: Return format.
        :rtype: dic
        :return: Dictionary representing the JSON parsed data.
        """
        data = {
            'apikey': self._api_key,
            'hash': item_id,
            'format': 'xml',
        }
        response = self._request('/get/report', method='POST', params=data)
        if not response.ok:
            raise sandboxapi.SandboxError("{}: {}".format(response.status_code, response.content))
        return self.decode(response)

    def score(self):
        """Get the threat score for the submitted sample.

        :rtype: int
        :return: The assigned threat score.
        """
        if self._score == MALWARE:
            return 8
        elif self._score == GRAYWARE:
            return 2
        elif self._score == PHISHING:
            return 5
        else:
            return self._score


if __name__ == "__main__":

    def usage():
        msg = "{}: <url> <api_key> available | submit <fh> | report <hash> | check <hash>".format(sys.argv[0])
        print(msg)
        sys.exit(1)

    api_key_ = ''
    url_ = ''
    arg = ''
    cmd = ''
    if len(sys.argv) == 5:
        arg = sys.argv.pop()
        cmd = sys.argv.pop().lower()
        api_key_ = sys.argv.pop()
        url_ = sys.argv.pop()
    elif len(sys.argv) == 4:
        arg = sys.argv.pop()
        cmd = sys.argv.pop().lower()
        api_key_ = sys.argv.pop()
    elif len(sys.argv) == 3:
        cmd = sys.argv.pop().lower()
        api_key_ = sys.argv.pop()
    else:
        usage()

    wildfire = WildFireAPI(api_key=api_key_, url=url_) if url_ else WildFireAPI(api_key_)

    if cmd == 'available':
        print(wildfire.is_available())
    elif cmd == 'submit':
        with open(arg, "rb") as handle:
            print(wildfire.analyze(handle, arg))
    elif cmd == "report":
        print(wildfire.report(arg))
    elif cmd == "check":
        print(wildfire.check(arg))
    else:
        usage()
