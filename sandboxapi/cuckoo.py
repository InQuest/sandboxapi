from __future__ import print_function

import sys
import json

import sandboxapi

class CuckooAPI(sandboxapi.SandboxAPI):
    """Cuckoo Sandbox API wrapper."""

    def __init__(self, url, port=8090, api_path='/', verify_ssl=False, **kwargs):
        """Initialize the interface to Cuckoo Sandbox API with host and port.

        :type  url:      str
        :param url:      Cuckoo API URL. (Currently treated as host if not a fully formed URL -
                         this will be removed in a future version.)
        :type  port:     int
        :param port:     DEPRECATED! Use fully formed url instead. Will be removed in future version.
        :type  api_path: str
        :param api_path: DEPRECATED! Use fully formed url instead. Will be removed in future version.
        """
        sandboxapi.SandboxAPI.__init__(self, **kwargs)

        if not url:
            url = ''

        # NOTE: host/port/api_path support is DEPRECATED!
        if url.startswith('http://') or url.startswith('https://'):
            # Assume new-style url param. Ignore port and api_path.
            self.api_url = url
        else:
            # This is for backwards compatability and will be removed in a future version.
            self.api_url = 'http://' + url + ':' + str(port) + api_path

        self.verify_ssl = verify_ssl

        # assume Cuckoo is *not* available.
        self.server_available = False

    def analyses(self):
        """Retrieve a list of analyzed samples.

        :rtype:  list
        :return: List of objects referencing each analyzed file.
        """
        response = self._request("tasks/list")

        return json.loads(response.content.decode('utf-8'))['tasks']

    def analyze(self, handle, filename):
        """Submit a file for analysis.

        :type  handle:   File handle
        :param handle:   Handle to file to upload for analysis.
        :type  filename: str
        :param filename: File name.

        :rtype:  str
        :return: Task ID as a string
        """
        # multipart post files.
        files = {"file": (filename, handle)}

        # ensure the handle is at offset 0.
        handle.seek(0)

        response = self._request("tasks/create/file", method='POST', files=files)

        # return task id; try v1.3 and v2.0 API response formats
        try:
            return str(json.loads(response.content.decode('utf-8'))["task_id"])
        except KeyError:
            return str(json.loads(response.content.decode('utf-8'))["task_ids"][0])

    def check(self, item_id):
        """Check if an analysis is complete

        :type  item_id: int
        :param item_id: task_id to check.

        :rtype:  bool
        :return: Boolean indicating if a report is done or not.
        """
        response = self._request("tasks/view/{id}".format(id=item_id))

        if response.status_code == 404:
            # probably an unknown task id
            return False

        try:
            content = json.loads(response.content.decode('utf-8'))
            status = content['task']["status"]
            if status == 'completed' or status == "reported":
                return True

        except ValueError as e:
            raise sandboxapi.SandboxError(e)

        return False

    def delete(self, item_id):
        """Delete the reports associated with the given item_id.

        :type  item_id: int
        :param item_id: Report ID to delete.

        :rtype:  bool
        :return: True on success, False otherwise.
        """
        try:
            response = self._request("tasks/delete/{id}".format(id=item_id))

            if response.status_code == 200:
                return True

        except sandboxapi.SandboxError:
            pass

        return False

    def is_available(self):
        """Determine if the Cuckoo Sandbox API servers are alive or in maintenance mode.

        :rtype:  bool
        :return: True if service is available, False otherwise.
        """
        # if the availability flag is raised, return True immediately.
        # NOTE: subsequent API failures will lower this flag. we do this here
        # to ensure we don't keep hitting Cuckoo with requests while
        # availability is there.
        if self.server_available:
            return True

        # otherwise, we have to check with the cloud.
        else:
            try:
                response = self._request("cuckoo/status")

                # we've got cuckoo.
                if response.status_code == 200:
                    self.server_available = True
                    return True

            except sandboxapi.SandboxError:
                pass

        self.server_available = False
        return False

    def queue_size(self):
        """Determine Cuckoo sandbox queue length

        There isn't a built in way to do this like with Joe

        :rtype:  int
        :return: Number of submissions in sandbox queue.
        """
        response = self._request("tasks/list")
        tasks = json.loads(response.content.decode('utf-8'))["tasks"]

        return len([t for t in tasks if t['status'] == 'pending'])

    def report(self, item_id, report_format="json"):
        """Retrieves the specified report for the analyzed item, referenced by item_id.

        Available formats include: json, html, all, dropped, package_files.

        :type  item_id:       int
        :param item_id:       Task ID number
        :type  report_format: str
        :param report_format: Return format

        :rtype:  dict
        :return: Dictionary representing the JSON parsed data or raw, for other
                 formats / JSON parsing failure.
        """
        report_format = report_format.lower()

        response = self._request("tasks/report/{id}/{format}".format(id=item_id, format=report_format))

        # if response is JSON, return it as an object
        if report_format == "json":
            try:
                return json.loads(response.content.decode('utf-8'))
            except ValueError:
                pass

        # otherwise, return the raw content.
        return response.content

    def score(self, report):
        """Pass in the report from self.report(), get back an int."""
        score = 0

        try:
            # cuckoo-modified format
            score = report['malscore']
        except KeyError:
            # cuckoo-2.0 format
            score = report.get('info', {}).get('score', 0)

        return score


if __name__ == "__main__":

    def usage():
        msg = "%s: <host> <analyses | analyze <fh> | available | delete <id> | queue | report <id>"
        print(msg % sys.argv[0])
        sys.exit(1)

    if len(sys.argv) == 3:
        cmd = sys.argv.pop().lower()
        host = sys.argv.pop().lower()
        arg = None

    elif len(sys.argv) == 4:
        arg = sys.argv.pop()
        cmd = sys.argv.pop().lower()
        host = sys.argv.pop().lower()

    else:
        usage()

    # instantiate Cuckoo Sandbox API interface.
    cuckoo = CuckooAPI(host)

    # process command line arguments.
    if "analyses" in cmd:
        for a in cuckoo.analyses():
            print(a["id"], a["status"], a["tags"], a["target"])

    elif "analyze" in cmd:
        if arg is None:
            usage()
        else:
            with open(arg, "rb") as handle:
                print(cuckoo.analyze(handle, arg))

    elif "available" in cmd:
        print(cuckoo.is_available())

    elif "delete" in cmd:
        if arg is None:
            usage()
        else:
            print(cuckoo.delete(arg))

    elif "queue" in cmd:
        print(cuckoo.queue_size())

    elif "report" in cmd:
        if arg is None:
            usage()
        else:
            print(cuckoo.report(arg))

    else:
        usage()
