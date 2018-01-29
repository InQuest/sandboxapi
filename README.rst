sandboxapi
==========

.. image:: https://travis-ci.org/InQuest/python-sandboxapi.svg?branch=master
    :target: https://travis-ci.org/InQuest/python-sandboxapi
    :alt: Build Status
.. image:: https://api.codacy.com/project/badge/Grade/7ddb5b4791404aa2a6a9670099fe53ad
    :target: https://www.codacy.com/app/rshipp/python-sandboxapi?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=InQuest/python-sandboxapi&amp;utm_campaign=Badge_Grade
    :alt: Code Health
.. image:: http://img.shields.io/pypi/v/sandboxapi.svg
    :target: https://pypi.python.org/pypi/sandboxapi
    :alt: PyPi Version

A minimal, consistent API for building integrations with malware sandboxes.

This library currently supports the following sandbox systems:

* `Cuckoo Sandbox`_
* `FireEye AX Series`_
* `Joe Sandbox`_
* `VMRay Analyzer`_
* `Falcon Sandbox`_ (Formerly VxStream)

It provides at least the following methods for each sandbox:

* ``is_available()``: Check if the sandbox is operable and reachable; returns a boolean
* ``analyze(handle, filename)``: Submit a file for analysis; returns an ``item_id``
* ``check(item_id)``: Check if analysis has completed for a file; returns a boolean
* ``report(item_id, report_format='json')``: Retrieve the report for a submitted file
* ``score(report)``: Parse out and return an integer score from the report object

Some sandbox classes may have additional methods implemented. See inline
documentation for more details.

Note that the value returned from the ``score`` method may be on the range
0-10, or 0-100, depending on the sandbox in question, so you should refer to
the specific sandbox's documentation when interpreting this value.

Installation
------------

Install through pip::

    pip install sandboxapi

Supports Python 2.6+.

Usage
-----

Basic usage is as follows::

    import sys
    import time
    import pprint

    from sandboxapi import cuckoo

    # connect to the sandbox
    sandbox = cuckoo.CuckooAPI('192.168.0.20')

    # verify connectivity
    if not sandbox.is_available():
        print("sandbox is down, exiting")
        sys.exit(1)

    # submit a file
    with open('myfile.exe', "rb") as handle:
        file_id = sandbox.analyze(handle, 'myfile.exe')
        print("file {f} submitted for analysis, id {i}".format(f=filename, i=file_id))

    # wait for the analysis to complete
    while not sandbox.check(file_id):
        print("not done yet, sleeping 10 seconds...")
        time.sleep(10)

    # print the report
    print("analysis complete. fetching report...")
    report = sandbox.report(file_id)
    pprint.pprint(report)
    print("Score: {score}".format(score=sandbox.score(report)))

Cuckoo
~~~~~~

Constructor signature::

    CuckooAPI(host, port=8090, api_path='/', verify_ssl=False)

Example::

    CuckooAPI('192.168.0.20')

There is an `unofficial Cuckoo library`_ written by @keithjjones with much
more functionality. For more information on the Cuckoo API, see the `Cuckoo API
documentation`_.

FireEye
~~~~~~~

Constructor signature::

    FireEyeAPI(username, password, url, profile)

Example::

    FireEyeAPI('myusername', 'mypassword', 'https://192.168.0.20', 'winxp-sp3')

There is some limited `FireEye API documentation`_ on their blog. For more
information on FireEye's sandbox systems, see the `AX Series product page`_.

Joe
~~~

Constructor signature::

    JoeAPI(apikey, apiurl, accept_tac, timeout=None, verify_ssl=True, retries=3)

Example::

    JoeAPI('mykey', 'https://jbxcloud.joesecurity.org/api', True)

There is an `official Joe Sandbox library`_ with much more functionality.
This library is installed as a dependency of sandboxapi, and wrapped by the
``sandboxapi.joe.JoeSandbox`` class.

VMRay
~~~~~

Constructor signature::

    VMRayAPI(api_key, url='https://cloud.vmray.com')

Example::

    VMRayAPI('mykey')

VMRay customers have access to a Python library with much more functionality.
Check your VMRay documentation for more details.

Falcon
~~~~~~~~

Constructor signature::

    FalconAPI(key, secret, url='https://www.reverse.it', env=100)

Example::

    FalconAPI('mykey', 'mysecret')

There is an `official Falcon library`_ with much more functionality,
that only supports Python 3.4+.


Notes
-----

You may also be interested in `malsub`_, a similar project with support for a
number of online analysis services.


.. _Cuckoo Sandbox: https://www.cuckoosandbox.org/
.. _Fireeye AX Series: https://www.fireeye.com/products/malware-analysis.html
.. _Joe Sandbox: https://www.joesecurity.org/
.. _VMRay Analyzer: https://www.vmray.com/
.. _Falcon Sandbox: https://www.vxstream-sandbox.com/
.. _unofficial Cuckoo library: https://github.com/keithjjones/cuckoo-api
.. _Cuckoo API documentation: https://cuckoo.sh/docs/usage/api.html
.. _FireEye API documentation: https://www.fireeye.com/blog/products-and-services/2015/12/restful_apis_thatdo.html
.. _AX Series product page: https://www.fireeye.com/products/malware-analysis.html
.. _official Joe Sandbox library: https://github.com/joesecurity/joesandboxcloudapi
.. _official Falcon library: https://github.com/PayloadSecurity/VxAPI
.. _malsub: https://github.com/diogo-fernan/malsub
