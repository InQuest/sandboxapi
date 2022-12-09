sandboxapi
==========

.. image:: https://inquest.net/images/inquest-badge.svg
    :target: https://inquest.net/
    :alt: Developed by InQuest
.. image:: https://app.travis-ci.com/InQuest/python-sandboxapi.svg?branch=master
    :target: https://app.travis-ci.com/InQuest/python-sandboxapi
    :alt: Build Status
.. image:: https://github.com/InQuest/python-sandboxapi/workflows/sandbox-workflow/badge.svg?branch=master
    :target: https://github.com/InQuest/python-sandboxapi/actions
    :alt: Build Status (GitHub Workflow)
.. image:: https://github.com/InQuest/python-sandboxapi/workflows/sandbox-workflow/badge.svg?branch=develop
    :target: https://github.com/InQuest/python-sandboxapi/actions
    :alt: Build Status - Dev (GitHub Workflow)
.. image:: https://readthedocs.org/projects/sandboxapi/badge/?version=latest
    :target: https://inquest.readthedocs.io/projects/sandboxapi/en/latest/?badge=latest
    :alt: Documentation Status
.. image:: https://app.codacy.com/project/badge/Grade/1b08631cbade462792032c577ebb77ad
    :target: https://www.codacy.com/gh/InQuest/python-sandboxapi/dashboard?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=InQuest/python-sandboxapi&amp;utm_campaign=Badge_Grade
    :alt: Code Health
.. image:: https://api.codacy.com/project/badge/Coverage/1b08631cbade462792032c577ebb77ad
    :target: https://www.codacy.com/app/rshipp/python-sandboxapi?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=InQuest/python-sandboxapi&amp;utm_campaign=Badge_Coverage
    :alt: Test Coverage
.. image:: http://img.shields.io/pypi/v/sandboxapi.svg
    :target: https://pypi.python.org/pypi/sandboxapi
    :alt: PyPi Version

A minimal, consistent API for building integrations with malware sandboxes.

This library currently supports the following sandbox systems:

* `Cuckoo Sandbox`_
* `Falcon Sandbox`_ (Formerly VxStream)
* `FireEye AX Series`_
* `Hatching Triage`_
* `Joe Sandbox`_
* `OPSWAT Sandbox`_
* `VMRay Analyzer`_
* `WildFire Sandbox`_

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

Supports Python 2.7+.

Usage
-----

Basic usage is as follows:

.. code-block:: python

    import sys
    import time
    import pprint

    from sandboxapi import cuckoo

    # connect to the sandbox
    sandbox = cuckoo.CuckooAPI('http://192.168.0.20:8090/')

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

Since the library provides a consistent API, you can treat all sandoxes
the same way:

.. code-block:: python

    import sys
    import time
    import pprint

    from sandboxapi import cuckoo, fireeye, joe

    # connect to the sandbox
    sandboxes = [
        cuckoo.CuckooAPI('http://192.168.0.20:8090/'),
        fireeye.FireEyeAPI('myusername', 'mypassword', 'https://192.168.0.21', 'winxp-sp3'),
        joe.JoeAPI('mykey', 'https://jbxcloud.joesecurity.org/api', True)
    ]

    for sandbox in sandboxes:
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

Cuckoo Sandbox
~~~~~~~~~~~~~~

Constructor signature::

    CuckooAPI(url, verify_ssl=False)

Example::

    CuckooAPI('http://192.168.0.20:8090/')

This library attempts to support any Cuckoo-like API, including older 1.x
installations (though those without a score won't be able to use the ``.score``
method), compatible forks like spender-sandbox and CAPE, and the latest 2.x
Cuckoo releases. If you find a version that doesn't work, let us know.

There is an `unofficial Cuckoo library`_ written by @keithjjones with much
more functionality. For more information on the Cuckoo API, see the `Cuckoo API
documentation`_.

FireEye AX
~~~~~~~~~~

Constructor signature::

    FireEyeAPI(username, password, url, profile, legacy_api=False, verify_ssl=True)

Example::

    FireEyeAPI('myusername', 'mypassword', 'https://192.168.0.20', 'winxp-sp3')

By default, the ``FireEyeAPI`` class uses v1.2.0 of the FireEye API, which is
available on v8.x FireEye AX series appliances. The v1.1.0 API, which is
available on v7.x appliances, is also supported - just set ``legacy_api=True``
to use the older version.

There is some limited `FireEye API documentation`_ on their blog. For more
information on FireEye's sandbox systems, see the `AX Series product page`_.
FireEye customers have access to more API documentation.

Joe Sandbox
~~~~~~~~~~~

Constructor signature::

    JoeAPI(apikey, apiurl, accept_tac, timeout=None, verify_ssl=True, retries=3)

Example::

    JoeAPI('mykey', 'https://jbxcloud.joesecurity.org/api', True)

There is an `official Joe Sandbox library`_ with much more functionality.
This library is installed as a dependency of sandboxapi, and wrapped by the
``sandboxapi.joe.JoeSandbox`` class.

VMRay Analyzer
~~~~~~~~~~~~~~

Constructor signature::

    VMRayAPI(api_key, url='https://cloud.vmray.com', verify_ssl=True)

Example::

    VMRayAPI('mykey')

VMRay customers have access to a Python library with much more functionality.
Check your VMRay documentation for more details.

Falcon Sandbox
~~~~~~~~~~~~~~

Constructor signature::

    FalconAPI(key, url='https://www.reverse.it/api/v2', env=100)

Example::

    FalconAPI('mykey')

This class only supports version 2.0+ of the Falcon API, which is available
in version 8.0.0+ of the Falcon Sandbox.

There is an `official Falcon library`_ with much more functionality, that
supports the current and older versions of the Falcon API. Note that the
official library only supports Python 3.4+.


WildFire Sandbox
~~~~~~~~~~~~~~~~

Constructor signature::

    WildFireAPI(api_key, url='https://wildfire.paloaltonetworks.com/publicapi')

Example::

    WildFireAPI('mykey')

Currently, only the WildFire cloud sandbox is supported and not the WildFire appliance.


OPSWAT Sandbox
~~~~~~~~~~~~~~

Constructor signature::

    OpswatAPI(apikey, profile, verify_ssl=True)

Example::

    OpswatAPI(apikey, 'windows7')

OPSWAT sandbox on MetaDefender Cloud. Please create an account on `OPSWAT portal`_ to receive a free MetaDefender Cloud apikey.

More details in the `OPSWAT API documentation`_.


Hatching Triage
~~~~~~~~~~~~~~~~

Constructor signature::

    TriageAPI(api_key, url='https://api.tria.ge', api_path='/v0')

Example::

    TriageAPI("ApiKeyHere")

You're able to use this class with both the `Triage public cloud`_ and the
private Triage instances. Look up the documentation for the right host and
api path for your specific instance.

For more information on what is returned from the API you can look up the
official `Triage API documentation`_.


Notes
-----

You may also be interested in `malsub`_, a similar project with support for a
number of online analysis services.


.. _Cuckoo Sandbox: https://www.cuckoosandbox.org/
.. _Fireeye AX Series: https://www.fireeye.com/products/malware-analysis.html
.. _Joe Sandbox: https://www.joesecurity.org/
.. _VMRay Analyzer: https://www.vmray.com/
.. _Falcon Sandbox: https://www.falcon-sandbox.com/
.. _WildFire Sandbox: https://www.paloaltonetworks.com/products/secure-the-network/wildfire
.. _Hatching Triage: https://tria.ge/
.. _unofficial Cuckoo library: https://github.com/keithjjones/cuckoo-api
.. _Cuckoo API documentation: https://cuckoo.sh/docs/usage/api.html
.. _FireEye API documentation: https://www.fireeye.com/blog/products-and-services/2015/12/restful_apis_thatdo.html
.. _AX Series product page: https://www.fireeye.com/products/malware-analysis.html
.. _official Joe Sandbox library: https://github.com/joesecurity/joesandboxcloudapi
.. _official Falcon library: https://github.com/PayloadSecurity/VxAPI
.. _OPSWAT portal: https://go.opswat.com
.. _OPSWAT API documentation: https://onlinehelp.opswat.com/mdcloud/10._Dynamic_analysis.html
.. _malsub: https://github.com/diogo-fernan/malsub
.. _Triage public cloud: https://tria.ge/
.. _Triage API documentation: https://tria.ge/docs/
