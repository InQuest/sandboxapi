import os
from setuptools import setup

README = open(os.path.join(os.path.dirname(__file__), 'README.rst')).read()

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

requirements = open(os.path.join(os.path.dirname(__file__),
            'requirements.txt')).read()
requires = requirements.strip().split('\n')

setup(
    name='sandboxapi',
    version='1.4.1',
    include_package_data=True,
    packages=[
        'sandboxapi',
    ],
    install_requires=requires,
    license='GPL',
    description='Minimal, consistent API for building integrations with malware sandboxes.',
    long_description=README,
    url='https://github.com/InQuest/python-sandboxapi',
    author='InQuest Labs',
    author_email='labs@inquest.net',
    classifiers=[
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Software Development :: Libraries',
        'Topic :: Internet',
    ],
)
