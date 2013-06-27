from setuptools import setup
import os.path
import sys

ver = "0.0.2"

def read(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()

#This is a list of files to install, and where
#(relative to the 'root' dir, where setup.py is)
#You could be more specific.
files = ["lmap/ldap.py", "lmap/lmap.py"]

setup(name = "lmap",
    version = ver,
    description = "Python 3 LDAP interface using ctypes",
    license = "BSD",
    author = "jaseg",
    author_email = "jaseg@c-base.org",
    url = "https://github.com/jaseg/python-lmap",
    entry_points="""
    """,
    zip_safe = True,
    classifiers = [
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3.0',
        'Topic :: Scientific/Engineering :: Interface Engine/Protocol Translator',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Networking'
    ],

    #package_data = {'package' : files },
    #scripts = [""], # None yet
    long_description = read('README.md'),
    # Dependencies
    #
    # Note: Those are proven to work, older versions might work, 
    # but have never been tested.
    #
    dependency_links = [],
)
