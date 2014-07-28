import ez_setup
ez_setup.use_setuptools()

from setuptools import setup, find_packages

name = "Leak Detector"
version = "0.1-summer2014"
description = "Capture and analysis of network traffic for personal information"
packages = find_packages()
reqs = ['BeautifulSoup>=3.2.1', 'requests>=2.0.1', 'tldextract', 'simplejson', 'geoip2>=0.3.1']
genscripts = { 'console_scripts': ['leakdetector = leakdetector.leakdetector.commandline', 
                                   'leakdetector-analyze = leakdetector.analyze.commandline']
             }
setup(name=name, version=version, description=description, packages=packages, install_requires=reqs, entry_points=genscripts, include_package_data=True)