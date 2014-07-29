import ez_setup
ez_setup.use_setuptools()

from setuptools import setup, find_packages
from setuptools.command.install import install as _install
from pkg_resources import resource_filename

import logging, os.path

name = "leakdetector"
version = "0.1-summer2014"
description = "Capture and analysis of network traffic for personal information"
packages = find_packages()
reqs = ['BeautifulSoup>=3.2.1', 'requests>=2.0.1', 'tldextract', 'simplejson', 'geoip2']
genscripts = { 'console_scripts': ['leakdetector = leakdetector.leakdetector.commandline', 
                                   'leakdetector-analyze = leakdetector.analyze.commandline']
             }

setup(name=name, 
      version=version, 
      description=description, 
      packages=packages, 
      install_requires=reqs, 
      entry_points=genscripts
#      package_data = {'': ['*.zip']},
#      include_package_data=True
)

class install(_install):
    def run(self):
        logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)
        _install.run(self)
        db_loc = resource_filename('leakdetector', 'includes/site-data/archived-dmoz.zip')

        if os.path.exists(db_loc):
            logger.info("Extracting databases...")
            with ZipFile(db_loc) as z:
                z.extractall(os.path.dirname(db_loc))
            z.closed
        else:
            generate()    
    def generate(self):
	from gen_sitedata import generate_categorization_db, generate_trackerdata
        logger = logging.getLogger(__name__)
        logging.basicConfig(level=logging.INFO)
        db_loc = resource_filename('leakdetector', 'includes/site-data')
        if generate_categorization_db.db_exists(db_loc):
            logger.info("The site database file dmoz.db already exists. No setup needed.")
        else:
            if not generate_categorization_db.raw_db_exists(db_loc):
                logger.info("Downloading raw DMOZ database.")
                generate_categorization_db.download_and_extract(db_loc)
                logger.info("Parsing and processing DMOZ database.")
                generate_db(db_loc)
                logger.info("Finished!")

        
