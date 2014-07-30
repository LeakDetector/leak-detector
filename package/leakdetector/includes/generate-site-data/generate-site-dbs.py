from parser import DmozParser
from handlers import SqliteWriter
import tarfile
import os
import requests
import logging

def download_file(url):
    local_filename = url.split('/')[-1]
    # NOTE the stream=True parameter
    r = requests.get(url, stream=True)
    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024): 
            if chunk: # filter out keep-alive new chunks
                f.write(chunk)
                f.flush()
    return local_filename

def download_and_extract():
    dmoz = "http://rdf.dmoz.org/rdf/content.rdf.u8.gz"
    dmozfn = download_file(dmoz)
    dmoz_gz = tarfile.open()
    dmoz_gz.extractall()
    dmoz_gz.close()
    os.remove(dmozfn)
    
def raw_db_exists(path):
    rawfilename = "content.rdf.u8"
    return os.path.exists(path+rawfilename)

def db_exists(path):
    dbname = "dmoz.db"
    return os.path.exists(path+dbname)

def generate_db():
    parser = DmozParser()
    parser.add_handler(SqliteWriter('dmoz.db'))
    parser.run()

def main():
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)
    
    if db_exists("./"):
        logger.info("The site database file dmoz.db already exists.")
    else:
        if not raw_db_exists("./"): 
            logger.info("Downloading raw DMOZ database.")
            download_and_extract()
        logger.info("Parsing and processing DMOZ database.")
        generate_db()
        logger.info("Finished!")
            
if __name__ == '__main__':
    main()