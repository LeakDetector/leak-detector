import os
import shutil
import tempfile
import logging

TMP = None

def create_TMP():
    global TMP
    # If leakdetector TMP dir exists from a previous execution, delete it.
    # Then, either way, make a new one
    TMP = os.path.join(tempfile.gettempdir(), 'leakdetector')
    try:
        if os.path.exists(TMP):
            shutil.rmtree(TMP)
        os.makedirs(TMP)
    except Exception as e:
        TMP = None
        logging.getLogger(__name__).error('Error making temp directory: %s', e)

def delete_TMP():
    if TMP:
        logging.getLogger(__name__).info('Removing TMP directory: %s', TMP)
        shutil.rmtree(TMP)
