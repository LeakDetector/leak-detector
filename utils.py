import os
import shutil
import tempfile

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
        print e
        TMP = None
        dprint('Error making temp directory')

def delete_TMP():
    if TMP:
        dprint('Removing TMP directory: %s' % TMP)
        shutil.rmtree(TMP)
    



VERBOSE = False

def dprint(message):
    if VERBOSE:
        print message
