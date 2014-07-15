import os
import shutil
import tempfile
import logging

from subprocess import Popen, PIPE, STDOUT, CalledProcessError
from itertools import chain
from collections import defaultdict

def init_temp_dir(tag):
    """Create a temporary directory called leakdetector-`tag`/."""
    __master_temp = tempfile.gettempdir()

    # If leakdetector-<tag> dir exists from a previous execution, delete it.
    # Then, either way, make a new one
    tempdir = os.path.join(__master_temp, 'leakdetector-%s' % tag)
    try:
        if os.path.exists(tempdir):
            shutil.rmtree(tempdir)
        os.makedirs(tempdir)
    except Exception as e:
        logging.getLogger(__name__).error('Error making temp directory: %s\n%s', tempdir, e)

def get_temp_dir(tag):
    """Grab the temp directory path and create one if it doesn't exist."""
    __master_temp = tempfile.gettempdir()

    tempdir = os.path.join(__master_temp, 'leakdetector-%s' % tag)
    if not os.path.isdir(tempdir):
        init_temp_dir(tag)

    return tempdir

def remove_temp_dir(tag):
    """Remove the temp directory starting with leakdetector-."""
    __master_temp = tempfile.gettempdir()

    tempdir = os.path.join(__master_temp, 'leakdetector-%s' % tag)
    logging.getLogger(__name__).debug('Removing TMP directory: %s', tempdir)
    try:
        shutil.rmtree(tempdir)
    except Exception as e:
        logging.getLogger(__name__).warning('Could not remove temp dir: %s\n%s', tempdir, e)

def check_output(args, shouldPrint=True):
    """Grab subprocess output."""
    return check_both(args, shouldPrint)[0]

def check_both(args, shouldPrint=True, check=True):
    p = Popen(args,shell=True,stdout=PIPE,stderr=STDOUT)
    out, err = p.communicate()
    rc = p.returncode
    out = (out,"")
    out = (out, rc)
    if check and rc is not 0:
        logging.getLogger(__name__).warning("Process error: %s" % out[0])
        raise CalledProcessError(args, rc)
    return out
    
def merge_dicts(x, y):
    """Merge two dictionaries based on key."""
    return dict(chain(x.iteritems(), y.iteritems()))
    
def class_register(cls):
    """Class wrapper for registry."""
    cls._analyses = defaultdict(list)
    for methodname in dir(cls):
        method = getattr(cls,methodname)
        if hasattr(method,'_prop'):
            cls._analyses[method._prop].append(method.__name__)
    return cls

def register(order):
    """Wrapper function to register analysis order."""
    def wrapper(func):
        if not ( type(order) is int and order >= -1 ):
            raise TypeError("Invalid analysis order %s." % order)
        func._prop = order
        return func
    return wrapper