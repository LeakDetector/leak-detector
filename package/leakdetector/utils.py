import os
import shutil
import tempfile
import logging
import threading

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
    """Class wrapper for registry. Allows for in-class decorating."""
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
    
def allwith(l, attr, display=None):
    """
    Return all objects with attribute `attr` in list l, optionally
    displaying selected attributes listed in `display`.
    """
    with_attr = [i for i in l if hasattr(i, attr)]
    if display:
        assert( type(display) in [list, tuple] )
        return [ tuple(getattr(i,key) for key in display) for i in with_attr ]
    else:
        return with_attr    

def findformdata(dlist, key, exact=True, limit=None):
    from userdata import userdata
    
    """
    Extracts form data values from a list of domains. 
    
    The `limit` kwarg optionally takes a function that returns True given a domain,
    which allows limiting searches to certain domains or attributes.
    """
    # If we don't limit to certain attributes, use a dummy function.
    if not limit: limit = lambda v: True
    
    findings = defaultdict(list)
    
    for domain in dlist:
        # If the class is correct and form data is present
        if issubclass(type(domain), userdata.Service) and limit(domain) and hasattr(domain, 'formdata'):
            if exact:
                # Look for an exact match
                found = [key in f.data for f in domain.formdata]
                if any(found): 
                    # Exact match found -> grab indexes of relevant data in the form data list
                    # and add them to our findings
                    indexes = [i for i, v in enumerate(found) if v == True]
                    for i in indexes:
                        findings[key].append(domain.formdata[i].data[key])
            else:
                # If we're okay with fuzzy matches, run a `key in ...` search
                found = [ map(lambda k: key in k, keys) for keys in [f.data.keys() for f in domain.formdata]]
                for i, formfound in enumerate(found):
                    # If fuzzy match exists
                    if any(formfound):
                        # Grab the indexes of those matches
                        indexes = [j for j, v in enumerate(formfound) if v == True]
                        for idx in indexes:
                            # Loop through those indexes (which are of keys) and grab the data
                            thisdata = domain.formdata[i].data
                            thiskey = thisdata.keys()[idx]
                            data = thisdata[thiskey]
                            findings[thiskey].append(thisdata[thiskey])

    return findings                


class ThreadStop(threading.Thread):
    def __init__(self):
        super(ThreadStop, self).__init__()
        self.runningFlag = threading.Event()
        self.runningFlag.set()

    def stop(self):
        self.runningFlag.clear()
