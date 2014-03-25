import os
import shutil
import tempfile
import logging
import sys
import select
import time
from subprocess import Popen, PIPE, STDOUT

def init_temp_dir(tag):
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
    __master_temp = tempfile.gettempdir()

    tempdir = os.path.join(__master_temp, 'leakdetector-%s' % tag)
    if not os.path.isdir(tempdir):
        init_temp_dir(tag)

    return tempdir

def remove_temp_dir(tag):
    __master_temp = tempfile.gettempdir()

    tempdir = os.path.join(__master_temp, 'leakdetector-%s' % tag)
    logging.getLogger(__name__).debug('Removing TMP directory: %s', tempdir)
    try:
        shutil.rmtree(tempdir)
    except Exception as e:
        logging.getLogger(__name__).warning('Could not remove temp dir: %s\n%s', tempdir, e)

def check_output(args, shouldPrint=True):
    return check_both(args, shouldPrint)[0]

def check_both(args, shouldPrint=True, check=True):
    p = Popen(args,shell=True,stdout=PIPE,stderr=STDOUT)
    out, err = p.communicate()
    rc = p.returncode
    out = (out,"")
    out = (out, rc)
    if check and rc is not 0:
        #print "Error processes output: %s" % (out,)
        raise Exception("subprocess.CalledProcessError: Command '%s'" \
                            "returned non-zero exit status %s (%s)" % (args, rc, out[0]))
    return out
