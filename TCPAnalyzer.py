import os
import subprocess
import logging
import utils
from TCPStream import *

TCPFLOW = '/usr/bin/env tcpflow'

class TCPAnalyzer(object):
    def __init__(self, trace_file):
        # Use tcpflow to reconstruct TCP conversations; save them to a temp dir
        self.__outdir = utils.get_temp_dir('tcpflow')

        try:
            utils.check_output('%s -a -r %s -o %s' % (TCPFLOW, trace_file, self.__outdir))
        except Exception as e:
            logging.getLogger(__name__).error(e)

        #self.streams = []
        self.html_files = []
        self.images = []

        for f in os.listdir(self.__outdir):
            abspath = os.path.join(self.__outdir, f)
            if f.endswith('.html'):
                self.html_files.append(abspath)
            elif f.endswith('.jpg')\
                or f.endswith('.gif')\
                or f.endswith('.png'):
                self.images.append(abspath)
            elif f.endswith('.js'):
                pass
            elif f.endswith('.css'):
                pass
            elif f.endswith('.swf'):
                pass
            elif f.endswith('.ico'):
                pass
