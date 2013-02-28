import os
import subprocess
import utils
from TCPStream import *

class TCPAnalyzer(object):
    def __init__(self, trace_file):
        # Use tcpflow to reconstruct TCP conversations; save them to TMP dir
        self.__outdir = os.path.join(utils.TMP, 'tcpflow')
        os.makedirs(self.__outdir)
        p = subprocess.Popen(['tcpflow', '-AH', '-r', trace_file, '-o', self.__outdir], shell=False, stdout=subprocess.PIPE)
        out, err = p.communicate()

        self.streams = []
        for f in os.listdir(self.__outdir):
            if 'HTTP' not in f and 'report' not in f:
                stream = TCPStream(f, self.__outdir)
                if stream not in self.streams: self.streams.append(stream) 


    def _get_http_streams(self):
        return [stream for stream in self.streams if 80 in stream.ports]
    http_streams = property(_get_http_streams)
