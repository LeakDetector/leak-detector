import subprocess
from TCPStream import *

class TCPAnalyzer(object):
    def __init__(self, trace_file):
        # Use wireshark to get a list of TCP streams in the supplied trace file
        p = subprocess.Popen(['tshark', '-r', trace_file, '-q', '-z', 'conv,tcp'], shell=False, stdout=subprocess.PIPE)
        out, err = p.communicate()

        self.streams = []
        for line in out.split('\n')[5:-2]:
            self.streams.append(TCPStream(line, trace_file))


    def _get_http_streams(self):
        return [stream for stream in self.streams if 80 in stream.ports]
    http_streams = property(_get_http_streams)
