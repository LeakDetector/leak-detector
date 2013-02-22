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
