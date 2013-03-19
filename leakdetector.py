import sys
import time
import os
import logging
import re
import subprocess
from optparse import OptionParser
from userstats import *
import utils
import analyzer


# Setup command line options
parser = OptionParser()
parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Prints extra information useful for debugging.")
parser.add_option("-i", "--interface", action="store", dest="interface", default='en0', help="Name of interface to be sniffed")
parser.add_option("-G", "--rotate_seconds", action="store", dest="rotate_seconds", default='30', help="Number of seconds to sniff before creating new trace file and analyzing previous")
# MODE
#parser.add_option("-i", "--interface", action="store", dest="interface", default=None, help="Name of interface to be sniffed")
#parser.add_option("-f", "--filter", action="store_true", dest="filter_enabled", default=False, help="Runs PacketSniffer in FILTER mode.")



def main(options, args):
    # set up logging
    logging.basicConfig(
        #filename = fileName,
        format = "%(levelname) -10s %(asctime)s %(module)s:%(lineno)s %(funcName) -26s %(message)s",
        level = logging.DEBUG if options.verbose else logging.WARNING
    )


    # Start tcpdump
    utils.init_temp_dir('traces')
    tempdir = utils.get_temp_dir('traces')
    print tempdir
    tracefile = os.path.join(tempdir, '%F_%H-%M-%S_trace.pcap')
    try:
        # TODO: don't hardcode path?
        p = subprocess.Popen(['/usr/sbin/tcpdump', '-i', options.interface, '-G', options.rotate_seconds, '-w', tracefile], shell=False, stdout=subprocess.PIPE)
        #out, err = p.communicate()
    except Exception as e:
        logging.getLogger(__name__).error('Error starting tcpdump: %s', e)


    try:
        stats = UserStats()
        while True:
            full_traces = os.listdir(utils.get_temp_dir('traces'))[0:-1]  # don't start reading trace tcpdump is currently filling
            if len(full_traces) == 0:
                time.sleep(5)
            
            for trace in full_traces:
                trace_path = os.path.join(utils.get_temp_dir('traces'), trace)
                logging.getLogger(__name__).info('Analyzing trace %s', trace)
                stats = analyzer.analyze_trace(trace_path, stats)
                print stats
                os.remove(trace_path)
    except (KeyboardInterrupt, SystemExit), e:
        p.terminate()
        sys.exit()
    except Exception as e:
        logging.getLogger(__name__).error(e)
        p.terminate()
        sys.exit()
    finally:
        pass
        #utils.remove_temp_dir('traces')




if __name__ == '__main__':
    (options, args) = parser.parse_args()
    sys.exit(main(options, args))
