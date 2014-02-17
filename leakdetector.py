import sys
import time
import os
import logging
import re
import subprocess
import signal
from optparse import OptionParser
from userstats import *
import utils
import analyzer





def main():
    global p
    # set up logging
    logging.basicConfig(
        #filename = fileName,
        format = "%(levelname) -10s %(asctime)s %(module)s:%(lineno)s %(funcName) -26s %(message)s",
        level = logging.DEBUG if args.verbose else logging.WARNING
    )

    utils.init_temp_dir('images')

    # Start tcpdump
    utils.init_temp_dir('traces')
    tempdir = utils.get_temp_dir('traces')
    logging.getLogger(__name__).debug('Dumping traces to temp dir: %s', tempdir)
    tracefile = os.path.join(tempdir, '%F_%H-%M-%S_trace.pcap')
    try:
        # TODO: don't hardcode path?
        p = subprocess.Popen(['/usr/sbin/tcpdump', '-i', args.interface, '-G', args.rotate_seconds, '-w', tracefile], shell=False) #, stdout=subprocess.PIPE)
        #out, err = p.communicate()
    except Exception as e:
        logging.getLogger(__name__).error('Error starting tcpdump: %s', e)
        sys.exit()


    try:
        stats = UserStats()
        while True:
            full_traces = os.listdir(utils.get_temp_dir('traces'))[0:-1]  # don't start reading trace tcpdump is currently filling
            if len(full_traces) == 0:
                time.sleep(5)
            elif len(full_traces) * int(args.rotate_seconds) > 300:
                logging.getLogger(__name__).warning('Analyzer is more than 5 minutes behind (%d unprocessed trace files of %s seconds each)', len(full_traces), args.rotate_seconds)
            
            for trace in full_traces:
                trace_path = os.path.join(utils.get_temp_dir('traces'), trace)
                logging.getLogger(__name__).info('Analyzing trace %s', trace)
                stats = analyzer.analyze_trace(trace_path, stats)
                print stats.json
                os.remove(trace_path)
    except (KeyboardInterrupt, SystemExit), e:
        p.terminate()
        sys.exit()
    except Exception as e:
        logging.getLogger(__name__).error(e)
        p.terminate()
        sys.exit()
    finally:
        utils.remove_temp_dir('traces')


def kill_handler(signum, frame): 
    if p:
        p.terminate()
    sys.exit()



if __name__ == '__main__':
    # set up command line args
    parser = argparse.ArgumentParser(description='Analyze current network traffic for leaked information')
    parser.add_argument('-i', '--interface', default='en0', help='Name of interface to sniff (use "ifconfig" to see options).')
    parser.add_argument('-G', '--rotate_seconds', default='30', help='Number of seconds to sniff before creating new trace file and analyzing previous')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Print extra information for debugging.')
    args = parser.parse_args()


    signal.signal(signal.SIGTERM, kill_handler)
    signal.signal(signal.SIGINT , kill_handler)

    main()
