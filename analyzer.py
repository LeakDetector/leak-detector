import sys
import os
import time
import re
from pcap import *
from optparse import OptionParser
from userstats import *


# Setup command line options
parser = OptionParser()
# MODE
#parser.add_option("-i", "--interface", action="store", dest="interface", default=None, help="Name of interface to be sniffed")
#parser.add_option("-f", "--filter", action="store_true", dest="filter_enabled", default=False, help="Runs PacketSniffer in FILTER mode.")
## SNIFF mode options
#parser.add_option("-t", "--transcript", action="store_true", dest="save_transcript", default=False, help="Saves a transcript of your sniffing session (which can be used for filtering later).")
#parser.add_option("-n", "--seconds", action="store", dest="runtime_seconds", default=None, help="Specify the number of seconds for which you'd like to sniff.")
## FILTER mode options
#parser.add_option("-s", "--source", action="store", dest="filter_source_ip", default=None, help="The source IP used for filtering packets.")
#parser.add_option("-d", "--dest", action="store", dest="filter_destination_ip", default=None, help="The destination IP used for filtering packets.")
#parser.add_option("-l", "--protocol", action="store", dest="filter_protocol", default=None, help="The protocol name used for filtering packets.")
#parser.add_option("-p", "--port", action="store", dest="filter_port", default=None, help="The port used for filtering packets.")

def filter(packet):
    return True

def main(options, args):
    print "******************************************************"
    print "*                                                    *"
    print "*              WELCOME TO Leak Detector              *"
    print "*                                                    *"
    print "*                   by David Naylor                  *"
    print "*                                                    *"
    print "******************************************************"
    print
    
    
    try:
        # Create PCap object
        # Offline network capture
        listener = OfflineNetworkCapture(args[0])

    except (PCapPermissionDeniedException,PCapInvalidNetworkAdapter), e:
        print e
        sys.exit(1)
        

    # Create a UserStats object
    stats = UserStats()

    # Process packet trace
    try:
        for packet in listener.get_packets(filter):
            #print packet.length, packet,'\n'
            stats.update(packet)
    except (KeyboardInterrupt, SystemExit), e:
         sys.exit()
    finally:
        listener.close()
        
    print stats
       

if __name__ == '__main__':
    (options, args) = parser.parse_args()
    sys.exit(main(options, args))
