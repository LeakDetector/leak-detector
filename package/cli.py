import leakdetector
import argparse
import os

def commandline():
    """Command line entry point to run leak detector."""
    
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                        description='Analyze network traffic for leaked information')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Print extra information for debugging.')
    parser.add_argument('-o', '--outfile', default=None, help='Save output JSON to a file instead of printing to terminal.')
    parser.add_argument('-r', '--tracefile', default=None, help='Analyze existing trace (PCAP file) instead of live traffic.')
    parser.add_argument('-f', '--filter', default=None, help='A CSV string of keys to include in the output. (Useful to limit output to subset of keys you care about.)')
    parser.add_argument('-l', '--logdir', default=None, help='Use the specified directory to store/read bro logs.')
    parser.add_argument('-i', '--interface', default='en1', help='Name of interface to sniff (use "ifconfig" to see options).')
    args = parser.parse_args()
    
    if args.outfile:
        here = os.path.dirname(os.path.realpath(__file__))
        outfile = os.path.join(here, args.outfile)
    else:
        outfile = args.outfile    
        
    # Run
    leakdetector.run.main(args.interface, outfile=outfile, tracefile=args.tracefile, _filter=args.filter, logdir=args.logdir, verbose=args.verbose)

if __name__ == '__main__':
    commandline()
