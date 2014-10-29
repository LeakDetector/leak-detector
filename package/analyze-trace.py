#!/usr/bin/env python

import leakdetector.analyze
import argparse
import os

if __name__ == '__main__':
    """Command line entry point to run analysis function."""
    
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                        description='Analyze a recorded leak detector trace.')
    parser.add_argument('infile', metavar="tracefile",  help='Input trace file to analyze.')
    parser.add_argument('outfile', metavar="exportfile", help='Output JSON file.')
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help='Print extra information for debugging.')
    args = parser.parse_args()
    
    here = os.path.dirname(os.path.realpath(__file__))
    infile = os.path.join(here, args.infile)
    outfile = os.path.join(here, args.outfile)
        
    # Run
    leakdetector.analyze.main(infile, outfile, args.verbose)
