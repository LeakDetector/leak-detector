from __future__ import print_function

import leakdetector.leakdetector as ld
import plaintext_summary as summary

import argparse
import os
import multiprocessing
import threading
import time

def clear(): os.system("clear")

def generate_output_and_tail(outfile, interval):
    clear()
    try:
        output = summary.parse("%s.analyzed" % outfile, sections=["products", "stats"])
        print(output)
    except:
        print("Waiting for data...")
    finally:
        threading.Timer(interval + 2, generate_output_and_tail, args=[outfile, interval]).start()

if __name__ == '__main__':
    # set up command line args
    parser = argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter,\
                        description='Analyze network traffic for leaked information (demo).')
    parser.add_argument('-o', '--outfile', default=None, help='Save output JSON to a file instead of printing to terminal.', required=True)
    parser.add_argument('-i', '--interface', default='en1', help='Name of interface to sniff (use "ifconfig" to see options).')
    parser.add_argument('-t', '--analyzeinterval', type=int, default=5, help='When running in live mode, how often to analyze Bro logs? (seconds)')
    args = parser.parse_args()
    
    if args.outfile:
        here = os.path.dirname(os.path.realpath(__file__))
        outfile = os.path.join(here, args.outfile)
    else:
        outfile = args.outfile    
    
    clear()
    # Run Leak Detector in a thread
    kwargs = {'analyzeinterval': args.analyzeinterval, 'outfile': outfile}
    ld_proc = multiprocessing.Process(target=ld.main, args=(args.interface,), kwargs=kwargs)    
    print("Starting leak detector...")
    ld_proc.start()
    print("Please browse around for a little while (about 30 seconds) so that data can be collected.")
    
    # Wait a little while... and then start analyzing
    time.sleep(args.analyzeinterval + 30)
    print("Starting analysis...")
    generate_output_and_tail(outfile, args.analyzeinterval)