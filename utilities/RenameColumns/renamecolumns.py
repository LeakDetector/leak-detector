import csv
import pandas as pd
import argparse
from glob import glob

def parseKey(fn):
    """Expects CSV file with lines in the form of:
    File name specification: File, filename without extension, short name 
    Column renaming: Old name, new name
    """
    # Keep the name of Participant_ID the same over all the different
    # files so it's easier to join tables based on ID.
    excludeFromPrefix = ['Participant_ID']
    
    with open(fn) as f:
        rawKey = list(csv.reader(f))
    
    if rawKey[0][0] != 'File':
        raise ValueError("The survey key is not in the correct format.")
        
    # This is what will be built and returned
    key = {} 
    
    for row in rawKey:
        # If the row starts with "File", this is a separator
        # specifying the file the next n rows applies to
        if row[0] == 'File' and len(row) == 3:
            delimiter, filename, prefix = row
            key[filename] = {
                'prefix': prefix,
                'columns': {}
            }
        
        # Otherwise, this is just a mapping of old to new
        # column names-produce a dictionary with old names
        # as a key and new names as values
        else:
            if row[0] != 'File' and row[2] == '':
                old, new = row[0:2]
                if new not in excludeFromPrefix:
                    key[filename]['columns'][old]= "{}_{}".format(prefix, new)
                else:    
                    key[filename]['columns'][old]= new
    
    return key    

def rename(file, key):
    """Opens a CSV file and renames the columns using `key`."""

    try:
        df = pd.read_csv(file)
    except IOError:
        print "Couldn't open file {}.csv, skipping.".format(file) 
        return

    # The column name dictionary has the filename without ".csv"
    # as a key, so get that
    fileKey = file.split(".csv")[0]

    # Rename the columns
    renamed = df.rename(columns=key[fileKey]['columns'])
    
    # Export
    renamed.to_csv("*Renamed_{}".format(file))
    
    print "Finished renaming {}".format(file)
    
def renameFolder(path, key):
    # Don't rename the key
    exclude = ['Key.csv']
    
    # Get all CSV files otherwise
    canRename = [fn for fn in glob("*.csv") if fn not in exclude]
    
    for fn in canRename:
        rename(fn, key)
        
if __name__ == '__main__':
    # Set up command line interface
    parser = argparse.ArgumentParser(description='Rename columns in Qualtrics CSV files given a key.')
    parser.add_argument('--key', type=str, help='Input file mapping Qualtrics question IDs to new IDs.', required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--folder', type=str, help='Individual file to process. Use this or --file.')
    group.add_argument('--file', type=str, help='Process a whole folder. Use this or --folder.')
    args = parser.parse_args()
    
    key = parseKey(args.key)
    if args.folder:
        renameFolder(args.folder, key)
    elif args.file:
        rename(args.file, key)
    else:
        print "Did not specify anything."
    