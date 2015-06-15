**Rename Qualtrics exports**

This script lets you easily rename CSV exports from Qualtrics.  

# Installation
1. Download `renamecolumns.py`.  
2. Make sure the `pandas` Python module is installed. If you're not sure, run `sudo pip install pandas` to install it.

# Key file
The script requires a key file to run. The key file has two types of rows: file divider rows and column renaming rows.
File divider rows specify what file the following columns are in. They're in the format:

File | FileNameWithoutCSVExtension | Prefix

These rows must start with the word "File". "Prefix" is optional, but if it exists, renamed columns will start with this prefix.

All other rows should just be in the form:

OldColumnName | NewColumnName

# Running
To rename an entire folder:

    python renamecolumns.py --key Key.csv --folder /path/to/folder/goes/here
		
To rename one file:

    python renamecolumns.py --key Key.csv --file yourfilename.csv