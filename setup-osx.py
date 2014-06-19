import distutils.spawn
import subprocess

def cprint(string, indicator):
    termcolors = {
        'HEADER' : '\033[95m',
        'OKBLUE' : '\033[94m',
        'OKGREEN' : '\033[92m',
        'WARNING' : '\033[93m',
        'FAIL' : '\033[91m',
        'ENDC' : '\033[0m' 
    }
    if indicator not in termcolors:
        raise SyntaxError("%s is not a valid print color style." % indicator)
    else:
        return "%s%s%s" % (termcolors[indicator], string, termcolors['ENDC'])

def installed():
    print "%s: Bro is installed. " % cprint("OK", "OKGREEN")
    print "You can run the leak detector backend now."
	print "\n"
	print "For example, try %s for Ethernet connections..." % cprint("python bro/leakdetector.py -i en0", "OKBLUE")
	print "or %s for wireless connections." % cprint("python bro/leakdetector.py -i en1", "OKBLUE")
	print "Hit Ctrl-C when you're done to see the data dump."
    
def getbro():
    brew_path = distutils.spawn.find_executable("brew")
    
    print "%s: Bro is not installed.  Trying to install..." % cprint("MISSING", "FAIL")
    if not brew_path:
        print "Installing package manager..."
        subprocess.check_call("""ruby -e "$(curl -fsSL https://raw.github.com/Homebrew/homebrew/go/install)""", shell=True)

    subprocess.check_call("brew install libmagic && sudo brew link libmagic", shell=True)
    subprocess.check_call("brew install bro && sudo brew link bro", shell=True)

def main():
    bro_path = distutils.spawn.find_executable("bro")

    if not bro_path: getbro()

    installed()



if __name__ == '__main__':
    main()
