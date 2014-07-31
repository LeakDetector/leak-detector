import distutils.spawn
import subprocess
import sys
import platform
import requests

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
        
def download_file(url):
    local_filename = url.split('/')[-1]
    # NOTE the stream=True parameter
    r = requests.get(url, stream=True)
    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024): 
            if chunk: # filter out keep-alive new chunks
                f.write(chunk)
                f.flush()
    return local_filename        

def installed():
    print "%s: Bro is installed. " % cprint("OK", "OKGREEN")
    print "You can run the leak detector backend now \n"
    
def osx_getbro():
    brew_path = distutils.spawn.find_executable("brew")
    
    print "%s: Bro is not installed.  Trying to install..." % cprint("MISSING", "FAIL")
    if not brew_path:
        print "Installing package manager..."
        subprocess.check_call("""ruby -e "$(curl -fsSL https://raw.github.com/Homebrew/homebrew/go/install)""", shell=True)

    subprocess.check_call("brew install libmagic && sudo brew link libmagic", shell=True)
    subprocess.check_call("brew install bro && sudo brew link bro", shell=True)
    
    if check_install():
        return True
    else:
        return False
            
def check_install(): 
    if distutils.spawn.find_executable("bro"):
        return True
    else:
        return False

def linux_getbro():
            
    files = {'deb': 'http://www.bro.org/downloads/release/Bro-minimal-2.3-Linux-x86_64.deb',
             'rpm': 'http://www.bro.org/downloads/release/Bro-minimal-2.3-Linux-x86_64.rpm'}
    has_dpkg = distutils.spawn.find_executable("dpkg")
    has_rpm = distutils.spawn.find_executable("rpm")

    if has_dpkg:
        print "Downloading and installing Bro..."
        bro_dpkg = download_file(files['deb'])
        if distutils.spawn.find_executable("gdebi"):
            distutils.spawn.spawn( ('sudo', 'gdebi', bro_dpkg) ) 
        else:
            distutils.spawn.spawn( ('sudo', 'apt-get', 'install', 'gdebi-core') )
            distutils.spawn.spawn( ('sudo', 'gdebi', bro_dpkg) ) 
    elif has_rpm:
        print "Downloading and installing Bro..."
        bro_rpm = download_file(files['rpm'])
        distutils.spawn.spawn( ('sudo', 'rpm', '-Uhv', bro_rpm))
    
    if check_install():
        return True
    else:
        return False    
        

def main():
    bro_path = distutils.spawn.find_executable("bro")
    currentos = sys.platform.lower()
    if not bro_path:     
        if "darwin" in currentos:
            # OS X
            finished = osx_getbro()
        elif "linux" in currentos:
            finished = linux_getbro()
        else:
            raise OSError("Sorry, Bro is not currently supported on %s." % currentos)    

        if finished:
            installed()
    else:
        installed(x)


if __name__ == '__main__':
    main()
