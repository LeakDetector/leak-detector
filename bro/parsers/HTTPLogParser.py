from collections import defaultdict
from BroLogParser import BroLogParser

class HTTPLogParser(BroLogParser):
    WINDOWS = {
        'Windows NT 6.2': 'Windows 8',
        'Windows NT 6.1': 'Windows 7',
        'Windows NT 6.0': 'Windows Vista',
        'Windows NT 5.2': 'Windows Server 2003 or Windows XP x64 Edition',
        'Windows NT 5.1': 'Windows XP',
        'Windows NT 5.01': 'Windows 2000, Service Pack 1 (SP1)',
        'Windows NT 5.0': 'Windows 2000',
        'Windows NT 4.0': 'Microsoft Windows NT 4.0',
        'Windows 98': 'Windows 98',
        'Windows 95': 'Windows 95',
        'Windows CE': 'Windows CE'
    }

    def __init__(self, log_path):
        super(HTTPLogParser, self).__init__(log_path)
    
    def __process_user_agent(self, user_agent):
        os = None
        browser = None
        try:
            if '(' in user_agent:
                for token in user_agent.split('(')[1].split(')')[0].split(';'):
                    if 'OS X' in token:
                        os = token.strip().replace('_', '.')
                    elif 'Windows' in token:
                        os = WINDOWS[token]

            if 'Chrome' in user_agent or ('Chrome' in user_agent and 'Safari' in user_agent): browser = 'Google Chrome'
            elif 'Firefox' in user_agent: browser = 'Firefox'
            elif 'Safari': browser = 'Safari'
        except KeyError:
            pass

        return os, browser

    def _process_record(self, r):
        # user agent and browser
        os, browser = self.__process_user_agent(r['user_agent'])
        if os: self.data['os'].add(os)
        if browser: self.data['browser'].add(browser)
        
        # http basic auth usernames and passwords
        if r['username'] != '-': self.data['http-usernames'].add(r['username'])
        if r['password'] != '-': self.data['http-passwords'].add(r['password'])
        
        # ip address
        if r['id.orig_h'] != '-': self.data['device-ip'] = r['id.orig_h']
        