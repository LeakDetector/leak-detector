import subprocess
import re

PORTS = {
    'http':80,
    'https':443,
    'ldap':389,
    'ldaps':636,
    'imap':143,
    'imaps':993,
    'tripe':4070
}
def port_as_int(port):
    rv = -1
    try:
        rv = int(port)
    except:
        pass

    if rv > 0:
        return rv

    try:
        rv = PORTS[port]
    except KeyError:
        pass

    return rv

class TCPStream(object):
    def __init__(self, tshark_str, trace_file):
        self.__trace_file = trace_file

        # collapse multiple spaces to single spaces
        tshark_str = ' '.join(tshark_str.split())
        info = tshark_str.split()

        # grab the info we want
        self.ip_addresses = (info[0].split(':')[0], info[2].split(':')[0])
        self.ports = (port_as_int(info[0].split(':')[1]), port_as_int(info[2].split(':')[1]))
        self.bytes_exchanged = (int(info[4]), int(info[6]))
        self.frames_exchanged = (int(info[3]), int(info[5]))
        self.duration = float(info[10])

    def __str__(self):
        return '%s:%d <-> %s:%d' % (self.ip_addresses[0], self.ports[0], self.ip_addresses[1], self.ports[1])

    def _get_data(self):
        # Use tshark to get the TCP stream's data
        # http://www.wireshark.org/docs/man-pages/tshark.html
        follow_str = 'follow,tcp,raw,%s:%d,%s:%d' % (self.ip_addresses[0], self.ports[0], self.ip_addresses[1], self.ports[1])
        p = subprocess.Popen(['tshark', '-r', self.__trace_file, '-q', '-z', follow_str], shell=False, stdout=subprocess.PIPE)
        out, err = p.communicate()


        # Mark where we switch from lines beginning with tabs to lines not beginning
        # with tabs and vice versa, then remove the tabs
        data = re.sub(r'(\t.*\n)([^\t])', r'\1<<<<SWITCH>>>>\2', out)
        data = re.sub(r'(\n[^\t].*\n)(\t)', r'\1<<<<SWITCH>>>>\2', data)
        data = re.sub(r'\t', r'', data)

        # TODO: clean this up
        data = ''.join(data.split('\n')[6:-2]) #check -2
        sections = data.split('<<<<SWITCH>>>>')
        for i in range(0, len(sections)):
            lines = sections[i].split('\n')
            lines = [line.decode("hex") for line in lines]
            sections[i] = ''.join(lines)
        data = '\r\n\r\n'.join(sections)

        #with open('tmp', 'w') as f:
        #    f.write(data)
        #f.closed

        return data
    data = property(_get_data)
