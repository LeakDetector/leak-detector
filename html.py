import utils
from HttpConversationParser import *
from TCPAnalyzer import *

#with open('html_convo', 'r') as f:
#    data = f.read()
#f.closed
#
#parser = HttpConversationParser(data)
#print len(parser.html_pages)
#print parser.html_pages[0]

utils.init_temp_dir('tcpflow')
utils.init_temp_dir('images')

t = TCPAnalyzer('imgtest.pcap')
for stream in t.http_streams:
    if 63554 in stream.ports:
        p = HttpConversationParser(stream.http_data)
        p.save_images_to_dir(utils.get_temp_dir('images'))
        for m in p.messages:
            print m
            print '\n\n'
        #for page in p.html_pages:
        #    print '<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<'
        #    print page
        #    print '>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>'

#parser = HttpConversationParser(t.streams[26].data)
#print len(parser.html_pages)
#print parser.html_pages[0]
