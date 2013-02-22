from HttpConversationParser import *
from TCPAnalyzer import *

#with open('html_convo', 'r') as f:
#    data = f.read()
#f.closed
#
#parser = HttpConversationParser(data)
#print len(parser.html_pages)
#print parser.html_pages[0]

t = TCPAnalyzer('traces/cnn.pcap')

parser = HttpConversationParser(t.streams[26].data)
print len(parser.html_pages)
print parser.html_pages[0]
