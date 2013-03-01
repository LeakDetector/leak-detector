import StringIO
import gzip
from pcap import HTTPHeader

def is_http_header(piece):
    # TODO: This is really dumb
    return 'HTTP' in piece

# recombines a chunked HTTP message. Format of a series of chunk is:
# <len in hex>\r\n
# <data>\r\n
# <len in hex>\r\n
# <data>\r\n
# ...
# <len in hex>\r\n
# <data>\r\n
# 0
def combine_chunks(body):
    combined_data = ''
    chunks = body.split('\r\n')
    if len(chunks) == 1:
        return body
    for i in range(1,len(chunks)):
        if i % 2 == 1:
            combined_data += chunks[i]
    return combined_data

def unzip_html(zipped):
    try:
        zipped = StringIO.StringIO(zipped)
        gzipper = gzip.GzipFile(fileobj=zipped)
        html = gzipper.read()
        return html
    except:
        print 'Error unzipping html'

# Parses an HTTP conversation. Currently only useful for extracting
# transmitted HTML documents
#
# Reference: http://www.jmarshall.com/easy/http/
class HttpConversationParser:
    
    # Takes in raw data consisting of a series of HTTP headers and message bodies
    # "pieces" (headers and bodies) are separated by \r\n, so split on that first.
    # data may be in one chunk, or in separate chunks (one for each direction)
    def __init__(self, data):
        self.__html_pages = []

        self.messages = []

        for chunk in data:
            if chunk == None: continue
            pieces = chunk.split('\r\n\r\n')
            # break convo into "messages"; a message is an HTTP header
            # optionally followed by a message body. Each message is
            # stored as a list of pieces
            current_message = {}
            for piece in pieces:
                if piece == '': 
                    continue
                if is_http_header(piece):
                    # add previous message to self
                    if len(current_message) > 0: # make sure this isn't the first iteration
                        self.messages.append(current_message)
                    current_message = {'header': HTTPHeader(piece)}
                else:
                    # make sure we haven't already set body (in some places, there was an
                    # extra \r\n, so the real body was overwritten by the second blank one
                    if 'body' not in current_message and 'header' in current_message:
                        current_message['body'] = piece
            if len(current_message) > 0:
                self.messages.append(current_message)

    # scans messages looking for HTML pages
    # adds the pages it finds to self.__html_pages
    def __process_html_pages(self):
        for message in self.messages:
            if message['header'].status == '200 OK':
                try:
                    if 'text/html' in message['header']['Content-Type']:
                        data = message['body']
                        if 'Transfer-Encoding' in message['header'] and message['header']['Transfer-Encoding'] == 'chunked':
                            data = combine_chunks(data)
                        if 'Content-Encoding' not in message['header']:
                            # Assume it's straight HTML; there's nothing to do
                            pass
                        elif 'gzip' in message['header']['Content-Encoding']:  #TODO: handle other encodings
                            data = unzip_html(data)
                        else:
                            data = None
                        if data:
                            self.__html_pages.append(data)
                except KeyError:
                    pass

    def _get_html_pages(self):
        if len(self.__html_pages) == 0:
            self.__process_html_pages()
        return self.__html_pages
    html_pages = property(_get_html_pages)
