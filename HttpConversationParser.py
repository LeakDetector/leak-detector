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
    for i in range(1,len(chunks)):
        if i % 2 == 1:
            combined_data += chunks[i]
    return combined_data

def unzip_html(zipped):
    zipped = StringIO.StringIO(zipped)
    gzipper = gzip.GzipFile(fileobj=zipped)
    html = gzipper.read()
    return html

# Parses an HTTP conversation. Currently only useful for extracting
# transmitted HTML documents
#
# Reference: http://www.jmarshall.com/easy/http/
class HttpConversationParser:
    
    # Takes in raw data consisting of a series of HTTP headers and message bodies
    # "pieces" (headers and bodies) are separated by \r\n, so split on that first
    def __init__(self, data):
        self.__html_pages = []

        pieces = data.split('\r\n\r\n')

        # break convo into "messages"; a message is an HTTP header
        # optionally followed by a message body. Each message is
        # stored as a list of pieces
        self.messages = []
        current_message = {}
        for piece in pieces:
            if is_http_header(piece):
                # add previous message to self
                if len(current_message) > 0: # make sure this isn't the first iteration
                    self.messages.append(current_message)
                current_message = {'header': HTTPHeader(piece)}
            else:
                current_message['body'] = piece
        if len(current_message) > 0:
            self.messages.append(current_message)

    # scans messages looking for HTML pages
    # adds the pages it finds to self.__html_pages
    def __process_html_pages(self):
        for message in self.messages:
            if message['header'].status == '200 OK':
                try:
                    if message['header']['Content-Type'] == 'text/html':
                        data = message['body']
                        if message['header']['Transfer-Encoding'] == 'chunked':
                            data = combine_chunks(data)
                        if message['header']['Content-Encoding'] == 'gzip':  #TODO: handle other encodings
                            data = unzip_html(data)
                        self.__html_pages.append(data)
                except KeyError:
                    pass

    def _get_html_pages(self):
        if len(self.__html_pages) == 0:
            self.__process_html_pages()
        return self.__html_pages
    html_pages = property(_get_html_pages)
