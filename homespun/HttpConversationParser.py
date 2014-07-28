import os
import StringIO
import gzip
import logging
import hashlib
from pcap import HTTPHeader
from PIL import Image

# NOTE: This class is deprecated, since tcpflow now performs this functionality

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
    except Exception as e:
        logging.getLogger(__name__).warning('Error unzipping html: %s', e)
                
                
def do_display_image(filename):
    try:
        im = Image.open(filename)
        width, height = im.size
        if width < 150 or height < 150:
            return False

        colors = im.getcolors(10)  # returns None if there are more than 10 colors
        if colors:
            return False

        return True
    except Exception, e:
        logging.getLogger(__name__).warning('Error processing image: %s', e)

# Parses an HTTP conversation. Currently only useful for extracting
# transmitted HTML documents
#
# Reference: http://www.jmarshall.com/easy/http/
class HttpConversationParser:
    
    # Takes in raw data consisting of a series of HTTP headers and message bodies
    # "pieces" (headers and bodies) are separated by \r\n, so split on that first.
    # data may be in one chunk, or in separate chunks (one for each direction)
    def __init__(self, data):
        self.__processed_messages = False  # so we can do this lazily; wait until some asks for something
        self.__html_pages = []
        self.__images = []
        self.__image_paths = []
        self.messages = []

        for chunk in data:
            if chunk == None: continue
            chunk = chunk.replace('HTTP/1', '\r\n\r\nHTTP/1')  # sometimes there's not a \r\n\r\n at the end of a body; the next header connects to it and the whole thing can't be unzipped
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
    
    
    # attempts to extract an HTML document from the HTTP message
    def __process_html_page(self, message):
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

    def __process_image(self, message):
        self.__images.append( (message['header']['Content-Type'], message['body']) )

    # scans messages looking for HTML pages
    # adds the pages it finds to self.__html_pages
    # adds images it finds to self.__images
    def __process_messages(self):
        self.__processed_messages = True
        for message in self.messages:
            if message['header'].status == '200 OK':
                try:
                    if 'text/html' in message['header']['Content-Type']:
                        self.__process_html_page(message)
                    elif 'image' in message['header']['Content-Type']:
                        self.__process_image(message)
                except KeyError:
                    pass


    def _get_html_pages(self):
        if not self.__processed_messages:
            self.__process_messages()
        return self.__html_pages
    html_pages = property(_get_html_pages)

    def _get_image_paths(self):
        if not self.__processed_messages:
            self.__process_messages()
        return self.__image_paths
    image_paths = property(_get_image_paths)

    def save_images_to_dir(self, dir):
        if not self.__processed_messages:
            self.__process_messages()

        for image in self.__images:
            try:
                name = hashlib.sha1(image[1]).hexdigest()  # name image after its hash
                suffix = image[0].split('/')[1]
                filename = os.path.join(dir, '%s.%s' % (name, suffix))

                with open(filename, 'w') as f:
                    f.write(image[1])
                f.closed

                # Decide whether or not to include this image
                if do_display_image(filename):
                    self.__image_paths.append(filename)

            except Exception, e:
                logging.getLogger(__name__).warning('Error saving image: %s', e)
