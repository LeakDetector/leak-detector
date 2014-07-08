import copy
import simplejson
import cPickle as pickle
import tldextract

class JSONWriter:
  def __init__(self, name):
    self._file = open(name, 'w')

  def page(self, page, content):
    if page != None and page != "":
      newcontent = copy.copy(content)
      newcontent["url"] = page

      self._file.write(simplejson.dumps(newcontent) + "\n")
    else:
      print "Skipping page %s, page attribute is missing" % page

  def finish(self):
    self._file.close()

class SubsetPickleWriter(object):
    def __init__(self, name):
        self._file = open(name, 'w')
        self.out = {}
        
    def page(self, page, content):
        if page:
            topic = content['topic'].split("/")[1:] if 'topic' in content else None
            if not topic: pass
            name = content['d:Title'] if 'd:Title' in content else ""
            domain = tldextract.extract(page).registered_domain
            self.out[domain] = {'name': name, 'category': topic }
            
        else:
            print "Skipping page %s, page attribute is missing" % page

    def finish(self):
        print "Writing to file."
        pickle.dump(self.out, self._file)
        self._file.close()
        