import json
import pprint
from collections import defaultdict

class UserData(object):

    def __init__(self, data={}):
        self.data = data

    def merge(self, userdata):
        for k, v in userdata.data.iteritems():
            if k in self.data:
                if type(v) is set:
                    self.data[k] |= v
                elif type(v) is list:
                    self.data[k] += v
            else:
                self.data[k] = v

    def __str__(self):
        return pprint.pformat(self.data)

    def __to_json(self):
        return json.dumps(self.data)
    json = property(__to_json)
