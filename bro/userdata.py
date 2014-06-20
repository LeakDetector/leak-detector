import json
import pprint
from collections import defaultdict

class UserData(object):

    def __init__(self, data={}):
        self.data = data
        self.output_filter = []

    def merge(self, userdata):
        for k, v in userdata.data.iteritems():
            if k in self.data:
                if type(v) is set:
                    self.data[k] = list(self.data[k] or v)
                elif type(v) is list:
                    self.data[k] += v
            else:
                if type(v) is set: 
                    #import pdb; pdb.set_trace()
                    self.data[k] = list(v)
                else:    
                    self.data[k] = v

    def set_output_filter(self, filter_string):
        '''supply a CSV string of data tags to include in output'''
        self.output_filter = filter_string.strip().split(',')

    def __get_filtered_output(self):
        if self.output_filter:
            return {key: self.data[key] for key in self.output_filter if key in self.data}
        else:
            return self.data
    filtered_output = property(__get_filtered_output)

    def __str__(self):
        return pprint.pformat(self.filtered_output)

    def __to_json(self):
        return json.dumps(self.filtered_output)
    json = property(__to_json)
