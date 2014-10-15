import re
try:
    import cPickle as pickle
except:
    import pickle   

# TODO: Implement form data reader to find personal information based on
# TODO: autofill heuristics.

class ExtractFormdata(object):
    def __init__(self, regexes):
        with open(regexes) as f: self.regexes = pickle.load(f)
        
    def extract(self, formdict):
        extracted_info = {}
        for datatype, datapoints in self.regexes.items():
            extracted_info[datatype] = []
            for datapoint, data_re in datapoints.items():
                results = map(data_re.findall, [k.lower() for k in formdict.keys()] )