import pkgutil

"""
Import all parsers as their class name, not as a sub-module.

>>> import parsers 
>>> parsers.BroLogParser # you can refer to them as this
parsers.BroLogParser.BroLogParser
>>> # instead of the full name
"""

__all__ = []
for loader, module_name, is_pkg in  pkgutil.walk_packages(__path__):
    __all__.append(module_name)
    module = loader.find_module(module_name).load_module(module_name) # grab each module
    # redefine name
    exec('%s = module' % module_name)
    # import
    exec('from %s import *' % module_name)