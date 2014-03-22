from IPLocator import IPLocator

l = IPLocator()
#loc = l.locate('98.236.29.186')
loc = l.locate('173.22.42.117')

print loc['country']
print loc['region']
print loc['city']
