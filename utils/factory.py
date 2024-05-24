import copy

def unpack_config(obj):
    obj = copy.deepcopy(obj)
    objConfig = obj if 'Name' in obj else { 'Name': obj }
    if 'Subnet' not in objConfig:
        objConfig['Subnet'] = 'main'
    if 'PeerConfig' not in objConfig:
        objConfig['PeerConfig'] = 'main'
    return objConfig

