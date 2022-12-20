import os
import json

def read_resource(resource):
    with open(os.path.join('tests', 'resources', '{r}.json'.format(r=resource)), 'r') as f:
        return json.loads(f.read())
