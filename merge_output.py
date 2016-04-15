#!/usr/bin/python
import json
import sys

out = []
for filename in sys.argv[2:]:
	with open(filename, 'r') as f:
		out = out + json.load(f)

with open(sys.argv[1], 'w') as f:
	json.dump(out, f, sort_keys=True, separators=(',', ': '), indent = 2)
	f.write('\n')

