#!/usr/bin/python
import json
import sys
import os

INDEX_NAME = "index.html"
CPUINFO_FILE = "cpuinfo"

index_pre = '''
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <title>AF_KTLS Benchmarks Index</title>
  </head>
  <body>
    <h1>AF_KTLS Benchmarks Index</h1>
    <ul>
'''

index_post = \
'''
    </ul>
  </body>
</html>
'''

if len(sys.argv) != 2:
    raise ValueError("Expected directory as the first argument")

index = os.path.join(sys.argv[1], INDEX_NAME)
cpuinfo = os.path.join(sys.argv[1], CPUINFO_FILE)

with open(index, 'w') as f:
    f.write(index_pre)
    dirnames = os.listdir(sys.argv[1])
    dirnames.sort()

    for dirname in dirnames:
        if os.path.isdir(os.path.join(sys.argv[1], dirname)):
            f.write('      <li><a href="%s/index.html">%s</a></li>\n'
                    % (dirname, dirname))


    with open(cpuinfo, 'r') as c:
        f.write('<pre>%s</pre>' % c.read())

    f.write(index_post)



