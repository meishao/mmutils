#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys,socket
import os
import commands

#cti_file = sys.argv[1:][0]
#cti_type = sys.argv[1:][0].split(".")[0]
#print cti_file
#print cti_type

ip_dir = "./iplists/"
'''
for fn in os.listdir(ip_dir):
  cti_file = ip_dir + fn
  cti_type = fn.split(".")[0]
  print cti_file, cti_type
  
sys.exit()
'''

#input: 10.0.0.1
#output: 167772161,167772161,,,malware,,,,,

fo = open('cti_firehol_output.csv','w+')
fo.write('startIP,endIP,country,region,city,postalCode,latitude,longitude,metroCode,areaCode\n')

for fn in os.listdir(ip_dir):
  cti_file = ip_dir + fn
  cti_type = fn.split(".")[0]
  print cti_file + " processing..."
  with open(cti_file, 'r') as f:
    for row in f:
      if row and not row.isspace() and row[0].isdigit() and "/" not in row:
        #print str(row).strip()
        ip = str(row).strip()
        ip_int = int(socket.inet_aton(ip).encode("hex"),16)
        str_ip = str(ip_int) + "," + str(ip_int) + ",,," + str(cti_type) + ",,,,,"
        fo.write(str_ip + '\n')
      else:
        pass

fo.close()

# convert csv to dat(maxmind database)
commands.getoutput('/usr/bin/env python csv2dat.py -w cti_firehol.dat mmcity cti_firehol_output.csv')
print "binary ip data is done!"
