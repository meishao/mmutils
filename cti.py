#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys,socket
import os
import commands

cti_file = sys.argv[1:][0]
cti_type = sys.argv[1:][1]

#print cti_file, cti_type

#input: 10.0.0.1
#output: 167772161,167772161,,,malware,,,,,

fo = open('cti_output.csv','w+')
fo.write('startIP,endIP,country,region,city,postalCode,latitude,longitude,metroCode,areaCode\n')

with open(cti_file, 'r') as f:
  for row in f:
    #print str(row).strip()
    ip = str(row).strip()
    ip_int = int(socket.inet_aton(ip).encode("hex"),16)
    str_ip = str(ip_int) + "," + str(ip_int) + ",,," + str(cti_type) + ",,,,,"
    fo.write(str_ip + '\n')

fo.close()

# convert csv to dat(maxmind database)
commands.getoutput('/usr/bin/env python csv2dat.py -w cti.dat mmcity cti_output.csv')
