#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author:ray
# date:2019-12-02
import re
import os
from bs4 import BeautifulSoup
import sys

if len(sys.argv) != 2:
	print "Usage: python RSAS_Report_protocol.py ./DIRname "
	sys.exit(1)

path = sys.argv[1]

dirs = os.listdir(path+'/host/')
for filename in dirs:
	flag = 'html' in filename
	if flag == 0:
		continue
	f = open(path+'/host/'+filename,'r')
	html = f.read()
	soup = BeautifulSoup(html, 'lxml')
	ip = soup.select('.even > td')[0].text
	#提取2.1漏洞概况里面的vuln_list表格里的数据
	#使用id选择器选取含有ID=vuln_list的第一个table标签内所有的内容
	tables = soup.select('#vuln_list')
	if len(tables)>0:
		table = tables[0]		
	else:
		continue
	#print table
	tbody = table.select('tbody')[0]   #使用select选择器选择table里面的第一个tbody标签【也因为只有一个这个标签】
	#print tbody
	trs = tbody.select('tr')  #因为tbody标签下面有好多tr标签，也就是表格，所以选择器选择全部。	
	for tr in trs:
		port = tr.select('td')[0].text
		protocol = tr.select('td')[2].text
		#tt=[]
		#tt.append(tr.select('td')[0].text)
		#tt.append(tr.select('td')[2].text)
		#tmp.append(tt)
		print ip+':'+port+':'+protocol

	f.close()
	
