#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author:ray
# data:2019-11-27
# 支持的RSAS版本：V6.0R03
# 主要是特征为：扫描报告解压包里面的文件夹为：vulnhostHtml

import re
import os
import sys

if len(sys.argv) != 2:
	print "Usage: python RSAS_Report_V6.py ./DIRname"
	sys.exit(1)

while 1:
	vuln_name = raw_input('请输入您要查询的漏洞名字【RSAS漏洞全名】> ').strip()
	f = open('./'+sys.argv[1]+'/index.html','r')
	f0 = f.read()
	result_span = r'<!--<span class="level_danger_high">(.*?)</span></td>-->'
	vuln_all = re.findall(result_span,f0,re.S | re.M)
	index = (vuln_all.index(vuln_name))
	result_vulnhostHtml = r'vulnhostHtml/hosts_(.*?).html'
	vuln_group_id = re.findall(result_vulnhostHtml,f0,re.S | re.M)
	hosts_id = vuln_group_id[index]
	f.close()

	f1 = open('./'+sys.argv[1]+'/vulnhostHtml/hosts_'+hosts_id+'.html','r')
	f10 = f1.read()
	hosts = r'<a href="../host/(.*?).html'
	hosts_all = re.findall(hosts,f10,re.S | re.M)
	f1.close()

	for host in hosts_all:
			f2 = open('./'+sys.argv[1]+'/host/'+host+'.html','r')
			f20 = f2.read()
			vulns_name = r'onclick="show_vul(.*?)</span>'
			vulns_all = re.findall(vulns_name,f20,re.S | re.M)
			vulns_list_1 = map(lambda x : re.sub('^.*pointer">','',x),vulns_all)
			vulns_port = r'<div class="vul_summary(.*?)">'
			vulns_all_port = re.findall(vulns_port,f20,re.S | re.M)
			vulns_list_port1 = map(lambda x : re.sub('^.*data-port="','',x),vulns_all_port)
			res = [idx for idx, i in enumerate(vulns_list_1) if i == vuln_name]
			for i in range(len(res)):
				index1 = res[i]
				port = vulns_list_port1[index1]
				print host+':'+port
				f2.close()

