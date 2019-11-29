#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author:ray
# data:2019-11-27
# 支持的RSAS版本：V6.0R02部分版本
# 主要是特征为：扫描报告解压包里面的文件夹没有任何vulnhostHtml/vulnhostsfiles。只有host和index.html
# 早期极光报告漏洞详情全部打印，没有点击点击详情查询

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
	result_vulnhost = r'<td width="80%">(.*?);&nbsp</td>'
	vuln_hosts = re.findall(result_vulnhost,f0,re.S | re.M)

	vuln_hosts_id = vuln_hosts[index]
	vuln_hosts_id_1 = r'<a href="host/(.*?).html'
	vuln_hosts_id_2 = re.findall(vuln_hosts_id_1,vuln_hosts_id,re.S | re.M)
	f.close()

	for hosts_id in vuln_hosts_id_2:
		f1 = open('./'+sys.argv[1]+'/host/'+hosts_id+'.html','r')
		f10 = f1.read()
		vulns_name = r'onclick="show_vul(.*?)</span>'
		vulns_all = re.findall(vulns_name,f10,re.S | re.M)
		vulns_list_1 = map(lambda x : re.sub('^.*pointer">','',x),vulns_all)
		vulns_port = r'<div class="vul_summary(.*?)">'
		vulns_all_port = re.findall(vulns_port,f10,re.S | re.M)
		vulns_list_port1 = map(lambda x : re.sub('^.*data-port="','',x),vulns_all_port)
		res = [idx for idx, i in enumerate(vulns_list_1) if i == vuln_name]
		for i in range(len(res)):
			index1 = res[i]
			port = vulns_list_port1[index1]
			print hosts_id+':'+port
			f1.close()

