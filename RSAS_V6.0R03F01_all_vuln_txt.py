#!/usr/bin/env python
# -*- coding:utf-8 -*-
# author:ray
# data:2020-06-09
# 支持的RSAS版本：V6.0R03F01
# 主要是特征为：扫描报告解压包里面的文件夹为：vulnHtml
# 把所有rsas的扫描出来的漏洞，及对应的IP、端口，自动提取出来，输出txt或者word

import re
import os
import sys

if len(sys.argv) != 2:
	print "Usage: python RSAS_Report_V6.py ./DIRname"
	sys.exit(1)

def wirte_txt(a):
	s = open('./vuln_all.txt','aw')
	s.write(a)
	s.close()


def read_vuln_name_all(): #读取文件的所有漏洞名并写在文件vuln_name.txt中
	f = open('./'+sys.argv[1]+'/index.html','r')
	f0 = f.read()
	result_span = r'<!--<span class="level_danger_high">(.*?)</span></td>-->'
	vuln_all = re.findall(result_span,f0,re.S | re.M)
	with open("vuln_name.txt","w") as f:
		for i in range(len(vuln_all)):
			s = str(vuln_all[i]).replace('[','').replace(']','')
			s = s.replace("'",'').replace(',','') +'\n'
			f.write(s)
	f.close()

def read_vuln_name_exec_readlines():
	f = open('./vuln_name.txt','r')
	for lines in f:
		wirte_txt(lines)
		vuln_name = lines.strip()
		f = open('./'+sys.argv[1]+'/index.html','r')
		f0 = f.read()
		result_span = r'<!--<span class="level_danger_high">(.*?)</span></td>-->'
		vuln_all = re.findall(result_span,f0,re.S | re.M)
		index = (vuln_all.index(vuln_name))
		result_vulnHtml = r'vulnHtml/(.*?).html'
		vuln_group_id = re.findall(result_vulnHtml,f0,re.S | re.M)
		hosts_id = vuln_group_id[index]
		f.close()
		f1 = open('./'+sys.argv[1]+'/vulnHtml/'+hosts_id+'.html','r')
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
				ip = host+':'+port+'\n'
				wirte_txt(ip)
				f2.close()
	f.close()
	os.remove('./vuln_name.txt')

if __name__ == "__main__":
	
	read_vuln_name_all()
	read_vuln_name_exec_readlines()






