--------------绿盟极光扫描报告IP端口提取小工具-----------

背景：漏洞IP手工统计的时候，每次都web界面点点点，工作量大又重复；这个小工具能根据漏洞名字自动统计IP:端口。

环境：python2.7

对象：RSAS V6.0

说明：根据RSAS V6.0具体对版本不同导致报告的输出不一样，写了三个脚本分别解决不同的问题。

    1、RSAS_Report_V6.0R01          解决了早期V6的报告中只有index.html和host【前提解压导出的报告，形成文件夹】
    
    2、RSAS_Report_V6.0R02          解决了V6版本中报告存在vulnhostsfiles的
    
    3、RSAS_Report_V6.0R03          解决了V6版本中报告存在vulnhostHtml的
    
    4、RSAS_Report_V6.0R03F01       解决了V6版本中报告存在vulnHtml的【截止2020.6.9官方最新版本】  
    
    5、RSAS_Report_all_srv          脚本访问了host目录里面所有IP，并打印出2.1漏洞列表的所有的【ip:port:protocol】(不受版本影响)
    
    6、RSAS_Report_http             脚本访问host所有IP之后，根据需求打印出你需要的协议的IP和对应端口。(不受版本影响)
    
    7、RSAS_V6.0R03_all_vuln_txt    把所有rsas的扫描出来的漏洞，及对应的IP、端口，自动提取出来并输出txt。【限制版本为V6.0R03】
    
    8、RSAS_V6.0R03F01_all_vuln_txt 把所有rsas的扫描出来的漏洞，及对应的IP、端口，自动提取出来并输出txt。【限制版本为V6.0R03F01】
    

注1：附图片说明。
注2: windows环境下注意gbk编码。主要在输入上。更改为如下即可：【.decode('gbk').encode('utf-8')】
    
    vuln_name = raw_input('请输入您要查询的漏洞名字【RSAS漏洞全名】> ').decode('gbk').encode('utf-8').strip()
    
![如图](https://github.com/RayScri/RSAS-V6.0-Report_Out/blob/master/test002.jpg)
![如图](https://github.com/RayScri/RSAS-V6.0-Report_Out/blob/master/test04.jpg)
![如图](https://github.com/RayScri/RSAS-V6.0-Report_Out/blob/master/test05.jpg)
![如图](https://github.com/RayScri/RSAS-V6.0-Report_Out/blob/master/test0001.jpg)

