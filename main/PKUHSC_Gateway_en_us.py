# -*- coding: utf-8 -*-
# @Author: Doublefire.Chen
# @Author_BBS_id: Bigscience
# @Date: 2022-08-30 18:02:35
# @email: Doublefire.Chen@gmail.com
# @location: HSC of PKU or BJMU(dawu,23333)
# @Last Modified by: Doublefire.Chen
# @Last Modified time: 2022-08-31 18:24:36
# @version:v1.0_en
# @Github address:https://github.com/Doublefire-Chen/PKUHSC_Gateway
# 北大医学办学110周年纪念
import requests
import time
import re
import os
import execjs
import datetime
import PKUHSC_Gateway_zh_ch
from bs4 import BeautifulSoup
###########配置区##########
username='' #请在引号中填入您的学号
password='' #请在引号中填入您的密码
##########################
RED = '\033[31m'
SKYBLUE = '\033[36m'
GREEN = '\033[32m'
BOLD = '\033[1m'
END_COLOR = '\033[0m'
session = requests.session() #通用session
check = requests.session() #新建TCP连接，专用于检测cookie
PHPSESSID=''
user_realname=''
RemainingTime=''
account_remaining_time=''
service_remaining_time=''
PresentIP=''
policyM=''
maxOnlineNum=''
online_ip=[]
online_name=[]
online_mac=[]
online_bind_flag=[]
online_id=[]
offline_ip=[]
offline_name=[]
offline_mac=[]
offline_bind_flag=[]
dropable_num=[]
unbindable_mac=[]
renameable_mac=[]
renameable_bind_flag=[]
not_binded_mac=[]
class Login:
	#读取本地cookie登陆，没有的话就获取cookie并储存cookie
	cookie_file_name=username+"_cookie.txt" #cookie文件name
	path=os.path.dirname(os.path.realpath(__file__))+'/'+cookie_file_name #本地cookie绝对路径
	cookie=''
	lt=''
	execution=''
	pwdDefaultEncryptSalt=''
	ciphertext=''
	ticket=''
	def encrpt(self):#加密函数
		js_path=os.path.dirname(os.path.realpath(__file__))+'/encrpt.js'
		js_code = open(js_path,encoding='utf-8').read()
		js_encrpt = execjs.compile(js_code)
		ciphertext = js_encrpt.call('encryptAES',password,self.pwdDefaultEncryptSalt)
		return ciphertext
	def get_para(self):#获取隐藏在网页里面的参数
		header={
			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
			'Accept-Encoding': 'gzip, deflate, br',
			'Accept-Language': 'en-US,en;q=0.9',
			'Connection': 'keep-alive',
			'Host': 'auth.bjmu.edu.cn',
			'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
			'sec-ch-ua-mobile': '?0',
			'sec-ch-ua-platform': '"macOS"',
			'Sec-Fetch-Dest': 'document',
			'Sec-Fetch-Mode': 'navigate',
			'Sec-Fetch-Site': 'none',
			'Sec-Fetch-User': '?1',
			'Upgrade-Insecure-Requests': '1',
			'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36'
		}
		page=session.get('https://auth.bjmu.edu.cn/authserver/login?service=https://its.bjmu.edu.cn/cas.php',headers=header)
		self.cookie=page.headers["Set-Cookie"].replace(' path=/; HttpOnly','')+' org.springframework.web.servlet.i18n.CookieLocaleResolver.LOCALE=en'
		soup=BeautifulSoup(page.text,"html.parser") #解析
		self.lt=soup.find('input',{"name":"lt"})["value"]
		self.execution=soup.find('input',{"name":"execution"})["value"]
		self.pwdDefaultEncryptSalt=soup.find('input',id='pwdDefaultEncryptSalt')["value"]
		self.ciphertext=self.encrpt()
	def send_captch(self):#发送验证码请求，正常情况下不需要验证码
		header={
			'Accept': 'text/plain, */*; q=0.01',
			'Accept-Encoding': 'gzip, deflate, br',
			'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
			'Connection': 'keep-alive',
			'Cookie': self.cookie,
			'Host': 'auth.bjmu.edu.cn',
			'Referer': 'https://auth.bjmu.edu.cn/authserver/login?service=https://its.bjmu.edu.cn/cas.php',
			'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
			'sec-ch-ua-mobile': '?0',
			'sec-ch-ua-platform': '"macOS"',
			'Sec-Fetch-Dest': 'empty',
			'Sec-Fetch-Mode': 'cors',
			'Sec-Fetch-Site': 'same-origin',
			'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
			'X-Requested-With': 'XMLHttpRequest'
		}
		today = datetime.datetime.now()  # 获取今天时间
		time = str(int(round(today.timestamp()*1000))) #转化为时间戳
		data={
			'username': username,
			'pwdEncrypt2': 'pwdEncryptSalt',
			'_': time
		}
		login_for_captch=session.post('https://auth.bjmu.edu.cn/authserver/needCaptcha.html',headers=header,data=data)
		if login_for_captch.text!="false":
			Print().Green_print("The operation is too fast that the Captcha is needed, please try again later")
	def get_ticket(self):#获取ticket
		header={
			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/,apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
			'Accept-Encoding': 'gzip, deflate, br',
			'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
			'Cache-Control': 'max-age=0',
			'Connection': 'keep-alive',
			'Content-Length': '279',
			'Content-Type': 'application/x-www-form-urlencoded',
			'Cookie': self.cookie,
			'Host': 'auth.bjmu.edu.cn',
			'Origin': 'https://auth.bjmu.edu.cn',
			'Referer': 'https://auth.bjmu.edu.cn/authserver/login?service=https://its.bjmu.edu.cn/cas.php',
			'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
			'sec-ch-ua-mobile': '?0',
			'sec-ch-ua-platform': '"macOS"',
			'Sec-Fetch-Dest': 'document',
			'Sec-Fetch-Mode': 'navigate',
			'Sec-Fetch-Site': 'same-origin',
			'Sec-Fetch-User': '?1',
			'Upgrade-Insecure-Requests': '1',
			'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) ,Chrome/104.0.0.0 Safari/537.36'
		}
		data={
			'username': username,
			'password': self.ciphertext,
			'lt': self.lt,
			'dllt': 'userNamePasswordLogin',
			'execution': self.execution,
			'_eventId': 'submit',
			'rmShown': '1'
		}
		login_for_ticket=session.post('https://auth.bjmu.edu.cn/authserver/login?service=https://its.bjmu.edu.cn/cas.php',headers=header,data=data,allow_redirects=False)
		self.ticket=login_for_ticket.headers['Location'].replace('https://its.bjmu.edu.cn/cas.php?','')
	def get_PHPSESSID(self):#获取最后登陆需要的cookie
		global PHPSESSID
		self.get_para()
		self.send_captch()
		self.send_captch()
		self.get_ticket()
		header={
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
		'Accept-Encoding': 'gzip, deflate, br',
		'Accept-Language': 'en-US,en;q=0.9',
		'Cache-Control': 'max-age=0',
		'Connection': 'keep-alive',
		'Host': 'its.bjmu.edu.cn',
		'Referer': 'https://auth.bjmu.edu.cn/',
		'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
		'sec-ch-ua-mobile': '?0',
		'sec-ch-ua-platform': '"macOS"',
		'Sec-Fetch-Dest': 'document',
		'Sec-Fetch-Mode': 'navigate',
		'Sec-Fetch-Site': 'same-site',
		'Sec-Fetch-User': '?1',
		'Upgrade-Insecure-Requests': '1',
		'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36'
		}
		url='https://its.bjmu.edu.cn/cas.php?'+self.ticket
		login_for_PHPSESSID=session.get(url,headers=header,allow_redirects=False)
		PHPSESSID=login_for_PHPSESSID.headers['Set-Cookie'].replace('; path=/','')
	def check_PHPSESSID(self):#读取并检查cookie是否有效，没有或者失效的话就get一个
		global PHPSESSID
		if os.path.exists(self.path)==False:
			print("The local cookie is not detected")
			print("Start getting cookie")
			self.get_PHPSESSID()
			print("Cookie is obtained successfully")
			file=open(self.path,'w',encoding='utf-8') #创建文件
			file.write(PHPSESSID)
			file.close
			print("Cookie is stored in local file")
		else:
			print("The local cookie is detected")
			file=open(self.path,encoding='utf-8')
			PHPSESSID=file.readline()
			header={
			'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
			'Accept-Encoding': 'gzip, deflate, br',
			'Accept-Language': 'en-US,en;q=0.9',
			'Cache-Control': 'max-age=0',
			'Connection': 'keep-alive',
			'Cookie': PHPSESSID,
			'Host': 'its.bjmu.edu.cn',
			'Referer': 'https://auth.bjmu.edu.cn/',
			'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
			'sec-ch-ua-mobile': '?0',
			'sec-ch-ua-platform': '"macOS"',
			'Sec-Fetch-Dest': 'document',
			'Sec-Fetch-Mode': 'navigate',
			'Sec-Fetch-Site': 'same-site',
			'Sec-Fetch-User': '?1',
			'Upgrade-Insecure-Requests': '1',
			'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36'
			}
			print("Start checking if the cookie is useful")
			check_cookie=check.get('https://its.bjmu.edu.cn/self-service.php',headers=header)
			soup=BeautifulSoup(check_cookie.text,"html.parser") #解析
			form=soup.find('form',{"name":"form2"}) #爬取到大表单
			if form==None:
				print('Cookie is useless, the program will get a new one soon')
				self.get_PHPSESSID()
				file=open(self.path,'w',encoding='utf-8') #创建文件
				file.write(PHPSESSID)
				file.close
				print('Cookie is refreshed')
			else:
				print('Cookie is useful')
	def get_status(self): #爬取基本信息
		global online_ip,online_name,online_mac,online_bind_flag,offline_ip,offline_name,offline_mac,offline_bind_flag,online_id,user_realname,RemainingTime,account_remaining_time,service_remaining_time,PresentIP,policyM,maxOnlineNum,not_binded_mac
		#再次初始化，使得再次运行本函数即为刷新功能
		online_ip=[]
		online_name=[]
		online_mac=[]
		online_bind_flag=[]
		online_id=[]
		offline_ip=[]
		offline_name=[]
		offline_mac=[]
		offline_bind_flag=[]
		not_binded_mac=[]
		header={
		'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
		'Accept-Encoding': 'gzip, deflate, br',
		'Accept-Language': 'en-US,en;q=0.9',
		'Cache-Control': 'max-age=0',
		'Connection': 'keep-alive',
		'Cookie': PHPSESSID,
		'Host': 'its.bjmu.edu.cn',
		'Referer': 'https://auth.bjmu.edu.cn/',
		'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
		'sec-ch-ua-mobile': '?0',
		'sec-ch-ua-platform': '"macOS"',
		'Sec-Fetch-Dest': 'document',
		'Sec-Fetch-Mode': 'navigate',
		'Sec-Fetch-Site': 'same-site',
		'Sec-Fetch-User': '?1',
		'Upgrade-Insecure-Requests': '1',
		'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36'
		}
		get_status=session.get('https://its.bjmu.edu.cn/self-service.php',headers=header)
		soup=BeautifulSoup(get_status.text,"html.parser") #解析
		form=soup.find('form',{"name":"form2"}) #爬取到大表单
		article=form.find('article',class_='sub_SelfContent') #进入小框
		AvatarName=article.find('div',class_='AvatarName')
		user_realname=AvatarName.find('a',id='a_realname').text #爬取用户名
		#uname=AvatarName.find('p',id='uname').text #爬取用户学号
		sub_Selfmode02=article.find('div',class_='sub_Selfmode02') #进入账号信息框
		RemainingTime=sub_Selfmode02.find_all('div',class_='RemainingTime') #爬取有效期信息
		account_remaining_time=RemainingTime[0].find('i').text #获取到账号有效期
		service_remaining_time=RemainingTime[1].find('i').text #获取到网费有效期
		PresentIP=sub_Selfmode02.find('div',class_='PresentIP').find('i').text #获取当前ip
		policyM=sub_Selfmode02.find('div',class_='policyM').find('i').text.replace("        ","") #获取计费政策
		maxOnlineNum=sub_Selfmode02.find('div',class_='maxOnlineNum').find('i').text #获取最大连接数
		subSelfModeRT=article.find('div',class_='subSelfModeRT').find('div',class_='subSelfModeRTList').find('ul')
		for li in subSelfModeRT.find_all('li'):
			subSelfModeRTList=li.find_all('div',class_='height-1')
			ip=subSelfModeRTList[0].text.replace('\t\t\t\t','') #获取在线Device ip
			name=subSelfModeRTList[1].text.replace("\n","").replace("					","").replace('\r','').replace('\t\t\t\t','') #获取在线Device name
			mac=li.find('input')["name"].replace(username,"") #获取mac
			bind_a=li.find_all('a',class_='unbind')[2] #检测是否绑定mac用的tag
			if ip==' ':
				offline_ip.append(ip)
				offline_mac.append(mac)
				offline_name.append(name)
				if username in str(bind_a):
					offline_bind_flag.append('1')
				else:
					offline_bind_flag.append('0')
					not_binded_mac.append(mac)
			else:
				online_ip.append(ip)
				online_mac.append(mac)
				online_name.append(name)
				online_id_rough=li.find('a',class_='insertingCoil')["onclick"].replace(username,'')
				onlineid=re.search(r'\d\d\d\d+',online_id_rough).group(0)
				online_id.append(onlineid)
				if username in str(bind_a):
					online_bind_flag.append('1')
				else:
					online_bind_flag.append('0')
					not_binded_mac.append(mac)
class Print:
	#打印信息
	def SkyBlue_print(self,text):
		print(SKYBLUE+text+END_COLOR)
	def Green_print(self,text):
		print(GREEN+text+END_COLOR)
	def Red_print(self,text):
		print(RED+text+END_COLOR)
	def Bold_print(self,text):
		print(BOLD+text+END_COLOR)
	def account_info(self):
		print("Studentcard id:"+username)
		print("Accound remaining time:"+account_remaining_time)
		print("Service remaining time:"+service_remaining_time)
		print("Present ip:"+PresentIP)
		print("Charging policies:"+policyM)
		print("Maximum connection number:"+maxOnlineNum)
		Print().Green_print("*"*50)
	def welcome(self): #欢迎界面
		self.Red_print('''PPPPPP  KK  KK UU   UU HH   HH  SSSSS   CCCCC  
PP   PP KK KK  UU   UU HH   HH SS      CC    C 
PPPPPP  KKKK   UU   UU HHHHHHH  SSSSS  CC      
PP      KK KK  UU   UU HH   HH      SS CC    C 
PP      KK  KK  UUUUU  HH   HH  SSSSS   CCCCC  ''')
		self.SkyBlue_print('''__        __   _                          
\\ \\      / /__| | ___ ___  _ __ ___   ___ 
 \\ \\ /\\ / / _ \\ |/ __/ _ \\| '_ ` _ \\ / _ \\
  \\ V  V /  __/ | (_| (_) | | | | | |  __/
   \\_/\\_/ \\___|_|\\___\\___/|_| |_| |_|\\___|''')
		if policyM=='学生国际畅游包月':
			call="Classmate"
		else: #教工国际畅游包月
			call="Teacher"
		print(BOLD+call+user_realname+END_COLOR+','+GREEN+"PKUHSC welcomes you home!"+END_COLOR)
	def status(self): #打印设备在线状态
		Print().Green_print("*"*50)
		i=0
		for ip in online_ip:
			print("Device situation: Online")
			print("Device ip:"+ip)
			print("Device mac address:"+online_mac[i])
			print("Device name:"+online_name[i])
			if online_bind_flag[i]=='1':
				print("This device's mac is binded(In principle, future authentication free)")
			elif online_bind_flag[i]=='0':
				print("This device's mac is not binded(In principle, re-authentication is required in the future)")
			i=i+1
			Print().Green_print("-"*50)
		i=0
		for ip in offline_ip:
			print("Device situation: Offline")
			print("Device ip:"+ip)
			print("Device mac address:"+offline_mac[i])
			print("Device name:"+offline_name[i])
			if offline_bind_flag[i]=='1':
				print("This device's mac is binded(In principle, future authentication free)")
			elif offline_bind_flag[i]=='0':
				print("This device's mac is not binded(In principle, re-authentication is required in the future)")
			i=i+1
			Print().Green_print("-"*50)
	def wait_time_axis(self,seconds):
		t=seconds/100
		Print().Green_print("Waiting for server's refresh."+" Waiting time:"+str(seconds)+" seconds")
		for i in range(101):
			time.sleep(t)
			print('\r'+SKYBLUE+'▇'*(i//2)+END_COLOR+str(i)+'%', end='')
		print('\n')
class Command:
	#基本操作函数类
	header={
	'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
	'Accept-Encoding': 'gzip, deflate, br',
	'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
	'Cache-Control': 'max-age=0',
	'Connection': 'keep-alive',
	'Content-Length': '110',
	'Content-Type': 'application/x-www-form-urlencoded',
	'Host': 'its.bjmu.edu.cn',
	'Origin': 'https://its.bjmu.edu.cn',
	'Referer': 'https://its.bjmu.edu.cn/srun_portal_pc.php?ac_id=1',
	'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
	'sec-ch-ua-mobile': '?0',
	'sec-ch-ua-platform': '"macOS"',
	'Sec-Fetch-Dest': 'document',
	'Sec-Fetch-Mode': 'navigate',
	'Sec-Fetch-Site': 'same-origin',
	'Sec-Fetch-User': '?1',
	'Upgrade-Insecure-Requests': '1',
	'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36'
	} #通用普通请求头
	header_with_PHPSESSID={
	'Accept': 'application/json, text/javascript, */*; q=0.01',
	'Accept-Encoding': 'gzip, deflate, br',
	'Accept-Language': 'en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7',
	'Connection': 'keep-alive',
	'Content-Length': '58',
	'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
	'Cookie': PHPSESSID,
	'Host': 'its.bjmu.edu.cn',
	'Origin': 'https://its.bjmu.edu.cn',
	'Referer': 'https://its.bjmu.edu.cn/self-service.php',
	'sec-ch-ua': '"Chromium";v="104", " Not A;Brand";v="99", "Google Chrome";v="104"',
	'sec-ch-ua-mobile': '?0',
	'sec-ch-ua-platform': '"macOS"',
	'Sec-Fetch-Dest': 'empty',
	'Sec-Fetch-Mode': 'cors',
	'Sec-Fetch-Site': 'same-origin',
	'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/104.0.0.0 Safari/537.36',
	'X-Requested-With': 'XMLHttpRequest'
	}
	def auth_by_ip(self,ip,bind_mac_flag): #flag为0不绑定mac，flag为1绑定mac
		bind_mac_flag=str(bind_mac_flag)
		data = {
		'action': 'login',
		'ac_id': '1',
		'user_ip': ip,
		'nas_ip': '',
		'user_mac': '',
		'url': '',
		'nas_init_port': bind_mac_flag,
		'username': username,
		'password': password
		} #登陆时发送请求包的data初始赋值
		login = session.post('https://its.bjmu.edu.cn/srun_portal_pc.php?ac_id=1',data=data,headers=self.header) #发送认证请求
		binf_tag=''
		ip_tag=''
		if bind_mac_flag=='1':
			bind_tag="In future, authentication is free"
		elif bind_mac_flag=='0':
			bind_tag="In future, re-authentication is needed"
		Print().wait_time_axis(6)
		Login().get_status()
		if ip!='' and ip in online_ip:
			ip_tag="The device with ip address "+ip+" is authenticated successfully. "
			Print().Green_print(ip_tag+bind_tag)
		elif ip!='' and ip not in online_ip:
			ip_tag="The device with ip address "+ip+" is failed to authenticate, please try again later. "
			Print().Green_print(ip_tag)	
		elif ip=='' and PresentIP in online_ip:
			ip_tag="This devive is authenticated successfully. "
			Print().Green_print(ip_tag+bind_tag)
		elif ip=='' and PresentIP not in online_ip:
			ip_tag="This devive is failed to authenticate. Please try again later"
			Print().Green_print(ip_tag)	
	def drop_by_onlineid(self,onlineid):#下线函数	
		data = {
		'action': 'droponline',
		'user_name': username,
		'online_id': onlineid
		}
		logout = session.post('https://its.bjmu.edu.cn/self_service_ajax.php',data=data,headers=self.header_with_PHPSESSID)
	def unbind_mac(self,mac):#解绑函数
		data = {
		'action': 'unbindmac',
		'user_name': username,
		'mac': mac
		}
		unbind_mac = session.post('https://its.bjmu.edu.cn/self_service_ajax.php',data=data,headers=self.header)#test pass
	def rename(self,mac,new_name,bind_mac_flag):#重命名函数
		data={
		'action': 'rename',
		'user_name': username,
		'mac': mac,
		'device_name': new_name,
		'is_mac_auth': bind_mac_flag
		}
		rename=session.post('https://its.bjmu.edu.cn/self_service_ajax.php',headers=self.header_with_PHPSESSID,data=data)
	def drop_all(self):#Drop all devices函数
		data={
		'action': 'force_uname',
		'username': username,
		'ajax': '1'
		}
		drop_all=session.post('https://its.bjmu.edu.cn/include/auth_action.php',headers=self.header_with_PHPSESSID,data=data)
		Print().wait_time_axis(5)
		Login().get_status()
		if online_ip==[]:
			Print().Green_print("All devices are dropped")
		else:
			Print().Green_print("It is failed to drop all devices, please try again later")
	'''
	def login_by_mac(mac): #校园网网关好像不支持这个功能，保留此项，欢迎大佬为爱发电
		data = {
		'action': 'login',
		'ac_id': '1',
		'user_ip': '',
		'nas_ip': '',
		'user_mac': mac,
		'url': '',
		'nas_init_port': '1',
		'username': username,
		'password': password
		} #登陆时发送请求包的data初始赋值
		login = session.post('https://its.bjmu.edu.cn/srun_portal_pc.php?ac_id=1',data=data,headers=header) #发送认证请求
		if str(login)=='<Response [200]>': #判断是否登陆成功
			print("mac地址为"+mac+"的设备校园网认证成功") #提示性输出
		else:
			print("mac地址为"+mac+"的设备网络错误，请检查网络设置后重试") #提示性输出
	unbind_mac('1234.abcd.5678')
	'''
class Menu:
	#交互界面函数类
	def main(self): #主页面
		Print().SkyBlue_print("Current location: Main menu")
		choose_in_main_menu=input("Please enter number key to continue your operation\n0、Quit\n1、Device management\n2、Device authentication\n3、Refresh\n4、Switch language to Chinese-simplified\n")
		if choose_in_main_menu not in {'0','1','2','3','4'}:
				Print().Red_print("Your input is invalid, please input again")
				self.main()
		else:
			if choose_in_main_menu=='0':
				print(GREEN+"PKUHSC wish you a wonderful experience with campus network"+END_COLOR+RED+"\nIf any problem, please call:010-82802999"+END_COLOR)
				os._exit(0) #结束程序
			elif choose_in_main_menu=='1':
				Print().status() #输出设备信息
				self.manage()
			elif choose_in_main_menu=='2':
				self.auth()
			elif choose_in_main_menu=='3':
				Login().get_status()
				Print().Green_print("Refresh successfully")
				self.main()
			elif choose_in_main_menu=='4':
				PKUHSC_Gateway_zh_ch.main_zh_cn()
	def manage(self): #Device management界面
		Print().SkyBlue_print("Current location: Main menu>>Device management")
		choose_in_manage=input("Please enter number key to continue your operation\n0、Quit\n1、Drop device\n2、Unbind device\n3、Rename device\n9、Return\n")
		if choose_in_manage not in {'0','1','2','3','9'}:
				Print().Red_print("Your input is invalid, please input again")
				self.manage()
		else:
			if choose_in_manage=='0':
				print(GREEN+"PKUHSC wish you a wonderful experience with campus network"+END_COLOR+RED+"\nIf any problem, please call:010-82802999"+END_COLOR)
				os._exit(0) #结束程序
			elif choose_in_manage=='1':
				self.drop_online()
			elif choose_in_manage=='2':
				self.unbind()
			elif choose_in_manage=='3':
				self.rename()
			elif choose_in_manage=='9':
				self.main()
	def drop_online(self): #Drop device界面
		Print().SkyBlue_print("Current location: Main menu>>Device management>>Drop device")
		Print().Green_print("*"*50)
		i=0
		if online_ip!=[]:
			for ip in online_ip:
				Print().Green_print("-"*50)
				print("Drop this device by typing:"+str(i+1))
				print("Device ip:"+ip)
				print("Device mac address:"+online_mac[i])
				print("Device name:"+online_name[i])
				if online_bind_flag[i]=='1':
					print("This device's mac is binded(In principle, future authentication free)")
				elif online_bind_flag[i]=='0':
					print("This device's mac is not binded(In principle, future re-authentication is required)")
				i=i+1
			choose_in_drop_online=input("Please enter number key to continue your operation\n0、Quit\n8、Drop all devices\n9、Return\n")
			check=0
			try: check=int(choose_in_drop_online)
			except: check=999
			if (choose_in_drop_online not in {'0','8','9'}) and (check>len(online_ip)):
				Print().Red_print("Your input is invalid, please input again")
				self.drop_online()
			else:
				if choose_in_drop_online=='0':
					print(GREEN+"PKUHSC wish you a wonderful experience with campus network"+END_COLOR+RED+"\nIf any problem, please call:010-82802999"+END_COLOR)
					os._exit(0) #结束程序
				elif choose_in_drop_online=='8':
					Command().drop_all()
					self.manage()
				elif choose_in_drop_online=='9':
					self.manage()
				else:
					t=int(choose_in_drop_online)-1
					tmp_ip=online_ip[t]
					Command().drop_by_onlineid(online_id[t])
					Print().wait_time_axis(5)
					Login().get_status()
					if tmp_ip in online_ip:
						Print().Green_print("It is failed to drop the decive with ip address :"+tmp_ip+". Please try again later")
					else:
						Print().Green_print("The decive with ip address:"+tmp_ip+" is dropped successfully")	
					self.drop_online()
		else:
			Print().Green_print("Currently, there is no any devices online")
			self.manage()
	def auth(self): #Device authentication界面
		Print().SkyBlue_print("Current location: Main menu>>Device management>>Device authentication")
		choose_in_auth=input("Please enter number key to continue your operation\n0、Quit\n1、Authenticate this device with mac binded\n2、Authenticate this device without mac binded\n3、Authenticate other device with mac binded\n4、Authenticate other device without mac binded\n9、Return\n")
		if choose_in_auth not in {'0','1','2','3','4','9'}:
				Print().Red_print("Your input is invalid, please input again")
				self.auth()
		else:
			if choose_in_auth=='0':
				print(GREEN+"PKUHSC wish you a wonderful experience with campus network"+END_COLOR+RED+"\nIf any problem, please call:010-82802999"+END_COLOR)
				os._exit(0) #结束程序
			elif choose_in_auth=='1':
				Command().auth_by_ip('',1)
				Login().get_status()
				self.auth()
			elif choose_in_auth=='2':
				Command().auth_by_ip('',0)
				Login().get_status()
				self.auth()
			elif choose_in_auth=='3':
				Print().SkyBlue_print("Main menu>>Device management>>Device authentication>>Authenticate other device with mac binded")
				ip_need_auth=input("Please enter the device's mac address which you want to authenticate, eg:172.20.22.66\nIf batch authentication, IP addresses are separated by semicolons, eg:172.20.22.1;172.20.22.2;172.20.22.3\n")
				ip_need_auth=ip_need_auth.replace('；',';').strip()
				ip_need_auth=ip_need_auth.split(";")
				for ip in ip_need_auth:
					check=re.search(r'((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}',ip)
					if check==None:
						Print().Red_print(ip+"This is a invalid ip address, and the authentication request is not sent")
						self.auth()
					else:
						Command().auth_by_ip(ip,1)
				Login().get_status()
				self.auth()
			elif choose_in_auth=='4':
				Print().SkyBlue_print("Main menu>>Device management>>Device authentication>>Authenticate other device without mac binded")
				ip_need_auth=input("Please enter the device's mac address which you want to authenticate, eg:172.20.22.66\nIf batch authentication, IP addresses are separated by semicolons, eg:172.20.22.1;172.20.22.2;172.20.22.3\n")
				ip_need_auth=ip_need_auth.replace('；',';').strip()
				ip_need_auth=ip_need_auth.split(";")
				for ip in ip_need_auth:
					check=re.search(r'((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})(\.((2(5[0-5]|[0-4]\d))|[0-1]?\d{1,2})){3}',ip)
					if check==None:
						Print().Red_print(ip+"This is a invalid ip address, and the authentication request is not sent")
						self.auth()
					else:
						Command().auth_by_ip(ip,0)
				Login().get_status()
				self.auth()
			elif choose_in_auth=='9':
				self.main()
	def unbind(self): #Unbind device界面
		Print().SkyBlue_print("Current location: Main menu>>Device management>>Unbind device")
		global unbindable_mac
		unbindable_mac=[]
		i=0
		m=0
		for ip in online_ip:
			if online_bind_flag[m]=='0':
				m=m+1
			elif online_bind_flag[m]=='1':
				print("Unbind this device by typing:"+str(i+1))
				print("Device ip:"+ip)
				print("Device mac address:"+online_mac[m])
				print("Device name:"+online_name[m])
				unbindable_mac.append(online_mac[m])
				Print().Green_print("-"*50)
				i=i+1
				m=m+1
		m=0
		for ip in offline_ip:
			if offline_bind_flag[m]=='0':
				m=m+1
			elif offline_bind_flag[m]=='1':
				print("Unbind this device by typing:"+str(i+1))
				print("Device ip:"+ip)
				print("Device mac address:"+offline_mac[m])
				print("Device name:"+offline_name[m])
				unbindable_mac.append(offline_mac[m])
				Print().Green_print("-"*50)
				i=i+1
				m=m+1
		if unbindable_mac!=[]:
			choose_in_unbind_mac=input("Please enter number key to continue your operation\n0、Quit\n8、Unbind all devices\n9、Return\n")
			check=0
			try: check=int(choose_in_unbind_mac)
			except: check=999
			if (choose_in_unbind_mac not in {'0','8','9'}) and (check>len(unbindable_mac)):
				Print().Red_print("Your input is invalid, please input again")
				self.unbind()
			else:
				if choose_in_unbind_mac=='0':
					print(GREEN+"PKUHSC wish you a wonderful experience with campus network"+END_COLOR+RED+"\nIf any problem, please call:010-82802999"+END_COLOR)
					os._exit(0) #结束程序
				elif choose_in_unbind_mac=='8':
					for mac in unbindable_mac:
						Command().unbind_mac(mac)
					Print().wait_time_axis(6)
					Login().get_status()
					if len(not_binded_mac)==len(online_mac)+len(offline_mac):
						Print().Green_print("All devices are unbinded successfully")
					else:
						Print().Green_print("It is failed to unbind all device, please try again later")
					self.manage()
				elif choose_in_unbind_mac=='9':
					self.manage()
				else:
					t=int(choose_in_unbind_mac)-1
					tmp_mac=unbindable_mac[t]
					Command().unbind_mac(unbindable_mac[t])
					Print().wait_time_axis(6)
					Login().get_status()
					if tmp_mac not in online_mac and unbindable_mac[t] not in offline_mac: 
						Print().Green_print("The device with mac address"+tmp_mac+"is unbind successfully")
					else:
						Print().Green_print("It is failed to unbind device with mac address"+tmp_mac+", please try again later")
					self.unbind()
		else:
			Print().Green_print("Currently, there is no device is binded")
			self.manage()
	def rename(self): #重命名界面
		Print().SkyBlue_print("Current location: Main menu>>Device management>>Rename device")
		global renameable_mac
		renameable_mac=[]
		i=0
		m=0
		for ip in online_ip:
			print("Rename this device by typing:"+str(i+1))
			print("Device ip:"+ip)
			print("Device mac address:"+online_mac[m])
			print("Device name:"+online_name[m])
			renameable_mac.append(online_mac[m])
			renameable_bind_flag.append(online_bind_flag[m])
			i=i+1
			m=m+1
			Print().Green_print("-"*50)
		m=0
		for ip in offline_ip:
			print("Rename this device by typing:"+str(i+1))
			print("Device ip:"+ip)
			print("Device mac address:"+offline_mac[m])
			print("Device name:"+offline_name[m])
			renameable_mac.append(offline_mac[m])
			renameable_bind_flag.append(offline_bind_flag[m])
			Print().Green_print("-"*50)
			i=i+1
			m=m+1
		if renameable_mac!=[]:
			choose_in_rename=input("Please enter number key to continue your operation\n0、Quit\n9、Return\n")
			check=0
			try: check=int(choose_in_rename)
			except: check=999
			if (choose_in_rename not in {'0','9'}) and (check>len(renameable_mac)):
				Print().Red_print("Your input is invalid, please input again")
				self.rename()
			else:
				if choose_in_rename=='0':
					print(GREEN+"PKUHSC wish you a wonderful experience with campus network"+END_COLOR+RED+"\nIf any problem, please call:010-82802999"+END_COLOR)
					os._exit(0) #结束程序
				elif choose_in_rename=='9':
					self.manage()
				else:
					t=int(choose_in_rename)-1
					new_name=input("Please enter a new name\n")
					Command().rename(renameable_mac[t],new_name,renameable_bind_flag[t])
					Print().Green_print("The device with mac address "+renameable_mac[t]+" is renamed successfully")
					Print().wait_time_axis(5)
					Login().get_status()
					self.rename()
def main_en_us(): #主函数
	Login().check_PHPSESSID()
	Login().get_status()
	print("Initialization is successful")
	Print().welcome()
	Print().account_info()
	Menu().main()
if __name__ == '__main__':
	main_en_us()