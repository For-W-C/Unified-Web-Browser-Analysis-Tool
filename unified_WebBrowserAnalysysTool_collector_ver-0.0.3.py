#-*- coding: utf8 -*-
# ___CODE BY RINGGA___
import shutil
import os
import time
import sys
import platform

#################################
#####	  GET USER NAME		#####
username = os.getenv('USERNAME')		
#################################

#################################
#####	  GET LOCAL TIME	#####
now = time.localtime()
timestamp = "%04d%02d%02d-%02d%02d%02d" %(now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)		
#################################

#################################
#####	  CHECK Local OS	#####
local_os = platform.release()
#################################



def mkdir():	
	os.chdir('C:\\Users\%s\Desktop\\'%username)					# Change Directory
	if os.path.isdir("UWBAT_"+"%s"%timestamp) :					# If Directory is exist,
		pass													# PASS!
	else :														# Else, Make a Directory
		os.makedirs("UWBAT_"+"%s"%timestamp+"\\collection\\IE10++")
		os.makedirs("UWBAT_"+"%s"%timestamp+"\\collection\\IE10--")
		os.makedirs("UWBAT_"+"%s"%timestamp+"\\collection\\Chrome")
# Make base path directory (for IE10++, IE10--, Chrome)
#############################################
#############################################
### ___unified_WebBrowser_AnalysisTool___ ###
#############################################



def IE10_KilltoProcesses():								
	os.system('taskkill.exe /f /im iexplore.exe')
	os.system('taskkill.exe /f /im dllhost.exe')
	os.system('taskkill.exe /f /im taskhost.exe')
	# Kill to 'WebCacheV01.dat' processes (IE10++) 

def IE10_copydb():							
	if os.path.isdir('C:\Users\%s\AppData\Local\Microsoft\Windows\WebCache'%username) :
		os.chdir('C:\Users\%s\AppData\Local\Microsoft\Windows\WebCache'%username)
		os.system('esentutl /r V01 /d')
		os.system('esentutl /y WebCacheV01.dat /d C:\Users\%s\Desktop\\UWBAT_'%username+"%s"%timestamp+"\\collection\\IE10++\\WebCacheV01.dat")
	# Copy to base directory -WebCacheV01.dat- (IE10++)

#def IE10_repairEDB():
#	os.chdir('C:\Users\%s\Desktop\UWBAT_'%username+"%s"%timestamp+"\\collection\\IE10++")
#	if os.path.isfile('C:\Users\%s\Desktop\UWBAT_'%username+"%s"%timestamp+"\\collection\\IE10++\\WebCacheV01.dat") :
#		os.system('esentutl /y WebCacheV01.dat /d WebCacheV01.dat')
	# Repair database state (IE10++)
	#########################################
	#########################################
	### ___IE10++___ - collection fuction ###
	#########################################



def IE9_copyfile():
	if os.path.isfile('C:\Users\%s\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5\index.dat'%username) :
		os.chdir('C:\\Users\%s\Desktop\\'%username)
		os.makedirs("UWBAT_"+"%s"%timestamp+"\\collection\\IE10--\\Cache")
		os.chdir('C:\Users\%s\AppData\Local\Microsoft\Windows\Temporary Internet Files\Content.IE5'%username)
		shutil.copy2("index.dat", "C:\Users\%s\Desktop\\UWBAT_"%username+"%s"%timestamp+"\\collection\\IE10--\\Cache")
	# Copy to base directory -index.dat(cache)- (IE10--)

	if os.path.isfile('C:\Users\%s\AppData\Roaming\Microsoft\Windows\Cookies\index.dat'%username) :
		os.chdir('C:\\Users\%s\Desktop\\'%username)
		os.makedirs("UWBAT_"+"%s"%timestamp+"\\collection\\IE10--\\Cookies")
		os.chdir('C:\Users\%s\AppData\Roaming\Microsoft\Windows\Cookies'%username)
		shutil.copy2("index.dat", "C:\Users\%s\Desktop\\UWBAT+"%username+"%s"%timestamp+"\\collection\\IE10--\\Cookies")
	# Copy to base directory -index.dat(Cookies)- (IE10--)

	if os.path.isfile('C:\Users\%s\AppData\Roaming\Microsoft\Windows\IEDownloadHistory\index.dat'%username) :
		os.chdir('C:\\Users\%s\Desktop\\'%username)
		os.makedirs("UWBAT_"+"%s"%timestamp+"\\collection\\IE10--\\downloadlist")
		os.chdir('C:\Users\%s\AppData\Roaming\Microsoft\Windows\IEDownloadHistory'%username)
		shutil.copy2("index.dat", "C:\Users\%s\Desktop\\UWBAT+"%username+"%s"%timestamp+"\\collection\\IE10--\\downloadlist")
	# Copy to base directory -index.dat(IE Downloadlist)- (IE10--)

	if os.path.isfile('C:\Users\%s\AppData\Local\Microsoft\Windows\History\History.IE5\index.dat'%username) :
		os.chdir('C:\\Users\%s\Desktop\\'%username)
		os.makedirs("UWBAT_"+"%s"%timestamp+"\\collection\\IE10--\\History")
		os.chdir('C:\Users\%s\AppData\Local\Microsoft\Windows\History\History.IE5'%username)
		shutil.copy2("index.dat", "C:\Users\%s\Desktop\\UWBAT+"%username+"%s"%timestamp+"\\collection\\IE10--\\History")
	# Copy to base directory -index.dat(History)- (IE10--)
	#########################################
	#########################################
	### ___IE10--___ - collection fuction ###
	#########################################



def Chrome_copydb():
	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy2("Cookies", "C:\\Users\%s\Desktop\\UWBAT_"%username+"%s"%timestamp+"\\collection\\Chrome")
	# Copy to Directory ___Cookies___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy2("Favicons", "C:\\Users\%s\Desktop\\UWBAT_"%username+"%s"%timestamp+"\\collection\\Chrome")
	# Copy to Directory ___Favicons___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy2("History", "C:\\Users\%s\Desktop\\UWBAT_"%username+"%s"%timestamp+"\\collection\\Chrome")
	# Copy to Directory ___History___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy2("Login Data", "C:\\Users\%s\Desktop\\UWBAT_"%username+"%s"%timestamp+"\\collection\\Chrome")
	# Copy to Directory ___Login Data___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy2("Network Action Predictor", "C:\\Users\%s\Desktop\\UWBAT_"%username+"%s"%timestamp+"\\collection\\Chrome")
	# Copy to Directory ___Network Action Predictor___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy2("Origin Bound Certs", "C:\\Users\%s\Desktop\\UWBAT_"%username+"%s"%timestamp+"\\collection\\Chrome")
	# Copy to Directory ___Origin Bound Certs___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy2("QuotaManager", "C:\\Users\%s\Desktop\\UWBAT_"%username+"%s"%timestamp+"\\collection\\Chrome")
	# Copy to Directory ___QuotaManager___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy2("Shortcuts", "C:\\Users\%s\Desktop\\UWBAT_"%username+"%s"%timestamp+"\\collection\\Chrome")
	# Copy to Directory ___Shortcuts___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy2("Top Sites", "C:\\Users\%s\Desktop\\UWBAT_"%username+"%s"%timestamp+"\\collection\\Chrome")
	# Copy to Directory ___Top Sites___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy2("Web Data", "C:\\Users\%s\Desktop\\UWBAT_"%username+"%s"%timestamp+"\\collection\\Chrome")
	# Copy to Directory ___Web Data___

def Chrome_dbrename():
	os.chdir("C:\\Users\%s\Desktop\\UWBAT_"%username+"%s"%timestamp+"\\collection\\Chrome")
	# Choose Directory

	os.rename("Cookies", 'Cookies.db')
	os.rename("Favicons", 'Favicons.db')
	os.rename("History", 'History.db')
	os.rename("Login Data", 'Login Data.db')
	os.rename("Network Action Predictor", 'Network Action Predictor.db')
	os.rename("Origin Bound Certs", 'Origin Bound Certs.db')
	os.rename("QuotaManager", 'QuotaManager.db')
	os.rename("Shortcuts", 'Shortcuts.db')
	os.rename("Top Sites", 'Top Sites.db')
	os.rename("Web Data", 'Web Data.db')
	# Rename Chorme's DBfiles 
	#########################################
	#########################################
	### ___Chrome___ - collection fuction ###
	#########################################

def main():             
	mkdir()
	# Make base path directory (for IE10++, IE10--, Chrome)

   	IE10_KilltoProcesses()
	IE10_copydb()
#	IE10_repairEDB()
	# IE10++ collector...

	IE9_copyfile()
	# IE10-- collector...

	Chrome_copydb()
	Chrome_dbrename()
	# Chrome collector...
 
if __name__ == '__main__':
	main()
	sys.exit(1)