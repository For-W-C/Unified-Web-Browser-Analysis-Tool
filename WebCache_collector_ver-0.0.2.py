#-*- coding: cp949 -*-
# ___CODE BY RINGGA___
import shutil
import os
import time
import sys

#################################
#####	  GET USER NAME		#####
username = os.getenv('USERNAME')		
#################################

#################################
#####	  GET LOCAL TIME	#####
now = time.localtime()
timestamp = "%04d%02d%02d-%02d%02d%02d" %(now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)		
#################################

def mkdir():							
	os.chdir('C:\\Users\%s\Desktop\\'%username)					# Change Directory
	if os.path.isdir("IE") :									# If Directory is exist,
		pass													# PASS!
	else :														# Else, ...
		os.mkdir("IE_"+"%s"%timestamp)							# Make a Directory
	# Make base path directory

def KilltoProcesses():					
	os.system('taskkill.exe /f /im iexplore.exe')
	os.system('taskkill.exe /f /im dllhost.exe')
	os.system('taskkill.exe /f /im taskhost.exe')
	# Kill to 'WebCacheV01.dat' processes 

def copydb():							
	os.chdir('C:\Users\%s\AppData\Local\Microsoft\Windows\WebCache'%username)
	shutil.copy2("WebCacheV01.dat", "C:\\Users\%s\Desktop\\IE_"%username+"%s"%timestamp)
	# Copy to Directory -WebCacheV01.dat-

def repairEDB():
	os.chdir('C:\Users\%s\Desktop\IE_'%username+"%s"%timestamp)
	os.system('esentutl /p WebCacheV01.dat')
	# Repair database state

def main():             
    mkdir()
    KilltoProcesses()
    copydb()
    repairEDB()
 
if __name__ == '__main__':
    main()
    sys.exit(1)