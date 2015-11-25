#-*- coding: cp949 -*-
# ___CODE BY CRYTEK___
import os
import os.path
import glob
import sys
import time
import shutil
import sqlite3
import hashlib

#################################
#####		USER NAME 		#####
username = os.getenv('USERNAME')		# GET USER NAME
#################################
##### 		LOCAL TIME		#####
now = time.localtime()
timestamp = "%04d%02d%02d %02d%02d%02d" %(now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min, now.tm_sec)		# GET LOCAL TIME
#################################

def mkdir():		# Function about Make Directory

	os.chdir('C:\\Users\%s\Desktop\\'%username)	# Choose Directory
	if os.path.isdir("Chrome WebCache") :			# If Directory is exist,
		pass													# PASS!
	else :														# Else, ..
		os.mkdir("Chrome WebCache "+"%s"%timestamp)				# Make a Directory

	os.chdir("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp)
	os.mkdir("DB")
mkdir()

def copydb():

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy("Cookies", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp)
	# Copy to Directory ___Cookies___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy("Favicons", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp)
	# Copy to Directory ___Favicons___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy("History", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp)
	# Copy to Directory ___History___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy("Login Data", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp)
	# Copy to Directory ___Login Data___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy("Network Action Predictor", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp)
	# Copy to Directory ___Network Action Predictor___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy("Origin Bound Certs", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp)
	# Copy to Directory ___Origin Bound Certs___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy("QuotaManager", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp)
	# Copy to Directory ___QuotaManager___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy("Shortcuts", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp)
	# Copy to Directory ___Shortcuts___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy("Top Sites", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp)
	# Copy to Directory ___Top Sites___

	os.chdir('C:\Users\%s\AppData\Local\Google\Chrome\User Data\Default'%username)
	shutil.copy("Web Data", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp)
	# Copy to Directory ___Web Data___
copydb()

def dbrename():
	os.chdir("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp)
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
dbrename()

def sqlite():
	f = open("Chrome Web Caches.txt", 'w')

	def Cookies():
		con = sqlite3.connect("Cookies.db")
		dbcon = sqlite3.connect("Chrome WebCache.db")
		cursor = con.cursor()
		dbcursor = dbcon.cursor()

		dbcursor.execute("CREATE TABLE Cookies_DB(creation_utc text, host_key text, expires_utc text, last_access_utc text)")
		for row in cursor.execute("SELECT * from creation_utc") :
			dbcursor.execute("INSERT INTO Favicons_DB VALUES (?,?,?,?)", (row[0], row[1], row[2], row[3]))

		f.write(">>> Cookies.db <<< \n")
		for row in cursor.execute("SELECT 'host_key' WHERE 'cookies'") :
			f.write(str(row))
			f.write("\n")

		for row in cursor.execute("SELECT 'key' WHERE 'meta'") :
			f.write(str(row))
			f.write("\n")
		f.write("___Cookies.db___\n\n\n")
		dbcon.commit()
		con.close()
	


	def Favicons():
		
		Favicons_origin_md5 = hashlib.md5(open("C:\\Users\%s\AppData\\Local\\Google\\Chrome\\User Data\\Default"%username+"\Favicons", 'rb').read()).hexdigest()
		Favicons_copy_md5 = hashlib.md5(open("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"\Favicons.db", 'rb').read()).hexdigest()

		if Favicons_origin_md5 == Favicons_copy_md5:
			print "Orginal File Hash : " + "%s"%Favicons_origin_md5
			print "Copied File Hash : " + "%s"%Favicons_copy_md5
		else:
			print "Wrong with file hash! Not matched..."
			print "Module going to be TERMINATE.."
			def TERMINATE(n):
				while n > 0:
					print (n)
					n = n - 1
				sys.exit()
				SystemExit
			TERMINATE(5)


		con = sqlite3.connect("Favicons.db")
		dbcon = sqlite3.connect("Chrome WebCache.db")
		cursor = con.cursor()
		dbcursor = dbcon.cursor()

		dbcursor.execute("CREATE TABLE Favicons_DB(id integer, url text, icon_type integer)")

		f.write(">>> Favicons.db <<< \n")
		for row in cursor.execute("SELECT * from favicons") :
			f.write(str(row))
			
			f.write("\n")

		for row in cursor.execute("SELECT * from favicons") :
			dbcursor.execute("INSERT INTO Favicons_DB VALUES (?,?,?)", (row[0],row[1],row[2]))
		f.write("___Favicons.db___\n\n\n")
		dbcon.commit()
		con.close()
	Favicons()

	def History():
		con = sqlite3.connect("History.db")
		cursor = con.cursor()

		f.write(">>> History.db <<< \n")
		for row in cursor.execute("SELECT * from downloads") : 
			f.write(str(row))
			f.write("\n")

		for row in cursor.execute("SELECT * from downloads_url_chains") : 
			f.write(str(row))
			f.write("\n")

		for row in cursor.execute("SELECT * from keyword_search_terms") : 
			f.write(str(row))
			f.write("\n")

		for row in cursor.execute("SELECT * from meta") : 
			f.write(str(row))
			f.write("\n")

		for row in cursor.execute("SELECT * from segment_usage") :
			f.write(str(row))
			f.write("\n")

		for row in cursor.execute("SELECT * from segments") : 
			f.write(str(row))
			f.write("\n")

		for row in cursor.execute("SELECT * from urls") : 
			f.write(str(row))
			f.write("\n")

		for row in cursor.execute("SELECT * from visit_source") : 
			f.write(str(row))
			f.write("\n")

		for row in cursor.execute("SELECT * from visits") : 
			f.write(str(row))
			f.write("\n")
		f.write("___History.db___\n\n\n")
		con.close()
	History()

	def Login_Data():
		con = sqlite3.connect("Login Data.db")
		cursor = con.cursor()

		f.write(">>> Login Data.db <<<\n")
		for row in cursor.execute("SELECT * FROM logins ORDER BY origin_url ASC") :
			f.write(str(row))
			f.write("\n")
		f.write("___Login Data.db___\n\n\n")
		con.close()
	Login_Data()

	def Network_Action_Predictor():
		con = sqlite3.connect("Network Action Predictor.db")
		cursor = con.cursor()

		f.write(">>> Network Action Predictor.db <<<\n")
		for row in cursor.execute("SELECT * FROM network_action_predictor") :
			f.write(str(row))
			f.write("\n")
		f.write("___Login Data___\n\n\n")
		con.close()
	Network_Action_Predictor()
	
	def Top_Sites():
		con = sqlite3.connect("Top Sites.db")
		cursor = con.cursor()

		f.write(">>> Top Sites.db <<<\n")
		for row in cursor.execute("SELECT * FROM thumbnails ORDER BY url") :
			f.write(str(row))
			f.write("\n")
		f.write("___Top Sites___\n\n\n")
		con.close()
	Top_Sites()

	def Web_Data():
		con = sqlite3.connect("Web Data.db")
		cursor = con.cursor()

		f.write(">>> Web Data.db <<<\n")
		for row in cursor.execute("SELECT * FROM autofill ORDER BY name") :
			f.write(str(row))
			f.write("\n")
		f.write("___Web Data___\n\n\n")
	Web_Data()

	f.close()
sqlite()

def dbremove():
	os.chdir("C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp)
	# Choose Directory

	shutil.move("Cookies.db", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"/DB")
	shutil.move("Favicons.db", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"/DB")
	shutil.move("History.db", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"/DB")
	shutil.move("Login Data.db", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"/DB")
	shutil.move("Network Action Predictor.db", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"/DB")
	shutil.move("Origin Bound Certs.db", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"/DB")
	shutil.move("QuotaManager.db", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"/DB")
	shutil.move("Shortcuts.db", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"/DB")
	shutil.move("Top Sites.db", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"/DB")
	shutil.move("Web Data.db", "C:\\Users\%s\Desktop\\Chrome WebCache "%username+"%s"%timestamp+"/DB")
dbremove()