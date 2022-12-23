from selenium import webdriver
import selenium.webdriver.support.ui as ui
from selenium.webdriver.support import expected_conditions as ec
from selenium.webdriver.firefox.firefox_profile import FirefoxProfile
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter
import warnings
from selenium.webdriver.common.by import By
from time import sleep

import os
import time

import argparse

arg=argparse.ArgumentParser()

arg.add_argument("-u","--username",required=True,help="username")
arg.add_argument("-p","--password",required=True,help="password")
arg.add_argument("-sn","--scan_name",required=True,help="scan name")
arg.add_argument("-sf","--scan_file",required=True,help="scan file")
args=vars(arg.parse_args())

scanname=args["scan_name"]
filename=args["scan_file"]
uname=args["username"]
pass1=args["password"]

browser = webdriver.Firefox(executable_path="./geckodriver")
browser.get("https://localhost:8834/") 
wait = ui.WebDriverWait(browser,30)

user=wait.until(ec.visibility_of_element_located((By.XPATH, "/html/body/div/form/div[1]/input")))
user.send_keys(uname)

pass2=browser.find_element(by=By.XPATH, value='/html/body/div/form/div[2]/input')
pass2.send_keys(pass1)

log_in=browser.find_element(by=By.XPATH, value='/html/body/div/form/button')
log_in.click()


time.sleep(10)

#alertoff=browser.find_element(by=By.XPATH, value='/html/body/section[1]/div/div[2]/i[2]')
#alertoff.click()
#time.sleep(1)

new_scan=browser.find_element(by=By.XPATH, value='/html/body/section[3]/section[1]/a[1]')
new_scan.click()
sleep(10)

webtest=browser.find_element(by=By.XPATH, value='/html/body/section[3]/section[3]/section/div[1]/div[2]/div[2]/a[6]')
webtest.click()



name=wait.until(ec.visibility_of_element_located((By.XPATH, '/html/body/section[3]/section[3]/section/form/div[1]/div/div/div[1]/section/div[1]/div[1]/div[1]/div[1]/div/input')))
name.send_keys(scanname)

sleep(10)

upload_ele=browser.find_element(by=By.XPATH, value='//*[@id="editor-tab-view"]/div/div[1]/section/div[1]/div[1]/div[1]/div[6]/div/input')

upload_ele.send_keys(filename)

sleep(10)



dropmenu=browser.find_element(by=By.XPATH, value='/html/body/section[3]/section[3]/section/form/div[2]/i')
dropmenu.click()

sleep(10)
launch=browser.find_element(by=By.XPATH, value='/html/body/section[3]/section[3]/section/form/div[2]/ul/li')
launch.click()
sleep(10)

browser.close()
