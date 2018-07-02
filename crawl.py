#-*- coding:utf-8 -*-
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import requests
import pymysql

url = "http://xa.58.com/pinpaigongyu/pn/{page}"
db=pymysql.connect(host="localhost",user="root",password="83438023",db="rent",port=3306,charset="utf8")
cur = db.cursor()

#已完成的页数序号，初时为0
page = 0

while True:
    page += 1
    print("fetch: ", url.format(page=page))
    response = requests.get(url.format(page=page))
    html = BeautifulSoup(response.text, "lxml")
    house_list = html.select(".list > li")

    # 循环在读不到新的房源时结束
    if not house_list:
        break

    for house in house_list:
        house_title = house.select("h2")[0].string
        house_url = urljoin(url, house.select("a")[0]["href"])
        house_info_list = house_title.split()

        # 如果第二列是公寓名则取第一列作为地址
        if "公寓" in house_info_list[1] or "青年社区" in house_info_list[1]:
            house_location = house_info_list[0]
        else:
            house_location = house_info_list[1]

        house_money = house.select(".money")[0].select("b")[0].string
        
        cur.execute("INSERT INTO house(title,location,money,url)VALUES('{0}','{1}','{2}','{3}');".format(house_title,house_location,house_money,house_url))        
        db.commit()  

db.close()  
