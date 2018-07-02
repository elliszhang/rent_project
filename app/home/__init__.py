# _*_ coding: utf-8 _*_
__author__ = 'zhj'
__date__ = '2018/3/18 17:06'

from flask import Blueprint

home = Blueprint("home", __name__)

import app.home.views