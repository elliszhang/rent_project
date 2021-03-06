# _*_ coding: utf-8 _*_
import datetime
import json
from functools import wraps

import os
from werkzeug.utils import secure_filename

__author__ = 'zhj'
__date__ = '2018/3/15 17:07'

import uuid
from werkzeug.security import generate_password_hash
from app import db, app, rd
from app.home.forms import RegistForm, LoginForm, UserdetailForm, PwdForm, HouseForm
from app.models import User, Userlog, House, Housecol
from . import home
from flask import render_template, url_for, redirect, flash, session, request, Response, jsonify

def change_filename(filename):
    """
    修改文件名称
    """
    fileinfo = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + \
               str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


def user_login_req(f):
    """
    登录装饰器
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("home.login", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


@home.route("/login/", methods=["GET", "POST"])
def login():
    """
    登录
    """
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(name=data["name"]).first()
        if user:
            if not user.check_pwd(data["pwd"]):
                flash("密码错误！", "err")
                return redirect(url_for("home.login"))
        else:
            flash("账户不存在！", "err")
            return redirect(url_for("home.login"))
        session["user"] = user.name
        session["user_id"] = user.id
        userlog = Userlog(
            user_id=user.id,
            ip=request.remote_addr
        )
        db.session.add(userlog)
        db.session.commit()
        return redirect(url_for("home.user"))
    return render_template("home/login.html", form=form)


@home.route("/logout/")
def logout():
    """
    退出登录
    """
    # 重定向到home模块下的登录。
    session.pop("user", None)
    session.pop("user_id", None)
    return redirect(url_for('home.login'))


@home.route("/register/", methods=["GET", "POST"])
def register():
    """
    会员注册
    """
    form = RegistForm()
    if form.validate_on_submit():
        data = form.data
        user = User(
            name=data["name"],
            email=data["email"],
            phone=data["phone"],
            pwd=generate_password_hash(data["pwd"]),
            uuid=uuid.uuid4().hex
        )
        db.session.add(user)
        db.session.commit()
        flash("注册成功！", "ok")
    return render_template("home/register.html", form=form)

@home.route("/house/", methods=["GET", "POST"])
@user_login_req
def house():
    form = HouseForm()
    houses_count=House.query.count()
    houses=House.query.all()
    return render_template("home/house.html", total=houses_count,houses=houses,form=form)

@home.route("/user/", methods=["GET", "POST"])
@user_login_req
def user():
    form = UserdetailForm()
    user = User.query.get(int(session["user_id"]))
    form.face.validators = []
    if request.method == "GET":
        # 赋初值
        form.name.data = user.name
        form.email.data = user.email
        form.phone.data = user.phone
        form.info.data = user.info
    if form.validate_on_submit():
        data = form.data
        if form.face.data != "":
            file_face = secure_filename(form.face.data.filename)
            if not os.path.exists(app.config["FC_DIR"]):
                os.makedirs(app.config["FC_DIR"])
                os.chmod(app.config["FC_DIR"])
            user.face = change_filename(file_face)
            form.face.data.save(app.config["FC_DIR"] + user.face)

        name_count = User.query.filter_by(name=data["name"]).count()
        if data["name"] != user.name and name_count == 1:
            flash("昵称已经存在!", "err")
            return redirect(url_for("home.user"))

        email_count = User.query.filter_by(email=data["email"]).count()
        if data["email"] != user.email and email_count == 1:
            flash("邮箱已经存在!", "err")
            return redirect(url_for("home.user"))

        phone_count = User.query.filter_by(phone=data["phone"]).count()
        if data["phone"] != user.phone and phone_count == 1:
            flash("手机已经存在!", "err")
            return redirect(url_for("home.user"))

        # 保存
        user.name = data["name"]
        user.email = data["email"]
        user.phone = data["phone"]
        user.info = data["info"]
        db.session.add(user)
        db.session.commit()
        flash("修改成功!", "ok")
        return redirect(url_for("home.user"))
    return render_template("home/user.html", form=form, user=user)


@home.route("/pwd/", methods=["GET", "POST"])
@user_login_req
def pwd():
    """
    修改密码
    """
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        user = User.query.filter_by(name=session["user"]).first()
        if not user.check_pwd(data["old_pwd"]):
            flash("旧密码错误！", "err")
            return redirect(url_for('home.pwd'))
        user.pwd = generate_password_hash(data["new_pwd"])
        db.session.add(user)
        db.session.commit()
        flash("修改密码成功，请重新登录！", "ok")
        return redirect(url_for('home.logout'))
    return render_template("home/pwd.html", form=form)



@home.route("/loginlog/<int:page>/", methods=["GET"])
@user_login_req
def loginlog(page=None):
    """
    会员登录日志
    """
    if page is None:
        page = 1
    page_data = Userlog.query.filter_by(
        user_id=int(session["user_id"])
    ).order_by(
        Userlog.addtime.desc()
    ).paginate(page=page, per_page=2)
    return render_template("home/loginlog.html", page_data=page_data)


@home.route("/housecol/add/", methods=["GET"])
@user_login_req
def housecol_add():
    """
    添加房源收藏
    """
    uid = request.args.get("uid", "")
    mid = request.args.get("mid", "")
    housecol = Housecol.query.filter_by(
        user_id=int(uid),
        house_id=int(mid)
    ).count()
    # 已收藏
    if housecol == 1:
        data = dict(ok=0)
    # 未收藏进行收藏
    if housecol == 0:
        housecol = Housecol(
            user_id=int(uid),
            house_id=int(mid)
        )
        db.session.add(housecol)
        db.session.commit()
        data = dict(ok=1)
    import json
    return json.dumps(data)


@home.route("/housecol/<int:page>/")
@user_login_req
def housecol(page=None):
    """
    房源收藏
    """
    if page is None:
        page = 1
    page_data = Housecol.query.join(
        House
    ).join(
        User
    ).filter(
        House.id == Housecol.house_id,
        User.id == session["user_id"]
    ).order_by(
        Housecol.addtime.desc()
    ).paginate(page=page, per_page=2)
    return render_template("home/housecol.html", page_data=page_data)


@home.route("/<int:page>/", methods=["GET"])
@home.route("/", methods=["GET"])
def index(page=None):
    return render_template("home/index.html")


@home.route("/search/<int:page>/")
def search(page=None):
    """
    搜索
    """
    if page is None:
        page = 1
    key = request.args.get("key", "")
    house_count = House.query.filter(
        House.title.ilike('%' + key + '%')
    ).count()
    page_data = House.query.filter(
        House.title.ilike('%' + key + '%')
    ).order_by(
        House.addtime.desc()
    ).paginate(page=page, per_page=10)
    page_data.key = key
    return render_template("home/search.html", house_count=house_count, key=key, page_data=page_data)

