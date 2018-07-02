# _*_ coding: utf-8 _*_
__author__ = 'zhj'
__date__ = '2018/3/15 17:05'

from datetime import datetime
from app import db

def to_json(inst, cls):
    """
    Jsonify the sql alchemy query result.
    """
    convert = dict()
    # add your coversions for things like datetime's 
    # and what-not that aren't serializable.
    d = dict()
    for c in cls.__table__.columns:
        v = getattr(inst, c.name)
        if c.type in convert.keys() and v is not None:
            try:
                d[c.name] = convert[c.type](v)
            except:
                d[c.name] = "Error:  Failed to covert using ", str(convert[c.type])
        elif v is None:
            d[c.name] = str()
        else:
            d[c.name] = v
    return json.dumps(d)
# 会员数据模型
class User(db.Model):
    __tablename__ = "user"
    __table_args__ = {"useexisting": True}
    id = db.Column(db.Integer, primary_key=True)  # 编号
    name = db.Column(db.String(100), unique=True)  # 昵称
    pwd = db.Column(db.String(100))  # 密码
    email = db.Column(db.String(100), unique=True)  # 邮箱
    phone = db.Column(db.String(11), unique=True)  # 手机号
    info = db.Column(db.Text)  # 个性简介
    face = db.Column(db.String(255), unique=True)  # 头像
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 注册时间
    uuid = db.Column(db.String(255), unique=True)  # 唯一标识符
    # （下面是设置外键的第二步,指向Userlog模型，进行一个互相关系的绑定）
    userlogs = db.relationship('Userlog', backref='user')  # 会员日志外键关系关联
    housecols = db.relationship('Housecol', backref='user')  # 收藏外键关系关联

    def __repr__(self):
        return '<User %r>' % self.name

    def check_pwd(self, pwd):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.pwd, pwd)


# 会员登录日志
class Userlog(db.Model):
    __tablename__ = "userlog"
    __table_args__ = {"useexisting": True}
    id = db.Column(db.Integer, primary_key=True)  # 编号
    # （下面是设置外键的第一步）:指向user表的id字段
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # 所属会员
    ip = db.Column(db.String(100))  # ip地址
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 登录时间

    def __repr__(self):
        return '<User %r>' % self.id



# 房源
class House(db.Model):
    __tablename__ = "house"
    __table_args__ = {"useexisting": True}
    id = db.Column(db.Integer, primary_key=True)  # 编号
    title = db.Column(db.Text)  # 名称
    location = db.Column(db.Text)  # 地址
    money = db.Column(db.String(20)) # 价格
    url = db.Column(db.String(255), unique=True)  # url
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间
    #  （设置外键第一步）
    housecols = db.relationship("Housecol", backref='house')  # 收藏外键关系关联

    def __repr__(self):
        return "{location:%r,money:%r,title:%r}" %(self.location,self.money,self.title)


# 房源收藏
class Housecol(db.Model):
    __tablename__ = "moviecol"
    __table_args__ = {"useexisting": True}
    id = db.Column(db.Integer, primary_key=True)  # 编号
    # 关联外键第一步，还要去user表和movie表进行第二步
    house_id = db.Column(db.Integer, db.ForeignKey('house.id'))  # 所属电影
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))  # 所属用户
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间

    def __repr__(self):
        return "<House col %r>" % self.id


# 权限
class Auth(db.Model):
    __tablename__ = "auth"
    __table_args__ = {"useexisting": True}
    id = db.Column(db.Integer, primary_key=True)  # 编号
    name = db.Column(db.String(100), unique=True)  # 名称
    url = db.Column(db.String(255), unique=True)  # 地址
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间

    def __repr__(self):
        return "<Auth %r>" % self.name


# 角色
class Role(db.Model):
    __tablename__ = "role"
    __table_args__ = {"useexisting": True}
    id = db.Column(db.Integer, primary_key=True)  # 编号
    name = db.Column(db.String(100), unique=True)  # 名称
    auths = db.Column(db.String(600))  # 角色权限列表
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间
    admins = db.relationship("Admin", backref='role')  # 管理员外键关系关联

    def __repr__(self):
        return "<Role %r>" % self.name


# 管理员
class Admin(db.Model):
    __tablename__ = "admin"
    __table_args__ = {"useexisting": True}
    id = db.Column(db.Integer, primary_key=True)  # 编号
    name = db.Column(db.String(100), unique=True)  # 管理员账号
    pwd = db.Column(db.String(100))  # 管理员密码
    is_super = db.Column(db.SmallInteger)  # 是否为超级管理员，0为超级管理员
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))  # 所属角色
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 添加时间
    adminlogs = db.relationship("Adminlog", backref='admin')  # 管理员登录日志外键关系关联
    oplogs = db.relationship("Oplog", backref='admin')  # 管理员操作日志外键关系关联

    def __repr__(self):
        return "<Admin %r>" % self.name

    def check_pwd(self, pwd):
        from werkzeug.security import check_password_hash
        return check_password_hash(self.pwd, pwd)


# 管理员登录日志
class Adminlog(db.Model):
    __tablename__ = "adminlog"
    __table_args__ = {"useexisting": True}
    id = db.Column(db.Integer, primary_key=True)  # 编号
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))  # 所属管理员
    ip = db.Column(db.String(100))  # 登录IP
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 登录时间

    def __repr__(self):
        return "<Adminlog %r>" % self.id


# 操作日志
class Oplog(db.Model):
    __tablename__ = "oplog"
    __table_args__ = {"useexisting": True}
    id = db.Column(db.Integer, primary_key=True)  # 编号
    admin_id = db.Column(db.Integer, db.ForeignKey('admin.id'))  # 所属管理员
    ip = db.Column(db.String(100))  # 操作IP
    reason = db.Column(db.String(600))  # 操作原因
    addtime = db.Column(db.DateTime, index=True, default=datetime.now)  # 登录时间

    def __repr__(self):
        return "<Oplog %r>" % self.id

if __name__ == "__main__":
    db.create_all()

    # 测试数据的插入

    role = Role(
        name="超级管理员",
        auths=""
    )
    db.session.add(role)
    db.session.commit()
    from werkzeug.security import generate_password_hash
    
    admin = Admin(
        name="admin",
        pwd=generate_password_hash("123456"),
        is_super=0,
        role_id=1
    )
    db.session.add(admin)
    db.session.commit()


