from flask import Flask, render_template, redirect, url_for, request, flash,abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.mysql import VARCHAR
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import Integer, String, Text
from flask_ckeditor import CKEditor
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
import os
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, UserMixin, logout_user, current_user
from functools import wraps
import hashlib
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

load_dotenv()


MY_EMAIL=os.environ['MYUSER']
MY_PAASWORD=os.environ['PASS']

app = Flask(__name__)
ckeditor = CKEditor(app)
app.config['SECRET_KEY'] = os.environ['KEY']
app.config['CKEDITOR_PKG_TYPE'] = 'standard'



login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)



#admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.is_authenticated and current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

#Gravatar
@app.template_filter("gravatar")
def gravatar(email, size=100):
    email_hash = hashlib.md5(email.lower().encode('utf-8')).hexdigest()
    return f"https://www.gravatar.com/avatar/{email_hash}?s={size}&d=identicon"

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///posts.db")
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE USER TABLE
class User(UserMixin,db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(VARCHAR(250), unique=True)
    password: Mapped[str] = mapped_column(VARCHAR(250), nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)

    posts = relationship("BlogPost", back_populates="author")

    comments = relationship("Comment", back_populates="comment_author")

# CONFIGURE POST TABLE
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")

    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post" ,cascade="all, delete-orphan")


#COMMENT TABLE
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(Text, nullable=False)

    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")

    post_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    parent_post = relationship("BlogPost", back_populates="comments")



with app.app_context():
    db.create_all()


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register',methods=["GET","POST"])
def register():
    form=RegisterForm()
    if form.validate_on_submit():
        user=db.session.execute(db.select(User).where(User.email==form.email.data)).scalar()
        if user:
            flash("Email already registered !")
            return redirect(url_for('login'))
        new_password=generate_password_hash(password=form.password.data,method="pbkdf2:sha256",salt_length=8)
        new_user=User(email=form.email.data,password=new_password,name=form.name.data)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html",form=form)


# TODO: Retrieve a user from the database based on their email.
@app.route('/login',methods=["GET","POST"])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        email=form.email.data
        user=db.session.execute(db.select(User).where(User.email == email)).scalar()
        if not user:
            flash("Email Doesn't Exist ! Register now")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, form.password.data):
            flash("Wrong Password !")
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html",form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))



@app.route('/')
def get_all_posts():
    result=db.session.execute(db.select(BlogPost))
    all_posts=result.scalars().all()
    return render_template("index.html", all_posts=all_posts)

# TODO: Use a decorator so only an admin user can create a new post
@app.route("/add-post",methods=["GET","POST"])
@admin_only
def make_post():
    form=CreatePostForm()
    if form.validate_on_submit():
        new_post=BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            img_url=form.img_url.data,
            body=form.body.data,
            date=datetime.now().strftime("%B %d, %Y"),
            author_id=current_user.id
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('get_all_posts'))
    return render_template("make-post.html",form=form, is_edit=False)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:index>",methods=["GET","POST"])
@admin_only
def edit_post(index):
    post = db.get_or_404(BlogPost, index)
    edit_form = CreatePostForm(
        title= post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        body=post.body,
    )
    if edit_form.validate_on_submit():
        post.title=edit_form.title.data
        post.subtitle=edit_form.subtitle.data
        post.img_url=edit_form.img_url.data
        post.body=edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", index=post.id))
    return render_template("make-post.html",form=edit_form, is_edit=True,  post=post)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact",methods=["GET","POST"])
def contact():
    if request.method == "POST":
        #Extracting Data
        name=request.form["name"]
        email=request.form["email"]
        phone=request.form["phone"]
        msg=request.form["message"]

        #Writing MSg
        content=f"Name: {name}\nEmail: {email}\nPhone: {phone}\nMessage: {msg}"
        person=os.environ["PERSON"]

        #Sending Message
        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(MY_EMAIL, MY_PAASWORD)
            msg = MIMEText(content, _charset="utf-8")
            msg['Subject'] = "Success !"
            msg['From'] = MY_EMAIL
            msg['To'] = person
            connection.sendmail(from_addr=MY_EMAIL, to_addrs=person, msg=msg.as_string())

        return render_template("contact.html",success=True)
    else:
        return render_template("contact.html",success=False)

# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:index>")
@admin_only
def delete_post(index):
    post_to_delete = db.get_or_404(BlogPost, index)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for("get_all_posts"))


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:index>", methods=["GET", "POST"])
def show_post(index):
    post=db.get_or_404(BlogPost,index)
    comment_form = CommentForm()
    if comment_form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))

        new_comment = Comment(
            text=comment_form.comment_text.data,
            comment_author=current_user,
            parent_post=post
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", index=post.id))
    return render_template("post.html", post=post,form=comment_form)



if __name__ == "__main__":
    app.run(debug=False)
