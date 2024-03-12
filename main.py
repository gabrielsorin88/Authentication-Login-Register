from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

#config Flask_login
login_manager = LoginManager()
login_manager.init_app(app)

# CREATE DATABASE
class Base(DeclarativeBase):
    pass

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    #UserMixin gives methods like: is_authenticated(),is_active(),is_anonymous(),get_id()
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), unique=True)
    password: Mapped[str] = mapped_column(String(100))
    name: Mapped[str] = mapped_column(String(1000))

# Create a user_loader callback

with app.app_context():
    db.create_all()

#generate_password_hash()

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        user = User.query.filter_by(email = request.form.get('email') ).first()
        if user :
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        else:
            # hashing users password
            plain_text_pw = request.form.get('password')
            hash_password = generate_password_hash(plain_text_pw, method='pbkdf2:sha256', salt_length=8)
            new_user = User(
                email= request.form.get('email'),
                name=request.form.get('name'),
                password = hash_password
            )
            db.session.add(new_user)
            db.session.commit()
            # Log in and authenticate user after adding details to database.
            # also sets the current_user of the session/UserMixin inheritance
            login_user(new_user)

        return render_template('secrets.html')
    return render_template("register.html")



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

    #     find user by email:

        user = User.query.filter_by(email=email).first()
        # Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password): # provided by UserMixin
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user) #also sets the current_user of the session/UserMixin inheritance
            return redirect(url_for('secrets'))

    return render_template("login.html")

# Only logged-in users can access the route prov by UserMixin
@app.route('/secrets')
@login_required  #UserMixin
def secrets():
    return render_template("secrets.html", name = current_user.name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))



@app.route('/download')
@login_required  #UserMixin
def download():
    return send_from_directory(directory='static', path="files/cheat_sheet.pdf" )
    #the directory should be relative to the rooth path
    #the path should be relative to the directory
    #if you want to just downloadit as an attachment tou can use the arg: as_attachment=True,  after the path


if __name__ == "__main__":
    app.run(debug=True)
