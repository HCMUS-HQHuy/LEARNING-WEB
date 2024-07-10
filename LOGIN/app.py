from flask import Flask, render_template, url_for, redirect
from flask_sqlalchemy import SQLAlchemy   
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Length, ValidationError, Email
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisissecretkey'
db = SQLAlchemy(app)
bcript = Bcrypt(app)
    

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Username"})
    email = EmailField('Email', validators=[DataRequired(), Email(), Length(max=80)], render_kw={"placeholder": "Email"})    
    password = PasswordField('Password', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Password"})
    repassword = PasswordField('Re-Password', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Confirm Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

    def validate_email(self, email):
        email = User.query.filter_by(email=email.data).first()
        if email:
            raise ValidationError('That email is taken. Please choose a different one.')

    def validate_password(self, password):
        password = self.password.data
        repassword = self.repassword.data
        if password != repassword:
            raise ValidationError('Password and Confirm Password must be same.')

class Login(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email(), Length(max=80)], render_kw={"placeholder": "Email"})    
    password = PasswordField('Password', validators=[DataRequired(), Length(min=2, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField('Login')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if not user:
            raise ValidationError('There is no account with that email. You must register first.')

    def validate_password(self, password):
        user = User.query.filter_by(email=self.email.data).first()
        if user:
            if not bcript.check_password_hash(user.password, password.data):
                raise ValidationError('Password is incorrect.')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()
    if form.validate_on_submit():
        return redirect(url_for('home'))
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcript.generate_password_hash(form.password.data)
        user = User(username=form.username.data, email= form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)