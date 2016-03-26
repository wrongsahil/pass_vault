from flask import Flask, url_for, render_template, request, flash, redirect, session
from wtforms import Form, validators, TextField, PasswordField, BooleanField
from passlib.hash import sha256_crypt
from dbconnect import connection
from MySQLdb import escape_string as thwart
import gc

app = Flask(__name__)
app.secret_key = "hello"


@app.route('/')
def index():
	return render_template("index.html")


class RegisterationForm(Form):
	username = TextField("Username", [validators.Required(), validators.Length(min=5, max=50)])
	email = TextField("Email", [validators.Required(), validators.Length(min=5, max=50)])
	password = PasswordField("Password", [validators.EqualTo('confirm', message='Both passwords must match'), validators.Required(), validators.Length(min=8, max=20)])
	confirm = PasswordField("Confirm Password")
	accept_tc = BooleanField("Accept <a href='#'>Terms and Conditions</a>", [validators.Required()])


@app.route('/register/', methods=['GET', 'POST'])
def register():

	form = RegisterationForm(request.form)
	error = ""

	try:
		if request.method == 'POST' and form.validate():
			username = form.username.data
			email = form.email.data
			password = sha256_crypt.encrypt(str(form.password.data))
			c, conn = connection()

			x = c.execute("SELECT * FROM data WHERE username = (%s)", thwart(username))

			if int(x) > 0:
				error = "Username already exist"
				return render_template('register.html', error=error, form=form)

			else:
				email_x = c.execute("SELECT * FROM data WHERE email = (%s)", thwart(email))
				if int(email_x) > 0:
					error = "Email already occupied"
					return render_template('register.html', error=error, form=form)

				else:
					c.execute("INSERT INTO data (username, email, password) VALUES (%s, %s, %s)", (thwart(username), thwart(email), thwart(password)))
					conn.commit()
					session['logged_in'] = True
					session['username'] = username
					c.close()
					conn.close()
					gc.collect()

					flash("Successfully Registered")
					return redirect(url_for('index'))

		return render_template('register.html', error=error, form=form)

	except Exception as e:
		error = str(e)
		return render_template('register.html', error=error, form=form)

@app.route('/login/', methods=['GET', 'POST'])
def login():
	try:
		pass
	except Exception as e:
		error = str(e)
		return render_template('login.html', error=error)

if __name__ == '__main__':
	app.run(debug=True)