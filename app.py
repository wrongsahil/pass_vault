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
					c.execute("CREATE TABLE "+ str(username) +" (uid INT(11) AUTO_INCREMENT PRIMARY KEY, title VARCHAR(50), username VARCHAR(50), password VARCHAR(50))")
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


@app.route('/logout/')
def logout():
	session.clear()
	flash("Successfully logged out")
	return redirect(url_for("index"))


@app.route('/login/', methods=['GET', 'POST'])
def login():
	error = ""
	try:
		if request.method == 'POST':
			c, conn = connection()

			data = c.execute("SELECT * FROM data WHERE username = (%s)", thwart(request.form['username']))
			data = c.fetchone()[3]

			if sha256_crypt.verify(str(request.form['password']), str(data)):
				session['logged_in'] = True
				session['username'] = request.form['username']
				c.close()
				conn.close()
				gc.collect()
				flash('Logged in Successfully')
				return redirect(url_for('index'))

			else:
				error = "Invalid Credentials"
				return render_template("login.html", error=error)

		return render_template("login.html", error=error)

	except Exception as e:
		error = "Invalid Credentials" #str(e)
		return render_template('login.html', error=error)


@app.route('/show_vault/')
def show_vault():

	if 'logged_in' in session:
		c, conn = connection()
		vault_data = c.execute("SELECT * FROM "+ session['username'])
		vault_data = c.fetchall()
		#print str(vault_data)
		#return redirect(url_for('index'))
		return render_template('show_vault.html', vault_data=vault_data)

	else:
		flash("You need to login first to see the vault data")
		return redirect(url_for('login'))


class vaultForm(Form):
	title = TextField('Title', [validators.Required(), validators.Length(min=5, max=50)])
	username = TextField('Username to be stored', [validators.Required(), validators.Length(min=5, max=50)])
	password = PasswordField("Password to be stored", [validators.Required(), validators.Length(min=5, max=50)])


@app.route('/enter_vault/', methods=['POST', 'GET'])
def enter_vault():
	error = ""

	if 'logged_in' in session:
		form = vaultForm(request.form)

		if request.method == 'POST' and form.validate():
			title = form.title.data
			username = form.username.data
			password = form.password.data

			c, conn = connection()

			c.execute("INSERT INTO "+ str(session['username']) + " (title, username, password) VALUES (%s, %s, %s)", (thwart(title), thwart(username), thwart(password)))
			conn.commit()
			c.close()
			conn.close()
			gc.collect()
			flash("Data Entered Succesfully")
			#return redirect(url_for('index'))
			return redirect(url_for('show_vault'))

		else:
			error = "Fill out all details"
			return render_template('enter_vault.html', error=error, form=form)

	else:
		flash("You need to login first")
		return redirect(url_for('login'))


if __name__ == '__main__':
	app.run(debug=True)