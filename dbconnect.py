import MySQLdb


def connection():
	conn = MySQLdb.connect(host='localhost', user='root', passwd='xxxxx', db='pass_vault')
	c = conn.cursor()
	return c, conn