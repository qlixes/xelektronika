from configparser import ConfigParser
import os

config = ConfigParser()

basedir = os.path.dirname(__file__)

config.read(os.path.join(basedir, 'config.ini'))

SECRET_KEY = '#tf=35$uhu+40e4oqqm8ki4^288$u2uq95pf97zn_l6x=3=t+#'

SQLALCHEMY_DATABASE_URI = config.get('inv03','databaseuri')
#SQLALCHEMY_DATABASE_URI = 'firebird+fdb://PROGRAMER:programer@localhost:3050/c:/database/inv03/database/datainv03.fdb'
SQLALCHEMY_COMMIT_ON_TEARDOWN = True
DEBUG = True #change into False for production
SQLALCHEMY_ECHO = True
SQLALCHEMY_TRACK_MODIFICATIONS = False

#PAGING_ROW = 10
#SHOW_PAGING_ERROR = False

PAGING_ROW = config.getint('inv03','paging')
SHOW_PAGING_ERROR = False