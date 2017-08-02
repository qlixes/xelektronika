import models
#from models import *
from functools import wraps
import jwt
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

now = datetime.datetime.now()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        
        token = None

        if 'x-token-access' in request.headers: #llooping
            token = request.headers['x-token-access']
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'])

                current_user = models.userid.query.filter_by(nomor = data['id']).first()
            except:
                
                return jsonify({'status': False, 'message' : 'token invalid.'}), 401
        else:
            return jsonify({'status': False, 'message' : 'token is missing'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

def verify(username, password):

    user = models.userid.query.filter_by(kode=username).first()

    if user:

        phash = generate_password_hash(user.psw)

        divisi = models.divisiuserid.query.filter_by(nomoruserid=user.nomor).first()       

        if check_password_hash(phash, password):
            #payload
            token = jwt.encode({'id' : user.nomor, 'uuid' : user.lokasi, 'guid' : divisi.nomordivisi, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=10), 'iss': 'klikmediasoft'}, app.config['SECRET_KEY'])

            return jsonify({'status': True, 'token': token.decode('UTF-8')})

        else:
            return jsonify({'status': False, 'message': 'invalid credentials'}), 401

    else:
        return jsonify({'status': False, 'message': 'login is empty.'}), 401