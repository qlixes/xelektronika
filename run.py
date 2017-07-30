from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import jwt
from functools import wraps

import config

app = Flask(__name__)
app.config.from_object(config)

#sslify = SSLify(app)

db = SQLAlchemy(app)
#engine = db.engine

from models import *

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        
        token = None

        if 'x-token-access' in request.headers: #llooping
            token = request.headers['x-token-access']
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'])

                current_user = userid.query.filter_by(nomor = data['id']).first()
            except:
                
                return jsonify({'message' : 'token invalid.'}), 401
        else:
            return jsonify({'message' : 'token is missing'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

def verify(username, password):

    user = vdivisiuserid01.query.filter_by(useridkode=username).first()

    if user:

        phash = generate_password_hash(user.psw)

        if check_password_hash(phash, password):
            #payload
            token = jwt.encode({'id' : user.nomor, 'nama': user.nama, 'lokasi': user.lokasi, 'divisi': user.divisinomor, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=10), 'iss': 'klikmediasoft'}, app.config['SECRET_KEY'])

            return jsonify({'token': token.decode('UTF-8')})

        else:
            return jsonify({'message': 'user and password did not match.'}), 401

    else:
        return jsonify({'message': 'login is empty.'}), 401

@app.route('/login', methods=['POST'])
def set_login():

    data = request.json

    #if not data or not data['username'] or not data['password']:
    #    return jsonify({'message' : 'invalid credentials.'})
    if data and data['username'] and data['password']:
        return verify(data['username'], data['password'])
    else:
        return jsonify({'message' : 'login was empty'}), 401
    #    return verify(data['username'], data['password'])

@app.route('/lokasi')
@app.route('/lokasi/<int:detail>')
@token_required
def get_lokasi(current_user, detail = None):

    if detail:
        lokasi = vpublokasi.query.filter_by(lokasi=detail).all()
    else:
        lokasi = vpublokasi.query.all()

    dLokasi = []

    for vlokasi in lokasi:
        rLokasi = {}

        rLokasi['lokasi'] = vlokasi.lokasi
        rLokasi['nama'] = vlokasi.nama

        if detail:
            rLokasi['nama2'] = vlokasi.nama2
            rLokasi['alamat'] = vlokasi.alamat
            rLokasi['telp'] = vlokasi.telp
            rLokasi['kota'] = vlokasi.kota
            #rLokasi['ket1'] = vlokasi.ket1
            #rLokasi['ket2'] = vlokasi.ket2

        dLokasi.append(rLokasi)

    return jsonify({'result':dLokasi})

@app.route('/<transac>/', defaults={'page':1})
@app.route('/<transac>/<int:page>')
@token_required
def get_list_transaction(current_user, transac,page):

    noBukti = request.args.get('inv', None)
    with_detail = request.args.get('detail', None,type=int)
    start_date = request.args.get('start', None)
    end_date = request.args.get('end', None)
    bayar = request.args.get('bayar', None, type=int)
    lokasi = request.args.get('lokasi', -1, type=int)

    jTransaksi = trmst[transac]

    if lokasi >=0 and lokasi <=9:
        vTransaksi = jTransaksi+'0%r' % lokasi
    elif lokasi >=10 and lokasi <=99:
        vTransaksi = jTransaksi+'%r' % lokasi
    else:
        vTransaksi = jTransaksi+'%'

    #if noBukti is not None:
    if noBukti:
        datatrmst02 = vpubtrmst02.query.filter(vpubtrmst02.transaksi.like(vTransaksi), vpubtrmst02.nobukti == noBukti).paginate(page, app.config['PAGING_ROW'], app.config['SHOW_PAGING_ERROR']) #.items
    #elif start_date is not None and end_date is not None:
    elif start_date and end_date:
        datatrmst02 = vpubtrmst02.query.filter(vpubtrmst02.transaksi.like(vTransaksi), vpubtrmst02.tgl.between(start_date, end_date)).paginate(page, app.config['PAGING_ROW'], app.config['SHOW_PAGING_ERROR'])
    else:
        datatrmst02 = vpubtrmst02.query.filter(vpubtrmst02.transaksi.like(vTransaksi)).paginate(page, app.config['PAGING_ROW'], app.config['SHOW_PAGING_ERROR'])

    output_trmst = [] #list
    output_trdet = []

    if datatrmst02.has_next:
        for trmst02 in datatrmst02.items:

            row_data = {} #dict
            # disabled with comment for unused field

            row_data['nomor'] = trmst02.nomor
            row_data['transaksi'] = trmst02.transaksi
            row_data['nobukti'] = trmst02.nobukti
            row_data['tgl'] = trmst02.tgl
            row_data['login'] = trmst02.login
            row_data['status'] = trmst02.status

            row_data['discpersen0'] = trmst02.discpersen0
            row_data['discrp0'] = trmst02.discrp0
            row_data['discpersen1'] = trmst02.discpersen1
            row_data['discrp1'] = trmst02.discrp1
            row_data['ppnpersen'] = trmst02.ppnpersen
            row_data['ppnrp'] = trmst02.ppnrp
            row_data['biayarp0'] = trmst02.biayarp0
            row_data['biayarp1'] = trmst02.biayarp1
            row_data['totalbruto'] = trmst02.totalbruto
            row_data['totaldisc'] = trmst02.totaldisc
            row_data['totalppn'] = trmst02.totalppn
            row_data['totalnetto'] = trmst02.totalnetto
            row_data['nama'] = trmst02.nama
            row_data['alamat'] = trmst02.alamat
            row_data['telp'] = trmst02.telp
            row_data['keterangan'] = trmst02.keterangan
            row_data['tglkirim'] = trmst02.tglkirim
            #row_data['tgljatuhtempo'] = trmst02.tgljatuhtempo
            #row_data['tglinvoice'] = trmst02.tglinvoice
            #row_data['ketnosuratjalan'] = trmst02.ketnosuratjalan
            #row_data['ketnobukti'] = trmst02.ketnobukti
            #row_data['ketket1'] = trmst02.ketket1
            #row_data['ketket2'] = trmst02.ketket2

            if with_detail is 1:

                #datatrdet06 = vpubtrdet06.query.filter_by(nomortrmst=trmst02.nomor).all()

                trdet06_data = {}

                datatrdet04 = vpubtrdet04.query.filter_by(nomortrmst=trmst02.nomor).all()

                for trdet04 in datatrdet04:

                    datatrdet06 = vpubtrdet06.query.filter_by(nomor=trdet04.nomor).first()

                    trdet06_data['kodestok'] = datatrdet06.kodestok
                    trdet06_data['kodestok'] = datatrdet06.namastok

                    trdet06_data['banyaknya'] = trdet04.banyaknya
                    trdet06_data['satuan'] = trdet04.satuan
                    trdet06_data['harga'] = trdet04.harga
                    trdet06_data['discpersen0'] = trdet04.discpersen0
                    trdet06_data['discrp0'] = trdet04.discrp0
                    trdet06_data['discpersen1'] = trdet04.discpersen1
                    trdet06_data['discrp1'] = trdet04.discrp1
                    trdet06_data['ppnpersen'] = trdet04.ppnpersen
                    trdet06_data['ppnrp'] = trdet04.ppnrp
                    trdet06_data['hpp'] = trdet04.hpp
                    trdet06_data['totalhpp'] = trdet04.totalhpp
                    trdet06_data['totalbruto'] = trdet04.totalbruto
                    trdet06_data['harganetto'] = trdet04.harganetto
                    trdet06_data['totalnetto'] = trdet04.totalnetto

                    output_trdet.append(trdet06_data)

                row_data['trdet06'] = output_trdet

            if bayar is 1:

                databayardet02 = vbayardet02.query.filter_by(nomortrmst=trmst02.nomor).first()

                if databayardet02:
                    #row_data['bayar'] = format(databayardet02.nilai, '.1f')
                    row_data['bayar'] = databayardet02.nilai
                else:
                    #row_data['bayar'] = format(0, '.1f')
                    row_data['bayar'] = 0.0

            output_trmst.append(row_data)

    return jsonify({'result':output_trmst})

@app.route('/stok', defaults={'thn' : '2017'}) #show all stok
@app.route('/stok/<int:thn>')
def get_stok(thn):
    return ''

#context = SSL.Context(SSL.TLSv1_2_METHOD)
#context.use_privatekey('client03.key')
#context.use_certificate_file('client03.crt')

if __name__ == '__main__':
    app.run(debug=True)
    #app.run(host=,port=,debug=,ssl_context=context, Threaded=True)