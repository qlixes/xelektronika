from sqlalchemy.ext.declarative import declarative_base
from flask_sqlalchemy import SQLAlchemy
from run import db
import config

engine = db.create_engine(config.SQLALCHEMY_DATABASE_URI, convert_unicode = True)
db_session = db.scoped_session(db.sessionmaker(autocommit = False,
    autoflush = False, bind = engine))

db.Base = declarative_base()
db.Base.query = db_session.query_property()

# if has more transaction type must add manual
trmst = {
    "beli":"11" ,
    "returJual":"31" ,
    "mutasi":"51" ,
    "jual":"61" ,
    "returBeli":"71" ,
    "salesOrder":"81" ,
    "purchaseOrder":"82" ,
}




class vpublokasi(db.Model):

    __tablename__ = 'vpublokasi'

    lokasi = db.Column(db.Integer, primary_key=True)
    nama = db.Column(db.String(10), unique=True)
    nama2 = db.Column(db.String(250))
    alamat = db.Column(db.Text)
    telp = db.Column(db.Text)
    kota = db.Column(db.String(250))
    ket1 = db.Column(db.String(250))
    ket2 = db.Column(db.String(250))

class userid(db.Model):
    __tablename__ = 'userid'

    nomor = db.Column(db.Integer, primary_key=True)
    kode = db.Column(db.String(10), unique=True)
    nama = db.Column(db.String(30))
    psw = db.Column(db.String(50))
    lokasi = db.Column(db.Integer, db.ForeignKey('vpublokasi.lokasi'))
    vpublokasi = db.relationship('vpublokasi', uselist = True, lazy = 'dynamic')

class vpubph(db.Model):

    __tablename__ = 'vpubph'

    nomor = db.Column(db.Integer, primary_key=True)
    kode = db.Column(db.String(20), unique=True)
    jenis = db.Column(db.String(1))
    nama = db.Column(db.String(50))
    tampil = db.Column(db.SmallInteger)
    login = db.Column(db.Integer, db.ForeignKey('userid.kode'))
    tglisi = db.Column(db.DateTime)
    kunci = db.Column(db.SmallInteger)

class vpubtrmst02(db.Model):

    __tablename__ = 'vpubtrmst02'

    nomor = db.Column(db.Integer, primary_key=True)
    transaksi = db.Column(db.SmallInteger)
    nobukti = db.Column(db.String(20))
    tgl = db.Column(db.DateTime)
    login = db.Column(db.String(10), db.ForeignKey('userid.kode'))
    status = db.Column(db.String(1))
    nomorph = db.Column(db.Integer, db.ForeignKey('vpubph.nomor'))
    discpersen0 = db.Column(db.Float)
    discrp0 = db.Column(db.Float)
    discpersen1 = db.Column(db.Float)
    discrp1 = db.Column(db.Float)
    ppnpersen = db.Column(db.Float)
    ppnrp = db.Column(db.Float)
    biayarp0 = db.Column(db.Float)
    biayarp1 = db.Column(db.Float)
    totalbruto = db.Column(db.Float)
    totaldisc = db.Column(db.Float)
    totalppn = db.Column(db.Float)
    totalnetto = db.Column(db.Float)
    nama = db.Column(db.String(50))
    alamat = db.Column(db.Text)
    telp = db.Column(db.Text)
    keterangan = db.Column(db.Text)
    tglkirim = db.Column(db.DateTime)
    tgljatuhtempo = db.Column(db.DateTime)
    tglinvoice = db.Column(db.DateTime)
    ketnosuratjalan = db.Column(db.String(50))
    ketnobukti = db.Column(db.String(50))
    ketket1 = db.Column(db.String(255))
    ketket2 = db.Column(db.String(255))

class jenis0(db.Model):

    __tablename__ = 'jenis0'

    nomor = db.Column(db.Integer, primary_key=True)
    jenis0 = db.Column(db.String(20), unique=True)
    login = db.Column(db.String(10), db.ForeignKey('userid.kode'))
    tglisi = db.Column(db.DateTime)

class jenis1(db.Model):

    __tablename__ = 'jenis1'

    nomor = db.Column(db.Integer, primary_key=True)
    jenis1 = db.Column(db.String(20), unique=True)
    login = db.Column(db.String(10), db.ForeignKey('userid.kode'))
    tglisi = db.Column(db.DateTime)

class jenis2(db.Model):

    __tablename__ = 'jenis2'

    nomor = db.Column(db.Integer, primary_key=True)
    jenis2 = db.Column(db.String(20), unique=True)
    login = db.Column(db.String(10), db.ForeignKey('userid.kode'))
    tglisi = db.Column(db.DateTime)

class vjenisstok01(db.Model):

    __tablename__ = 'vjenisstok01'

    nomor = db.Column(db.Integer, primary_key=True)
    jenis0 = db.Column(db.String(20))
    jenis1 = db.Column(db.String(20))
    jenis2 = db.Column(db.String(20))

class stok(db.Model):

    __tablename__ = 'stok'

    nomor = db.Column(db.Integer, primary_key=True)
    kode = db.Column(db.String(30), unique=True)
    nama = db.Column(db.String(50))
    satuan0 = db.Column(db.String(5))
    satuan1 = db.Column(db.String(5))
    faktor = db.Column(db.Float)
    tampil = db.Column(db.SmallInteger)
    login = db.Column(db.String(10), db.ForeignKey('userid.kode'))
    tglisi = db.Column(db.DateTime)
    nomorjenisstok = db.Column(db.Integer, db.ForeignKey('vjenisstok01.nomor'))
    nomorlimitstok = db.Column(db.Integer) #unused
    nomordiscstok = db.Column(db.Integer) #unused

class vpubtrdet04(db.Model):

    __tablename__ = 'vpubtrdet04'

    nomor = db.Column(db.Integer, primary_key = True)
    nomortrmst = db.Column(db.Integer, db.ForeignKey('vpubtrmst02.nomor'))
    nomorstok = db.Column(db.Integer, db.ForeignKey('stok.nomor'))
    #kodestok = db.Column(db.String(30), db.ForeignKey('stok.kode'))
    #namastok = db.Column(db.String(50))
    banyaknya = db.Column(db.Float)
    satuan = db.Column(db.String(5))
    harga = db.Column(db.Float)
    banyaknya0 = db.Column(db.Float)
    satuan0 = db.Column(db.String(5))
    satuan1 = db.Column(db.String(5))
    faktor = db.Column(db.Float)
    discpersen0 = db.Column(db.Float)
    discrp0 = db.Column(db.Float)
    discpersen1 = db.Column(db.Float)
    discrp1 = db.Column(db.Float)
    ppnpersen = db.Column(db.Float)
    ppnrp = db.Column(db.Float)
    biayarp0 = db.Column(db.Float)
    biayarp1 = db.Column(db.Float)
    lokasi2 = db.Column(db.Integer, db.ForeignKey('vpublokasi.lokasi'))
    hpp = db.Column(db.Float)
    totalhpp = db.Column(db.Float)
    totalbruto = db.Column(db.Float)
    totaldisc0 = db.Column(db.Float)
    total0 = db.Column(db.Float)
    totaldisc1 = db.Column(db.Float)
    total1 = db.Column(db.Float)
    totaldisc = db.Column(db.Float)
    totalppn = db.Column(db.Float)
    total2 = db.Column(db.Float)
    totalnetto = db.Column(db.Float)
    harganetto = db.Column(db.Float)
    hargasatuannetto = db.Column(db.Float)

class vpubtrdet06(db.Model):

    __tablename__ = 'vpubtrdet06'

    nomor = db.Column(db.Integer, primary_key = True)
    nomortrmst = db.Column(db.Integer, db.ForeignKey('vpubtrmst02.nomor'))
    nomorstok = db.Column(db.Integer, db.ForeignKey('stok.nomor'))
    kodestok = db.Column(db.String(30), db.ForeignKey('stok.kode'))
    namastok = db.Column(db.String(50))
    banyaknya = db.Column(db.Float)
    satuan = db.Column(db.String(5))
    harga = db.Column(db.Float)
    banyaknya0 = db.Column(db.Float)
    satuan0 = db.Column(db.String(5))
    satuan1 = db.Column(db.String(5))
    faktor = db.Column(db.Float)
    lokasi = db.Column(db.SmallInteger, db.ForeignKey('vpublokasi.lokasi'))
    lokasi2 = db.Column(db.SmallInteger, db.ForeignKey('vpublokasi.lokasi'))
    namalokasi = db.Column(db.String(10))
    namalokasi2 = db.Column(db.String(10))
    hpp = db.Column(db.Float)
    totalhpp = db.Column(db.Float)
    totalbruto = db.Column(db.Float)
    harganetto = db.Column(db.Float)
    totalnetto = db.Column(db.Float)
    hargasatuannetto = db.Column(db.Float)
    ordertransaksi = db.Column(db.Integer)
    ordernobukti = db.Column(db.String(20))
    ordertgl = db.Column(db.DateTime)

class vpublapstok01(db.Model):

    __tablename__ = 'vpublapstok01'

    nomor = db.Column(db.Integer, primary_key=True)
    thn = db.Column(db.SmallInteger)
    bln = db.Column(db.SmallInteger)
    nomorstok = db.Column(db.Integer, db.ForeignKey('stok.nomor'))
    lokasi = db.Column(db.SmallInteger, db.ForeignKey('vpublokasi.lokasi'))
    kode = db.Column(db.String(30))
    nama = db.Column(db.String(50))
    satuan0 = db.Column(db.String(5))
    satuan1 = db.Column(db.String(5))
    faktor = db.Column(db.Float)
    jenis0 = db.Column(db.String(20))
    jenis1 = db.Column(db.String(20))
    jenis2 = db.Column(db.String(20))
    sa = db.Column(db.Float)
    sarp = db.Column(db.Float)
    beli = db.Column(db.Float)
    belirp = db.Column(db.Float)
    beliretur = db.Column(db.Float)
    belireturrp = db.Column(db.Float)
    jual = db.Column(db.Float)
    jualrp = db.Column(db.Float)
    jualretur = db.Column(db.Float)
    jualreturrp = db.Column(db.Float)
    koreksi = db.Column(db.Float)
    koreksirp = db.Column(db.Float)
    mutasike = db.Column(db.Float)
    mutasikerp = db.Column(db.Float)
    mutasidari = db.Column(db.Float)
    mutasidarirp = db.Column(db.Float)
    masuk = db.Column(db.Float)
    masukrp = db.Column(db.Float)
    keluar = db.Column(db.Float)
    keluarrp = db.Column(db.Float)
    sisa = db.Column(db.Float)
    sisarp = db.Column(db.Float)
    sisapluskoreksi = db.Column(db.Float)
    sisapluskoreksirp = db.Column(db.Float)
    sisa_satbesar = db.Column(db.Float)
    sisa_satkecil = db.Column(db.Float)
    hpp = db.Column(db.Float)
    penjualanrp = db.Column(db.Float)
    penjualanreturrp = db.Column(db.Float)
    pembelianreturrp = db.Column(db.Float)

class vpubbayarmst(db.Model):

    __tablename__ = 'vpubbayarmst'

    nomor = db.Column(db.Integer, primary_key=True)
    transaksi = db.Column(db.SmallInteger)
    nobukti = db.Column(db.String(20))
    tgl = db.Column(db.DateTime)
    tglisi = db.Column(db.DateTime)
    login = db.Column(db.String(10), db.ForeignKey('userid.kode'))
    ket1 = db.Column(db.String(255))
    status1 = db.Column(db.String(5))

class vpubbayarjenis(db.Model):

    __tablename__ = 'vpubbayarjenis'

    nomor = db.Column(db.Integer, primary_key=True)
    kode = db.Column(db.String(20), unique=True)
    nama = db.Column(db.String(20))
    tanda = db.Column(db.SmallInteger)
    kodeperkiraan = db.Column(db.String(20))
    namaperkiraan = db.Column(db.String(50))
    phjenis = db.Column(db.String(1))

class vpubbayardet01(db.Model):

    __tablename__ = 'vpubbayardet01'

    nomor = db.Column(db.Integer, primary_key=True)
    nomorbayarmst = db.Column(db.Integer, db.ForeignKey('vpubbayarmst.nomor'))
    nomorbayarjenis = db.Column(db.Integer, db.ForeignKey('vpubbayarjenis.nomor'))
    nilai = db.Column(db.Float)
    tanda = db.Column(db.SmallInteger)
    ket1 = db.Column(db.String(255))
    status1 = db.Column(db.String(5))

class vpubbayardet02(db.Model):

    __tablename__ = 'vpubbayardet02'

    nomor = db.Column(db.Integer, primary_key=True)
    nomorbayarmst = db.Column(db.Integer, db.ForeignKey('vpubbayarmst.nomor'))
    nomortrmst = db.Column(db.Integer, db.ForeignKey('vpubtrmst02.nomor'))
    nilai = db.Column(db.Float)
    tanda = db.Column(db.SmallInteger)
    ket1 = db.Column(db.String(255))
    ket2 = db.Column(db.String(255))

class vbayardet02(db.Model):

    __tablename__ = 'vbayardet02'

    nomor = db.Column(db.Integer, primary_key=True)
    nomorbayarmst = db.Column(db.Integer, db.ForeignKey('vpubbayarmst.nomor'))
    nomortrmst = db.Column(db.Integer, db.ForeignKey('vpubtrmst02.nomor'))
    nilai = db.Column(db.Float)

class divisi(db.Model):

    __tablename__ = 'divisi'

    nomor = db.Column(db.Integer, primary_key = True)
    kode = db.Column(db.String(20), unique=True)
    keterangan = db.Column(db.String(128))