import csv
import hashlib
import json
import logging
import os
import re
import secrets
import datetime
from pathlib import Path
import uvicorn

from fastapi import FastAPI, Form, Request, UploadFile, File
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware
from PIL import Image

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# ---------- настройки ----------
USERS_FILE = 'user.csv'
NEWS_FILE = 'news.json'
SECRET_FILE = '.secret_key'
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'
AVATAR_DIR = 'avatars'
AVATAR_SIZE = 256
MAX_AVATAR_BYTES = 5 * 1024 * 1024

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler('sessions.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ---------- сертификат ----------
def generate_or_load_cert():
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return KEY_FILE, CERT_FILE

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'BY'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Minsk'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, 'Minsk'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'BarbieLand'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'localhost'),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName('localhost'), x509.DNSName('10.100.0.2')]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    with open(KEY_FILE, 'wb') as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
    with open(CERT_FILE, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return KEY_FILE, CERT_FILE


def get_secret_key():
    if os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, encoding='utf-8') as f:
            key = f.read().strip()
            if key:
                return key
    key = secrets.token_hex(32)
    with open(SECRET_FILE, 'w', encoding='utf-8') as f:
        f.write(key)
    return key


# ---------- приложение ----------
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key=get_secret_key(), max_age=1500, same_site='lax')
app.mount('/static', StaticFiles(directory='static'), name='static')
app.mount('/sources', StaticFiles(directory='sources'), name='sources')
templates = Jinja2Templates(directory='templates')


# ---------- пользователи ----------
def read_users():
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, encoding='utf-8-sig', newline='') as f:
        return list(csv.DictReader(f))


def find_user(email):
    for user in read_users():
        if user['email'] == email:
            if 'role' not in user or not user['role']:
                user['role'] = 'reader'
            return user
    return None


def add_user(name, email, password, role='reader'):
    new_file = not os.path.exists(USERS_FILE)
    with open(USERS_FILE, 'a', encoding='utf-8-sig', newline='') as f:
        writer = csv.writer(f)
        if new_file:
            writer.writerow(['name', 'email', 'password', 'role'])
        writer.writerow([name, email, hash_password(password), role])


def hash_password(password):
    salt = secrets.token_hex(8)
    h = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return salt + '$' + h


def check_password(password, saved):
    salt = saved.split('$')[0]
    h = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return saved == salt + '$' + h


def check_name(name):
    if len(name) < 2:
        return 'Введите имя (минимум 2 символа)'
    if len(name) > 50:
        return 'Имя слишком длинное (максимум 50 символов)'
    return None


def check_email(email):
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
        return 'Некорректный email'
    return None


def check_password_strength(password):
    if len(password) < 8:
        return 'Пароль должен быть не короче 8 символов'
    if len(password) > 64:
        return 'Пароль слишком длинный (не больше 64 символов)'
    if not re.search(r'[A-Za-zА-Яа-яЁё]', password):
        return 'В пароле должна быть хотя бы одна буква'
    if not re.search(r'[0-9]', password):
        return 'В пароле должна быть хотя бы одна цифра'
    return None


# ---------- новости ----------
def read_news():
    if not os.path.exists(NEWS_FILE):
        return []
    try:
        with open(NEWS_FILE, encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []


def save_news(news_list):
    with open(NEWS_FILE, 'w', encoding='utf-8') as f:
        json.dump(news_list, f, ensure_ascii=False, indent=2)


def add_news(title, text, author):
    news = read_news()
    news.insert(0, {
        'id': secrets.token_hex(4),
        'title': title,
        'text': text,
        'author': author,
        'date': datetime.datetime.now().strftime('%d.%m.%Y %H:%M')
    })
    save_news(news)


def delete_news(news_id):
    news = read_news()
    news = [n for n in news if n.get('id') != news_id]
    save_news(news)


# ---------- аватар ----------
def get_avatar_path(email):
    name = hashlib.sha256(email.encode('utf-8')).hexdigest() + '.png'
    return os.path.join(AVATAR_DIR, name)


def save_avatar(email, file: UploadFile):
    os.makedirs(AVATAR_DIR, exist_ok=True)
    path = get_avatar_path(email)
    data = file.file.read()
    if len(data) > MAX_AVATAR_BYTES:
        raise ValueError('Файл слишком большой (максимум 5 МБ)')
    tmp = Path(AVATAR_DIR) / ('tmp_' + secrets.token_hex(6))
    with open(tmp, 'wb') as f:
        f.write(data)
    try:
        img = Image.open(tmp)
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGBA')
        w, h = img.size
        side = min(w, h)
        left = (w - side) // 2
        top = (h - side) // 2
        img = img.crop((left, top, left + side, top + side))
        img = img.resize((AVATAR_SIZE, AVATAR_SIZE), Image.LANCZOS)
        img.save(path, 'PNG')
    finally:
        if tmp.exists():
            tmp.unlink()
    return path


# ---------- сессии ----------
active_sessions = set()


def client_ip(request):
    return request.client.host if request.client else '?'


def start_session(request, email):
    end_session(request)
    sid = secrets.token_hex(16)
    active_sessions.add(sid)
    request.session['sid'] = sid
    request.session['user_email'] = email
    logger.info(f'Сессия создана | email={email}')


def end_session(request):
    email = request.session.get('user_email')
    sid = request.session.get('sid')
    if sid:
        active_sessions.discard(sid)
    request.session.clear()
    if email:
        logger.info(f'Сессия завершена | email={email}')


def get_user(request):
    sid = request.session.get('sid')
    email = request.session.get('user_email')
    if not email or sid not in active_sessions:
        if email:
            logger.warning(f'Устаревшая сессия | email={email}')
        return None
    user = find_user(email)
    if user is None:
        end_session(request)
    return user


def can_edit_news(user):
    return user and user.get('role') in ('moderator', 'admin')


def is_admin(user):
    return user and user.get('role') == 'admin'


# ---------- middleware ----------
@app.middleware('http')
async def no_cache(request: Request, call_next):
    response = await call_next(request)
    if response.headers.get('content-type', '').startswith('text/html'):
        response.headers['Cache-Control'] = 'no-store'
    return response


# ---------- страницы ----------
@app.get('/', response_class=HTMLResponse)
@app.get('/home', response_class=HTMLResponse)
def home(request: Request):
    user = get_user(request)
    name = user['name'] if user else 'красотка'
    return templates.TemplateResponse(
        request=request, name='home.html',
        context={
            'username': name,
            'user': user,
            'can_edit': can_edit_news(user),
            'is_admin': is_admin(user),
            'news': read_news()
        }
    )


@app.get('/login', response_class=HTMLResponse)
def login_page(request: Request, registered: str = None, loggedout: str = None):
    notice = None
    if registered:
        notice = 'Аккаунт создан, нужно войти'
    elif loggedout:
        notice = 'Ты нажала «Назад», поэтому сессия закрыта. Войди снова 💖'
    return templates.TemplateResponse(
        request=request, name='login.html',
        context={'notice': notice}
    )


@app.get('/register', response_class=HTMLResponse)
def register_page(request: Request):
    return templates.TemplateResponse(request=request, name='register.html')


@app.get('/main', response_class=HTMLResponse)
def cabinet(request: Request):
    user = get_user(request)
    if user is None:
        logger.warning(f'Отказано в доступе к /main | ip={client_ip(request)}')
        raise StarletteHTTPException(status_code=403)
    has_avatar = os.path.exists(get_avatar_path(user['email']))
    return templates.TemplateResponse(
        request=request, name='main.html',
        context={
            'username': user['name'],
            'has_avatar': has_avatar,
            'role': user.get('role', 'reader')
        }
    )


@app.get('/logout')
def logout(request: Request):
    end_session(request)
    return RedirectResponse(url='/login', status_code=303)


@app.post('/back')
def pressed_back(request: Request):
    email = request.session.get('user_email')
    if email:
        logger.info(f'Нажата кнопка «Назад» | email={email}')
    was_logged = email is not None and request.session.get('sid') in active_sessions
    end_session(request)
    return {'logged_out': was_logged}


@app.get('/404', response_class=HTMLResponse)
def page_404(request: Request):
    return templates.TemplateResponse(request=request, name='404.html', status_code=404)


@app.get('/403', response_class=HTMLResponse)
def page_403(request: Request):
    return templates.TemplateResponse(request=request, name='403.html', status_code=403)


@app.exception_handler(StarletteHTTPException)
async def error_pages(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 403:
        return templates.TemplateResponse(request=request, name='403.html', status_code=403)
    if exc.status_code == 404:
        return templates.TemplateResponse(request=request, name='404.html', status_code=404)
    return await http_exception_handler(request, exc)


# ---------- регистрация ----------
@app.post('/register')
def register(request: Request,
             name: str = Form(...),
             email: str = Form(...),
             password: str = Form(...),
             confirm: str = Form(...)):
    name = name.strip()
    email = email.strip().lower()

    error = check_name(name) or check_email(email) or check_password_strength(password)
    if not error and password != confirm:
        error = 'Пароли не совпадают'
    if not error and find_user(email):
        error = 'Такой email уже зареган'

    if error:
        return templates.TemplateResponse(
            request=request, name='register.html',
            context={'error': error, 'name': name, 'email': email},
            status_code=400
        )

    # первый пользователь = админ, остальные = читатели
    users = read_users()
    role = 'admin' if len(users) == 0 else 'reader'

    add_user(name, email, password, role)
    logger.info(f'Новый пользователь | email={email} | name={name} | role={role}')
    return RedirectResponse(url='/login?registered=1', status_code=303)


# ---------- вход ----------
@app.post('/login')
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    user = find_user(username.strip().lower())
    if user is None or not check_password(password, user['password']):
        logger.warning(f'Неудачный вход | email={username!r} | ip={client_ip(request)}')
        return templates.TemplateResponse(
            request=request, name='login.html',
            context={'error': 'Неверный email или пароль'}
        )
    start_session(request, user['email'])
    return RedirectResponse(url='/main', status_code=303)


# ---------- новости ----------
@app.post('/add_news')
def add_news_route(request: Request, title: str = Form(...), text: str = Form(...)):
    user = get_user(request)
    if not can_edit_news(user):
        raise StarletteHTTPException(status_code=403)
    title = title.strip()
    text = text.strip()
    if title and text:
        add_news(title, text, user['name'])
        logger.info(f'Новость добавлена | author={user["email"]} | title={title}')
    return RedirectResponse(url='/home', status_code=303)


@app.post('/delete_news')
def delete_news_route(request: Request, news_id: str = Form(...)):
    user = get_user(request)
    if not is_admin(user):
        raise StarletteHTTPException(status_code=403)
    delete_news(news_id)
    logger.info(f'Новость удалена | id={news_id} | by={user["email"]}')
    return RedirectResponse(url='/home', status_code=303)


# ---------- аватар ----------
@app.get('/avatar')
def serve_avatar(request: Request):
    user = get_user(request)
    if user is None:
        raise StarletteHTTPException(status_code=403)
    path = get_avatar_path(user['email'])
    if not os.path.exists(path):
        raise StarletteHTTPException(status_code=404)
    return FileResponse(path, media_type='image/png')


@app.post('/avatar')
async def update_avatar(request: Request, file: UploadFile = File(...)):
    user = get_user(request)
    if user is None:
        raise StarletteHTTPException(status_code=403)
    has_avatar = os.path.exists(get_avatar_path(user['email']))
    if not file.filename:
        return templates.TemplateResponse(
            request=request, name='main.html',
            context={'username': user['name'], 'has_avatar': has_avatar, 'role': user.get('role'), 'message': 'Файл не выбран'}
        )
    try:
        save_avatar(user['email'], file)
    except Exception as e:
        return templates.TemplateResponse(
            request=request, name='main.html',
            context={'username': user['name'], 'has_avatar': has_avatar, 'role': user.get('role'), 'message': str(e)}
        )
    return RedirectResponse(url='/main', status_code=303)


if __name__ == '__main__':
    key_path, cert_path = generate_or_load_cert()
    uvicorn.run(
        '__main__:app',
        host='10.100.0.2',
        port=443,
        ssl_keyfile=key_path,
        ssl_certfile=cert_path,
    )