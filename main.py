from ast import Not
import datetime
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi_login import LoginManager
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel
import hashlib
import requests
from lxml import html as etree

app = FastAPI()
manager = LoginManager(
    '1e4179dc8adab15e29cbcbb588af4a71bd54e7cfc99d0652', '/auth')

sessions = []


@app.get('/')
def index(session=Depends(manager)):
    return {'user_id': session['user_id'], 'password': session['password'], 'apache_token': session['apache_token'], 'login_datetime': session['login_datetime']}


@manager.user_loader
def load_session(user_id: str):
    return next((x for x in sessions if x['user_id'] == user_id), None)


def login(user_id, password):
    session = requests.session()
    session.get('https://gakujo.shizuoka.ac.jp/portal/')
    session.post(
        'https://gakujo.shizuoka.ac.jp/portal/login/preLogin/preLogin', data={'mistakeChecker': '0'})
    session.get(
        'https://gakujo.shizuoka.ac.jp/UI/jsp/topPage/topPage.jsp')
    session.post('https://gakujo.shizuoka.ac.jp/portal/shibbolethlogin/shibbolethLogin/initLogin/sso',
                 data={'selectLocale': 'ja', 'mistakeChecker': '0', 'EXCLUDE_SET': ''})
    session.get(
        'https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s1')
    response = session.post('https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s1', data={
        'j_username': user_id, 'j_password': password, '_eventId_proceed': ''})
    document = etree.fromstring(response.text)
    if (len(document.xpath('/html/body/form/div/input[1]/@value')) == 0 or len(document.xpath('/html/body/form/div/input[2]/@value')) == 0):
        return False
    relay_state = document.xpath('/html/body/form/div/input[1]/@value')[0]
    saml_response = document.xpath(
        '/html/body/form/div/input[2]/@value')[0]
    session.post('https://gakujo.shizuoka.ac.jp/Shibboleth.sso/SAML2/POST', data={
        'RelayState': relay_state, 'SAMLResponse': saml_response}, headers={'Referer': 'https://idp.shizuoka.ac.jp/'})
    session.get('https://gakujo.shizuoka.ac.jp/portal/shibbolethlogin/shibbolethLogin/initLogin/sso',
                headers={'Referer': 'https://idp.shizuoka.ac.jp/'})
    response = session.post('https://gakujo.shizuoka.ac.jp/portal/home/home/initialize',
                            data={'EXCLUDE_SET': ''}, headers={'Referer': 'https://idp.shizuoka.ac.jp/'})
    document = etree.fromstring(response.text)
    hashed_password = hashlib.sha512(str(password).encode('utf-8')).hexdigest()
    apache_token = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    login_datetime = datetime.datetime.now()
    return {'user_id': user_id, 'password': hashed_password, 'session': session, 'apache_token': apache_token, 'login_datetime': login_datetime}


@app.post('/auth')
def auth(data: OAuth2PasswordRequestForm = Depends()):
    user_id = data.username
    password = data.password
    session = load_session(user_id)
    if session is None:
        status = login(user_id, password)
        if status is False:
            raise HTTPException(
                status_code=400, detail="Incorrect username or password")
        sessions.append(status)
    else:
        hashed_password = hashlib.sha512(
            str(password).encode('utf-8')).hexdigest()
        if session['password'] != hashed_password:
            raise HTTPException(
                status_code=400, detail="Incorrect username or password")
    access_token = manager.create_access_token(data=dict(sub=user_id))
    return {'access_token': access_token, 'token_type': 'bearer'}
