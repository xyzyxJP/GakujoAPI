import hashlib
import html
import re
from datetime import datetime
from typing import List, Optional

import requests
from dateutil import parser
from fastapi import Depends, FastAPI, HTTPException
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.responses import HTMLResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi_login import LoginManager
from lxml import html as etree
from pydantic import BaseModel

# uvicorn main:app --reload
app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
manager = LoginManager(
    '1e4179dc8adab15e29cbcbb588af4a71bd54e7cfc99d0652', '/auth')

sessions = []


class Parse:
    @staticmethod
    def space(value):
        return re.sub(' +', ' ', re.sub('\s+', '', value.replace('\r', '').replace('\n', '').replace('\t', '').replace('&nbsp;', '').strip()))

    @staticmethod
    def js_args(value, index):
        return value.split(',')[index].replace('\'', '').replace('(', '').replace(')', '').replace(';', '').strip()

    @staticmethod
    def time_span(value, index):
        return parser.parse(value.strip().split('～')[index], "")

    @staticmethod
    def html_newlines(value):
        return re.sub('[\r\n]+', html.unescape(value).replace('<br>', ' \r\n').strip('\r').strip('\n'), '\r\n', re.MULTILINE).strip()


class Report(BaseModel):
    subjects: str
    id: str
    school_year: str
    subject_code: str
    class_code: str
    status: str
    start_date_time: datetime
    end_date_time: datetime
    implementation_format: str
    operation: str
    submitted_date_time: Optional[datetime] = None
    evaluation_method: Optional[str] = None
    description: Optional[str] = None
    message: Optional[str] = None


def element_to_report(element):
    report = Report(subjects=Parse.space(element.xpath('td')[0].text), title=element.xpath('td')[1].xpath('a')[0].text.strip(), id=Parse.js_args(element.xpath(
        'td')[1].xpath('a')[0].attrib['onclick'], 1), school_year=Parse.js_args(
        element.xpath('td')[1].xpath('a')[0].attrib['onclick'], 3), subject_code=Parse.js_args(
        element.xpath('td')[1].xpath('a')[0].attrib['onclick'], 4), class_code=Parse.js_args(
        element.xpath('td')[1].xpath('a')[0].attrib['onclick'], 5), status=element.xpath('td')[2].text.strip(), start_date_time=Parse.time_span(
        element.xpath('td')[3].text, 0), end_date_time=Parse.time_span(
        element.xpath('td')[3].text, 1), implementation_format=element.xpath('td')[
        5].text.strip(), operation=element.xpath('td')[6].text.strip())
    if element.xpath('td')[4].text != None:
        report.submitted_date_time = parser.parse(
            element.xpath('td')[4].text.strip())
    return report


class Quiz(BaseModel):
    subjects: str
    title: str
    id: str
    school_year: str
    subject_code: str
    class_code: str
    status: str
    start_date_time: datetime
    end_date_time: datetime
    submission_status: str
    implementation_format: str
    operation: str
    questions_count: Optional[int] = None
    evaluation_method: Optional[str] = None
    description: Optional[str] = None
    message: Optional[str] = None


def element_to_quiz(element):
    return Quiz(subjects=Parse.space(element.xpath('td')[0].text), title=element.xpath('td')[1].xpath('a')[0].text.strip(), id=Parse.js_args(element.xpath('td')[1].xpath('a')[0].attrib['onclick'], 1),
                school_year=Parse.js_args(
        element.xpath('td')[1].xpath('a')[0].attrib['onclick'], 3), subject_code=Parse.js_args(
        element.xpath('td')[1].xpath('a')[0].attrib['onclick'], 4), class_code=Parse.js_args(
        element.xpath('td')[1].xpath('a')[0].attrib['onclick'], 5), status=element.xpath('td')[2].text.strip(), start_date_time=Parse.time_span(
            element.xpath('td')[3].text, 0), end_date_time=Parse.time_span(
            element.xpath('td')[3].text, 1), submission_status=element.xpath('td')[4].text.strip(), implementation_format=element.xpath('td')[5].text.strip(), operation=element.xpath('td')[6].text.strip())


class ClassContact(BaseModel):
    subjects: str
    teacher_name: str
    contact_type: Optional[str] = None
    title: str
    content: Optional[str] = None
    file_link_release: Optional[str] = None
    reference_url: Optional[str] = None
    severity: Optional[str] = None
    target_date_time: Optional[datetime] = None
    contact_date_time: datetime
    web_reply_request: Optional[str] = None


def element_to_class_contact(element):
    class_contact = ClassContact(subjects=Parse.space(element.xpath('td')[1].text), teacher_name=element.xpath(
        'td')[2].text.strip(), title=html.unescape(element.xpath('td')[3].xpath('a')[0].text).strip(), contact_date_time=parser.parse(element.xpath('td')[6].text))
    if element.xpath('td')[5].text != None:
        class_contact.target_date_time = parser.parse(
            element.xpath('td')[5].text.strip())
    return class_contact


@ app.post('/auth')
async def post_auth(data: OAuth2PasswordRequestForm = Depends()):
    user_id = data.username
    password = data.password
    session = load_session(user_id)
    if session is None:
        status = login(user_id, password)
        if status is False:
            raise HTTPException(
                status_code=401, detail="Unauthorized")
        sessions.append(status)
    else:
        hashed_password = hashlib.sha512(
            str(password).encode('utf-8')).hexdigest()
        if session['password'] != hashed_password:
            raise HTTPException(
                status_code=401, detail="Unauthorized")
    access_token = manager.create_access_token(data=dict(sub=user_id))
    return {'access_token': access_token, 'token_type': 'bearer'}


@ app.get('/status')
async def get_status(session=Depends(manager)):
    return {'user_id': session['user_id'], 'password': session['password'], 'apache_token': session['apache_token'], 'login_datetime': session['login_datetime']}


@ app.get('/reports', response_model=List[Report])
async def get_reports(session=Depends(manager)):
    response = session['session'].post('https://gakujo.shizuoka.ac.jp/portal/common/generalPurpose/', data={
        'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'headTitle': '授業サポート', 'menuCode': 'A02', 'nextPath': '/report/student/searchList/initialize'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    response = session['session'].post('https://gakujo.shizuoka.ac.jp/portal/report/student/searchList/search', data={
        'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'reportId': '', 'hidSchoolYear': '', 'hidSemesterCode': '', 'hidSubjectCode': '', 'hidClassCode': '', 'entranceDiv': '', 'backPath': '', 'listSchoolYear': '', 'listSubjectCode': '', 'listClassCode': '', 'schoolYear': '2022', 'semesterCode': '1', 'subjectDispCode': '', 'operationFormat': ['1', '2'], 'searchList_length': '-1', '_searchConditionDisp.accordionSearchCondition': 'true', '_screenIdentifier': 'SC_A02_01_G', '_screenInfoDisp': '', '_scrollTop': '0'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    reports = []
    for x in document.xpath('//*[@id="searchList"]/tbody/tr'):
        reports.append(element_to_report(x))
    return reports


@ app.get('/report/{id}', response_model=Report)
async def get_report(id: str, subject_code: str, class_code: str, session=Depends(manager)):
    response = session['session'].post('https://gakujo.shizuoka.ac.jp/portal/common/generalPurpose/', data={
        'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'headTitle': '授業サポート', 'menuCode': 'A02', 'nextPath': '/report/student/searchList/initialize'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    response = session['session'].post('https://gakujo.shizuoka.ac.jp/portal/report/student/searchList/search', data={
        'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'reportId': '', 'hidSchoolYear': '', 'hidSemesterCode': '', 'hidSubjectCode': '', 'hidClassCode': '', 'entranceDiv': '', 'backPath': '', 'listSchoolYear': '', 'listSubjectCode': '', 'listClassCode': '', 'schoolYear': '2022', 'semesterCode': '1', 'subjectDispCode': '', 'operationFormat': ['1', '2'], 'searchList_length': '-1', '_searchConditionDisp.accordionSearchCondition': 'true', '_screenIdentifier': 'SC_A02_01_G', '_screenInfoDisp': '', '_scrollTop': '0'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    report = None
    for x in document.xpath('//*[@id="searchList"]/tbody/tr'):
        x = element_to_report(x)
        if x.id == id and x.subject_code == subject_code and x.class_code == class_code:
            report = x
            break
    if report is None:
        raise HTTPException(
            status_code=404, detail="Not Found")
    response = session['session'].post(
        'https://gakujo.shizuoka.ac.jp/portal/report/student/searchList/forwardSubmitRef', data={
            'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'reportId': id, 'hidSchoolYear': '', 'hidSemesterCode': '', 'hidSubjectCode': '', 'hidClassCode': '', 'entranceDiv': '', 'backPath': '', 'listSchoolYear':  '2022', 'listSubjectCode': subject_code, 'listClassCode': class_code, 'schoolYear': '2022', 'semesterCode': '0', 'subjectDispCode': '', 'operationFormat': ['1', '2'], 'searchList_length': '-1', '_searchConditionDisp.accordionSearchCondition': 'true', '_screenIdentifier': 'SC_A02_01_G', '_screenInfoDisp': '', '_scrollTop': '0'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    element = document.xpath(
        '/html/body/div[2]/div[1]/div/form/div[3]/div/div/div/table')[0]
    report.evaluation_method = element.xpath('tr')[3].xpath('td')[0].text
    report.description = Parse.html_newlines(
        element.xpath('tr')[4].xpath('td')[0].text_content())
    # required to replace innerHtml
    report.message = Parse.html_newlines(
        element.xpath('tr')[5].xpath('td')[0].text_content())
    # required to replace innerHtml
    return report


@ app.get('/quizzes', response_model=List[Quiz])
async def get_quizzes(session=Depends(manager)):
    response = session['session'].post('https://gakujo.shizuoka.ac.jp/portal/common/generalPurpose/', data={
        'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'headTitle': '小テスト一覧', 'menuCode': 'A03', 'nextPath': '/test/student/searchList/initialize'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    response = session['session'].post('https://gakujo.shizuoka.ac.jp/portal/test/student/searchList/search', data={
        'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'testId': '', 'hidSchoolYear': '', 'hidSemesterCode': '', 'hidSubjectCode': '', 'hidClassCode': '', 'entranceDiv': '', 'backPath': '', 'listSchoolYear': '', 'listSubjectCode': '', 'listClassCode': '', 'schoolYear': '2022', 'semesterCode': '1', 'subjectDispCode': '', 'operationFormat': ['1', '2'], 'searchList_length': '-1', '_searchConditionDisp.accordionSearchCondition': 'true', '_screenIdentifier': 'SC_A03_01_G', '_screenInfoDisp': '', '_scrollTop': '0'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    quizzes = []
    for x in document.xpath('//*[@id="searchList"]/tbody/tr'):
        quizzes.append(element_to_quiz(x))
    return quizzes


@ app.get('/quiz/{id}', response_model=Quiz)
async def get_quiz(id: str, subject_code: str, class_code: str, session=Depends(manager)):
    response = session['session'].post('https://gakujo.shizuoka.ac.jp/portal/common/generalPurpose/', data={
        'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'headTitle': '小テスト一覧', 'menuCode': 'A03', 'nextPath': '/test/student/searchList/initialize'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    response = session['session'].post('https://gakujo.shizuoka.ac.jp/portal/report/student/searchList/search', data={
        'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'testId': '', 'hidSchoolYear': '', 'hidSemesterCode': '', 'hidSubjectCode': '', 'hidClassCode': '', 'entranceDiv': '', 'backPath': '', 'listSchoolYear': '', 'listSubjectCode': '', 'listClassCode': '', 'schoolYear': '2022', 'semesterCode': '1', 'subjectDispCode': '', 'operationFormat': ['1', '2'], 'searchList_length': '-1', '_searchConditionDisp.accordionSearchCondition': 'true', '_screenIdentifier': 'SC_A03_01_G', '_screenInfoDisp': '', '_scrollTop': '0'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    quiz = None
    for x in document.xpath('//*[@id="searchList"]/tbody/tr'):
        x = element_to_quiz(x)
        if x.id == id and x.subject_code == subject_code and x.class_code == class_code:
            quiz = x
            break
    if quiz is None:
        raise HTTPException(
            status_code=404, detail="Not Found")
    response = session['session'].post(
        'https://gakujo.shizuoka.ac.jp/portal/test/student/searchList/forwardSubmitRef', data={
            'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'testId': id, 'hidSchoolYear': '', 'hidSemesterCode': '', 'hidSubjectCode': '', 'hidClassCode': '', 'entranceDiv': '', 'backPath': '', 'listSchoolYear':  '2022', 'listSubjectCode': subject_code, 'listClassCode': class_code, 'schoolYear': '2022', 'semesterCode': '0', 'subjectDispCode': '', 'operationFormat': ['1', '2'], 'searchList_length': '-1', '_searchConditionDisp.accordionSearchCondition': 'true', '_screenIdentifier': 'SC_A03_01_G', '_screenInfoDisp': '', '_scrollTop': '0'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    element = document.xpath(
        '/html/body/div[2]/div[1]/div/form/div[3]/div/div/div/div/table')[0]
    quiz.questions_count = int(element.xpath('tr')[2].xpath('td')[
        0].text.replace('問', '').strip())
    quiz.evaluation_method = element.xpath('tr')[3].xpath('td')[0].text
    quiz.description = Parse.html_newlines(
        element.xpath('tr')[4].xpath('td')[0].text_content())
    # required to replace innerHtml
    quiz.message = Parse.html_newlines(
        element.xpath('tr')[6].xpath('td')[0].text_content())
    # required to replace innerHtml
    return quiz


@ app.get('/class_contacts', response_model=List[ClassContact])
async def get_class_contacts(session=Depends(manager)):
    response = session['session'].post('https://gakujo.shizuoka.ac.jp/portal/common/generalPurpose/', data={
        'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'headTitle': '授業連絡一覧', 'menuCode': 'A01', 'nextPath': '/classcontact/classContactList/initialize'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    response = session['session'].post('https://gakujo.shizuoka.ac.jp/portal/classcontact/classContactList/selectClassContactList', data={
        'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'teacherCode': '', 'schoolYear': '2022', 'semesterCode': '0', 'subjectDispCode': '', 'searchKeyWord': '', 'checkSearchKeywordTeacherUserName': 'on', 'checkSearchKeywordSubjectName': 'on', 'checkSearchKeywordTitle': 'on', 'contactKindCode': '', 'targetDateStart': '', 'targetDateEnd': '', 'reportDateStart': '2022/03/01'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    class_contacts = []
    for x in document.xpath('//*[@id="tbl_A01_01"]/tbody/tr'):
        class_contacts.append(element_to_class_contact(x))
    return class_contacts


@app.get('/class_contact/{index}', response_model=ClassContact)
async def get_class_contact(index: int, session=Depends(manager)):
    response = session['session'].post('https://gakujo.shizuoka.ac.jp/portal/common/generalPurpose/', data={
        'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'headTitle': '授業連絡一覧', 'menuCode': 'A01', 'nextPath': '/classcontact/classContactList/initialize'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    response = session['session'].post('https://gakujo.shizuoka.ac.jp/portal/classcontact/classContactList/selectClassContactList', data={
        'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'teacherCode': '', 'schoolYear': '2022', 'semesterCode': '0', 'subjectDispCode': '', 'searchKeyWord': '', 'checkSearchKeywordTeacherUserName': 'on', 'checkSearchKeywordSubjectName': 'on', 'checkSearchKeywordTitle': 'on', 'contactKindCode': '', 'targetDateStart': '', 'targetDateEnd': '', 'reportDateStart': '2022/03/01'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    if len(document.xpath('//*[@id="tbl_A01_01"]/tbody/tr')) <= index:
        raise HTTPException(
            status_code=404, detail="Not Found")
    class_contact = element_to_class_contact(
        document.xpath('//*[@id="tbl_A01_01"]/tbody/tr')[index])
    response = session['session'].post(
        'https://gakujo.shizuoka.ac.jp/portal/classcontact/classContactList/goDetail/' + str(index), data={
            'org.apache.struts.taglib.html.TOKEN': session['apache_token'], 'teacherCode': '', 'schoolYear': '2022', 'semesterCode': '0', 'subjectDispCode': '', 'searchKeyWord': '', 'checkSearchKeywordTeacherUserName': 'on', 'checkSearchKeywordSubjectName': 'on', 'checkSearchKeywordTitle':  'on', 'contactKindCode': '', 'targetDateStart': '', 'targetDateEnd': '', 'reportDateStart': '2022/03/01', 'reportDateEnd': '', 'requireResponse': '', 'studentCode': '', 'studentName': '', 'tbl_A01_01_length': '-1', '_searchConditionDisp.accordionSearchCondition': 'false', '_screenIdentifier': 'SC_A01_01', '_screenInfoDisp': 'true', '_scrollTop': '0'})
    document = etree.fromstring(response.text)
    session['apache_token'] = document.xpath(
        '/html/body/div[1]/form[1]/div/input/@value')[0]
    element = document.xpath(
        '/html/body/div[2]/div/div/form/div[3]/div/div/div/table')[0]
    class_contact.contact_type = element.xpath('tr')[0].xpath('td')[0].text
    class_contact.content = Parse.html_newlines(
        element.xpath('tr')[2].xpath('td')[0].text_content())
    class_contact.file_link_release = Parse.space(
        element.xpath('tr')[4].xpath('td')[0].text)
    class_contact.reference_url = Parse.space(
        element.xpath('tr')[5].xpath('td')[0].text)
    class_contact.severity = Parse.space(
        element.xpath('tr')[6].xpath('td')[0].text)
    class_contact.web_reply_request = element.xpath('tr')[8].xpath('td')[
        0].text
    return class_contact


@ manager.user_loader()
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
    login_datetime = datetime.now()
    return {'user_id': user_id, 'password': hashed_password, 'session': session, 'apache_token': apache_token, 'login_datetime': login_datetime}


@ app.delete('/logout')
async def delete_logout(session=Depends(manager)):
    sessions.remove(session)
    return {'message': 'logout', 'count': len(sessions)}
