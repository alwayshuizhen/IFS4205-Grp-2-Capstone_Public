from datetime import timedelta, date
from flask import Flask, url_for, render_template, redirect
from flask import request, session, send_from_directory
from flask_talisman import Talisman
from flask_login import LoginManager, UserMixin, login_user, current_user, login_required, logout_user
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re
import uuid
import base64
import os
import mimetypes
import logging

import database.sshConnection
import database.sqlDataRetrieval
import database.dataCreation.convertCSVToSQL
import database.dataAnonymization as dataAnonymization
import baseapp.src.secretKey
import faceRecognition.faceRecog

import baseapp.src.messages as messages

from flask_bcrypt import Bcrypt

# Define logger capabilities
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logFileName = "logs/mainlog-" + date.today().strftime("%b-%d-%Y") + ".log"
formatter = logging.Formatter('%(asctime)s:%(levelname)s:%(name)s:%(funcName)s:%(message)s')
file_handler = logging.FileHandler(logFileName)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

class User(UserMixin):
    def __init__(self, username):
        self.name = username
        self.role = database.sqlDataRetrieval.getCurrentLoginInfo(session['sessionId'])[2]
        self.fullName = database.sqlDataRetrieval.publicGetUser(self.name)[0]

    @property
    def id(self):
        return self.name

    def set_role(self, value):
        self.role = value

    def set_fullName(self, value):
        self.fullName = value


# DO NOT RENAME THIS FUNCTION
def create_app():
    logger.info(messages.startServer)
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=baseapp.src.secretKey.secret_key,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_SAMESITE='Lax',
    )
    Talisman(app)
    bcrypt = Bcrypt(app)
    CSRFProtect(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    login_manager.session_protection = "strong"

    @login_manager.user_loader
    def load_user(username):
        user = User(username)
        return user

    limiter = Limiter(app, key_func=get_remote_address,
                      default_limits=["60000 per day", "3600 per hour"])

    csp = {'default-src': '\'self\'', 'style-src': ['\'self\'', 'fonts.googleapis.com']}
    cspForScripts = {'default-src': '\'self\'',
                     'script-src': ['\'self\'', 'cdnjs.cloudflare.com'],
                     'style-src': ['\'self\'', 'fonts.googleapis.com']}
    talisman = Talisman(app, content_security_policy=csp)
    mimetypes.add_type('application/javascript', '.js')
    mimetypes.add_type('application/javascript', '.js')
    app.secret_key = baseapp.src.secretKey.secret_key
    bcrypt = Bcrypt(app)
    currentUser = None
    currentUserPassed = None
    currentUserFailed = None

    @app.before_request
    def before_request():
        session.modified = True

    def safe_redirect(next, urlToRedirect):
        if next != urlToRedirect:
            next = urlToRedirect
        return next

    # Use the route() decorator to tell Flask what URL should trigger our function
    @app.route('/')
    def index():
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("60 per minute")
    def login():
        if current_user.is_authenticated:
            next = safe_redirect(request.args.get('next'), url_for('logout'))
            return redirect(next or url_for('logout'))
        error = None
        if request.method == 'POST':
            if 'username' in request.form and 'password' in request.form:
                username = request.form['username']
                password = request.form['password']
                role = request.form['role']
                logger.info(messages.verifyUserCred % (username, role))
                global currentUser
                currentUser = (username, role)
                global currentUserPassed
                currentUserPassed = ('passed', username, role)
                global currentUserFailed
                currentUserFailed = ('failed', username, role)
                session['sessionId'] = uuid.uuid4()
                loginAttemptCount = database.sqlDataRetrieval.getLoginAttemptCount(username)
                if loginAttemptCount[0] <= 3:
                    data = database.sqlDataRetrieval.verifyUser(username)
                    if data is not None:
                        validPassword = bcrypt.check_password_hash(data[0], password)
                        if validPassword:
                            user = [data[1][0], data[1][2]]
                        else:
                            user = None
                        if user:
                            if role == user[1]:
                                database.sqlDataRetrieval.logCredentialsCheck(
                                    session['sessionId'], username, user[1], 1, 0)
                            else:
                                database.sqlDataRetrieval.logCredentialsCheck(
                                    session['sessionId'], username, "public", 1, 0)
                            logger.info(messages.passwordLogin % currentUserPassed)
                            next = safe_redirect(request.args.get('next'), url_for('dongle_check'))
                            return redirect(next or url_for('dongle_check'))
                else:
                    logger.info(messages.passwordLogin % currentUserFailed)
                    return messages.loginTooManyAttemptsMsg
                database.sqlDataRetrieval.logCredentialsCheck(session['sessionId'], username, role, 0, 0)
                error = messages.loginErrorMsg
        return render_template('pages/login.html', error=error)

    @app.route('/donglecheck', methods=['GET', 'POST'])
    @limiter.limit("60 per minute")
    @talisman(content_security_policy=cspForScripts)
    def dongle_check():
        global currentUserPassed
        global currentUserFailed
        currentLoginInfo = database.sqlDataRetrieval.getCurrentLoginInfo(session['sessionId'])
        if currentLoginInfo[4] == 1 and not current_user.is_authenticated:
            if request.method == 'POST':
                storedDongleId = database.sqlDataRetrieval.getDongleId(currentLoginInfo[1])[0]
                dongleUsed = database.sqlDataRetrieval.getDongleAuth(currentLoginInfo[1])[0]
                if storedDongleId == dongleUsed:
                    donglePassed = True
                else:
                    donglePassed = False

                database.sqlDataRetrieval.updateDongleAuth_reset(currentLoginInfo[1])
                if donglePassed:
                    database.sqlDataRetrieval.logDongleCheck(session['sessionId'], currentLoginInfo[1], 1)
                    logger.info(messages.dongleLogin % currentUserPassed)
                    next = safe_redirect(request.args.get('next'), url_for('facialRegRedirect'))
                    return redirect(next or url_for('facialRegRedirect'))
                else:
                    database.sqlDataRetrieval.logDongleCheck(session['sessionId'], currentLoginInfo[1], 0)
                    logger.info(messages.dongleLogin % currentUserFailed)
                    next = safe_redirect(request.args.get('next'), url_for('login'))
                    return redirect(url_for('login'))
            return render_template('pages/donglecheck.html', username=currentLoginInfo[1])
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/facialregredirect', methods=['GET', 'POST'])
    @limiter.limit("60 per minute")
    @talisman(content_security_policy=cspForScripts)
    def facialRegRedirect():
        global currentUserPassed
        global currentUserFailed
        currentLoginInfo = database.sqlDataRetrieval.getCurrentLoginInfo(session['sessionId'])
        if currentLoginInfo[5] == 1 and not current_user.is_authenticated:
            if request.method == 'POST':
                result = faceRecogCheck(request.form['vidData'])
                if result:
                    logger.info(messages.faceRecogLogin % currentUserPassed)
                    user = load_user(currentLoginInfo[1])
                    login_user(user)
                    database.sqlDataRetrieval.logFacialRegCheck(session['sessionId'], current_user.name, 1, 1)
                    app.permanent_session_lifetime = timedelta(minutes=5)
                    session.permanent = True
                    next = safe_redirect(request.args.get('next'), url_for('home'))
                    return redirect(url_for('home'))
                logger.info(messages.faceRecogLogin % currentUserFailed)
            return render_template('pages/facialregcheck.html', username=currentLoginInfo[1])
        database.sqlDataRetrieval.logFacialRegCheck(session['sessionId'], currentLoginInfo[1], 0, 0)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    def processVid(data):
        with open('sample.jpg', 'wb') as f:
            f.write(base64.decodestring(data.split(',')[1].encode()))

    def faceRecogCheck(imgData):
        processVid(imgData)
        currentLoginInfo = database.sqlDataRetrieval.getCurrentLoginInfo(session['sessionId'])
        # Get full path to user's profile picture
        profilePictureName = database.sqlDataRetrieval.getProfileImgLink(currentLoginInfo[1])
        profilePicture = "../../baseapp/src/static/img/humans/" + str(profilePictureName[0])
        # Compare DB profile picture with video feed
        result = faceRecognition.faceRecog.compareVidFeedDB('../../baseapp/src/sample.jpg', profilePicture)
        os.remove('../../baseapp/src/sample.jpg')
        return result

    @app.route('/logout')
    @login_required
    def logout():
        global currentUser
        if current_user.is_authenticated:
            database.sqlDataRetrieval.logLogoutTime(session['sessionId'], current_user.name)
            logger.info(messages.logout % currentUser)
            session.clear()
            logout_user()
            return render_template('pages/signOut.html')
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/home')
    @login_required
    def home():
        global currentUser
        if current_user.is_authenticated:
            logger.info(messages.atHomePg % currentUser)
            if current_user.role == 'admin':
                next = safe_redirect(request.args.get('next'), url_for('adminProfile'))
                return redirect(next or url_for('adminProfile'))
            elif current_user.role == 'staff':
                next = safe_redirect(request.args.get('next'), url_for('staffLocation'))
                return redirect(next or url_for('staffLocation'))
            elif current_user.role == 'contacttracer':
                next = safe_redirect(request.args.get('next'), url_for('ctDashboard'))
                return redirect(url_for('ctDashboard'))
            elif current_user.role == 'researcher':
                return redirect(url_for('researcherDashboard'))
            else:
                next = safe_redirect(request.args.get('next'), url_for('publicProfile'))
                return redirect(next or url_for('publicProfile'))
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/location', methods=['GET', 'POST'])
    @login_required
    def staffLocation():
        if current_user.is_authenticated and current_user.role == 'staff':
            error = None
            profile = database.sqlDataRetrieval.getProfile(current_user.name)
            photoLink = profile[2]
            if request.method == 'POST':
                location = request.form['location']

                validLocation = database.sqlDataRetrieval.getActiveLocation(location)
                if validLocation is not None:
                    print(validLocation)
                    if validLocation[0] == 1:
                        session['location'] = location
                        next = safe_redirect(request.args.get('next'), url_for('staffDashboard'))
                        return redirect(next or url_for('staffDashboard'))
                    else:
                        error = "Invalid location"
            return render_template('pages/staffLocation.html', photoLink='/img/humans/' + photoLink, error=error)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/user/', methods=['GET', 'POST'])
    @login_required
    @limiter.limit("60 per minute")
    def publicProfile():
        global currentUser
        global currentUserPassed
        global currentUserFailed
        if current_user.is_authenticated and current_user.role == 'public':
            logger.info(messages.atProfilePg % currentUser)
            # Get profile picture link and phone number
            profile = database.sqlDataRetrieval.getProfile(current_user.name)
            photoLink = profile[2]
            error = None
            errorConsent = None
            message = None
            if request.method == 'POST':
                if "username" in request.form:
                    outcome = editPasswordForm(request.form['username'], request.form['currentPassword'],
                                               request.form['password'], request.form['confirmPassword'])
                    if outcome[0] == 'Error':
                        error = outcome[1]
                        logger.warning(messages.resultOfChangePassword % currentUserFailed)
                    elif outcome[0] == 'Message':
                        message = outcome[1]
                        logger.warning(messages.resultOfChangePassword % currentUserPassed)
                else:
                    requestDict = {"testQuarantine":
                                   ["test_log", "quarantine_log"],
                                   "vaccination_log": ["vaccination_log"],
                                   "visitation": ["visitation", "entry_log"]}
                    # print(request.form)
                    counter = 0
                    for name in requestDict.keys():
                        consentStatus = False
                        if name in request.form:
                            consentStatus = True
                        else:
                            consentStatus = False
                        for consentTable in requestDict[name]:
                            logger.warning(messages.updateOfConsent % currentUser)
                            result = database.sqlDataRetrieval.insertConsentLogForUser(profile[0],
                                                                                       profile[1], consentTable, consentStatus)
                            if result is not None:
                                counter += 1
                    errorConsent = messages.getConsentMessage(counter)
            return render_template('pages/publicProfile.html',
                                   error=error, message=message, profile=profile, errorConsent=errorConsent,
                                   photoLink='/img/humans/' + photoLink)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/user/dashboard')
    @login_required
    def publicDashboard():
        if current_user.is_authenticated and current_user.role == 'public':
            logger.info(messages.atDashboard % (current_user.name, current_user.role, 'user'))
            data = database.sqlDataRetrieval.publicDashboardHistory(current_user.name)
            return render_template('pages/publicDashboard.html', data=data)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/staff/dashboard', methods=['GET', 'POST'])
    @login_required
    def staffDashboard():
        if current_user.is_authenticated and current_user.role == 'staff':
            logger.info(messages.atDashboard % (current_user.name, current_user.role, current_user.role))
            profile = database.sqlDataRetrieval.getProfile(current_user.name)
            photoLink = profile[2]
            if request.method == 'POST':
                next = safe_redirect(request.args.get('next'), url_for('dongleCheckIn_staff'))
                return redirect(next or url_for('dongleCheckIn_staff'))
            return render_template('pages/staffDashboard.html', photoLink='/img/humans/' + photoLink)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/dongleCheckIn-staff', methods=['GET', 'POST'])
    @login_required
    @talisman(content_security_policy=cspForScripts)
    def dongleCheckIn_staff():
        if request.method == 'POST':
            staffEnteredLocation = session['location']
            try:
                f = open("/home/dongleMan/server/" + staffEnteredLocation, "r")
                nameFromDongle = f.readline().strip()
                phoneNumFromDongle = f.readline().strip()
                dongleIdFromDongle = f.readline().strip()
                f.close()
                
                regex = re.compile('[@_!#$%^&*()<>?/\\|}{~:]')
                if (regex.search(nameFromDongle) == None 
                    and regex.search(phoneNumFromDongle) == None 
                    and regex.search(dongleIdFromDongle) == None):
                    validInput = True
                else:
                    validInput = False
                if validInput:
                    storedDongleId = database.sqlDataRetrieval.getDongleIdCheckIn(nameFromDongle, phoneNumFromDongle)[0]
                    if storedDongleId == dongleIdFromDongle:
                        donglePassed = True
                    else:
                        donglePassed = False

                    session['profilePictureName'] = database.sqlDataRetrieval.getProfileImgLink_checkIn(
                                nameFromDongle, phoneNumFromDongle)[0]
                    try:
                        if donglePassed:
                            data = database.sqlDataRetrieval.getAccessStatus(nameFromDongle, phoneNumFromDongle)
                            if data is not None:
                                accessStatus = data[0]
                                if accessStatus == 1:
                                    os.remove("/home/dongleMan/server/" + staffEnteredLocation)
                                    next = safe_redirect(request.args.get('next'), url_for('facialCheckInRedirect_staff'))
                                    return redirect(next or url_for('facialCheckInRedirect_staff'))
                                else:
                                    database.sqlDataRetrieval.logCheckInRecord(nameFromDongle, phoneNumFromDongle, 0, staffEnteredLocation)
                                    next = safe_redirect(request.args.get('next'), url_for('checkInFail'))
                                    return redirect(next or url_for('checkInFail'))
                    except Exception:
                        database.sqlDataRetrieval.logCheckInRecord(nameFromDongle, phoneNumFromDongle, 0, staffEnteredLocation)
                        next = safe_redirect(request.args.get('next'), url_for('checkInFail'))
                        return redirect(next or url_for('checkInFail'))
                else:
                    database.sqlDataRetrieval.logCheckInRecord(nameFromDongle, phoneNumFromDongle, 0, staffEnteredLocation)
                    next = safe_redirect(request.args.get('next'), url_for('checkInFail'))
                    return redirect(next or url_for('checkInFail'))
            except Exception as e:
                print("Exception:" + str(e))
                print("Receiver not found")
                if current_user.is_authenticated and current_user.role == 'staff':
                    error = "Please enter a mall ID that is active!"
                    profile = database.sqlDataRetrieval.getProfile(current_user.name)
                    photoLink = profile[2]
                    return render_template('pages/staffLocation.html', photoLink='/img/humans/' + photoLink, error=error)
        return render_template('pages/checkIn-dongle.html')

    @app.route('/facialCheckInRedirect-staff', methods=['GET', 'POST'])
    @login_required
    @talisman(content_security_policy=cspForScripts)
    def facialCheckInRedirect_staff():
        staffEnteredLocation = session['location']
        if request.method == 'POST':
            data = database.sqlDataRetrieval.getUserInfo(session['profilePictureName'])
            try:
                result = faceRecogCheck2(request.form['vidData'])
                if result:
                    database.sqlDataRetrieval.logCheckInRecord(data[0], data[1], 1, staffEnteredLocation)
                    next = safe_redirect(request.args.get('next'), url_for('checkInPass'))
                    return redirect(next or url_for('checkInPass'))
                else:
                    database.sqlDataRetrieval.logCheckInRecord(data[0], data[1], 0, staffEnteredLocation)
                    next = safe_redirect(request.args.get('next'), url_for('checkInFail'))
                    return redirect(next or url_for('checkInFail'))
            except Exception:
                database.sqlDataRetrieval.logCheckInRecord(data[0], data[1], 0, staffEnteredLocation)
                next = safe_redirect(request.args.get('next'), url_for('checkInFail'))
                return redirect(next or url_for('checkInFail'))
        return render_template('pages/checkIn-facial.html')

    def faceRecogCheck2(imgData):
        processVid(imgData)
        # Get full path to user's profile picture
        profilePicture = "../../baseapp/src/static/img/humans/" + str(session['profilePictureName'])
        # Compare DB profile picture with video feed
        result = faceRecognition.faceRecog.compareVidFeedDB('../../baseapp/src/sample.jpg', profilePicture)
        os.remove('../../baseapp/src/sample.jpg')
        return result

    @app.route('/checkInFail', methods=['GET', 'POST'])
    @login_required
    def checkInFail():
        if current_user.is_authenticated and current_user.role == 'staff':
            profile = database.sqlDataRetrieval.getProfile(current_user.name)
            photoLink = profile[2]
            if request.method == 'POST':
                next = safe_redirect(request.args.get('next'), url_for('staffDashboard'))
                return redirect(next or url_for('staffDashboard'))
            return render_template('pages/checkInFail.html', photoLink='/img/humans/' + photoLink)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/checkInPass', methods=['GET', 'POST'])
    @login_required
    def checkInPass():
        if current_user.is_authenticated and current_user.role == 'staff':
            profile = database.sqlDataRetrieval.getProfile(current_user.name)
            photoLink = profile[2]
            if request.method == 'POST':
                next = safe_redirect(request.args.get('next'), url_for('staffDashboard'))
                return redirect(next or url_for('staffDashboard'))
            return render_template('pages/checkInPass.html', photoLink='/img/humans/' + photoLink)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/contacttracer/dashboard')
    @login_required
    def ctDashboard():
        if current_user.is_authenticated and current_user.role == 'contacttracer':
            logger.info(messages.atDashboard % (current_user.name, current_user.role, current_user.role))
            profile = database.sqlDataRetrieval.getProfile(current_user.name)
            photoLink = profile[2]
            data = database.sqlDataRetrieval.ctViewDeniedEntries()
            # print(data)
            return render_template('pages/ctDashboard.html', data=data, photoLink='img/humans/' + photoLink)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/researcher/dashboard', methods=['GET', 'POST'])
    def researcherDashboard():
        global currentUser
        if current_user.is_authenticated and current_user.role == 'researcher':
            logger.info(messages.atDashboard % (current_user.name, current_user.role, current_user.role))
            profile = database.sqlDataRetrieval.getProfile(current_user.name)
            photoLink = profile[2]
            print("hi")
            if request.method == 'POST':
                logger.info(messages.requestExport % currentUser)
                researchPurpose = request.form["purpose"]
                # print(researchPurpose)
                if researchPurpose == "demographic":
                    data = dataAnonymization.changeDOBToAge(database.sqlDataRetrieval.getDemographic())
                else:
                    data = database.sqlDataRetrieval.getAccessLogs()
                print(len(data))
                # print(len(data))
                # Level 0 Data Anonymization
                # data = database.sqlDataRetrieval.getEntryLogs()
                # userQuantity = database.sqlDataRetrieval.getNumberOfUsers()
                # Level 1 + 2 Data Anonymization
                # print(userQuantity)
                # newData = dataAnonymization.generateMappingForTests(data, userQuantity)
                dataAnonymization.writeToCSV(data, researchPurpose)
                # Creation of file
                today = date.today()
                fileName = "accessTogether-" + today.strftime("%b-%d-%Y") + ".csv"
                app = "../../baseapp/src/"
                return send_from_directory(directory=app, path=fileName, as_attachment=True)
            return render_template('pages/researcherDashboard.html', photoLink='img/humans/' + photoLink)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/superadmin/', methods=['GET', 'POST'])
    @login_required
    def adminProfile():
        global currentUser
        if current_user.is_authenticated and current_user.role == 'admin':
            logger.info(messages.atAdminProfile % currentUser)
            # Get profile picture link and phone number
            profile = database.sqlDataRetrieval.getProfile(current_user.name)
            photoLink = profile[2]
            phoneNum = profile[1]
            return render_template('pages/adminProfile.html', phoneNum=phoneNum,
                                   photoLink='img/humans/' + photoLink)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/superadmin/AC')
    @login_required
    def adminAccessControl():
        global currentUser
        if current_user.is_authenticated and current_user.role == 'admin':
            logger.info(messages.atAdminAC % currentUser)
            data = database.sqlDataRetrieval.adminAccessControl()
            return render_template('pages/adminAccessControl.html', data=data)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/superadmin/Dashboard', methods=['GET', 'POST'])
    @login_required
    @limiter.limit("60 per minute")
    def adminDashboard():
        global currentUserPassed
        global currentUserFailed
        message = None
        if current_user.is_authenticated and current_user.role == 'admin':
            logger.info(messages.atDashboard % (current_user.name, current_user.role, 'superadmin'))
            if request.method == "POST":
                requestList = {"vaccination": "vaccination",
                               "testQuarantine": "testQuarantine",
                               "createUser": "createUsers",
                               "updateDongles": "dongle",
                               "userRole": "roleLog"}
                username = request.form["username"]
                password = request.form["password"]
                data = database.sqlDataRetrieval.verifyAdminUser(username, session["sessionId"])
                if data is not None:
                    validPassword = bcrypt.check_password_hash(data[0], password)
                    if validPassword:
                        for name in requestList.keys():
                            if name in request.form:
                                textArea = request.form[name]
                                filename = database.dataCreation.convertCSVToSQL.createCSVForConversion(requestList[name],
                                                                                                        textArea)
                                sqlFile = database.dataCreation.convertCSVToSQL.convertCSVForWebApp(filename)
                                # print(sqlFile)
                                if sqlFile is not None:
                                    data = database.sqlDataRetrieval.wrapperForSQLFile("admin", sqlFile)
                                else:
                                    data = "error"
                                    logger.error(messages.requestToBulkAction % currentUserFailed)
                                message = messages.getMessage(name, data)
                                break
                else:
                    message = messages.adminErrorMsg
            return render_template('pages/adminDashboard.html', message=message)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/superadmin/DongleMgmt')
    @login_required
    def adminDongleManagement():
        global currentUser
        if current_user.is_authenticated and current_user.role == 'admin':
            logger.info(messages.atAdminDM % currentUser)
            data = database.sqlDataRetrieval.adminDongleManagement()
            return render_template('pages/adminDongleManagement.html', data=data)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    @app.route('/superadmin/MallMgmt', methods=['GET', 'POST'])
    @login_required
    def adminMallManagement():
        global currentUser
        if current_user.is_authenticated and current_user.role == 'admin':
            logger.info(messages.atAdminMM % currentUser)
            data = database.sqlDataRetrieval.adminMallManagement()
            currActiveStatus = {}
            newActiveStatus = {}
            for row in data:
                currActiveStatus[row[0]] = row[2]
            if request.method == 'POST':
                logger.info(messages.updateMall % currentUser)
                newActiveStatus = formToDict(request.form.to_dict())
                paddedNewActiveStatus = padDiffToDict(currActiveStatus, newActiveStatus)
                recordsToUpdate = list(set(paddedNewActiveStatus.items())-set(currActiveStatus.items()))
                for record in recordsToUpdate:
                    database.sqlDataRetrieval.adminUpdateMall(record[0], record[1])
                    # print(result)
            return render_template('pages/adminMallManagement.html', data=data)
        next = safe_redirect(request.args.get('next'), url_for('login'))
        return redirect(next or url_for('login'))

    # Utility function for adminMallManagement to covert form to Python dictionary
    def formToDict(form):
        newDict = {}
        for formItem in form:
            newDict[formItem] = 1
        return newDict

    # Utility function for adminMallManagement to reflect new status
    def padDiffToDict(curr, new):
        paddedDict = new
        for key in curr.keys():
            if key not in paddedDict:
                paddedDict[key] = 0
        return paddedDict

    @app.errorhandler(404)
    def pageNotFound(error):
        if current_user.is_authenticated:
            next = safe_redirect(request.args.get('next'), url_for('home'))
            return redirect(next or url_for('home'))
        else:
            next = safe_redirect(request.args.get('next'), url_for('login'))
            return redirect(next or url_for('login'))

    def editPasswordForm(username, currentPassword, password, confirmPassword):
        global currentUser
        requirement = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!#%*?&]{8,}$"
        regexPattern = re.compile(requirement)
        validPassword = re.search(regexPattern, password)

        # Check if the current password is correct
        data = database.sqlDataRetrieval.verifyUser(username)
        if data is not None:
            validCurrentPassword = bcrypt.check_password_hash(data[0], currentPassword)
        else:
            validCurrentPassword = False

        if username != current_user.name:
            logger.warning(messages.changeOthersPW % (username, session['username'], session['role']))
            return ['Error', 'You can only change your own password']
        elif password != confirmPassword:
            logger.info(messages.diffPW % currentUser)
            return ['Error', 'Passwords do not match']
        elif not validCurrentPassword:
            return ['Error', 'Current password is incorrect']
        elif not validPassword:
            logger.info(messages.failPWreq % currentUser)
            return ['Error',
                    '''New password does not meet password requirements: at least 1 uppercase, 1 lowercase,
                    1 numeric, 1 special character, and 8 characters long''']
        else:
            newHash = (bcrypt.generate_password_hash(password)).decode('utf-8')
            database.sqlDataRetrieval.changePassword(current_user.role, username, newHash)
            logger.info(messages.successfulChangePW % currentUser)
            return ['Message', 'Password updated successfully']

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        error = "Error: The CSRF token is missing or invalid."
        return error

    @app.errorhandler(429)
    def too_many_requests(error):
        error = "Error: Too many requests! Please try again later."
        return error

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(ssl_context=('cert.pem', 'key.pem'))
