import database.sshConnection
import database.crypto
LIMIT = 50

def wrapper(role, sql, sqlData, type):
    """Runs a given SQL query via the global database connection
    and returns the dataset of the SQL.
    
    :param role: public/ staff/ admin
    :param sql: MySQL query
    :param type: expecting one or many rows
    :return data: Rows of results in list
    """

    database.sshConnection.openSSHTunnel(role)
    database.sshConnection.mysqlConnect()
    data = database.sshConnection.runQuery(sql, sqlData, type)
    database.sshConnection.mysqlDisconnect()
    database.sshConnection.closeSSHTunnel()
    return data

def wrapperForSQLFile(role, sqlFile, type=None):
    """
    Runs all the SQL queries in the stated sqlFile via the global 
    database connection. 

    :param role: public/ staff/ admin
    :param sqlType: MySQL file containing SQL queries
    :param type: None, as no results are to be expected
    """
    data = None
    database.sshConnection.openSSHTunnel(role)
    database.sshConnection.mysqlConnect()
    with open(sqlFile, "r") as readFile:
        for line in readFile:
            data = database.sshConnection.runQuery(line, None, type)
            if data == "error":
                return data
    database.sshConnection.mysqlDisconnect()
    database.sshConnection.closeSSHTunnel()

# ----- CODE FOR ANY USER ----- #

def updateDongleAuth_valid(role, dongle_name, dongle_number, dongle_id):
    """Change the dongle auth status of the user to valid

    :param role: dongle
    :param dongle_name: dongle's name stored on dongle
    :param dongle_number: dongle's phone number stored on dongle
    :param dongle_id: dongle's id stored on dongle
    :return data: None on successful execution, 'error' otherwise
    """
    sql = """UPDATE webapp_users SET dongle_auth = %s WHERE username IN (SELECT username FROM dongle WHERE name = %s and phone_num = %s);"""
    sqlData = (dongle_id, dongle_name, dongle_number)
    data = wrapper(role, sql, sqlData, None)
    return data

def updateDongleAuth_reset(username):
    """reset the dongle auth status of the user to 0 after validation is done

    :param role: dongle
    :param dongle_name: dongle's name stored on dongle
    :param dongle_number: dongle's number stored on dongle
    :return data: None on successful execution, 'error' otherwise
    """
    sql = """UPDATE webapp_users SET dongle_auth = 0 WHERE username = %s;"""
    sqlData = (username)
    data = wrapper('dongleMan', sql, sqlData, None)
    return data

def changePassword(role, username, newHash):
    """Change the password of the user

    :param role: public/ staff/ admin
    :param username: the current user
    :param newHash: new hash of the password to be set
    :return data: None on successful execution, 'error' otherwise
    """
    encryptedInfo = database.crypto.encrypt(newHash, database.crypto.password)

    sql = """UPDATE webapp_users SET password = %s WHERE username = %s;"""
    sqlData = (encryptedInfo, username)
    data = wrapper(role, sql, sqlData, None)
    return data

def verifyUser(username):
    """Check that user exists. Returns a row when true, zero otherwise

    :param username: the current user
    :param password: user's password
    :return data: a row on the user's username and role if exist, else no row is returned
    """
    sql = """SELECT * FROM appUsers WHERE username = %s;"""
    sqlData = username
    data = wrapper('public', sql, sqlData, 'one')
    
    if data is not None and data is not "error":
        storedHash = data[1]
        decryptedInfo = database.crypto.decrypt(storedHash)
        renewHash(decryptedInfo, username)
        return (decryptedInfo, data)

def renewHash(decryptedInfo, username):
    """Re-encrypt the hash to store in the database

    :param decryptedInfo: the decrypted hash
    :param username: user's username
    :return data: None on successful execution, 'error' otherwise
    """
    encryptedInfo = database.crypto.encrypt(decryptedInfo, database.crypto.password)
    sql = """UPDATE webapp_users SET password = %s WHERE username = %s;"""
    sqlData = (encryptedInfo, username)
    data = wrapper('public', sql, sqlData, None)
    return data

def logCredentialsCheck(sessionId, username, role, validCredentials, loginSuccess):
    """Log the first FA of the login process

    :param sessionId: current session ID
    :param username: username used for login
    :param role: role used for login
    :param validCredentials: validity of user credentials
    :loginSuccess: To indicate the start of login attempt
    :return data: None on successful execution, 'error' otherwise
    """
    sql = """INSERT INTO login_log (session_id, username, rolename, login_time, is_valid_pw, is_successful) 
    VALUES (%s, %s, %s, NOW(), %s, %s);"""
    sqlData = (sessionId, username, role, validCredentials, loginSuccess)
    data = wrapper('public', sql, sqlData, None)
    return data

def logDongleCheck(sessionId, username, validDongle):
    """Log the second FA of the login process

    :param sessionId: current session ID
    :param username: user's username
    :param validDongle: validity of dongle
    :return data: None on successful execution, 'error' otherwise
    """
    sql = """UPDATE login_log SET is_valid_dongle = %s
    WHERE session_id = %s AND username = %s;"""
    sqlData = (validDongle, sessionId, username)
    data = wrapper('public', sql, sqlData, None)
    return data
    
def logFacialRegCheck(sessionId, username, validFacialReg, loginSuccess):
    """Log the third FA of the login process

    :param sessionId: current session ID
    :pram username: user's username
    :param validFacialReg: validity of facial recognition
    :param loginSuccess: validity of login attempt
    :return data: None on successful execution, 'error' otherwise
    """
    sql = """UPDATE login_log SET is_valid_faceRecog = %s, is_successful = %s
    WHERE session_id = %s AND username = %s;"""
    sqlData = (validFacialReg, loginSuccess, sessionId, username)
    data = wrapper('public', sql, sqlData, None)
    return data

def logLogoutTime(sessionId, username):
    """Log the logout time

    :param sessionId: current session ID
    :param username: user's username
    :return data: None on successful execution, 'error' otherwise
    """
    sql = """UPDATE login_log SET logout_time = NOW() WHERE session_id = %s AND username = %s;"""
    sqlData = (sessionId, username)
    data = wrapper('public', sql, sqlData, None)
    return data

def getLoginAttemptCount(username):
    """Retrieve the number of failed login attempts

    :param username: username used for login
    :return data: the count on number of failed attempts by this username
    """
    sql = """SELECT COUNT(*) FROM login_log 
    WHERE username = %s AND login_time >= (NOW() - INTERVAL 5 MINUTE) 
    AND is_valid_pw = %s and ISNULL(logout_time);"""
    sqlData = (username, 0)
    data = wrapper('public', sql, sqlData, 'one')
    return data

def getProfile(username):
    """Retrieve profile information such as photo file name and phone number
    
    :param username: the current user
    :return data: a row on the user's information
    """
    sql = """SELECT name, phone_num, photo_link, test_log, vaccination_log, visitation FROM userProfile WHERE username=%s LIMIT 1;"""
    sqlData = username
    data = wrapper('public', sql, sqlData, 'one')
    return data

def getDongleId(username):
    """Retrieves dongle ID
    
    :param username: the current user
    :return data: a row on the user's dongle id
    """
    sql = """SELECT dongle_id FROM dongle WHERE username = %s AND is_active = %s;"""
    sqlData = (username, 1)
    data = wrapper('public', sql, sqlData, 'one')
    return data

def getDongleIdCheckIn(name, phoneNum):
    """Retrieves dongle ID for check in

    :param name: name of user checking in
    :param phoneNum: phone number of user checking in
    :return data: a row on the user's dongle id
    """
    sql = """SELECT dongle_id FROM dongle WHERE name = %s AND phone_num = %s AND is_active = %s;"""
    sqlData = (name, phoneNum, 1)
    data = wrapper('public', sql, sqlData, 'one')
    return data

def getDongleAuth(username):
    """Retrieve value stored in dongle_auth
    
    :param username: the current user
    :return data: the value stored in dongle_auth
    """
    sql = """SELECT dongle_auth FROM webapp_users WHERE username = %s;"""
    sqlData = (username)
    data = wrapper('public', sql, sqlData, 'one')
    return data

def getProfileImgLink(username):
    """Retrieve profile image
    
    :param username: the current user
    :return data: a row of the user's image filename
    """
    sql = """SELECT photo_link FROM userProfile WHERE username=%s LIMIT 1;"""
    sqlData = username
    data = wrapper('public', sql, sqlData, 'one')
    return data

def getCurrentLoginInfo(sessionId):
    """Retrieve information from login process

    :param sessionId: unique id to identify the login
    :return data: a row of the current login attempt details
    """
    sql = """SELECT * FROM login_log WHERE session_id = %s;"""
    sqlData = sessionId
    data = wrapper('public', sql, sqlData, 'one')
    return data

def getProfileImgLink_checkIn(name, phoneNum):
    """Retrieve image of user checking in
    
    :param name: name of user checking in
    :param phoneNum: phone number of user checking in
    :return data: a row of the user's image filename
    """
    sql = """SELECT photo_link FROM userProfile WHERE name=%s AND phone_num=%s LIMIT 1;"""
    sqlData = (name, phoneNum)
    data = wrapper('public', sql, sqlData, 'one')
    return data

# ----- CODE FOR PUBLIC USER ----- #

def publicDashboardHistory(username):
    """Extracts the recent entry logs of the currently logged in user,
    count subjected to LIMIT

    :param username: the current user
    :return data: rows of entry logs
    """

    sql = """SELECT mall_name, access_status, timestamp FROM publicDashboardHistory WHERE username = %s 
            ORDER BY entry_id DESC LIMIT %s"""
    sqlData = (username, LIMIT)      
    data = wrapper('public', sql, sqlData, 'many')
    return data


def publicGetUser(username):
    """Get the user's name

    :param username: the current user
    :return data: user's name
    """
    sql = """SELECT name FROM getName WHERE username = %s"""
    sqlData = username
    data = wrapper('public', sql, sqlData, 'one')
    return data

def getUserInfo(photo_link):
    """Get name and phone number of user checking in

    :param photo_link: photo link of user checking in
    :return data: name and phone number of user checking in
    """
    sql = """SELECT name, phone_num FROM userProfile WHERE photo_link = %s;"""
    sqlData = photo_link
    data = wrapper('public', sql, sqlData, 'one')
    return data

# ----- CODE FOR STAFF USER ----- #

def getAccessStatus(name, phoneNum):
    """Get access status of user checking in

    :param name: name of user checking in
    :param phoneNum: phone number of user checking in
    :return data: access status of user checking in
    """
    sql = """SELECT status FROM access WHERE name = %s AND phone_num = %s;"""
    sqlData = (name, phoneNum)
    data = wrapper('staff', sql, sqlData, 'one')
    return data

def logCheckInRecord(name, phoneNum, accessStatus, receiver_id):
    """Log the access status when user checking in

    :param name: name of user checking in
    :param phoneNum: phone number of user checking in
    :param accessStatus: access of user checking in if allowed or denied
    :return data: None on successful execution, 'error' otherwise
    """
    sql = """SELECT MAX(entry_id) FROM entry_log;"""
    sqlData = None
    numberOfEntries = wrapper('staff', sql, sqlData, 'one')
    newEntryId = numberOfEntries[0] + 1

    sql = """INSERT INTO entry_log VALUES (%s, NOW(), %s);"""
    sqlData = (newEntryId, accessStatus)
    data = wrapper('staff', sql, sqlData, None)

    sql = """INSERT INTO visitation VALUES (%s, %s, %s, %s);"""
    sqlData = (name, phoneNum, receiver_id, newEntryId)
    data = wrapper('staff', sql, sqlData, None)

    return data

def getActiveLocation(location):
    """Retrieve if receiver_id is currently active

    :param location: location that receiver is at
    :return data: return the active status of the receiver
    """
    sql = """SELECT is_active FROM location WHERE receiver_id = %s;"""
    sqlData = location
    data = wrapper('staff', sql, sqlData, 'one')
    return data

# ----- CODE FOR ADMIN USER ----- #

def adminRecentDeniedEntries():
    """Extracts list of denied entries sorted by the most recent records,
    count subject to LIMIT

    :return data: rows of denied entries 
    """
    
    sql = """SELECT * FROM adminRecentDeniedEntries LIMIT %s;"""
    sqlData = LIMIT
    data = wrapper('admin', sql, sqlData, 'many')
    return data

def adminAccessControl():
    """Extracts list of users and their roles, count subjected to LIMIT

    :return data: rows of users and their roles
    """

    sql = """SELECT * FROM adminAccessControl LIMIT %s;"""
    sqlData = LIMIT
    data = wrapper('admin', sql, sqlData, 'many')
    return data

def adminDongleManagement():
    """Extracts list of currently in-use dongles, count subjected to LIMIT

    :return data: rows of dongles
    """
    sql = """SELECT * FROM adminDongleManagement LIMIT %s;"""
    sqlData = LIMIT
    data = wrapper('admin', sql, sqlData, 'many')
    return data

def adminMallManagement():
    """Extracts list of mall and their receiver id

    :return data: rows of malls
    """

    sql = """SELECT * FROM adminMallManagement;"""
    data = wrapper('admin', sql, None, 'many')
    return data

def adminUpdateMall(receiverId, isActive):
    """Updates the location table base on the availability of receivers
    
    :return data: None
    """
    sql = """UPDATE location SET is_active = %s WHERE receiver_id = %s;"""
    sqlData = (isActive, receiverId)
    data = wrapper("admin", sql, sqlData, None)
    return data


def insertConsentLogForUser(name, phoneNum, consentTable, consentStatus):
    """
    Insert into the consent table based on the user's preference 

    :return data: List of consent logs
    """
    sql = """INSERT INTO consent VALUES(%s, %s, %s, %s, NOW());"""
    sqlData = (name, phoneNum, consentTable, consentStatus)
    data = wrapper("public", sql, sqlData, None)
    return data

def verifyAdminUser(username, currentSession):
    """Check that this user with admin privileges exists. Returns a row when true, zero otherwise

    :param username: the current user
    :param password: user's password
    :return data: a row on the user's username and password if exist, else no row is returned
    """
    sql = """SELECT * FROM appUsers WHERE username = %s and rolename = %s and username NOT IN (SELECT username FROM login_log WHERE session_id=%s);"""

    sqlData = (username, 'admin', currentSession)
    data = wrapper('public', sql, sqlData, 'one')
    
    if data is not None and data is not "error":
        storedHash = data[1]
        decryptedInfo = database.crypto.decrypt(storedHash)
        renewHash(decryptedInfo, username)
        return (decryptedInfo, data)
    else: 
        return data

# ----- CODE FOR CONTACT TRACER USER ----- #

def ctViewDeniedEntries():
    """
    Extracts the list of entry logs for contact tracers' viewing
    
    :return data: List of entry logs
    """
    sql = """SELECT * FROM ctViewDeniedEntries WHERE DATE(timestamp) = DATE_SUB(CURDATE(), INTERVAL 20 DAY);""" # Change to 1 Day 
    data = wrapper('contacttracer', sql, None, 'many')
    return data

# ----- CODE FOR RESEARCHER USER ----- #

def getNumberOfUsers():
    """
    Extracts the number of users

    :return data: Number of users in the database
    """
    sql = """SELECT * FROM numUsers;"""
    data = wrapper('researcher', sql, None, 'one')
    return data[0] 

def getDemographic():
    """
    Extracts the demographic of different users

    :return data: Demographic of different users
    """
    #sql = """SELECT DISTINCT username, DOB, zipcode, test, latestDate, test_status, vaccination_status FROM getEntryLogs;"""

    sql = """SELECT DOB, zipcode, test, latestDate, test_status, type, (CASE WHEN (totalCount = 0) THEN NULL WHEN(totalCount = 1) THEN (CASE WHEN (latestDate < v2_time) THEN NULL ELSE v2_time END) ELSE (CASE WHEN (latestDate < v2_time) THEN NULL WHEN (latestDate > v3_time) THEN v3_time ELSE v2_time END) END) AS vac_timestamp  FROM getDemographic;"""
    data = wrapper('researcher', sql, None, 'many')
    return data

def getAccessLogs():
    """
    Extracts access logs

    :return data: access logs
    """
    sql = """SELECT test, latestDate, test_status, vaccination_status, mall_name, mall_zipcode, timestamp, access_status FROM getEntryLogs;"""
    data = wrapper('researcher', sql, None, 'many')
    return data
