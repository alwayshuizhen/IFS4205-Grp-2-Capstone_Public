# login related error/ info messages
loginErrorMsg = 'Invalid username or password. Please try again.'
loginDongleErrorMsg = 'Invalid token. Please try again.'
loginFaceRegErrorMsg = 'Facial recognition failed. Please try again.'
loginTooManyAttemptsMsg = 'Error: Too many tries. Please try again later.'
adminErrorMsg = 'Invalid credentials. Please try again.'

# Logging messages
startServer = "Server is starting, preparing application now"
verifyUserCred = "Verifying %s's login attempt as %s"
passwordLogin = "Password stage of 3FA %s for %s as %s"
dongleLogin = "Dongle stage of 3FA %s for %s as %s"
faceRecogLogin = "Face Recognition stage of 3FA %s for %s as %s"
logout = "User %s as %s has logged out"
atHomePg = "User %s as %s is at /home"
atProfilePg = "User %s as %s is at /user"
resultOfChangePassword = "Attempt to change password %s by %s as %s"
updateOfConsent = "Consent has been updated by % as %s"
atDashboard = "User %s as %s is at /%s/dashboard"
requestExport = "Exportation of data has been requested by %s as %s"
atAdminProfile = "User %s as %s is at /superadmin"
atAdminAC = "User %s as %s is at /superadmin/AC"
requestToBulkAction = "Create CSV for conversion %s by %s as %s"
atAdminDM = "User %s as %s is at /superadmin/DongleMgmt"
atAdminMM = "User %s as %s is at /superadmin/MallMgmt"
updateMall = "Mall receivers has been updated by %s as %s"
changeOthersPW = "Attempt to change %s's password by %s as %s"
diffPW = "Difference in password request in password change by %s as %s"
failPWreq = "Did not meet password requirement when changing by %s as %s"
successfulChangePW = "Password has been changed successfully by %s as %s"

def getConsentMessage(counter):
    if counter == 5:
        return "The status remains the same!"
    else:
        return "Status has been changed!"


def getMessage(name, data):
    messageDict = {
        "vaccination": [
            "Vaccination logs have been inserted successfully!",
            "There has been an error in insertion of vaccination logs!"],
        "testQuarantine": [
            "Test and Quarantine logs have been inserted successfully!",
            "There has been an error in insertion of test and quarantine logs!"],
        "createUser": [
            "All the users have been inserted successfully!",
            "There has been an error in insertion for creation of users!"],
        "updateDongles": [
            "All dongles have been updated successfully!",
            "There has been an error in update of dongles!"],
        "userRole": [
            "All roles have been updated successfully!",
            "There has been an error in the update of user roles!"]}
    if name in messageDict.keys():
        if data != "error":
            return messageDict[name][0]
        else:
            return messageDict[name][1]
