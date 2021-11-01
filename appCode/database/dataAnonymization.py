import csv
from os import remove
import database.sqlDataRetrieval as sqlRetrieval
import database.dataCreation.convertCSVToSQL as convertToSQL
from datetime import date
from string import ascii_letters, digits
from random import *
IDList = []
secondLevelIDList = []
chosenID = []
mappingDict = {}
sqlStatements = []
anonymiseFilename = "./dataAnonymise.sql"

def writeToCSV(dataset, type):
    """
    This function creates a CSV file for the researcher.

    :param dataset: The data to write into CSV file.
    """

    headersList = {"demographic" : ["DOB", "zipcode", "test", "latestDate", "test_status", "vac_type", "vac_timestamp"], 
                   "accessLogs" : ["test", "latestDate", "test_status", "vaccination_status", "mall_name", "mall_zipcode", "timestamp", "access_status"]}

    header = headersList[type]
    today = date.today()
    fileName = "accessTogether-" + today.strftime("%b-%d-%Y") + ".csv"
    with open(fileName, 'w', encoding='UTF8', newline='') as file:
        writer = csv.writer(file)
        # write the header
        writer.writerow(header)
        # write the data
        for row in dataset:
            writer.writerow(row)

def getRangeFromAge(age):
    """
    This function return an age from the given range.

    :param age: Age derived from the database
    :return new age
    """
    divisibleBy10 = age % 10
    if (divisibleBy10 == 0):
        return age - 5
    else:
        return int(age / 10)*10 + 5

def getAgeFromDOB(DOB):
    """
    This function return the age from the date of birth.

    :param DOB: The date of birth retrieved from the database
    :return age: The age based on the date of birth
    """
    today = date.today()
    age = today.year - DOB.year - ((today.month, today.day) < (DOB.month, DOB.day))
    return getRangeFromAge(age)

def changeDOBToAge(dataset):
    """
    This is the main function to convert DOB of each user to an age range

    :param dataset: dataset from the database
    :return newData: new anonymised dataset
    """
    newData = []

    for row in dataset:
        age = getAgeFromDOB(row[0])
        newData.append((age, row[1], row[2], row[3], row[4], row[5], row[6]))
    return newData    