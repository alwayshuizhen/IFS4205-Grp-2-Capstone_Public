# IFS4205-Grp-2-Capstone_Public
This project contains the development of a system to manage access of the public into various locations, such as malls, in a safe and secure manner during times of a pandemic. This system will be equipped with Bluetooth Low Energy (BLE) dongles, facial recognition, and a web interface component. The team will also be designing a secure protocol for communications between the dongle and verification service.  The focus of the system is to combat technical social engineering methods from trained adversaries and more rudimentary crime such as impersonation or theft of physical dongles, by ensuring that the information stored in the dongles cannot be duplicated / replicated / forged.

## System Tech Stack
Type | Tool Name
-----|----------
Operating System of Servers | ![Ubuntu](https://img.shields.io/badge/Ubuntu-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)
Database Server | ![MySQL](https://img.shields.io/badge/MySQL-005C84?style=for-the-badge&logo=mysql&logoColor=white)
Dongle | Bluetooth Low Energy
Facial Recognition | ![OpenCV](https://img.shields.io/badge/OpenCV-27338e?style=for-the-badge&logo=OpenCV&logoColor=white)
Application Framework / Server | ![Flask](https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white)
Source Code Management | ![Github](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)
Continuous Integration | ![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=github-actions&logoColor=white)

## Accessing the Web Application

Please visit Access Together [here](https://4205-grp2-1.comp.nus.edu.sg/login)

## Navigating this repository

* `appCode` folder: contains all code related to web application and integration with dongle
* `userGuides` folder: contains all the how-to guides for the various roles. More info in folder `README`
* `securityClaims.pdf` file: the list of security claims

## Counter claim Format
```
Counter claim against claim : #(please indicate which security claim)
Description: (what is the bug/ issue that may have breached the security claim)
Reproduction: (what were the steps taken to produce a breach in security)
```