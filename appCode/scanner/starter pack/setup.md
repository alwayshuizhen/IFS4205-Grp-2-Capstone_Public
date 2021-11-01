
* To install the RFduino (now end-of-life) environment, needed to program the GMS, use the idea here:
     (From https://forum.arduino.cc/t/is-it-possible-to-install-support-for-rfduino-manually/586243)
     Which involves putting this URL in the Arduino preferences:
         https://gist.github.com/per1234/f7822073e05276c4243740eaab4235d1/raw/9c34051294ddd54dbbdf3bec392df0afef8da938/package_rfduino166_index.json
     And then starting the Board Manager, selecting RFduino and installing it
      
* You need to install python prerequisites pip3 and adafruit_ble:
     python -m pip install --upgrade pip
     pip3 install --upgrade adafruit-blinka-bleio adafruit-circuitpython-ble
     And then you need to put this file in the python ble service area: The location will
     be different on OSX, Windows and Linux, but it is the same directory that contains nordic.py:
         cp gmsservice.py  /opt/homebrew/lib/python3.9/site-packages/adafruit_ble/services/ (for my MAC)
     Possibly
        copy gmsservice.py  C:\Users\hugh\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.9_qbz5n2kfra8p0\LocalCache\local-packages\Python39\site-packages\adafruit_ble\services
        or copy gmsservice.py C:\Users\hugh\AppData\Local\Packages\PythonSoftwareFoundation.Python.3.8_qbz5n2kfra8p0\LocalCache\local-packages\Python38\site-packages\adafruit_ble\services

* Check you can see BLE devices, and ping them with the two demo programs:
     python3 scanner.py
     python3 pinger.py

* Debugging - you can use your phones or your PCs:
     Android: Bluefruit connect or BLE Scanner OR nRF connect for mobile   
     OSX: Developer tools and BlueSee
     Windows: Bluetooth LE Lab?
   
* There are some docs in the Docs directory

*https://support.arduino.cc/hc/en-us/articles/360016495679-Error-opening-serial-port-Linux-

* Use arduino 1.6.x

* Works rfduino works best responding to data rather than transmitting first
     * Treat things like events than a loop

* https://github.com/DavyLandman/AESLib for the AES encryption because the crypto lib does not have CBC - does not work

* Fix the existing library by adding required files in crypto folder from this verion on git: https://github.com/rweather/arduinolibs. Then, manually extract the CBC + CryptoLegacy file and put into main crypto lib

* using default hmac library and hmac instance within arduino crypto library