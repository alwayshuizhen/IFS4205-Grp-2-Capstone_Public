
#include <RFduinoBLE.h>
boolean connected = false;

void setup() {
  
  Serial.begin(9600);

  RFduinoBLE.deviceName = "IFS4205"; // Daisy's dongle
  // start the BLE stack
  RFduinoBLE.begin();
  
}

void loop() {
  // switch to lower power mode
  RFduino_ULPDelay(INFINITE);

  while(connected) 
    {
      RFduinoBLE.send("hello!",6);
      delay(2000);
     }
    
}

void RFduinoBLE_onAdvertisement(bool start)
{

  RFduinoBLE.advertisementData = "Daniel";
  
  if (start)
    Serial.print("Advertisement: start\n");
  else
    Serial.print("Advertisement: stop\n");
}

void RFduinoBLE_onConnect()
{
    Serial.print("Connect: start\n");
    connected = true;

}

void RFduinoBLE_onDisconnect()
{
    connected = false;
    Serial.print("Connect: stop\n");
}