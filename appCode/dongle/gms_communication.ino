/*
The sketch demonstrates a simple echo BLE device
*/

#include <RFduinoBLE.h>

bool rssidisplay;

const char * myid = "Thing0006";         

void setup() {
   RFduinoBLE.advertisementData = "echo";
   RFduinoBLE.deviceName = myid;           // Specify BLE device name
   RFduinoBLE.begin();                            // Start the BLE stack
   Serial.begin(9600);                            // Debugging to the serial port
   Serial.print(myid); 
   Serial.println(" device restarting..."); 
}

void RFduinoBLE_onConnect() {
   Serial.println("Start connection..."); 
   rssidisplay = true;
}

void RFduinoBLE_onDisconnect() {
   Serial.println("Disconnection..."); 
}

void RFduinoBLE_onReceive(char *data, int len) { 
   data[len] = 0;
   Serial.print("Received: ");
   Serial.print(data);
   Serial.println("...And sending back an echo with my ID.");
   RFduinoBLE.send("Echo from ",10);
   RFduinoBLE.send(myid,strlen(myid));
   RFduinoBLE.send(": ",2);
   RFduinoBLE.send(data,len);
}

void RFduinoBLE_onRSSI(int rssi) { 
   if (rssidisplay) {
      Serial.print("RSSI is "); 
      Serial.println(rssi);                        // print rssi value
      rssidisplay = false;
   }
}

int dotcount=0;

void loop() {
   RFduino_ULPDelay( SECONDS(0.5) );                // Ultra Low Power delay for 0.5 second
   dotcount++;
   if (dotcount<40) {
      Serial.print("."); 
   } else {
      Serial.println();
      dotcount=0;
   }
}
