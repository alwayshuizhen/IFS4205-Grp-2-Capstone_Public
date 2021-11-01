/*
The sketch demonstrates a simple echo BLE device
*/

#include <RFduinoBLE.h>
#include <Crypto.h>
#include <Curve25519.h>
#include <RNG.h>
#include <string.h>


bool rssidisplay;

const char * myid = "IFS4205";         

char key_transfer[100];
char scanner_key[64];
 int scanner_key_index = 0;

static uint8_t alice_k[32];
static uint8_t alice_f[32];
int receive_count = 0;


void setup() {
   RFduinoBLE.advertisementData = "Contact tracing";
   RFduinoBLE.deviceName = myid;           // Specify BLE device name
   RFduinoBLE.begin();                            // Start the BLE stack
   Serial.begin(9600);                            // Debugging to the serial port
   Serial.print(myid); 
   Serial.println(" device restarting..."); 
   
}

// Convert to hex, saves key into key_transfer
void printNumber(const char *name, const uint8_t *x)
{ 
    int i = 0;
    static const char hexchars[] = "0123456789ABCDEF";
    Serial.print(name);
    Serial.print(" = ");
    for (uint8_t posn = 0; posn < 32; ++posn) {
        Serial.print(hexchars[(x[posn] >> 4) & 0x0F]);
        key_transfer[i++] = hexchars[(x[posn] >> 4) & 0x0F];
        
        Serial.print(hexchars[x[posn] & 0x0F]);
        key_transfer[i++] = hexchars[x[posn] & 0x0F];
    }
    Serial.println();
}

void RFduinoBLE_onConnect() {
   Serial.println("Start connection..."); 
   rssidisplay = true;
}

void RFduinoBLE_onDisconnect() {
   Serial.println("Disconnection..."); 
}

void RFduinoBLE_onReceive(char *data, int len) { 

  // Prepare to receive 4 packets (max receive is 20 bytes) for scanner key
   data[len] = 0;
   int in_buf_index = 0;
  
   Serial.println("\n\nReceived: ");
    
   if (receive_count < 3) {
    Serial.print("packet number: ");
    Serial.println(receive_count);
    for (int i = 0; i < 20; i++){
      scanner_key[scanner_key_index++] = data[i];
    }
 
   }

   // Save last 4 bytes and carry on protocol to send over dongle key
   if (receive_count == 3) {
    Serial.print("packet number: ");
    Serial.println(receive_count);
    for (int i = 0; i < 4; i++){
      Serial.print(data[i]);
      scanner_key[scanner_key_index++] = data[i];
    }

    // Setting last byte as terminator
    scanner_key[scanner_key_index] = '\0';

    
    if (scanner_key_index == 64) {
      Serial.println(scanner_key);
      generate_DH();
      Serial.println("Sending public key");
      send_64(key_transfer);
    } else {

      Serial.println("Error: Did not process 64 bytes of key");
    }
    
   }

   receive_count++;

}

void RFduinoBLE_onRSSI(int rssi) { 
   if (rssidisplay) {
      Serial.print("RSSI is "); 
      Serial.println(rssi);                        // print rssi value
      rssidisplay = false;
   }
}


//void testDH(uint8_t bob_k[32])

// Sending in bytes of 20 due to maximum sending buffer
void send_64( char *to_send)
{

     
  // RFduinoBLE.send(key_transfer,64);
  
  // split into 20 byte packets
  char out_buf[20];
  int out_buf_index = 0;
  
  for (int i = 0; i < 64; i++)
  {
      out_buf[out_buf_index++] = to_send[i];
  
      if (out_buf_index == 20) {
        RFduinoBLE.send(out_buf,20);
        out_buf_index = 0;
      }
  
      if (i == 63) {
        RFduinoBLE.send(out_buf,4);
      }
  
    }
}

void generate_DH()
{

    char print_value[100];

    Serial.println("\nDiffie-Hellman key exchange:");
    Serial.print("Generate random k/f for Alice ... ");
    Serial.flush();
    unsigned long start = micros();
    Curve25519::dh1(alice_k, alice_f);
    unsigned long elapsed = micros() - start;
    Serial.print("elapsed ");
    Serial.print(elapsed);
    Serial.println(" us");

    Serial.println("Generate shared secret for Alice ... ");
    Serial.flush();
    start = micros();
    
    /*Curve25519::dh2(bob_k, alice_f);
    elapsed = micros() - start;
    Serial.print("elapsed ");
    Serial.print(elapsed);
    Serial.println(" us");
    */
    Serial.println("Dongle key:");
    printNumber(print_value,alice_k);


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