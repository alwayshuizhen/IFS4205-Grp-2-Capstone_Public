/*
The sketch demonstrates a simple echo BLE device
*/


#include <CryptoLegacy.h>
#include <AES.h>
#include <CBC.h>


#include <RFduinoBLE.h>
#include <Crypto.h>
#include <Curve25519.h>
#include <RNG.h>
#include <string.h>

const int BUFF_SIZE = 20;
const int IV_SIZE = 16;
const int KEY_SIZE = 32;
const int MAX_SEND_SIZE = 64;

const uint8_t dongle_data[64] = {0x44,0x61,0x69,0x73,0x79,0x20,0x74,0x68,0x65,0x20,0x46,0x6c,0x6f,
          0x77,0x65,0x72,0x2e,0x35,0x35,0x35,0x35,0x35,0x35,0x35,0x35,0x2e,0x4f,0xf7,0x9b,0x49,
          0x77,0x18,0x3e,0xe6,0xc1,0xb9,0x18,0x49,0x5d,0x09,0x0f,0x3d,0xee,0x4c,0xc0,0x4e,0xc4,
          0x39,0x14,0xcc,0x95,0x1d,0xd9,0xd9,0x69,0x06,0x75,0xc6,0x59,0x2a,0x2b,0x7c,0xec,0x8e};

bool rssidisplay;

const char * myid = "IFS4205";         

char key_transfer[100];
char scanner_key[64];
int scanner_key_index = 0;
char shared_secret[100];

static uint8_t bob_k[32];
static uint8_t alice_k[32];
static uint8_t alice_f[32];

int receive_count = 0;
char receive_data[100];
int receive_data_index;

char * ciphertext_hex;


void setup() {
   RFduinoBLE.advertisementData = "Contact tracing";
   RFduinoBLE.deviceName = myid;           // Specify BLE device name
   RFduinoBLE.begin();                            // Start the BLE stack
   Serial.begin(9600);                            // Debugging to the serial port
   Serial.print(myid); 
   Serial.println(" device restarting..."); 
   
}

// converts hex to byte int and returns it 
uint8_t* hex_to_uint8(char * input, int len){
  //Serial.println(input);
  static uint8_t hex_to_uint8_buff[256];
  int buff_counter = 0;
  
  for (int i = 0; i < len-1; i+=2){
    char temp[3];
    temp[0] = input[i];
    temp[1] = input[i + 1];
    temp[2] = '\0';
    //Serial.println(strtol(temp, NULL, 16));
    uint8_t output = strtol(temp, NULL, 16);
    hex_to_uint8_buff[buff_counter++] = output;
    
  }
 
  //Serial.println("\n hex_to_uint8: ");
  //print_uint8_as_hex(result,len/2);

  return hex_to_uint8_buff;
}


// prints but does not save final hex

void print_uint8_as_hex( uint8_t *x, int len)
{ 
    int i = 0;
    static const char hexchars[] = "0123456789ABCDEF";
  
    for (uint8_t posn = 0; posn < len; ++posn) {
        Serial.print(hexchars[(x[posn] >> 4) & 0x0F]);
        Serial.print(hexchars[x[posn] & 0x0F]);
    }
    Serial.println();
}


// save final hex

char * uint8_to_hex( uint8_t *x, int len)
{     
  
    static char uint8_to_hex_buff[256];
    int uint8_to_hex_buff_counter = 0;
    
    static const char hexchars[] = "0123456789ABCDEF";
  
    for (uint8_t posn = 0; posn < len; ++posn) {
        ///Serial.print(hexchars[(x[posn] >> 4) & 0x0F]);
        uint8_to_hex_buff[uint8_to_hex_buff_counter++] = hexchars[(x[posn] >> 4) & 0x0F];
        
        //Serial.print(hexchars[x[posn] & 0x0F]);
        uint8_to_hex_buff[uint8_to_hex_buff_counter++] = hexchars[x[posn] & 0x0F];

    }
    uint8_to_hex_buff[uint8_to_hex_buff_counter] = '\0';

    return uint8_to_hex_buff;

}


// Convert byte to hex, saves key into key_transfer
// quick transfer of 32 byte keys

void store_key_transfer(const uint8_t *x)
{ 
    int i = 0;
    static const char hexchars[] = "0123456789ABCDEF";
  
    for (uint8_t posn = 0; posn < 32; ++posn) {
        Serial.print(hexchars[(x[posn] >> 4) & 0x0F]);
        key_transfer[i++] = hexchars[(x[posn] >> 4) & 0x0F];
        
        Serial.print(hexchars[x[posn] & 0x0F]);
        key_transfer[i++] = hexchars[x[posn] & 0x0F];
    }
    Serial.println();
}

// sends data over to Scanner
// maximum working len is 64

void send_byte( char *to_send, int len)
{
  // RFduinoBLE.send(key_transfer,64);
  
  // split into 20 byte packets
  char out_buf[20];
  int out_buf_index = 0;
  
  while (out_buf_index < len) {
    if (len - out_buf_index < BUFF_SIZE) {
      RFduinoBLE.send(&(to_send[out_buf_index]), len - out_buf_index);
      break;
    }
    RFduinoBLE.send(&(to_send[out_buf_index]), 20);
    
    out_buf_index+=20;
  }
  
}


void RFduinoBLE_onConnect() {
   Serial.println("Start connection..."); 
   rssidisplay = true;
}

void RFduinoBLE_onDisconnect() {
   Serial.println("Disconnection..."); 
   receive_count = 0; // reset the protocol per new connection
   scanner_key_index = 0;
   receive_data_index = 0;
}


// have to keep a running count of the receive 

void RFduinoBLE_onReceive(char *data, int len) { 

    // prepare to receive 4 packets (max receive is 20 bytes) for scanner key
    // receive_count 0 - 3: sacanner public key
      
    if (receive_count < 3) {
      for (int i = 0; i < 20; i++){
      scanner_key[scanner_key_index++] = data[i];
      }
    }
   
    // save last 4 bytes and carry on protocol to send over dongle key and shared secret
    if (receive_count == 3) {
      for (int i = 0; i < 4; i++){
        scanner_key[scanner_key_index++] = data[i];
      }
      
      // setting last byte as terminator
      scanner_key[scanner_key_index] = '\0';
      
      if (strlen(scanner_key) == 64) {
        Serial.println("Received Scanner public key");
        Serial.println(scanner_key);
        generate_DH();
        Serial.println("\nSending Dongle public key");
        send_byte(key_transfer,64);
      
      } else {
        Serial.println("Error: Did not process 64 bytes of key");
      }
   }

    // receiving IV
    // expected 32 bytes: packets 4, 5
    
    if (receive_count == 4) {
      for (int i = 0; i < BUFF_SIZE; i++){
        receive_data[receive_data_index++] = data[i];
      }
    }

    if (receive_count == 5) {
      for (int i = 0; i < 12; i++){
        receive_data[receive_data_index++] = data[i];
      }
      receive_data[receive_data_index] = '\0';
      if (strlen(receive_data) == 32){
        Serial.println("\nReceived Scanner IV");
        Serial.println(receive_data);
        receive_data_index = 0;

        // encrypt and send to scanner
        encrypt_aes(receive_data, 64);

        // send first half of dongle data
        char ciphertext_temp[65];
        for (int i = 0; i < 64; i++){
          ciphertext_temp[i] = ciphertext_hex[i];
        }
        ciphertext_temp[MAX_SEND_SIZE] = '\0';
        send_byte(ciphertext_temp,64);
        
      } else {
          Serial.println("Error: Did not process 32 bytes of IV");
      }
      
    }

    if (receive_count == 6) {
      
      char response = data[0];
      Serial.print(response);
      if (response == '6'){
        Serial.print("\n Received dongle response");

        char ciphertext_temp[65];
        for (int i = 0, j = 64; j < 128; i++, j++){
          ciphertext_temp[i] = ciphertext_hex[j];
        }
        ciphertext_temp[MAX_SEND_SIZE] = '\0';
        send_byte(ciphertext_temp,64);

        
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



// convert iv to bytes form,prepare ciphertext for sending
void encrypt_aes(char * iv_hex, int len){
  uint8_t ciphertext[128];
  
  
  CBC<AES256> cbc;
  uint8_t * iv = hex_to_uint8(iv_hex, IV_SIZE * 2);
  cbc.setKey(bob_k,KEY_SIZE);
  cbc.setIV(iv, IV_SIZE);
  cbc.encrypt(ciphertext, dongle_data, len);
  ciphertext_hex = uint8_to_hex(ciphertext, 64); // this is a global variable with the latest encrypted ciphertext

//  if ( ciphertext_hex_len <= MAX_SEND_SIZE) {
//    send_byte(ciphertext_hex, ciphertext_hex_len);
//  } else {
//    
//    
//    int temp_block_counter = 0;
//    Serial.println("hello!");
//    while (temp_block_counter < ciphertext_hex_len){
//      
//      char temp_block[64];
//      int remainder_to_send = ciphertext_hex_len - temp_block_counter;
//      
//      if (remainder_to_send > MAX_SEND_SIZE){
//        for(int i = 0; i < MAX_SEND_SIZE; i++){
//          temp_block[i] = ciphertext_hex[temp_block_counter++];
//        }
//        send_byte(temp_block, MAX_SEND_SIZE);
//      } else {
//        
//        for(int i = 0; i < remainder_to_send; i++){
//          temp_block[i] = ciphertext_hex[temp_block_counter++];
//        }
//        send_byte(temp_block, remainder_to_send);
//        
//      }
//    }
     
//  }

 
  

  Serial.println("Sending Encrypted data:");
  Serial.println(ciphertext_hex);
  
}

// generates DH keys and saves scanner public key into bob_k
// saves dongle public key in key_transfer
void generate_DH()
{

    char print_value[100];

    Serial.println("\nDiffie-Hellman key exchange:");
    // Serial.println("Generate random k/f for Alice ... ");
    Serial.flush();
   
    Curve25519::dh1(alice_k, alice_f);
    
    // Serial.println("Generate shared secret for Alice ... ");
 
    //Serial.println("Dongle private key:");
    //store_key_transfer(alice_f);
    Serial.println("Dongle public key:");
    store_key_transfer(alice_k);
    
    uint8_t * a = hex_to_uint8(scanner_key, sizeof(scanner_key));

    for (int i = 0; i < 32; i++){
      bob_k[i] = a[i];
    }

    Serial.println("\nbob_k: ");
    
    print_uint8_as_hex(bob_k, 32);
    
    bool checker = Curve25519::dh2(bob_k, alice_f);
   
    Serial.println("\nshared secret: ");
    
    print_uint8_as_hex(bob_k, 32);

}

int dotcount = 0;

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