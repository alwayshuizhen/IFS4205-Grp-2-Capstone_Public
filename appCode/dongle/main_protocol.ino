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

#include <SHA256.h>

#define HASH_SIZE 32
#define BLOCK_SIZE 64

const int BUFF_SIZE = 20;
const int IV_SIZE = 16;
const int KEY_SIZE = 32;
const int MAX_SEND_SIZE = 64;

const char checksum_input[] = "1234567";
char CHECKSUM_LETTER = 'N';
const int CHECKSUM_REMAINDER = 5;
bool checksum_connect = false;


const uint8_t dongle_data[64] = {0x44,0x61,0x69,0x73,0x79,0x20,0x74,0x68,0x65,0x20,0x46,0x6c,0x6f,
0x77,0x65,0x72,0x2e,0x35,0x35,0x35,0x35,0x35,0x35,0x35,0x35,0x2e,0x35,0x2e,0xdd,0x08,0xc0,0x92,0x2e,
0x20,0xc6,0x40,0x88,0x01,0x80,0xc7,0xca,0xda,0x4c,0xf9,0x1c,0x24,0xfa,0x05,0xf3,0xe3,0x13,0xcd,0x82,
0xee,0xf3,0x32,0xb7,0x73,0x35,0xac,0x4e,0xe0,0x98,0xed};

char * dongle_data_hex = "44616973792074686520466c6f7765722e35353535353535352e352edd08c0922e20c640880180c7cada4cf91c24fa05f3e313cd82eef332b77335ac4ee098ed";



bool rssidisplay;

const char * myid = checksum_input;         

char key_transfer[100];
char scanner_key[64];
int scanner_key_index = 0;

static uint8_t bob_k[32];  // this will be the shared secret
static uint8_t alice_k[32];
static uint8_t alice_f[32];
bool set_at_previous_connection = false;

int receive_count = 0;
char receive_data[100];
int receive_data_index;

char * ciphertext_hex;

void hmac(char * message){
  SHA256 sha256;
  
  char * shared_key = uint8_to_hex(bob_k,32);
  
  testHMAC(&sha256, shared_key, message);
}

void testHMAC(Hash *hash, char * key, char * data)
{
    uint8_t result[HASH_SIZE];
    hash->resetHMAC(key, strlen(key));
    hash->update(data, strlen(data));
    hash->finalizeHMAC(key, strlen(key), result, sizeof(result));
    Serial.println("\nHMAC value:");
    print_uint8_as_hex(result, 32);
    char * hmac_data = uint8_to_hex(result,32);
    send_byte(hmac_data,64);
}

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
   checksum_connect = false;
   Curve25519::dh1(alice_k, alice_f);
   Serial.println("\nPre compute DH key:");
   print_uint8_as_hex(alice_k, 32);
   set_at_previous_connection = true;
}


// have to keep a running count of the receive 

void RFduinoBLE_onReceive(char *data, int len) { 

    // receive_count 0: checksum verification
    if ( receive_count == 0){
       if (len == 20){
          if (data[CHECKSUM_REMAINDER]!= CHECKSUM_LETTER){
            receive_count = 0;
            Serial.print("\nChecksum error! Received:");
            Serial.println(data[CHECKSUM_REMAINDER]);
          } else {
                Serial.println("\nChecksum correct!");
                checksum_connect = true;
          }
       } else{
        receive_count = 0;
        Serial.print("\nChecksum error! Received:");
        Serial.println(data[CHECKSUM_REMAINDER]);
       }
    }

    if (checksum_connect) {

      // prepare to receive 4 packets (max receive is 20 bytes) for scanner key
      // receive_count 1 - 4: sacanner public key
        
      if ( receive_count > 0 && receive_count < 4) {
        for (int i = 0; i < 20; i++){
        scanner_key[scanner_key_index++] = data[i];
        }
      }
     
      // save last 4 bytes and carry on protocol to send over dongle key and shared secret, receive_count 4
      if (receive_count == 4) {
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
      // expected 32 bytes: packets 5, 6
      
      if (receive_count == 5) {
        for (int i = 0; i < BUFF_SIZE; i++){
          receive_data[receive_data_index++] = data[i];
        }
      }
  
      if (receive_count == 6) {
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
  
      // sending second half after receivng confirmation
      if (receive_count == 7) {
        
        char response = data[0];
        Serial.print(response);
        if (response == '7'){
          Serial.print("\n Received dongle response");
  
          char ciphertext_temp[65];
          for (int i = 0, j = 64; j < 128; i++,j++){
            ciphertext_temp[i] = ciphertext_hex[j];
          }
          ciphertext_temp[MAX_SEND_SIZE] = '\0';
          send_byte(ciphertext_temp,64);
          //Serial.println("huh");
          //Serial.print(ciphertext_temp);
        }
      }
        
        if (receive_count == 8) {

        char hmac_message[129];
        for (int i = 0; i < 128; i++){
          hmac_message[i] = ciphertext_hex[i];
        }

        hmac_message[128] = '\0';
        
        char response = data[0];
          Serial.print(response);
          if (response == '8'){
            hmac(hmac_message);
          }
        }
        
        
      
     receive_count++;
    } else {
      RFduinoBLE_onDisconnect();
    }
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
  Serial.println("\nSending Encrypted data:");
  Serial.println(ciphertext_hex);
  
}

// generates DH keys and saves scanner public key into bob_k
// saves dongle public key in key_transfer

void pre_calculating_DH(){
  Curve25519::dh1(alice_k, alice_f);
}

void generate_DH()
{

    char print_value[100];
    Serial.println("\nDiffie-Hellman key exchange:");
    if (!set_at_previous_connection) {
      // Serial.println("Generate random k/f for Alice ... ");
      Serial.flush();
      Curve25519::dh1(alice_k, alice_f);
    }
    
    // Serial.println("Generate shared secret for Alice ... ");
 
    //Serial.println("Dongle private key:");
    //store_key_transfer(alice_f);
    Serial.println("Dongle public key:");
    store_key_transfer(alice_k);
    
    uint8_t * a = hex_to_uint8(scanner_key, sizeof(scanner_key));

    for (int i = 0; i < 32; i++){
      bob_k[i] = a[i];
    }

    Serial.println("\nScanner public key: ");
    
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
