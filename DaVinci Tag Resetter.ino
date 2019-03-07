// DaVinci Jr Automatic 300m Tag Resetter - ChazMeister

// NTAG AUTH example made by GARGANTUA from RoboCreators.com & paradoxalabs.com
// From MFRC522 Library: https://github.com/miguelbalboa/rfid

/*
    Licence for key generation code:
    https://nfckey.xyz/
    Copyright (C) 2018  github.com/Sinitax
    This file is part of NfcKey.
    NfcKey is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    NfcKey is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    You should have received a copy of the GNU Affero General Public License
    along with NfcKey.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <SPI.h>
#include <MFRC522.h>

#ifndef ROTL
# define ROTL(x,n) (((uintmax_t)(x) << (n)) | ((uintmax_t)(x) >> ((sizeof(x) * 8) - (n))))
#endif

uint32_t c[] = {
  0x6D835AFC, 0x7D15CD97, 0x0942B409, 0x32F9C923, 0xA811FB02, 0x64F121E8,
  0xD1CC8B4E, 0xE8873E6F, 0x61399BBB, 0xF1B91926, 0xAC661520, 0xA21A31C9,
  0xD424808D, 0xFE118E07, 0xD18E728D, 0xABAC9E17, 0x18066433, 0x00E18E79,
  0x65A77305, 0x5AE9E297, 0x11FC628C, 0x7BB3431F, 0x942A8308, 0xB2F8FD20,
  0x5728B869, 0x30726D5A
};

#define RST_PIN    9   // 
#define SS_PIN    10    //

MFRC522 mfrc522(SS_PIN, RST_PIN); // Create MFRC522 instance

void setup() {
  Serial.begin(115200);   // Initialize serial communications with the PC
  while (!Serial);    // Do nothing if no serial port is opened (added for Arduinos based on ATMEGA32U4)
  SPI.begin();      // Init SPI bus
  mfrc522.PCD_Init();   // Init MFRC522
//  Serial.println(F("Scan PICC to see UID, type, and data blocks..."));
  Serial.print("\n\n--------------\n\nWaiting for tag\n\n--------------\n\n\n");

}

void loop() {
  // Look for new cards
  if ( ! mfrc522.PICC_IsNewCardPresent()) {
    return;
  }

  // Select one of the cards
  if ( ! mfrc522.PICC_ReadCardSerial()) {
    return;
  }
  // Get key and print information about tag
  uint32_t k = getkey(mfrc522.uid.uidByte);
  uint16_t p = getpack(mfrc522.uid.uidByte);
  Serial.print("UID:"); printHex(mfrc522.uid.uidByte, 7);
  Serial.print("KEY:"); Serial.println(k, HEX);
  Serial.print("PACK:"); Serial.println(p, HEX);

  uint8_t bytes[4];
  
  bytes[0] = (k >> 24)  & 0xFF;
  bytes[1] = (k >> 16)  & 0xFF;
  bytes[2] = (k >> 8) & 0xFF;
  bytes[3] = (k >> 0) & 0xFF;

  for (int i = 0; i < sizeof(bytes); i++) {
    Serial.println(bytes[i], HEX);
  }
  
  byte pACK[] = {0, 0}; //16 bit PassWord ACK returned by the NFCtag

  Serial.print("Auth: ");
  Serial.println(mfrc522.PCD_NTAG216_AUTH(&bytes[0], pACK)); //Request Authentification if return STATUS_OK we are good

  //Print PassWordACK
  Serial.print(pACK[0], HEX);
  Serial.println(pACK[1], HEX);

  byte WBuff[] = {0x00, 0x00, 0x00, 0x04};
  byte RBuff[18];
  
  Serial.print("\n\n--------------\n\nDumping data before write\n\n--------------\n\n\n");
  
  mfrc522.PICC_DumpMifareUltralightToSerial(); //This is a modifier dunp just cghange the for cicle to < 232 instead of < 16 in order to see all the pages on NTAG216

  MFRC522::StatusCode status;
  Serial.print("\n\n--------------\n\nWriting data...\n\n--------------\n\n\n");
  // Write data to reset to 300m
  Serial.print("0x0A: E0 93 04 00:   ");
  byte page = 0x0A;
  byte dBuff1[] = {0xE0, 0x93, 0x04, 0x00};
  byte buffSize = 4;
  Serial.println((MFRC522::StatusCode) mfrc522.MIFARE_Ultralight_Write(page, dBuff1, buffSize) == MFRC522::STATUS_OK ? "OK" : "NOT WRITTEN");
  Serial.print("0x0B: E0 93 04 00:   ");
  page = 0x0B;
  byte dBuff2[] = {0xE0, 0x93, 0x04, 0x00};
  Serial.println((MFRC522::StatusCode) mfrc522.MIFARE_Ultralight_Write(page, dBuff2, buffSize) == MFRC522::STATUS_OK ? "OK" : "NOT WRITTEN");
  Serial.print("0x14: E0 93 04 00:   ");
  page = 0x14;
  byte dBuff3[] = {0xE0, 0x93, 0x04, 0x00};
  Serial.println((MFRC522::StatusCode) mfrc522.MIFARE_Ultralight_Write(page, dBuff3, buffSize) == MFRC522::STATUS_OK ? "OK" : "NOT WRITTEN");

  Serial.print("0x15: A8 81 36 54:   ");
  page = 0x15;
  byte dBuff4[] = {0xA8, 0x81, 0x36, 0x54};
  Serial.println((MFRC522::StatusCode) mfrc522.MIFARE_Ultralight_Write(page, dBuff4, buffSize) == MFRC522::STATUS_OK ? "OK" : "NOT WRITTEN");

  Serial.print("0x16: F0 3F EE CE:   ");
  page = 0x16;
  byte dBuff5[] = {0xF0, 0x3F, 0xEE, 0xCE};
  Serial.println((MFRC522::StatusCode) mfrc522.MIFARE_Ultralight_Write(page, dBuff5, buffSize) == MFRC522::STATUS_OK ? "OK" : "NOT WRITTEN");

  Serial.print("0x17: F2 6E 4D 76:   ");
  page = 0x17;
  byte dBuff6[] = {0xF2, 0x6E, 0x4D, 0x76};
  Serial.println((MFRC522::StatusCode) mfrc522.MIFARE_Ultralight_Write(page, dBuff6, buffSize) == MFRC522::STATUS_OK ? "OK" : "NOT WRITTEN");

  Serial.print("\n\n--------------\n\nData Written\n\n--------------\n\n\n");
  Serial.print("\n\n--------------\n\nDumping new memory...\n\n--------------\n\n\n");
  mfrc522.PICC_DumpMifareUltralightToSerial();
  Serial.print("\n\n--------------\n\nRemove tag\n\n--------------\n\n\n");
  delay(3000);
  Serial.print("\n\n--------------\n\nWaiting for tag\n\n--------------\n\n\n");
}

void printHex(uint8_t array[], unsigned int len) {
  char buffer[3];
  buffer[2] = NULL;
  for (int j = 0; j < len; j++) {
    sprintf(&buffer[0], "%02X", array[j]);
    Serial.print(buffer);
  } Serial.println();
}

void transform(uint8_t* ru)
{
  //Transform
  uint8_t i;
  uint8_t p = 0;
  uint32_t v1 = (((uint32_t)ru[3] << 24) | ((uint32_t)ru[2] << 16) | ((uint32_t)ru[1] << 8) | (uint32_t)ru[0]) + c[p++];
  uint32_t v2 = (((uint32_t)ru[7] << 24) | ((uint32_t)ru[6] << 16) | ((uint32_t)ru[5] << 8) | (uint32_t)ru[4]) + c[p++];

  for (i = 0; i < 12; i += 2)
  {
    uint32_t t1 = ROTL(v1 ^ v2, v2 & 0x1F) + c[p++];
    uint32_t t2 = ROTL(v2 ^ t1, t1 & 0x1F) + c[p++];
    v1 = ROTL(t1 ^ t2, t2 & 0x1F) + c[p++];
    v2 = ROTL(t2 ^ v1, v1 & 0x1F) + c[p++];
  }

  //Re-use ru
  ru[0] = v1 & 0xFF;
  ru[1] = (v1 >> 8) & 0xFF;
  ru[2] = (v1 >> 16) & 0xFF;
  ru[3] = (v1 >> 24) & 0xFF;
  ru[4] = v2 & 0xFF;
  ru[5] = (v2 >> 8) & 0xFF;
  ru[6] = (v2 >> 16) & 0xFF;
  ru[7] = (v2 >> 24) & 0xFF;
}

uint32_t getkey(uint8_t* uid)
{
  int i;
  //Rotate
  uint8_t r = (uid[1] + uid[3] + uid[5]) & 7; //Rotation offset
  uint8_t ru[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; //Rotated UID
  for (i = 0; i < 7; i++)
    ru[(i + r) & 7] = uid[i];

  //Transform
  transform(ru);

  //Calc key
  uint32_t k = 0; //Key as int
  r = (ru[0] + ru[2] + ru[4] + ru[6]) & 3; //Offset
  for (i = 3; i >= 0; i--) 
    k = ru[i + r] + (k << 8);

  return k;
}

uint16_t getpack(uint8_t* uid)
{
  int i;
  //Rotate
  uint8_t r = (uid[2] + uid[5]) & 7; //Rotation offset
  uint8_t ru[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; //Rotated UID
  for (i = 0; i < 7; i++)
    ru[(i + r) & 7] = uid[i];

  //Transform
  transform(ru);

  //Calc pack
  uint16_t p = 0;
  for (i = 0; i < 8; i++)
    p += ru[i] * 13;
  
  p = (p ^ 0x5555) & 0xFFFF;
  return (p & 0xFF00) >> 8 | (p & 0x00FF) << 8;
}
