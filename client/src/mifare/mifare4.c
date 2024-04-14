//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// iso14443-4 mifare commands
//-----------------------------------------------------------------------------

#include "mifare4.h"
#include <string.h>
#include <time.h> // For charge command
#include <stdlib.h>
#include "commonutil.h"  // ARRAYLEN
#include "comms.h" // DropField
#include "cmdhf14a.h"
#include "ui.h"
#include "crypto/libpcrypto.h"

static bool g_verbose_mode = false;
void mfpSetVerboseMode(bool verbose) {
    g_verbose_mode = verbose;
}

static const PlusErrorsElm_t PlusErrors[] = {
    {0xFF, ""},
    {0x00, "Transfer cannot be granted within the current authentication."},
    {0x06, "Access Conditions not fulfilled. Block does not exist, block is not a value block."},
    {0x07, "Too many read or write commands in the session or in the transaction."},
    {0x08, "Invalid MAC in command or response"},
    {0x09, "Block Number is not valid"},
    {0x0a, "Invalid block number, not existing block number"},
    {0x0b, "The current command code not available at the current card state."},
    {0x0c, "Length error"},
    {0x0f, "General Manipulation Error. Failure in the operation of the PICC (cannot write to the data block), etc."},
    {0x90, "OK"},
};

const char *mfpGetErrorDescription(uint8_t errorCode) {
    for (int i = 0; i < ARRAYLEN(PlusErrors); i++)
        if (errorCode == PlusErrors[i].Code)
            return PlusErrors[i].Description;

    return PlusErrors[0].Description;
}

AccessConditions_t MFAccessConditions[] = {
    {0x00, "read AB; write AB; increment AB; decrement transfer restore AB", "transport config"},
    {0x01, "read AB; decrement transfer restore AB", "value block"},
    {0x02, "read AB", "read/write block"},
    {0x03, "read B; write B", "read/write block"},
    {0x04, "read AB; write B", "read/write block"},
    {0x05, "read B", "read/write block"},
    {0x06, "read AB; write B; increment B; decrement transfer restore AB", "value block"},
    {0x07, "none", "read/write block"}
};

AccessConditions_t MFAccessConditionsTrailer[] = {
    {0x00, "read A by A; read ACCESS by A; read/write B by A", ""},
    {0x01, "write A by A; read/write ACCESS by A; read/write B by A", ""},
    {0x02, "read ACCESS by A; read B by A", ""},
    {0x03, "write A by B; read ACCESS by AB; write ACCESS by B; write B by B", ""},
    {0x04, "write A by B; read ACCESS by AB; write B by B", ""},
    {0x05, "read ACCESS by AB; write ACCESS by B", ""},
    {0x06, "read ACCESS by AB", ""},
    {0x07, "read ACCESS by AB", ""}
};

bool mfValidateAccessConditions(const uint8_t *data) {
    uint8_t nd1 = NIBBLE_LOW(data[0]);
    uint8_t nd2 = NIBBLE_HIGH(data[0]);
    uint8_t nd3 = NIBBLE_LOW(data[1]);
    uint8_t d1  = NIBBLE_HIGH(data[1]);
    uint8_t d2  = NIBBLE_LOW(data[2]);
    uint8_t d3  = NIBBLE_HIGH(data[2]);

    return ((nd1 == (d1 ^ 0xF)) && (nd2 == (d2 ^ 0xF)) && (nd3 == (d3 ^ 0xF)));
}

bool mfReadOnlyAccessConditions(uint8_t blockn, const uint8_t *data) {

    uint8_t d1  = NIBBLE_HIGH(data[1]) >> blockn;
    uint8_t d2  = NIBBLE_LOW(data[2]) >> blockn;
    uint8_t d3  = NIBBLE_HIGH(data[2]) >> blockn;
    uint8_t cond = (d1 & 0x01) << 2 | (d2 & 0x01) << 1 | (d3 & 0x01);

    if (blockn == 3) {
        if ((cond == 0x02) || (cond == 0x06) || (cond == 0x07)) return true;
    } else {
        if ((cond == 0x02) || (cond == 0x05)) return true;
    }
    return false;
}

const char *mfGetAccessConditionsDesc(uint8_t blockn, const uint8_t *data) {
    uint8_t d1 = NIBBLE_HIGH(data[1]) >> blockn;
    uint8_t d2 = NIBBLE_LOW(data[2]) >> blockn;
    uint8_t d3 = NIBBLE_HIGH(data[2]) >> blockn;

    uint8_t cond = (d1 & 0x01) << 2 | (d2 & 0x01) << 1 | (d3 & 0x01);

    if (blockn == 3) {
        for (int i = 0; i < ARRAYLEN(MFAccessConditionsTrailer); i++)
            if (MFAccessConditionsTrailer[i].cond == cond) {
                return MFAccessConditionsTrailer[i].description;
            }
    } else {
        for (int i = 0; i < ARRAYLEN(MFAccessConditions); i++)
            if (MFAccessConditions[i].cond == cond) {
                return MFAccessConditions[i].description;
            }
    };

    static char none[] = "none";
    return none;
}

uint8_t mf_get_accesscondition(uint8_t blockn, const uint8_t *data) {
    uint8_t d1 = NIBBLE_HIGH(data[1]) >> blockn;
    uint8_t d2 = NIBBLE_LOW(data[2]) >> blockn;
    uint8_t d3 = NIBBLE_HIGH(data[2]) >> blockn;
    return (d1 & 0x01) << 2 | (d2 & 0x01) << 1 | (d3 & 0x01);
}

/*
static int CalculateEncIVCommand(mf4Session_t *mf4session, uint8_t *iv, bool verbose) {
    memcpy(&iv[0], &mf4session->TI, 4);
    memcpy(&iv[4], &mf4session->R_Ctr, 2);
    memcpy(&iv[6], &mf4session->W_Ctr, 2);
    memcpy(&iv[8], &mf4session->R_Ctr, 2);
    memcpy(&iv[10], &mf4session->W_Ctr, 2);
    memcpy(&iv[12], &mf4session->R_Ctr, 2);
    memcpy(&iv[14], &mf4session->W_Ctr, 2);

    return 0;
}

static int CalculateEncIVResponse(mf4Session *mf4session, uint8_t *iv, bool verbose) {
    memcpy(&iv[0], &mf4session->R_Ctr, 2);
    memcpy(&iv[2], &mf4session->W_Ctr, 2);
    memcpy(&iv[4], &mf4session->R_Ctr, 2);
    memcpy(&iv[6], &mf4session->W_Ctr, 2);
    memcpy(&iv[8], &mf4session->R_Ctr, 2);
    memcpy(&iv[10], &mf4session->W_Ctr, 2);
    memcpy(&iv[12], &mf4session->TI, 4);

    return 0;
}
*/

/* Here are all the functions required to operate FMCOS cards for basic transport card functionality.
This includes wallet, unlimited rides, transaction logs, so on, so forth.
For proper safety there's a KDF.
VOS use only.
*/

int FudanKDF(uint8_t *UID, uint16_t keytype, uint8_t* dataout){
    uint8_t resultkey[16]={16, 0x78, 0x80, 0x90, 0x2, 0x20, 0x90, 0, 0, 0, 0, 0, UID[0], UID[1], UID[2], UID[3]}; // This will be our base output
    uint8_t pin[2] = {0};
    int writeval = 0;
    uint8_t keyconstant[16] = {68, 253, 151, 135, 6, 69, 76, 10, 80, 103, 218, 24, 89, 205, 177, 9}; // This is a constant to make proper keys and not something easily reversible.
    // The end user doesnt even know what we do with the keys or how do we secure the data altogether (currently - I'm looking to encrypting the communication).
    // All they see is the command-response, except with an itty bitty MAC that they cannot compute.
    switch (keytype){
        case 0x0234: // Charge TAC key
            des3_encrypt(resultkey, resultkey, keyconstant, 2);
            des3_encrypt(&resultkey[8], &resultkey[8], keyconstant, 2);
            resultkey[0] = resultkey[0] ^ UID[0];
            resultkey[1] = resultkey[1] ^ UID[1];
            resultkey[2] = resultkey[2] ^ UID[2];
            resultkey[3] = resultkey[3] ^ UID[3];
            resultkey[12] = resultkey[12] ^ UID[3];
            des3_decrypt(resultkey, resultkey, keyconstant, 2);
            des3_encrypt(&resultkey[8], &resultkey[8], keyconstant, 2);
            memcpy(dataout, resultkey, 16);
            return 0;
            break;
        case 0x0239: // Charge binary access key
            des3_decrypt(resultkey, resultkey, keyconstant, 2);
            des3_decrypt(&resultkey[8], &resultkey[8], keyconstant, 2);
            resultkey[4] = resultkey[4] ^ UID[3];
            resultkey[5] = resultkey[5] ^ UID[2];
            resultkey[6] = resultkey[6] ^ UID[1];
            resultkey[7] = resultkey[7] ^ UID[0];
            resultkey[12] = resultkey[12] ^ UID[3];
            des3_encrypt(resultkey, resultkey, keyconstant, 2);
            des3_decrypt(&resultkey[8], &resultkey[8], keyconstant, 2);
            memcpy(dataout, resultkey, 16);
            return 0;
            break;
        case 0x023E: // Charge key
            des3_encrypt(resultkey, resultkey, keyconstant, 2);
            des3_encrypt(&resultkey[8], &resultkey[8], keyconstant, 2);
            resultkey[0] = resultkey[0] ^ UID[0];
            resultkey[1] = resultkey[1] ^ UID[1];
            resultkey[2] = resultkey[2] ^ UID[2];
            resultkey[3] = resultkey[3] ^ UID[3];
            resultkey[4] = resultkey[4] ^ UID[0];
            resultkey[5] = resultkey[5] ^ UID[1];
            resultkey[6] = resultkey[6] ^ UID[2];
            resultkey[7] = resultkey[7] ^ UID[3];
            resultkey[15] = resultkey[15] ^ UID[0];
            des3_decrypt(resultkey, resultkey, keyconstant, 2);
            des3_encrypt(&resultkey[8], &resultkey[8], keyconstant, 2);
            memcpy(dataout, resultkey, 16);
            return 0;
            break;
        case 0x0334: // Recharge TAC key
            resultkey[0] = resultkey[0] ^ UID[0];
            resultkey[1] = resultkey[1] ^ UID[1];
            resultkey[2] = resultkey[2] ^ UID[2];
            resultkey[3] = resultkey[3] ^ UID[3];
            des3_decrypt(resultkey, resultkey, keyconstant, 2);
            des3_decrypt(&resultkey[8], &resultkey[8], keyconstant, 2);
            resultkey[4] = resultkey[4] ^ UID[0];
            resultkey[5] = resultkey[5] ^ UID[1];
            resultkey[6] = resultkey[6] ^ UID[2];
            resultkey[7] = resultkey[7] ^ UID[3];
            des3_encrypt(resultkey, resultkey, keyconstant, 2);
            memcpy(dataout, resultkey, 16);
            return 0;
            break;
        case 0x0339: // Recharge binary access key
            resultkey[0] = resultkey[0] ^ UID[0];
            resultkey[1] = resultkey[1] ^ UID[1];
            resultkey[2] = resultkey[2] ^ UID[2];
            resultkey[3] = resultkey[3] ^ UID[3];
            des3_encrypt(resultkey, resultkey, keyconstant, 2);
            des3_encrypt(&resultkey[8], &resultkey[8], keyconstant, 2);
            resultkey[4] = resultkey[7] ^ UID[0];
            resultkey[5] = resultkey[6] ^ UID[1];
            resultkey[6] = resultkey[5] ^ UID[2];
            resultkey[7] = resultkey[4] ^ UID[3];
            resultkey[13] = resultkey[13] ^ UID[2];
            des3_decrypt(resultkey, resultkey, keyconstant, 2);
            des3_decrypt(&resultkey[8], &resultkey[8], keyconstant, 2);
            memcpy(dataout, resultkey, 16);
            return 0;
            break;
        // So there's kind of a bug in the above. If you want to charge the user with their unlimited rides, you need to get write perms to the binary.
        // But if you have write perms as level 2 and are malicious, you could just elevate your rights and give yourself unlimited rights.
        // Maybe I should transfer wallet <-> unlimited uses when one or the other is active?
        // Might be tedious, however... I know of passbooks, but I'm not exactly sure on how to work with those things.
        case 0x033F: // Recharge key
            resultkey[8] = resultkey[8] ^ UID[0];
            resultkey[9] = resultkey[9] ^ UID[1];
            resultkey[10] = resultkey[10] ^ UID[2];
            resultkey[11] = resultkey[11] ^ UID[3];
            des3_decrypt(resultkey, resultkey, keyconstant, 2);
            des3_decrypt(&resultkey[8], &resultkey[8], keyconstant, 2);
            resultkey[4] = resultkey[4] ^ UID[0];
            resultkey[5] = resultkey[5] ^ UID[1];
            resultkey[6] = resultkey[6] ^ UID[2];
            resultkey[7] = resultkey[7] ^ UID[3];
            memcpy(dataout, resultkey, 16);
            return 0;
            break;
        // If I figure out how it works, I will add key type 36, which should encrypt the transmission.
        case 0x36:
            resultkey[12] = resultkey[12] ^ UID[3];
            resultkey[13] = resultkey[13] ^ UID[2];
            resultkey[14] = resultkey[14] ^ UID[1];
            resultkey[15] = resultkey[15] ^ UID[0];
            resultkey[0] = resultkey[0] ^ UID[3];
            des3_encrypt(resultkey, resultkey, keyconstant, 2);
            des3_encrypt(&resultkey[8], &resultkey[8], keyconstant, 2);
            resultkey[6] = resultkey[6] ^ UID[2];
            memcpy(dataout, resultkey, 16);
            return 0;
            break;
        case 1: // PIN key
            for (int i=0; i<4; ++i){writeval = writeval ^ UID[i];};
            pin[0] = writeval / 100;
            pin[1] = pin[1] + (writeval%100/10)*16+ writeval%10;
            memcpy(dataout, pin, 2);
            return 0;
            break;
        default:
            PrintAndLogEx(WARNING, "Key type not recognized!");
            return 1;
    }
}
// I also should note that when I was making this KDF function I didn't have TACs implemented. No worries, I will get it done, so don't mind mismatches in code and comments.

int FudanPrepare(uint8_t* uid){
    uint8_t keybuffer[16] = {0};
    uint8_t pin[2] = {0};
    uint8_t buffer[250] = {0}; // Garbage zone, maybe there is a better way
    int garbage = 20;
    uint8_t cmdwipe[5] = {0x80, 0x0e, 0}; // Step 1: wipe tag
    uint8_t cmdmakeapp[19] = {0x80, 0xe0, 0, 1, 14, 0x38, 0x4, 0x00, 0xf0, 0xf0, 0x81, 0xff, 0xff, 0x54, 0x52, 0x4f, 0x49, 0x4b, 0x41}; // Step 2: Make the new application
    uint8_t cmdsel[11]={0, 0xa4, 4, 0, 6, 0x54, 0x52, 0x4f, 0x49, 0x4b, 0x41}; // We'll make use of this a lot
    uint8_t cmdmakekey[12]={0x80, 0xE0, 0xFF, 0xFE, 0x07, 0x3F, 0x00, 0xB0, 0x81, 0xF0, 0xFF, 0xFF}; // Keyfile
    uint8_t cmdmakebin[12]={0x80, 0xE0, 0, 4, 0x07, 0x68, 0, 8, 0xF2, 0xF3, 0xFF, 0x7F}; // Config file
    uint8_t cmdmakerec[12]={0x80, 0xE0, 0, 3, 0x07, 0x2e, 0x0a, 23, 0xF2, 0xEF, 0xFF, 0x74}; // Records file
    // For charging
    FudanKDF(uid, 0x023e, keybuffer);
    PrintAndLogEx(INFO, "Key ID 02 type 3E: %s", sprint_hex(keybuffer, 16)); // Charging
    uint8_t cmdwritekey3e[26]={0x80, 0xd4, 0x01, 0x02, 0x15, 0x3e, 0xf1, 0xfe, 0x00, 0x2d, 0};
    memcpy(&cmdwritekey3e[10], keybuffer, 16);
    FudanKDF(uid, 0x0239, keybuffer);
    PrintAndLogEx(INFO, "Key ID 02 type 39: %s", sprint_hex(keybuffer, 16)); // Charging
    uint8_t cmdwritekey39[26]={0x80, 0xd4, 0x01, 0x02, 0x15, 0x39, 0xf1, 0xfe, 0x22, 0x33, 0};
    memcpy(&cmdwritekey39[10], keybuffer, 16);
    FudanKDF(uid, 0x0234, keybuffer);
    PrintAndLogEx(INFO, "Key ID 02 type 34: %s", sprint_hex(keybuffer, 16)); // Verifying charges
    uint8_t cmdwritekey34[26]={0x80, 0xd4, 0x01, 0x02, 0x15, 0x34, 0xf1, 0xfe, 0x00, 0x2d, 0};
    memcpy(&cmdwritekey34[10], keybuffer, 16);
    // For recharging
    FudanKDF(uid, 0x033F, keybuffer);
    PrintAndLogEx(INFO, "Key ID 03 type 3F: %s", sprint_hex(keybuffer, 16)); // Recharging
    uint8_t cmdwritekey3f[26]={0x80, 0xd4, 0x01, 0x03, 0x15, 0x3f, 0xf1, 0xfe, 0x00, 0x2d, 0};
    memcpy(&cmdwritekey3f[10], keybuffer, 16);
    FudanKDF(uid, 0x0339, keybuffer);
    PrintAndLogEx(INFO, "Key ID 03 type 39: %s", sprint_hex(keybuffer, 16)); // Recharging
    uint8_t cmdwritekey339[26]={0x80, 0xd4, 0x01, 0x03, 0x15, 0x39, 0xf1, 0xfe, 0x33, 0x33, 0};
    memcpy(&cmdwritekey339[10], keybuffer, 16);
    FudanKDF(uid, 0x0334, keybuffer);
    PrintAndLogEx(INFO, "Key ID 03 type 34: %s", sprint_hex(keybuffer, 16)); // Verifying recharges
    uint8_t cmdwritekey343[26]={0x80, 0xd4, 0x01, 0x03, 0x15, 0x34, 0xf1, 0xfe, 0x00, 0x2d, 0};
    memcpy(&cmdwritekey343[10], keybuffer, 16);
    FudanKDF(uid, 0x36, keybuffer);
    PrintAndLogEx(INFO, "Key type 36: %s", sprint_hex(keybuffer, 8)); // Verifying recharges
    uint8_t cmdwritekey36[18]={0x80, 0xd4, 0x01, 0x00, 0x0d, 0x36, 0xf0, 0xfe, 0xff, 0x44, 0};
    memcpy(&cmdwritekey36[10], keybuffer, 8);
    FudanKDF(uid, 1, pin);
    PrintAndLogEx(INFO, "PIN: %s", sprint_hex_inrow(pin, 2));
    uint8_t cmdwritekey3A[12] = {0x80, 0xD4, 0x01, 0x00, 0x07, 0x7A, 0xF0, 0xEF, 0x11, 0x44, pin[0], pin[1]};

    ExchangeRAW14a(cmdwipe, sizeof(cmdwipe), true, false, buffer, 250, &garbage, false);
    ExchangeRAW14a(cmdmakeapp, sizeof(cmdmakeapp), true, false, buffer, 250, &garbage, false);
    ExchangeRAW14a(cmdsel, sizeof(cmdsel), true, true, buffer, 250, &garbage, false);
    ExchangeRAW14a(cmdmakekey, sizeof(cmdmakekey), false, true, buffer, 250, &garbage, false); // Step 3: make keyfile in app, as well as
    //ExchangeRAW14a(cmdsel, sizeof(cmdsel), true, true, buffer, 250, &garbage, false);
    // Step 4: Let's make the keys!
    ExchangeRAW14a(cmdwritekey3e, sizeof(cmdwritekey3e), false, true, buffer, 250, &garbage, false); // lower down...
    ExchangeRAW14a(cmdwritekey39, sizeof(cmdwritekey39), false, true, buffer, 250, &garbage, false);
    ExchangeRAW14a(cmdwritekey34, sizeof(cmdwritekey34), false, true, buffer, 250, &garbage, false);
    ExchangeRAW14a(cmdwritekey3f, sizeof(cmdwritekey3f), false, true, buffer, 250, &garbage, false);
    ExchangeRAW14a(cmdwritekey339, sizeof(cmdwritekey339), false, true, buffer, 250, &garbage, false);
    ExchangeRAW14a(cmdwritekey343, sizeof(cmdwritekey343), false, true, buffer, 250, &garbage, false);
    ExchangeRAW14a(cmdwritekey36, sizeof(cmdwritekey36), false, true, buffer, 250, &garbage, false);
    // PIN because it's needed. More security is more security!
    ExchangeRAW14a(cmdwritekey3A, sizeof(cmdwritekey3A), false, true, buffer, 250, &garbage, false);
    ExchangeRAW14a(cmdmakebin, sizeof(cmdmakebin), false, true, buffer, 250, &garbage, false); // make the binary file with the unlimited date, free uses and config
    ExchangeRAW14a(cmdmakerec, sizeof(cmdmakerec), false, true, buffer, 250, &garbage, false); // and the records file. Needed for logging
    // Step 5: make the wallet and call it a day
    uint8_t cmdmakewallet[12] = {0x80, 0xe0, 0, 2, 7, 0x2f, 0x02, 0x08, 0xf0, 0, 0xff, 0x03};
    ExchangeRAW14a(cmdmakewallet, sizeof(cmdmakewallet), false, false, buffer, 250, &garbage, false);
    return 0;
}

int FudanCharge(uint8_t *uid, uint8_t *dataout, int maxdataoutlen, int *dataoutlen){
    uint8_t pincode[2] = {0};
    FudanKDF(uid, 1, pincode);
    uint8_t binkey[16] = {0};
    FudanKDF(uid, 0x0239, binkey);
    uint8_t mackey[8] = {0};
    FudanKDF(uid, 0x36, mackey);
    int garbage = 30;
    uint8_t buffer[250] = {0}; // Garbage zone, maybe there is a better way
    uint8_t cmdsel[11] = {0x00, 0xa4, 0x04, 0x00, 0x06, 0x54, 0x52, 0x4F, 0x49, 0x4B, 0x41}; // Step 1: Select troika app
    uint8_t getnt[5] = {0, 0x84, 0, 0, 4}; // Get challenge to authenticate
    uint8_t sendar[13] = {0, 0x82, 0, 2, 8, 0}; // Send response. Must be filled in place
    uint8_t ar[8] = {0};
    uint8_t cmdunlock[7] = {0x00, 0x20, 0x00, 0x00, 0x02, pincode[0], pincode[1]}; // Step 2: do PIN unlock so we can charge wallet
    uint8_t cmdreadbal[5]={0x80, 0x5c, 0x00, 0x02, 0x04}; // Step 3: read balance so user knows what they altered
    uint8_t cmdcharge1[17] = {0x80, 0x50, 0x01, 0x02, 0x0b, 0x02, 0x00, 0x00, 0x00, 0x36, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 15};
    ExchangeRAW14a(cmdsel, sizeof(cmdsel), true, true, buffer, 250, &garbage, false);
    if (buffer[0] != 0x6f){return 0xa4;}
    ExchangeRAW14a(cmdunlock, sizeof(cmdunlock), false, true, buffer, 250, &garbage, false);
    if (buffer[0] != 0x90){return 0x20;}
    ExchangeRAW14a(cmdreadbal, sizeof(cmdreadbal), false, true, buffer, 250, &garbage, false);
    PrintAndLogEx(INFO, "Current balance: %s", sprint_hex_inrow(buffer, 4));
    // Try reading the binary
    ExchangeRAW14a(getnt, sizeof(getnt), false, true, buffer, 250, &garbage, false); // Get challenge
    memcpy(ar, buffer, 4);
    des3_encrypt(ar, ar, binkey, 2); // Make response
    memcpy(&sendar[5], ar, 8);
    ExchangeRAW14a(sendar, sizeof(sendar), false, true, buffer, 250, &garbage, false); // Send response
    if (buffer[0] != 0x90){return 0x82;} // If it fails, quit to avoid making problems
    uint8_t cmdselectbin[7] = {0, 0xa4, 0, 0, 2, 0, 4}; // Select binary
    ExchangeRAW14a(cmdselectbin, sizeof(cmdselectbin), false, true, buffer, 250, &garbage, false);
    ExchangeRAW14a(getnt, sizeof(getnt), false, true, buffer, 250, &garbage, false); // Get new challenge
    uint8_t readbiniv[8] = {0};
    memcpy(readbiniv, buffer, 4);
    uint8_t cmdreadbin[9] = {4, 0xb0, 0, 0, 4, 0};
    uint8_t readmac[8] = {4, 0xb0, 0, 0, 4, 0x80, 0}; // Need to supply MAC to get access to the file
    des_encrypt_cbc(readmac, readmac, 8, mackey, readbiniv); // Make the MAC
    memcpy(&cmdreadbin[5], readmac, 4); // Append MAC
    ExchangeRAW14a(cmdreadbin, sizeof(cmdreadbin), false, true, buffer, 250, &garbage, false); // Read binary
    des_decrypt_ecb(buffer, buffer, 8, mackey);
    PrintAndLogEx(INFO, "Binary data: %s", sprint_hex_inrow(&buffer[1], 4));
    // Finish reading the binary
    ExchangeRAW14a(cmdcharge1, sizeof(cmdcharge1), false, true, buffer, 250, &garbage, false);
    // We will not look at what this thing even tells us. All we need to have is what we're charging the card.
    // Begin making MAC1
    uint8_t chargekey[16] = {0};
    FudanKDF(uid, 0x023E, chargekey);
    uint8_t tempkey[8] = {buffer[11], buffer[12], buffer[13], buffer[14], buffer[4], buffer[5], 0x52, 0x4f};
    des3_encrypt(tempkey, tempkey, chargekey, 2);
    PrintAndLogEx(INFO, "Session key: %s", sprint_hex(tempkey, 8));
    uint8_t mac1[24] = {0, 0, 0, 54, 6, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 7, 4, 0x20, 0x24, 0x22, 0x43, 0x15, 0x80, 0}; // Once again hardcoded values but can be changed if needed
    uint8_t iv[8] = {0};
    des_encrypt_cbc(mac1, mac1, 24, tempkey, iv);
    // MAC1 has been made and is hopefully correct
    uint8_t cmdcharge2[21] = {0x80, 0x54, 1, 0, 15, 0x4d, 0x54, 0x52, 0x4F, 7, 4, 0x20, 0x24, 0x22, 0x43, 0x15, mac1[16], mac1[17], mac1[18], mac1[19], 8};
    // I assume that TRANSACTION SERIAL NR. is some sort of identification, we have a counter anyway. As such it's MTRO
    garbage = 10;
    ExchangeRAW14a(cmdcharge2, sizeof(cmdcharge2), false, true, buffer, 250, &garbage, false);
    if(buffer[8]!=0x90){return 0x54;}
    // Begin verifying MAC2
    uint8_t mac2[8] = {0, 0, 0, 54, 0x80, 0};
    uint8_t iv2[8] = {0};
    des_encrypt_cbc(mac2, mac2, 8, tempkey, iv2);
    uint8_t mac2r[4] = {0};
    memcpy(mac2r, mac2, 4);
    uint8_t mac2t[4] = {0};
    memcpy(mac2t, &buffer[4], 4);
    PrintAndLogEx(INFO, "Card MAC2: %02X%02X%02X%02X, our MAC2: %02X%02X%02X%02X", mac2t[0], mac2t[1], mac2t[2], mac2t[3], mac2r[0], mac2r[1], mac2r[2], mac2r[3]);
    if (memcmp(mac2r, mac2t, 4) != 0){PrintAndLogEx(ERR, "Card MAC2 did not match!"); return 0x90;}
    // MAC2 has been verified
    garbage = 6;
    ExchangeRAW14a(cmdreadbal, sizeof(cmdreadbal), false, false, buffer, 250, &garbage, false);
    PrintAndLogEx(INFO, "New balance: %s", sprint_hex_inrow(buffer, 4));
    return 0;
}

int FudanReCharge(uint8_t *uid, uint8_t *value, uint8_t *dataout, int maxdataoutlen, int *dataoutlen){
    uint8_t pincode[2] = {0};
    FudanKDF(uid, 1, pincode);
    uint8_t buffer[250] = {0}; // Garbage zone, maybe there is a better way
    uint8_t cmdsel[11] = {0x00, 0xa4, 0x04, 0x00, 0x06, 0x54, 0x52, 0x4F, 0x49, 0x4B, 0x41}; // Step 1: Select troika app
    uint8_t cmdunlock[7] = {0x00, 0x20, 0x00, 0x00, 0x02, pincode[0], pincode[1]}; // Step 2: do PIN unlock so we can recharge wallet
    uint8_t cmdreadbal[5]={0x80, 0x5c, 0x00, 0x02, 0x04}; // Step 3: read balance so user knows what they altered
    uint8_t cmdcharge1[16] = {0x80, 0x50, 0x00, 0x02, 0x0b, 0x03, 0x00, 0x00, value[0], value[1], 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t mac2data[24] = {0, 0, value[0], value[1], 2, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x05, 0x04, 0x20, 0x24, 0x17, 0x03, 0x15, 0x80, 0};
    uint8_t mac2result[24] = {0};
    uint8_t rechargekey[16] = {0};
    FudanKDF(uid, 0x033F, rechargekey);
    uint8_t iv2[8] = {0};
    int garbage = 31;
    ExchangeRAW14a(cmdsel, sizeof(cmdsel), true, true, buffer, 250, &garbage, false);
    if (buffer[0] != 0x6f){return 0xa4;}
    ExchangeRAW14a(cmdunlock, sizeof(cmdunlock), false, true, buffer, 250, &garbage, false);
    if (buffer[0] != 0x90){return 0x20;}
    /*uint8_t nothing[4] = {0};
    if (memcmp(nothing, date, 4)){ // If we are asked to update the unlimited date
    // In theory the buffer of the reply value is NEVER that long. So as such its just 0's
        uint8_t binwritekey[16] = {0};
        FudanKDF(uid, 0x0339, binwritekey);
        uint8_t mackey[8] = {0};
        FudanKDF(uid, 0x36, mackey);
        uint8_t getnt[5] = {0, 0x84, 0, 0, 4};
        uint8_t sendar[13] = {0, 0x82, 0, 3, 8, 0};
        uint8_t cmdselectbin[7] = {0, 0xa4, 0, 0, 2, 0, 4}; // Select binary
        ExchangeRAW14a(cmdselectbin, sizeof(cmdselectbin), false, true, buffer, 250, &garbage, false);
        ExchangeRAW14a(getnt, sizeof(getnt), false, true, buffer, 250, &garbage, false); // Request challenge to get write perms
        uint8_t ar[8] = {buffer[0], buffer[1], buffer[2], buffer[3], 0};
        des3_encrypt(ar, ar, binwritekey, 2);
        memcpy(&sendar[5], ar, 8);
        ExchangeRAW14a(sendar, sizeof(sendar), false, true, buffer, 250, &garbage, false); // Send response to get write perms
        if (buffer[0] != 0x90){return 0x82;} // If it fails, stop

        uint8_t targetdata[8] = {4, date[0], date[1], date[2], date[3], 0x80, 0};
        des_encrypt_ecb(targetdata, targetdata, 8, mackey); // Provide encrypted data for writing
        ExchangeRAW14a(getnt, sizeof(getnt), false, true, buffer, 250, &garbage, false); // Request challenge to write binary
        uint8_t maciv[8] = {buffer[0], buffer[1], buffer[2], buffer[3], 0};
        uint8_t macdata[16] = {4, 0xd6, 0, 0, 12, 0};
        memcpy(&macdata[5], targetdata, 8); // Get the encrypted data 
        macdata[13] = 0x80;
        des_encrypt_cbc(macdata, macdata, 16, mackey, maciv); // Make MAC

        uint8_t cmdwritebin[17] = {4, 0xd6, 0, 0, 12, 0};
        memcpy(&cmdwritebin[5], targetdata, 8);
        memcpy(&cmdwritebin[13], &macdata[8], 4);
        ExchangeRAW14a(cmdwritebin, sizeof(cmdwritebin), false, true, buffer, 250, &garbage, false); // Write binary
        if (buffer[0] != 0x90){return 0xd6;} // If it fails, stop

    }*/
    ExchangeRAW14a(cmdreadbal, sizeof(cmdreadbal), false, true, buffer, 250, &garbage, false);
    PrintAndLogEx(INFO, "Current balance: %s", sprint_hex_inrow(buffer, 4));
    ExchangeRAW14a(cmdcharge1, sizeof(cmdcharge1), false, true, buffer, 250, &garbage, false);
    // ******************************************************************************************************************************************* //
    // Begin verifying MAC1
    uint8_t tempkey[8] = {buffer[8], buffer[9], buffer[10], buffer[11], buffer[4], buffer[5], 0x80, 0};
    des3_encrypt(tempkey, tempkey, rechargekey, 2);
    PrintAndLogEx(INFO, "Session key: %s", sprint_hex(tempkey, 8));
    // As we now have sesskey, we can now verify MAC1, which is composed of OLD BAL + REFILL VAL + TRANSACTION TYPE + READER ID and a padding 0x80
    uint8_t mac1data[16] = {buffer[0], buffer[1], buffer[2], buffer[3], 0, 0, value[0], value[1], 2, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x80};
    uint8_t iv[8] = {0};
    des_encrypt_cbc(mac1data, mac1data, 16, tempkey, iv);
    uint8_t mac1r[4] = {0};
    memcpy(mac1r, &mac1data[8], 4);
    uint8_t mac1t[4] = {0};
    memcpy(mac1t, &buffer[12], 4);
    PrintAndLogEx(INFO, "Our MAC1: %s, Card MAC1: %s", sprint_hex(mac1r, 4), sprint_hex(mac1t, 4));
    if(memcmp(mac1r, mac1t, 4) != 0){return 0x50;}
    // End verification
    // ******************************************************************************************************************************************* //

    // We can now compute MAC2 using the same key with data of REFILL VAL + TRANSACTION TYPE + READER ID + DATE + TIME
    // I don't know how to set the time, so let's hardcode it to April 5th, 2024 at 17:03:15.
    
    PrintAndLogEx(INFO, "MAC2 input: %s", sprint_hex(mac2data,24));
    des_encrypt_cbc(mac2result, mac2data, 24, tempkey, iv2);
    PrintAndLogEx(INFO, "MAC2 result: %s", sprint_hex(mac2result,24));
    uint8_t cmdcharge2[17]={0x80, 0x52, 0,0,0xb, 5, 4, 0x20, 0x24, 0x17, 3, 0x15, mac2result[16], mac2result[17], mac2result[18], mac2result[19], 0x04};
    ExchangeRAW14a(cmdcharge2, sizeof(cmdcharge2), false, true, buffer, 250, &garbage, false);
    if (buffer[4] != 0x90){return 0x52;}
    ExchangeRAW14a(cmdreadbal, sizeof(cmdreadbal), false, false, buffer, 250, &garbage, false);
    PrintAndLogEx(INFO, "New balance: %s", sprint_hex_inrow(buffer, 4));
    return 0;
}

int CalculateMAC(mf4Session_t *mf4session, MACType_t mtype, uint8_t blockNum, uint8_t blockCount, uint8_t *data, int datalen, uint8_t *mac, bool verbose) {
    if (!mf4session || !mf4session->Authenticated || !mac || !data || !datalen)
        return 1;

    memset(mac, 0x00, 8);

    uint16_t ctr = mf4session->R_Ctr;
    switch (mtype) {
        case mtypWriteCmd:
        case mtypWriteResp:
            ctr = mf4session->W_Ctr;
            break;
        case mtypReadCmd:
        case mtypReadResp:
            break;
    }

    uint8_t macdata[2049] = {data[0], (ctr & 0xFF), (ctr >> 8), 0};
    int macdatalen = datalen;
    memcpy(&macdata[3], mf4session->TI, 4);

    switch (mtype) {
        case mtypReadCmd:
            memcpy(&macdata[7], &data[1], datalen - 1);
            macdatalen = datalen + 6;
            break;
        case mtypReadResp:
            macdata[7] = blockNum;
            macdata[8] = 0;
            macdata[9] = blockCount;
            memcpy(&macdata[10], &data[1], datalen - 1);
            macdatalen = datalen + 9;
            break;
        case mtypWriteCmd:
            memcpy(&macdata[7], &data[1], datalen - 1);
            macdatalen = datalen + 6;
            break;
        case mtypWriteResp:
            macdatalen = 1 + 6;
            break;
    }

    if (verbose)
        PrintAndLogEx(INFO, "MAC data[%d]: %s", macdatalen, sprint_hex(macdata, macdatalen));

    return aes_cmac8(NULL, mf4session->Kmac, macdata, mac, macdatalen);
}

int MifareAuth4(mf4Session_t *mf4session, uint8_t *keyn, uint8_t *key, bool activateField, bool leaveSignalON, bool dropFieldIfError, bool verbose, bool silentMode) {
    uint8_t data[257] = {0};
    int datalen = 0;

    uint8_t RndA[17] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00};
    uint8_t RndB[17] = {0};

    if (silentMode)
        verbose = false;

    if (mf4session)
        mf4session->Authenticated = false;

    uint8_t cmd1[] = {0x70, keyn[1], keyn[0], 0x00};
    int res = ExchangeRAW14a(cmd1, sizeof(cmd1), activateField, true, data, sizeof(data), &datalen, silentMode);
    if (res != PM3_SUCCESS) {
        if (silentMode == false) {
            PrintAndLogEx(ERR, "Exchange raw error: %d", res);
        }

        if (dropFieldIfError) {
            DropField();
        }
        return PM3_ERFTRANS;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "< phase1: %s", sprint_hex(data, datalen));
    }

    if (datalen < 1) {
        if (!silentMode) PrintAndLogEx(ERR, "Card response wrong length: %d", datalen);
        if (dropFieldIfError) DropField();
        return PM3_EWRONGANSWER;
    }

    if (data[0] != 0x90) {
        if (!silentMode) PrintAndLogEx(ERR, "Card response error: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        if (dropFieldIfError) DropField();
        return PM3_EWRONGANSWER;
    }

    if (datalen != 19) { // code 1b + 16b + crc 2b
        if (!silentMode) PrintAndLogEx(ERR, "Card response must be 19 bytes long instead of: %d", datalen);
        if (dropFieldIfError) DropField();
        return PM3_EWRONGANSWER;
    }

    aes_decode(NULL, key, &data[1], RndB, 16);
    RndB[16] = RndB[0];
    if (verbose) {
        PrintAndLogEx(INFO, "RndB: %s", sprint_hex(RndB, 16));
    }

    uint8_t cmd2[33] = {0};
    cmd2[0] = 0x72;

    uint8_t raw[32] = {0};
    memmove(raw, RndA, 16);
    memmove(&raw[16], &RndB[1], 16);

    aes_encode(NULL, key, raw, &cmd2[1], 32);
    if (verbose) {
        PrintAndLogEx(INFO, ">phase2: %s", sprint_hex(cmd2, 33));
    }
    res = ExchangeRAW14a(cmd2, sizeof(cmd2), false, true, data, sizeof(data), &datalen, silentMode);
    if (res != PM3_SUCCESS) {
        if (silentMode == false) {
            PrintAndLogEx(ERR, "Exchange raw error: %d", res);
        }
        if (dropFieldIfError) {
            DropField();
        }
        return PM3_ERFTRANS;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "< phase2: %s", sprint_hex(data, datalen));
    }

    aes_decode(NULL, key, &data[1], raw, 32);

    if (verbose) {
        PrintAndLogEx(INFO, "res: %s", sprint_hex(raw, 32));
        PrintAndLogEx(INFO, "RndA`: %s", sprint_hex(&raw[4], 16));
    }

    if (memcmp(&raw[4], &RndA[1], 16)) {
        if (!silentMode) PrintAndLogEx(ERR, "\nAuthentication FAILED. rnd is not equal");
        if (verbose) {
            PrintAndLogEx(ERR, "RndA reader: %s", sprint_hex(&RndA[1], 16));
            PrintAndLogEx(ERR, "RndA   card: %s", sprint_hex(&raw[4], 16));
        }
        if (dropFieldIfError) DropField();
        return PM3_EWRONGANSWER;
    }

    if (verbose) {
        PrintAndLogEx(INFO, " TI: %s", sprint_hex(raw, 4));
        PrintAndLogEx(INFO, "pic: %s", sprint_hex(&raw[20], 6));
        PrintAndLogEx(INFO, "pcd: %s", sprint_hex(&raw[26], 6));
    }

    uint8_t kenc[16] = {0};
    memcpy(&kenc[0], &RndA[11], 5);
    memcpy(&kenc[5], &RndB[11], 5);
    for (int i = 0; i < 5; i++) {
        kenc[10 + i] = RndA[4 + i] ^ RndB[4 + i];
    }
    kenc[15] = 0x11;

    aes_encode(NULL, key, kenc, kenc, 16);
    if (verbose) {
        PrintAndLogEx(INFO, "kenc: %s", sprint_hex(kenc, 16));
    }

    uint8_t kmac[16] = {0};
    memcpy(&kmac[0], &RndA[7], 5);
    memcpy(&kmac[5], &RndB[7], 5);
    for (int i = 0; i < 5; i++) {
        kmac[10 + i] = RndA[0 + i] ^ RndB[0 + i];
    }
    kmac[15] = 0x22;

    aes_encode(NULL, key, kmac, kmac, 16);
    if (verbose) {
        PrintAndLogEx(INFO, "kmac: %s", sprint_hex(kmac, 16));
    }

    if (leaveSignalON == false) {
        DropField();
    }

    if (verbose) {
        PrintAndLogEx(NORMAL, "");
    }

    if (mf4session) {
        mf4session->Authenticated = true;
        mf4session->R_Ctr = 0;
        mf4session->W_Ctr = 0;
        mf4session->KeyNum = keyn[1] + (keyn[0] << 8);
        memmove(mf4session->RndA, RndA, 16);
        memmove(mf4session->RndB, RndB, 16);
        memmove(mf4session->Key, key, 16);
        memmove(mf4session->TI, raw, 4);
        memmove(mf4session->PICCap2, &raw[20], 6);
        memmove(mf4session->PCDCap2, &raw[26], 6);
        memmove(mf4session->Kenc, kenc, 16);
        memmove(mf4session->Kmac, kmac, 16);
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Authentication OK");
    }

    return PM3_SUCCESS;
}

static int intExchangeRAW14aPlus(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    if (g_verbose_mode) {
        PrintAndLogEx(INFO, ">>> %s", sprint_hex(datain, datainlen));
    }

    int res = ExchangeRAW14a(datain, datainlen, activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen, false);

    if (g_verbose_mode) {
        PrintAndLogEx(INFO, "<<< %s", sprint_hex(dataout, *dataoutlen));
    }
    return res;
}

int MFPWritePerso(uint8_t *keyNum, uint8_t *key, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    uint8_t rcmd[3 + 16] = {0xa8, keyNum[1], keyNum[0], 0x00};
    memmove(&rcmd[3], key, 16);

    return intExchangeRAW14aPlus(rcmd, sizeof(rcmd), activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen);
}

int MFPCommitPerso(bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    uint8_t rcmd[1] = {0xaa};

    return intExchangeRAW14aPlus(rcmd, sizeof(rcmd), activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen);
}

int MFPReadBlock(mf4Session_t *mf4session, bool plain, bool nomaccmd, bool nomacres, uint8_t blockNum, uint8_t blockCount, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, uint8_t *mac) {

    int cmdb = 0x31;
    if (nomacres) {
        cmdb = cmdb ^ 0x01;  // If we do not want MAC in reply, remove 0x01
    }

    if (plain) {
        cmdb = cmdb ^ 0x02;  // If we do not need an encrypted transmission, add 0x02
    }

    if (nomaccmd) {
        cmdb = cmdb ^ 0x04; // If we do not want to send a MAC, remove 0x04
    }

    uint8_t rcmd1[4] = {cmdb, blockNum, 0x00, blockCount};
    uint8_t maccmddat[8] = {0};
    uint8_t rcmd[nomaccmd ? 4 : 12];

    if (nomaccmd == false && mf4session) {
        CalculateMAC(mf4session, mtypReadCmd, blockNum, blockCount, rcmd1, 4, &maccmddat[0], g_verbose_mode);
    }

    memmove(rcmd, rcmd1, 4);
    if (nomaccmd == false) {
        memmove(&rcmd[4], maccmddat, 8);
    }

    int res = intExchangeRAW14aPlus(rcmd, sizeof(rcmd), activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (mf4session) {
        mf4session->R_Ctr++;
    }

    if (mf4session && !nomacres && *dataoutlen > 11) {
        CalculateMAC(mf4session, mtypReadResp, blockNum, blockCount, dataout, *dataoutlen - 8 - 2, mac, g_verbose_mode);
    }

    return PM3_SUCCESS;
}

int MFPWriteBlock(mf4Session_t *mf4session, bool plain, bool nomacres, uint8_t blockNum, uint8_t blockHdr, uint8_t *data, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, uint8_t *mac) {
    int cmdb = 0xA1;
    if (nomacres) {
        cmdb = cmdb ^ 0x01; // If we do not want MAC in reply, remove 0x01
    }

    if (plain) {
        cmdb = cmdb ^ 0x02; // If we do not need an encrypted transmission, add 0x02
    }

    uint8_t rcmd[1 + 2 + 16 + 8] = {cmdb, blockNum, blockHdr};
    memmove(&rcmd[3], data, 16);
    if (mf4session) {
        CalculateMAC(mf4session, mtypWriteCmd, blockNum, 1, rcmd, 19, &rcmd[19], g_verbose_mode);
    }

    int res = intExchangeRAW14aPlus(rcmd, sizeof(rcmd), activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (mf4session) {
        mf4session->W_Ctr++;
    }

    if (mf4session && mac && *dataoutlen > 3 && !nomacres) {
        CalculateMAC(mf4session, mtypWriteResp, blockNum, 1, dataout, *dataoutlen, mac, g_verbose_mode);
    }

    return PM3_SUCCESS;
}

int mfpReadSector(uint8_t sectorNo, uint8_t keyType, uint8_t *key, uint8_t *dataout, bool verbose) {
    uint8_t keyn[2] = {0};
    bool plain = false;

    uint16_t uKeyNum = 0x4000 + sectorNo * 2 + (keyType ? 1 : 0);
    keyn[0] = uKeyNum >> 8;
    keyn[1] = uKeyNum & 0xff;
    if (verbose) {
        PrintAndLogEx(INFO, "--sector[%u]:%02x key:%04x", mfNumBlocksPerSector(sectorNo), sectorNo, uKeyNum);
    }

    mf4Session_t _session;
    int res = MifareAuth4(&_session, keyn, key, true, true, true, verbose, false);
    if (res) {
        PrintAndLogEx(ERR, "Sector %u authentication error: %d", sectorNo, res);
        return res;
    }

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};
    uint8_t firstBlockNo = mfFirstBlockOfSector(sectorNo);
    for (int n = firstBlockNo; n < firstBlockNo + mfNumBlocksPerSector(sectorNo); n++) {
        res = MFPReadBlock(&_session, plain, false, false, n & 0xff, 1, false, true, data, sizeof(data), &datalen, mac);
        if (res) {
            PrintAndLogEx(ERR, "Sector %u read error: %d", sectorNo, res);
            DropField();
            return res;
        }

        if (datalen && data[0] != 0x90) {
            PrintAndLogEx(ERR, "Sector %u card read error: %02x %s", sectorNo, data[0], mfpGetErrorDescription(data[0]));
            DropField();
            return 5;
        }
        if (datalen != 1 + 16 + 8 + 2) {
            PrintAndLogEx(ERR, "Sector %u error returned data length:%d", sectorNo, datalen);
            DropField();
            return 6;
        }

        memcpy(&dataout[(n - firstBlockNo) * 16], &data[1], 16);

        if (verbose)
            PrintAndLogEx(INFO, "data[%03d]: %s", n, sprint_hex(&data[1], 16));

        if (memcmp(&data[1 + 16], mac, 8)) {
            PrintAndLogEx(WARNING, "WARNING: mac on block %d not equal...", n);
            PrintAndLogEx(WARNING, "MAC   card: %s", sprint_hex(&data[1 + 16], 8));
            PrintAndLogEx(WARNING, "MAC reader: %s", sprint_hex(mac, 8));

            if (verbose == false) {
                return 7;
            }
        } else {
            if (verbose) {
                PrintAndLogEx(INFO, "MAC: %s", sprint_hex(&data[1 + 16], 8));
            }
        }
    }
    DropField();

    return PM3_SUCCESS;
}

int MFPGetSignature(bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    uint8_t c[] = {0x3c, 0x00};
    return intExchangeRAW14aPlus(c, sizeof(c), activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen);
}

int MFPGetVersion(bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    uint8_t tmp[20] = {0};
    uint8_t c[] = {0x60};
    int res = intExchangeRAW14aPlus(c, sizeof(c), activateField, true, tmp, maxdataoutlen, dataoutlen);
    if (res != 0) {
        DropField();
        *dataoutlen = 0;
        return res;
    }

    memcpy(dataout, tmp + 1, (*dataoutlen - 3));

    *dataoutlen = 0;
    // MFDES_ADDITIONAL_FRAME
    if (tmp[0] == 0xAF) {
        c[0] = 0xAF;
        res = intExchangeRAW14aPlus(c, sizeof(c), false, true, tmp, maxdataoutlen, dataoutlen);
        if (res == PM3_SUCCESS) {

            memcpy(dataout + 7, tmp + 1, (*dataoutlen - 3));

            // MFDES_ADDITIONAL_FRAME
            res = intExchangeRAW14aPlus(c, sizeof(c), false, false, tmp, maxdataoutlen, dataoutlen);
            if (res == PM3_SUCCESS) {
                if (tmp[0] == 0x90) {
                    memcpy(dataout + 7 + 7, tmp + 1, (*dataoutlen - 3));
                    *dataoutlen = 28;
                }
            }
        }
    }
    DropField();
    return res;
}

// Mifare Memory Structure: up to 32 Sectors with 4 blocks each (1k and 2k cards),
// plus evtl. 8 sectors with 16 blocks each (4k cards)
uint8_t mfNumBlocksPerSector(uint8_t sectorNo) {
    if (sectorNo < 32) {
        return 4;
    } else {
        return 16;
    }
}

uint8_t mfFirstBlockOfSector(uint8_t sectorNo) {
    if (sectorNo < 32) {
        return sectorNo * 4;
    } else {
        return 32 * 4 + (sectorNo - 32) * 16;
    }
}

uint8_t mfSectorTrailerOfSector(uint8_t sectorNo) {
    if (sectorNo < 32) {
        return (sectorNo * 4) | 0x03;
    } else {
        return (32 * 4 + (sectorNo - 32) * 16) | 0x0f;
    }
}

// assumes blockno is 0-255..
uint8_t mfSectorTrailer(uint16_t blockNo) {
    if (blockNo < 32 * 4) {
        return (blockNo | 0x03);
    } else {
        return (blockNo | 0x0F);
    }
}

// assumes blockno is 0-255..
bool mfIsSectorTrailer(uint16_t blockNo) {
    return (blockNo == mfSectorTrailer(blockNo));
}

// assumes blockno is 0-255..
uint8_t mfSectorNum(uint16_t blockNo) {
    if (blockNo < 32 * 4)
        return (blockNo / 4);
    else
        return (32 + (blockNo - 32 * 4) / 16);

}

bool mfIsSectorTrailerBasedOnBlocks(uint8_t sectorno, uint16_t blockno) {
    if (sectorno < 32) {
        return ((blockno | 0x03) == blockno);
    } else {
        return ((blockno | 0x0F) == blockno);
    }
}
