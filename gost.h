#ifndef GOST_H
#define GOST_H

#include <qfile.h>
#include <qtextstream.h>

#define GOST_KEY_SIZE       256
#define GOST_DATA_SIZE      64
#define GOST_SBUFFER_SIZE   32
#define GOST_ROUNDS         32
#define GOST_BIT_SHIFT      11

class GOST
{private:
    void EncryptDecrypt(bool[GOST_DATA_SIZE],bool encryptFlag);
    unsigned long ExpansionKeys[GOST_ROUNDS];
    void Modes(bool data[GOST_DATA_SIZE],bool vector[GOST_DATA_SIZE]);
    void GenerateKeys(const bool buffer[GOST_KEY_SIZE]);
public:
    QString ErrorStr;
    bool EncryptDecryptFlag;
    int ModeIndex;
    int MainGOST(QFile*,QFile*,QFile*,QFile*);};
const unsigned char SBOX[16*8]=
{
//sbox1
     4,10, 9, 2,13, 8, 0,14, 6,11, 1,12, 7,15, 5, 3,
//sbox2
    14,11, 4,12, 6,13,15,10, 2, 3, 8, 1, 0, 7, 5, 9,
//sbox3
     5, 8, 1,13,10, 3, 4, 2,14,15,12, 7, 6, 0, 9,11,
//sbox4
     7,13,10, 1, 0, 8, 9,15,14, 4, 6,12,11, 2, 5, 3,
//sbox5
     6,12, 7, 1, 5,15,13, 8, 4,10, 9,14, 0, 3,11, 2,
//sbox6
     4,11,10, 0, 7, 2, 1,13, 3, 6, 8, 5, 9,12,15,14,
//sbox7
    13,11, 4, 1, 3,15, 5, 9, 0,10,14, 7, 6, 8, 2,12,
//sbox8
     1,15,13, 0, 5, 7,10, 4, 9, 2, 3,14, 6,11, 8,12};
#endif
