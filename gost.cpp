#include "gost.h"

void GOST::GenerateKeys(const bool buffer[GOST_KEY_SIZE])
{
    int round;
    int counter;
    int keyNumber;
    for (round = 0, keyNumber = 0; round < GOST_ROUNDS - 8; round++)
    {
        for(counter = 0, ExpansionKeys[round] = 0; counter < GOST_SBUFFER_SIZE; ++counter)
        {
            ExpansionKeys[round] <<= 1;
            ExpansionKeys[round] |= buffer[keyNumber * GOST_SBUFFER_SIZE + counter];
        }
        if(keyNumber == 7)
            keyNumber = 0;
        else
            keyNumber++;
    }
    for (keyNumber = 7; round < GOST_ROUNDS; round++)
    {
        for(counter = 0, ExpansionKeys[round] = 0; counter < GOST_SBUFFER_SIZE; ++counter)
        {
            ExpansionKeys[round] <<= 1;
            ExpansionKeys[round] |= buffer[keyNumber * GOST_SBUFFER_SIZE + counter];
        }
        keyNumber--;
    }
}

void GOST::EncryptDecrypt(bool data[GOST_DATA_SIZE],bool encryptFlag)
{
    bool sBuffer[GOST_SBUFFER_SIZE];
    bool aBuffer[GOST_SBUFFER_SIZE];
    bool bBuffer[GOST_SBUFFER_SIZE];
    bool shiftBufferLeft[GOST_BIT_SHIFT];

    unsigned long var;
    bool buf;

    int round;
    int counter;
    unsigned char x;

    /*битовая инверсия левого и правого блоков*/
    for(counter = 0; counter < GOST_SBUFFER_SIZE; counter++)
    {
        aBuffer[counter] = data[(GOST_DATA_SIZE / 2 - 1) - counter];
        bBuffer[counter] = data[(GOST_DATA_SIZE - 1) - counter];
    }

    for (round = 0; round < GOST_ROUNDS; round++)
    {
        for(counter = 0; counter < GOST_SBUFFER_SIZE; counter++)
        {
            sBuffer[counter] = aBuffer[counter];
        }

        for (counter = 0, var = 0; counter < GOST_SBUFFER_SIZE; counter++)
        {
            var <<= 1;
            var |= sBuffer[counter];
        }
        /*Сложение с ключом по модулю 2^32*/
        var += ExpansionKeys[encryptFlag ? round : ((GOST_ROUNDS - 1) - round)];

        for (counter = GOST_SBUFFER_SIZE - 1; counter >= 0; counter--)
        {
            sBuffer[counter] = var & 1;
            var >>= 1;
        }


        /* Преобразование через S-блоки */
        for (counter = 0; counter < 8; counter++)
        {
            x = sBuffer[counter * 4 + 0] << 3 |\
                sBuffer[counter * 4 + 1] << 2 |\
                sBuffer[counter * 4 + 2] << 1 |\
                sBuffer[counter * 4 + 3] << 0;

            x = SBOX[counter * 16 + x];

            sBuffer[counter * 4 + 0] = x >> 3 & 1;
            sBuffer[counter * 4 + 1] = x >> 2 & 1;
            sBuffer[counter * 4 + 2] = x >> 1 & 1;
            sBuffer[counter * 4 + 3] = x & 1;
        }
        /*Битовый сдвиг влево на 11*/
        for (counter = 0; counter < GOST_BIT_SHIFT; counter++)
        {
            shiftBufferLeft[counter] = sBuffer[counter];
        }

        for (counter = 0; counter < GOST_SBUFFER_SIZE - GOST_BIT_SHIFT; counter++)
        {
            sBuffer[counter] = sBuffer[counter + GOST_BIT_SHIFT];
        }
        for (counter = 0; counter < GOST_BIT_SHIFT; counter++)
        {
            sBuffer[GOST_SBUFFER_SIZE - GOST_BIT_SHIFT + counter] = shiftBufferLeft[counter];
        }
        /*B(i) = A(i)
        A(i) = B(i) xor F(A(i-1),K(i)*/
        if (round < GOST_ROUNDS - 1)
        {
            for (counter = 0; counter < GOST_SBUFFER_SIZE; counter++)
            {
                buf = aBuffer[counter];
                aBuffer[counter] = bBuffer[counter] ^ sBuffer[counter];
                bBuffer[counter] = buf;
            }
        }
        else
        {
            for (counter = 0; counter < GOST_SBUFFER_SIZE; counter++)
            {
                bBuffer[counter] ^= sBuffer[counter];
            }
        }
    }

    /*битовая инверсия левого и правого блоков*/
    for(counter = 0; counter < GOST_SBUFFER_SIZE; counter++)
    {
        data[(GOST_DATA_SIZE / 2 - 1) - counter] = aBuffer[counter];
        data[(GOST_DATA_SIZE - 1) - counter] = bBuffer[counter];
    }

}

void GOST::Modes(bool data[GOST_DATA_SIZE], bool vector[GOST_DATA_SIZE])
{
    bool buffer[GOST_DATA_SIZE];
    int counter;
    switch(ModeIndex)
    {
    case 0://ECB
        EncryptDecrypt(data, EncryptDecryptFlag);
        break;
    case 1://CBC
        if(EncryptDecryptFlag)
        {
            for(counter = 0; counter < GOST_DATA_SIZE; ++counter)
                data[counter] ^= vector[counter];
            EncryptDecrypt(data, EncryptDecryptFlag);
            memcpy(vector, data, GOST_DATA_SIZE);
        }
        else
        {
            memcpy(buffer, data, GOST_DATA_SIZE);
            EncryptDecrypt(data, EncryptDecryptFlag);
            for(counter = 0; counter < GOST_DATA_SIZE; ++counter)
            {
                data[counter] ^= vector[counter];
            }
            memcpy(vector, buffer, GOST_DATA_SIZE);
        }
        break;
    case 2://CFB
        EncryptDecrypt(vector, 1);
        if(EncryptDecryptFlag)
        {
            for(counter = 0; counter < GOST_DATA_SIZE; ++counter)
            {
                data[counter] ^= vector[counter];
            }
            memcpy(vector, data, GOST_DATA_SIZE);
        }
        else
        {
            memcpy(buffer, data, GOST_DATA_SIZE);
            for(counter = 0; counter < GOST_DATA_SIZE; ++counter)
            {
                data[counter] ^= vector[counter];
            }
            memcpy(vector, buffer, GOST_DATA_SIZE);
        }
        break;
    case 3://OFB
        EncryptDecrypt(vector, 1);
        for(counter = 0; counter < GOST_DATA_SIZE; ++counter)
            data[counter] ^= vector[counter];
        break;
    }
}

int GOST::MainGOST(QFile *inputFile, QFile *keyFile,\
                 QFile *outputFile, QFile *vectorFile)
{
    int size;
    int counter;
    bool buffer[GOST_DATA_SIZE];
    bool vectorBuffer[GOST_DATA_SIZE];
    bool endReadFlag = 0;
    bool firstReadFlag = 1;
    char InputByteBuffer[GOST_DATA_SIZE / 8];
    char OutputByteBuffer[GOST_DATA_SIZE / 8];
    char password[GOST_KEY_SIZE / 8];
    bool passwordBuffer[GOST_KEY_SIZE];

    if((size = keyFile->read(password, GOST_KEY_SIZE / 8)) < GOST_KEY_SIZE / 8)
        for(counter = size; counter < GOST_KEY_SIZE / 8; ++counter)
            password[counter] = 0;

    for(counter = 0; counter < GOST_KEY_SIZE / 8; ++counter)
    {
        passwordBuffer[counter * 8 + 0] = password[counter] >> 7 & 1;
        passwordBuffer[counter * 8 + 1] = password[counter] >> 6 & 1;
        passwordBuffer[counter * 8 + 2] = password[counter] >> 5 & 1;
        passwordBuffer[counter * 8 + 3] = password[counter] >> 4 & 1;
        passwordBuffer[counter * 8 + 4] = password[counter] >> 3 & 1;
        passwordBuffer[counter * 8 + 5] = password[counter] >> 2 & 1;
        passwordBuffer[counter * 8 + 6] = password[counter] >> 1 & 1;
        passwordBuffer[counter * 8 + 7] = password[counter] & 1;
    }

    GenerateKeys(passwordBuffer);

    if(ModeIndex)
    {
        if((size = vectorFile->read(InputByteBuffer, GOST_DATA_SIZE / 8)) < GOST_DATA_SIZE / 8)
            for(counter = size; counter < GOST_DATA_SIZE / 8; ++counter)
                InputByteBuffer[counter] = 0;
        for(counter = 0; counter < GOST_DATA_SIZE / 8; ++counter)
        {
            vectorBuffer[counter * 8 + 0] = InputByteBuffer[counter] >> 7 & 1;
            vectorBuffer[counter * 8 + 1] = InputByteBuffer[counter] >> 6 & 1;
            vectorBuffer[counter * 8 + 2] = InputByteBuffer[counter] >> 5 & 1;
            vectorBuffer[counter * 8 + 3] = InputByteBuffer[counter] >> 4 & 1;
            vectorBuffer[counter * 8 + 4] = InputByteBuffer[counter] >> 3 & 1;
            vectorBuffer[counter * 8 + 5] = InputByteBuffer[counter] >> 2 & 1;
            vectorBuffer[counter * 8 + 6] = InputByteBuffer[counter] >> 1 & 1;
            vectorBuffer[counter * 8 + 7] = InputByteBuffer[counter] & 1;
        }
    }

    while (!endReadFlag)
    {
        if((size = inputFile->read(InputByteBuffer, GOST_DATA_SIZE / 8)) < GOST_DATA_SIZE / 8)
        {
            endReadFlag = 1;
            for(counter = size; counter < GOST_DATA_SIZE / 8 - 1; ++counter)
                InputByteBuffer[counter] = 0;
            InputByteBuffer[GOST_DATA_SIZE / 8 - 1] = 8 - size;
        }
        for(counter = 0; counter < GOST_DATA_SIZE / 8; ++counter)
        {
            buffer[counter * 8 + 0] = InputByteBuffer[counter] >> 7 & 1;
            buffer[counter * 8 + 1] = InputByteBuffer[counter] >> 6 & 1;
            buffer[counter * 8 + 2] = InputByteBuffer[counter] >> 5 & 1;
            buffer[counter * 8 + 3] = InputByteBuffer[counter] >> 4 & 1;
            buffer[counter * 8 + 4] = InputByteBuffer[counter] >> 3 & 1;
            buffer[counter * 8 + 5] = InputByteBuffer[counter] >> 2 & 1;
            buffer[counter * 8 + 6] = InputByteBuffer[counter] >> 1 & 1;
            buffer[counter * 8 + 7] = InputByteBuffer[counter] & 1;
        }

        if(endReadFlag && !EncryptDecryptFlag)
        {
            if(size)
            {
                ErrorStr = "Unexpected end of file\n";
                return 1;
            }
            else
            {
                outputFile->write(OutputByteBuffer,\
                                  GOST_DATA_SIZE / 8 - OutputByteBuffer[GOST_DATA_SIZE / 8 - 1]);
                return 0;
            }
        }
        else
        {
            if(firstReadFlag)
                firstReadFlag = 0;
            else
            {
                outputFile->write(OutputByteBuffer, GOST_DATA_SIZE / 8);
            }
            Modes(buffer, vectorBuffer);
            for(counter = 0; counter < GOST_DATA_SIZE / 8; ++counter)
            {
                OutputByteBuffer[counter] = (\
                            buffer[counter * 8 + 0] << 7 |\
                            buffer[counter * 8 + 1] << 6 |\
                            buffer[counter * 8 + 2] << 5 |\
                            buffer[counter * 8 + 3] << 4 |\
                            buffer[counter * 8 + 4] << 3 |\
                            buffer[counter * 8 + 5] << 2 |\
                            buffer[counter * 8 + 6] << 1 |\
                            buffer[counter * 8 + 7]);
            }
        }
        if(endReadFlag)
        {
            outputFile->write(OutputByteBuffer, GOST_DATA_SIZE / 8);
        }
    }
    return 0;
}
