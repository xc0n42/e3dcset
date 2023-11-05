#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include "RscpProtocol.h"
#include "RscpTags.h"
#include "SocketConnection.h"
#include "AES.h"

#define DEBUG(...)if(debug) {printf(__VA_ARGS__);}

#define AES_KEY_SIZE	32
#define AES_BLOCK_SIZE	32

typedef struct {

	uint32_t MIN_LEISTUNG;
	uint32_t MAX_LEISTUNG;
	uint32_t MIN_LADUNGSMENGE;
	uint32_t MAX_LADUNGSMENGE;
    char 	 server_ip[20];
    uint32_t server_port;
    char 	 e3dc_user[128];
    char 	 e3dc_password[128];
    char 	 aes_password[128];
    bool	 debug;

} e3dc_config_t;

static int iSocket = -1;
static int iAuthenticated = 0;

static AES aesEncrypter;
static AES aesDecrypter;

static uint8_t ucEncryptionIV[AES_BLOCK_SIZE];
static uint8_t ucDecryptionIV[AES_BLOCK_SIZE];

static bool leistungAendern = false;
static bool automatischLeistungEinstellen = false;
static bool ladeLeistungGesetzt = false;
static bool entladeLeistungGesetzt = false;
static bool manuelleSpeicherladung = false;
static int powersave = -1;

static uint32_t ladungsMenge = 0;
static uint32_t ladeLeistung = 0;
static uint32_t entladeLeistung = 0;


static e3dc_config_t e3dc_config;

static bool debug = false;

static char *config = strdup("e3dcset.config");


int createRequestExample(SRscpFrameBuffer * frameBuffer) {
    RscpProtocol protocol;
    SRscpValue rootValue;
    // The root container is create with the TAG ID 0 which is not used by any device.
    protocol.createContainerValue(&rootValue, 0);

    //---------------------------------------------------------------------------------------------------------
    // Create a request frame
    //---------------------------------------------------------------------------------------------------------
    if(iAuthenticated == 0){
        DEBUG("Request authentication\n");
        // authentication request
        SRscpValue authenContainer;
        protocol.createContainerValue(&authenContainer, TAG_RSCP_REQ_AUTHENTICATION);
        protocol.appendValue(&authenContainer, TAG_RSCP_AUTHENTICATION_USER, e3dc_config.e3dc_user);
        protocol.appendValue(&authenContainer, TAG_RSCP_AUTHENTICATION_PASSWORD, e3dc_config.e3dc_password);
        // append sub-container to root container
        protocol.appendValue(&rootValue, authenContainer);
        // free memory of sub-container as it is now copied to rootValue
        protocol.destroyValueData(authenContainer);

    }else{

        if (manuelleSpeicherladung){
    		protocol.appendValue(&rootValue, TAG_EMS_REQ_START_MANUAL_CHARGE, ladungsMenge);
        }


        if (leistungAendern){

            SRscpValue PMContainer;
            protocol.createContainerValue(&PMContainer, TAG_EMS_REQ_SET_POWER_SETTINGS);

            if (powersave >= 0)
            {
                if (powersave == 0)
                {
                    printf("Schalte Power-Save aus\n");
                    protocol.appendValue(&PMContainer, TAG_EMS_POWERSAVE_ENABLED, (unsigned char)0);
                }
                else if (powersave == 1)
                {
                    printf("Schalte Power-Save ein\n");
                    protocol.appendValue(&PMContainer, TAG_EMS_POWERSAVE_ENABLED, (unsigned char)1);
                }
            }

            if (automatischLeistungEinstellen){

              printf("Setze Lade-/EntladeLeistung auf Automatik\n");
              protocol.appendValue(&PMContainer, TAG_EMS_POWER_LIMITS_USED, false);

            }

            if (ladeLeistungGesetzt || entladeLeistungGesetzt){

              protocol.appendValue(&PMContainer, TAG_EMS_POWER_LIMITS_USED, true);

              if (ladeLeistungGesetzt){

                printf("Setze LadeLeistung auf %iW\n",ladeLeistung);
                protocol.appendValue(&PMContainer, TAG_EMS_MAX_CHARGE_POWER, ladeLeistung);

              }

              if (entladeLeistungGesetzt){

                printf("Setze EntladeLeistung auf %iW\n",entladeLeistung);
                protocol.appendValue(&PMContainer, TAG_EMS_MAX_DISCHARGE_POWER, entladeLeistung);

              }

            }

          	// append sub-container to root container
            protocol.appendValue(&rootValue, PMContainer);
            // free memory of sub-container as it is now copied to rootValue
            protocol.destroyValueData(PMContainer);

    	}

    }

    // create buffer frame to send data to the S10
    protocol.createFrameAsBuffer(frameBuffer, rootValue.data, rootValue.length, true); // true to calculate CRC on for transfer
    // the root value object should be destroyed after the data is copied into the frameBuffer and is not needed anymore
    protocol.destroyValueData(rootValue);

    return 0;
}

int handleResponseValue(RscpProtocol *protocol, SRscpValue *response) {
    // check if any of the response has the error flag set and react accordingly
    if(response->dataType == RSCP::eTypeError) {
        // handle error for example access denied errors
        uint32_t uiErrorCode = protocol->getValueAsUInt32(response);
        printf("Tag 0x%08X received error code %u.\n", response->tag, uiErrorCode);
        return -1;
    }

    // check the SRscpValue TAG to detect which response it is
    switch(response->tag){
    case TAG_RSCP_AUTHENTICATION: {
        // It is possible to check the response->dataType value to detect correct data type
        // and call the correct function. If data type is known,
        // the correct function can be called directly like in this case.
        uint8_t ucAccessLevel = protocol->getValueAsUChar8(response);
        if(ucAccessLevel > 0) {
            iAuthenticated = 1;
        }
        DEBUG("RSCP authentitication level %i\n", ucAccessLevel);
        break;
    }
    case TAG_EMS_START_MANUAL_CHARGE: {

        if (protocol->getValueAsBool(response)){

        	if (ladungsMenge == 0){
        		printf("Manuelles Laden gestoppt\n");
        	}else{
        		printf("Manuelles Laden gestartet\n");
        	}

        }else{
          printf("Manuelles Laden abgeleht.\n");
        }
	break;
    } 
    case TAG_EMS_POWER_PV: {    // response for TAG_EMS_REQ_POWER_PV
        int32_t iPower = protocol->getValueAsInt32(response);
        printf("EMS PV power is %i W\n", iPower);
        break;
    }
    case TAG_EMS_POWER_BAT: {    // response for TAG_EMS_REQ_POWER_BAT
        int32_t iPower = protocol->getValueAsInt32(response);
        printf("EMS BAT power is %i W\n", iPower);
        break;
    }
    case TAG_EMS_POWER_HOME: {    // response for TAG_EMS_REQ_POWER_HOME
        int32_t iPower = protocol->getValueAsInt32(response);
        printf("EMS house power is %i W\n", iPower);
        break;
    }
    case TAG_EMS_POWER_GRID: {    // response for TAG_EMS_REQ_POWER_GRID
        int32_t iPower = protocol->getValueAsInt32(response);
        printf("EMS grid power is %i W\n", iPower);
        break;
    }
    case TAG_EMS_POWER_ADD: {    // response for TAG_EMS_REQ_POWER_ADD
        int32_t iPower = protocol->getValueAsInt32(response);
        printf("EMS add power meter power is %i W\n", iPower);
        break;
    }
    case TAG_BAT_DATA: {        // response for TAG_BAT_REQ_DATA
        uint8_t ucBatteryIndex = 0;
        std::vector<SRscpValue> batteryData = protocol->getValueAsContainer(response);
        for(size_t i = 0; i < batteryData.size(); ++i) {
            if(batteryData[i].dataType == RSCP::eTypeError) {
                // handle error for example access denied errors
                uint32_t uiErrorCode = protocol->getValueAsUInt32(&batteryData[i]);
                printf("Tag 0x%08X received error code %u.\n", batteryData[i].tag, uiErrorCode);
                return -1;
            }
            // check each battery sub tag
            switch(batteryData[i].tag) {
            case TAG_BAT_INDEX: {
                ucBatteryIndex = protocol->getValueAsUChar8(&batteryData[i]);
                break;
            }
            case TAG_BAT_RSOC: {              // response for TAG_BAT_REQ_RSOC
                float fSOC = protocol->getValueAsFloat32(&batteryData[i]);
                printf("Battery SOC is %0.1f %%\n", fSOC);
                break;
            }
            case TAG_BAT_MODULE_VOLTAGE: {    // response for TAG_BAT_REQ_MODULE_VOLTAGE
                float fVoltage = protocol->getValueAsFloat32(&batteryData[i]);
                printf("Battery total voltage is %0.1f V\n", fVoltage);
                break;
            }
            case TAG_BAT_CURRENT: {    // response for TAG_BAT_REQ_CURRENT
                float fVoltage = protocol->getValueAsFloat32(&batteryData[i]);
                printf("Battery current is %0.1f A\n", fVoltage);
                break;
            }
            case TAG_BAT_STATUS_CODE: {    // response for TAG_BAT_REQ_STATUS_CODE
                uint32_t uiErrorCode = protocol->getValueAsUInt32(&batteryData[i]);
                printf("Battery status code is 0x%08X\n", uiErrorCode);
                break;
            }
            case TAG_BAT_ERROR_CODE: {    // response for TAG_BAT_REQ_ERROR_CODE
                uint32_t uiErrorCode = protocol->getValueAsUInt32(&batteryData[i]);
                printf("Battery error code is 0x%08X\n", uiErrorCode);
                break;
            }
            // ...
            default:
                // default behaviour
                printf("Unknown battery tag %08X\n", response->tag);
                break;
            }
        }
        protocol->destroyValueData(batteryData);
        break;
       }

        case TAG_EMS_SET_POWER_SETTINGS: {        // response for TAG_PM_REQ_DATA
            uint8_t ucPMIndex = 0;
            std::vector<SRscpValue> PMData = protocol->getValueAsContainer(response);
            for(size_t i = 0; i < PMData.size(); ++i) {
                if(PMData[i].dataType == RSCP::eTypeError) {
                    // handle error for example access denied errors
                    uint32_t uiErrorCode = protocol->getValueAsUInt32(&PMData[i]);
                    printf("TAG_EMS_GET_POWER_SETTINGS 0x%08X received error code %u.\n", PMData[i].tag, uiErrorCode);
                    return -1;
                }
                // check each PM sub tag
                switch(PMData[i].tag) {
                    case TAG_PM_INDEX: {
                        ucPMIndex = protocol->getValueAsUChar8(&PMData[i]);
                        break;
                    }
                    case TAG_EMS_POWER_LIMITS_USED: {              // response for POWER_LIMITS_USED
                        if (protocol->getValueAsBool(&PMData[i])){
                            printf("POWER_LIMITS_USED\n");
                            }
                        break;
                    }
                    case TAG_EMS_MAX_CHARGE_POWER: {              // 101 response for TAG_EMS_MAX_CHARGE_POWER
                        uint32_t uPower = protocol->getValueAsUInt32(&PMData[i]);
                        printf("MAX_CHARGE_POWER %i W\n", uPower);
                        break;
                    }
                    case TAG_EMS_MAX_DISCHARGE_POWER: {              //102 response for TAG_EMS_MAX_DISCHARGE_POWER
                        uint32_t uPower = protocol->getValueAsUInt32(&PMData[i]);
                        printf("MAX_DISCHARGE_POWER %i W\n", uPower);
                        break;
                    }
                    case TAG_EMS_DISCHARGE_START_POWER:{              //103 response for TAG_EMS_DISCHARGE_START_POWER
                        uint32_t uPower = protocol->getValueAsUInt32(&PMData[i]);
                        printf("DISCHARGE_START_POWER %i W\n", uPower);
                        break;
                    }
                    case TAG_EMS_POWERSAVE_ENABLED: {              //104 response for TAG_EMS_POWERSAVE_ENABLED
                        if (protocol->getValueAsBool(&PMData[i])){
                            printf("POWERSAVE_ENABLED\n");
                        }
                        break;
                    }
                    case TAG_EMS_WEATHER_REGULATED_CHARGE_ENABLED: {//105 resp WEATHER_REGULATED_CHARGE_ENABLED
                        if (protocol->getValueAsBool(&PMData[i])){
                            printf("WEATHER_REGULATED_CHARGE_ENABLED\n");
                        }
                        break;
                    }
                        // ...
                    default:
                        // default behaviour
                        break;
                }
            }
            protocol->destroyValueData(PMData);
            break;

    }
    // ...
    default:
        // default behavior
        printf("Unknown tag %08X\n", response->tag);
        break;
    }
    return 0;
}

static int processReceiveBuffer(const unsigned char * ucBuffer, int iLength)
{
    RscpProtocol protocol;
    SRscpFrame frame;

    int iResult = protocol.parseFrame(ucBuffer, iLength, &frame);
    if(iResult < 0) {
        // check if frame length error occured
        // in that case the full frame length was not received yet
        // and the receive function must get more data
        if(iResult == RSCP::ERR_INVALID_FRAME_LENGTH) {
            return 0;
        }
        // otherwise a not recoverable error occured and the connection can be closed
        else {
            return iResult;
        }
    }

    int iProcessedBytes = iResult;

    // process each SRscpValue struct seperately
    for(unsigned int i; i < frame.data.size(); i++) {
        handleResponseValue(&protocol, &frame.data[i]);
    }

    // destroy frame data and free memory
    protocol.destroyFrameData(frame);

    // returned processed amount of bytes
    return iProcessedBytes;
}

static void receiveLoop(bool & bStopExecution)
{
    //--------------------------------------------------------------------------------------------------------------
    // RSCP Receive Frame Block Data
    //--------------------------------------------------------------------------------------------------------------
    // setup a static dynamic buffer which is dynamically expanded (re-allocated) on demand
    // the data inside this buffer is not released when this function is left
    static int iReceivedBytes = 0;
    static std::vector<uint8_t> vecDynamicBuffer;

    // check how many RSCP frames are received, must be at least 1
    // multiple frames can only occur in this example if one or more frames are received with a big time delay
    // this should usually not occur but handling this is shown in this example
    int iReceivedRscpFrames = 0;
    while(!bStopExecution && ((iReceivedBytes > 0) || iReceivedRscpFrames == 0))
    {
        // check and expand buffer
        if((vecDynamicBuffer.size() - iReceivedBytes) < 4096) {
            // check maximum size
            if(vecDynamicBuffer.size() > RSCP_MAX_FRAME_LENGTH) {
                // something went wrong and the size is more than possible by the RSCP protocol
                printf("Maximum buffer size exceeded %li\n", vecDynamicBuffer.size());
                bStopExecution = true;
                break;
            }
            // increase buffer size by 4096 bytes each time the remaining size is smaller than 4096
            vecDynamicBuffer.resize(vecDynamicBuffer.size() + 4096);
        }
        // receive data
        int iResult = SocketRecvData(iSocket, &vecDynamicBuffer[0] + iReceivedBytes, vecDynamicBuffer.size() - iReceivedBytes);
        if(iResult < 0)
        {
            // check errno for the error code to detect if this is a timeout or a socket error
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
                // receive timed out -> continue with re-sending the initial block
                printf("Response receive timeout (retry)\n");
                break;
            }
            // socket error -> check errno for failure code if needed
            printf("Socket receive error. errno %i\n", errno);
            bStopExecution = true;
            break;
        }
        else if(iResult == 0)
        {
            // connection was closed regularly by peer
            // if this happens on startup each time the possible reason is
            // wrong AES password or wrong network subnet (adapt hosts.allow file required)
            printf("Connection closed by peer\n");
            bStopExecution = true;
            break;
        }
        // increment amount of received bytes
        iReceivedBytes += iResult;

        // process all received frames
        while (!bStopExecution)
        {
            // round down to a multiple of AES_BLOCK_SIZE
            int iLength = ROUNDDOWN(iReceivedBytes, AES_BLOCK_SIZE);
            // if not even 32 bytes were received then the frame is still incomplete
            if(iLength == 0) {
                break;
            }
            // resize temporary decryption buffer
            std::vector<uint8_t> decryptionBuffer;
            decryptionBuffer.resize(iLength);
            // initialize encryption sequence IV value with value of previous block
            aesDecrypter.SetIV(ucDecryptionIV, AES_BLOCK_SIZE);
            // decrypt data from vecDynamicBuffer to temporary decryptionBuffer
            aesDecrypter.Decrypt(&vecDynamicBuffer[0], &decryptionBuffer[0], iLength / AES_BLOCK_SIZE);

            // data was received, check if we received all data
            int iProcessedBytes = processReceiveBuffer(&decryptionBuffer[0], iLength);
            if(iProcessedBytes < 0) {
                // an error occured;
                printf("Error parsing RSCP frame: %i\n", iProcessedBytes);
                // stop execution as the data received is not RSCP data
                bStopExecution = true;
                break;

            }
            else if(iProcessedBytes > 0) {
                // round up the processed bytes as iProcessedBytes does not include the zero padding bytes
                iProcessedBytes = ROUNDUP(iProcessedBytes, AES_BLOCK_SIZE);
                // store the IV value from encrypted buffer for next block decryption
                memcpy(ucDecryptionIV, &vecDynamicBuffer[0] + iProcessedBytes - AES_BLOCK_SIZE, AES_BLOCK_SIZE);
                // move the encrypted data behind the current frame data (if any received) to the front
                memcpy(&vecDynamicBuffer[0], &vecDynamicBuffer[0] + iProcessedBytes, vecDynamicBuffer.size() - iProcessedBytes);
                // decrement the total received bytes by the amount of processed bytes
                iReceivedBytes -= iProcessedBytes;
                // increment a counter that a valid frame was received and
                // continue parsing process in case a 2nd valid frame is in the buffer as well
                iReceivedRscpFrames++;
            }
            else {
                // iProcessedBytes is 0
                // not enough data of the next frame received, go back to receive mode if iReceivedRscpFrames == 0
                // or transmit mode if iReceivedRscpFrames > 0
                break;
            }
        }
    }
}

static void mainLoop(void)
{
    RscpProtocol protocol;
    bool bStopExecution = false;
    int counter = 0;

    while(!bStopExecution)
    {
        //--------------------------------------------------------------------------------------------------------------
        // RSCP Transmit Frame Block Data
        //--------------------------------------------------------------------------------------------------------------
        SRscpFrameBuffer frameBuffer;
        memset(&frameBuffer, 0, sizeof(frameBuffer));

        // create an RSCP frame with requests to some example data
        createRequestExample(&frameBuffer);

        // check that frame data was created
        if(frameBuffer.dataLength > 0)
        {
            // resize temporary encryption buffer to a multiple of AES_BLOCK_SIZE
            std::vector<uint8_t> encryptionBuffer;
            encryptionBuffer.resize(ROUNDUP(frameBuffer.dataLength, AES_BLOCK_SIZE));
            // zero padding for data above the desired length
            memset(&encryptionBuffer[0] + frameBuffer.dataLength, 0, encryptionBuffer.size() - frameBuffer.dataLength);
            // copy desired data length
            memcpy(&encryptionBuffer[0], frameBuffer.data, frameBuffer.dataLength);
            // set continues encryption IV
            aesEncrypter.SetIV(ucEncryptionIV, AES_BLOCK_SIZE);
            // start encryption from encryptionBuffer to encryptionBuffer, blocks = encryptionBuffer.size() / AES_BLOCK_SIZE
            aesEncrypter.Encrypt(&encryptionBuffer[0], &encryptionBuffer[0], encryptionBuffer.size() / AES_BLOCK_SIZE);
            // save new IV for next encryption block
            memcpy(ucEncryptionIV, &encryptionBuffer[0] + encryptionBuffer.size() - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

            // send data on socket
            int iResult = SocketSendData(iSocket, &encryptionBuffer[0], encryptionBuffer.size());
            if(iResult < 0) {
                printf("Socket send error %i. errno %i\n", iResult, errno);
                bStopExecution = true;
            }
            else {
                // go into receive loop and wait for response
                receiveLoop(bStopExecution);
                if (counter > 0) bStopExecution = true; // #MS# end program after first receive
            }
        }
        // free frame buffer memory
        protocol.destroyFrameData(&frameBuffer);

        // main loop sleep / cycle time before next request
        sleep(1);

	counter++;

    }
}

void usage(void){
    fprintf(stderr, "\n   Usage: e3dcset [-c LadeLeistung] [-d EntladeLeistung] [-e LadungsMenge] [-a] [-s 0=powersave off,1=powersave on] [-p Pfad zur Konfigurationsdatei]\n\n");
    exit(EXIT_FAILURE);
}

void readConfig(void){

    FILE *fp;

    fp = fopen(config, "r");

    char var[128], value[128], line[256];

    if(fp) {

    	while (fgets(line, sizeof(line), fp)) {

    		memset(var, 0, sizeof(var));
    		memset(value, 0, sizeof(value));

    		if(sscanf(line, "%[^ \t=]%*[\t ]=%*[\t ]%[^\n]", var, value) == 2) {

    			if(strcmp(var, "MIN_LEISTUNG") == 0)
    				e3dc_config.MIN_LEISTUNG = atoi(value);
 
			else if(strcmp(var, "MAX_LEISTUNG") == 0)
                                e3dc_config.MAX_LEISTUNG = atoi(value);

    			else if(strcmp(var, "MIN_LADUNGSMENGE") == 0)
    				e3dc_config.MIN_LADUNGSMENGE = atoi(value);

    			else if(strcmp(var, "MAX_LADUNGSMENGE") == 0)
    				e3dc_config.MAX_LADUNGSMENGE = atoi(value);

    			else if(strcmp(var, "server_ip") == 0)
    				strcpy(e3dc_config.server_ip, value);

    			else if(strcmp(var, "server_port") == 0)
    				e3dc_config.server_port = atoi(value);

    			else if(strcmp(var, "e3dc_user") == 0)
    				strcpy(e3dc_config.e3dc_user, value);

    			else if(strcmp(var, "e3dc_password") == 0)
    				strcpy(e3dc_config.e3dc_password, value);

    			else if(strcmp(var, "aes_password") == 0)
    				strcpy(e3dc_config.aes_password, value);

    			else if(strcmp(var, "debug") == 0)
    				debug = atoi(value);
                }
            }

    	DEBUG(" \n");
    	DEBUG("----------------------------------------------------------\n");
    	DEBUG("Gelesene Parameter aus Konfigurationsdatei %s:\n", config);
        DEBUG("MIN_LEISTUNG=%u\n",e3dc_config.MIN_LEISTUNG);
    	DEBUG("MAX_LEISTUNG=%u\n",e3dc_config.MAX_LEISTUNG);
    	DEBUG("MIN_LADUNGSMENGE=%u\n",e3dc_config.MIN_LADUNGSMENGE);
    	DEBUG("MAX_LADUNGSMENGE=%u\n",e3dc_config.MAX_LADUNGSMENGE);
    	DEBUG("server_ip=%s\n",e3dc_config.server_ip);
    	DEBUG("server_port=%i\n",e3dc_config.server_port);
    	DEBUG("e3dc_user=%s\n",e3dc_config.e3dc_user);
    	DEBUG("e3dc_password=%s\n",e3dc_config.e3dc_password);
    	DEBUG("aes_password=%s\n",e3dc_config.aes_password);
    	DEBUG("----------------------------------------------------------\n");

    	fclose(fp);

    } else {

    	printf("Konfigurationsdatei %s wurde nicht gefunden.\n\n",config);
    	exit(EXIT_FAILURE);
    }

}

void checkArguments(void){

    if (ladeLeistungGesetzt && (ladeLeistung < 0 || ladeLeistung < e3dc_config.MIN_LEISTUNG || ladeLeistung > e3dc_config.MAX_LEISTUNG)){
    	fprintf(stderr, "[-c ladeLeistung] muss zwischen %i und %i liegen\n\n", e3dc_config.MIN_LEISTUNG, e3dc_config.MAX_LEISTUNG);
    	exit(EXIT_FAILURE);
    }

    if (entladeLeistungGesetzt && (entladeLeistung < 0 || entladeLeistung < e3dc_config.MIN_LEISTUNG || entladeLeistung > e3dc_config.MAX_LEISTUNG)){
    	fprintf(stderr, "[-d entladeLeistung] muss zwischen %i und %i liegen\n\n", e3dc_config.MIN_LEISTUNG, e3dc_config.MAX_LEISTUNG);
    	exit(EXIT_FAILURE);
    }

    if (automatischLeistungEinstellen && (entladeLeistung > 0 || ladeLeistung > 0)){
    	fprintf(stderr, "bei Lade/Entladeleistung Automatik [-a] duerfen [-c ladeLeistung] und [-d entladeLeistung] nicht gesetzt sein\n\n");
    	exit(EXIT_FAILURE);
    }

    if (manuelleSpeicherladung && (ladungsMenge < e3dc_config.MIN_LADUNGSMENGE || ladungsMenge > e3dc_config.MAX_LADUNGSMENGE)){
    	fprintf(stderr, "Fuer die manuelle Speicherladung muss der angegebene Wert zwischen %iWh und %iWh liegen\n\n",e3dc_config.MIN_LADUNGSMENGE,e3dc_config.MAX_LADUNGSMENGE);
    	exit(EXIT_FAILURE);
    }

    if (!leistungAendern && !manuelleSpeicherladung){
        fprintf(stderr, "Keine Verbindung mit Server erforderlich\n\n");
        exit(EXIT_FAILURE);
    }

}

void connectToServer(void){

    DEBUG("Connecting to server %s:%i\n", e3dc_config.server_ip, e3dc_config.server_port);

    iSocket = SocketConnect(e3dc_config.server_ip, e3dc_config.server_port);

    if(iSocket < 0) {
    	printf("Connection failed\n");
    	exit(EXIT_FAILURE);
    }
    DEBUG("Connected successfully\n");

    // create AES key and set AES parameters
    {
    	// initialize AES encryptor and decryptor IV
    	memset(ucDecryptionIV, 0xff, AES_BLOCK_SIZE);
    	memset(ucEncryptionIV, 0xff, AES_BLOCK_SIZE);

    	// limit password length to AES_KEY_SIZE
    	int iPasswordLength = strlen(e3dc_config.aes_password);
    	if(iPasswordLength > AES_KEY_SIZE)
    		iPasswordLength = AES_KEY_SIZE;

    	// copy up to 32 bytes of AES key password
    	uint8_t ucAesKey[AES_KEY_SIZE];
    	memset(ucAesKey, 0xff, AES_KEY_SIZE);
    	memcpy(ucAesKey, e3dc_config.aes_password, iPasswordLength);

    	// set encryptor and decryptor parameters
    	aesDecrypter.SetParameters(AES_KEY_SIZE * 8, AES_BLOCK_SIZE * 8);
    	aesEncrypter.SetParameters(AES_KEY_SIZE * 8, AES_BLOCK_SIZE * 8);
    	aesDecrypter.StartDecryption(ucAesKey);
    	aesEncrypter.StartEncryption(ucAesKey);
    }

}

int main(int argc, char *argv[])
{

	// Argumente der Kommandozeile parsen
    
    if (argc == 1){
    	usage();
	}
    
    int opt;

    while ((opt = getopt(argc, argv, "c:d:s:e:ap:")) != -1) {

    	switch (opt) {

    	case 'c':
    		leistungAendern = true;
    		ladeLeistungGesetzt = true;
        	ladeLeistung = atoi(optarg);
        	break;
        case 'd':
        	leistungAendern = true;
            entladeLeistungGesetzt = true;
        	entladeLeistung = atoi(optarg);
        	break;
        case 'e':
        	manuelleSpeicherladung = true;
        	ladungsMenge = atoi(optarg);
        	break;
        case 'a':
        	leistungAendern = true;
        	automatischLeistungEinstellen = true;
        	break;
        case 'p':
        	config = strdup(optarg);
        	break;
        case 's':
            powersave = atoi(optarg);
            break;
        default:
        	usage();

        }
    }

    if (optind < argc){
    	usage();
    }

    // Lese Konfigurationsdatei
    readConfig();

    // Argumente der Kommandozeile plausibilisieren
    checkArguments();

    // Verbinde mit Hauskraftwerk
    connectToServer();

    // Starte Sende- / Empfangsschleife
    mainLoop();

    // Trenne Verbindung zum Hauskraftwerk
    SocketClose(iSocket);
    
    DEBUG("Ende!\n\n");

    return 0;
}

