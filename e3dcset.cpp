#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include "RscpProtocol.h"
#include "RscpTags.h"
#include "SocketConnection.h"
#include "AES.h"

#define DEBUG(...)           \
    if (debug)               \
    {                        \
        printf(__VA_ARGS__); \
    }

#define AES_KEY_SIZE 32
#define AES_BLOCK_SIZE 32

typedef struct
{

    uint32_t MIN_LEISTUNG;
    uint32_t MAX_LEISTUNG;
    uint32_t MIN_LADUNGSMENGE;
    uint32_t MAX_LADUNGSMENGE;
    char server_ip[20];
    uint32_t server_port;
    char e3dc_user[128];
    char e3dc_password[128];
    char aes_password[128];
    bool debug;

} e3dc_config_t;

static int iSocket = -1;
static int iAuthenticated = 0;
static int iMainRequestSent = 0;

static AES aesEncrypter;
static AES aesDecrypter;

static uint8_t ucEncryptionIV[AES_BLOCK_SIZE];
static uint8_t ucDecryptionIV[AES_BLOCK_SIZE];

static int powersave = -1;
static uint32_t powerValue = -1;
static uint8_t powerMode = -1;
static uint8_t wallboxMode = -1;
static uint8_t WBchar6[6] = {0};
static time_t timeout = -1;
static time_t now = time(NULL);

static e3dc_config_t e3dc_config;

static bool debug = false;
char cWBALG;
static bool bWBLademodus;                         // Lademodus der Wallbox; z.B. Sonnenmodus
static bool bWBChanged;                           // Lademodus der Wallbox; wurde extern geändertz.B. Sonnenmodus
static bool bWBConnect;                           // True = Dose ist verriegelt x08
static bool bWBStart;                             // True Laden ist gestartet x10
static bool bWBCharge;                            // True Laden ist gestartet x20
static bool bWBSonne;                             // Sonnenmodus x80
static bool bWBStopped;                           // Laden angehalten x40
static bool bWBmaxLadestrom, bWBmaxLadestromSave; // Ladestrom der Wallbox per App eingestellt.; 32=ON 31 = OFF
static int iWBSoll, iWBIst;                       // Soll = angeforderter Ladestrom, Ist = aktueller Ladestrom

static char *config = strdup("e3dcset.config");

int createRequest(SRscpFrameBuffer *frameBuffer)
{
    RscpProtocol protocol;
    SRscpValue rootValue;
    // The root container is create with the TAG ID 0 which is not used by any device.
    protocol.createContainerValue(&rootValue, 0);

    //---------------------------------------------------------------------------------------------------------
    // Create a request frame
    //---------------------------------------------------------------------------------------------------------
    if (iAuthenticated == 0)
    {
        // printf("Request authentication with user %s\n", e3dc_config.e3dc_user);
        // authentication request
        SRscpValue authenContainer;
        protocol.createContainerValue(&authenContainer, TAG_RSCP_REQ_AUTHENTICATION);
        protocol.appendValue(&authenContainer, TAG_RSCP_AUTHENTICATION_USER, e3dc_config.e3dc_user);
        protocol.appendValue(&authenContainer, TAG_RSCP_AUTHENTICATION_PASSWORD, e3dc_config.e3dc_password);
        // append sub-container to root container
        protocol.appendValue(&rootValue, authenContainer);
        // free memory of sub-container as it is now copied to rootValue
        protocol.destroyValueData(authenContainer);
    }
    else
    {

        if (powerValue >= 0 && powerMode >= 0)
        {
            switch (powerMode)
            {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
                SRscpValue SetPowerContainer;
                protocol.createContainerValue(&SetPowerContainer, TAG_EMS_REQ_SET_POWER);
                protocol.appendValue(&SetPowerContainer, TAG_EMS_REQ_SET_POWER_MODE, powerMode);
                protocol.appendValue(&SetPowerContainer, TAG_EMS_REQ_SET_POWER_VALUE, powerValue);
                protocol.appendValue(&rootValue, SetPowerContainer);
                protocol.destroyValueData(SetPowerContainer);
                break;
            default:
                break;
            }
        }

        if (powersave >= 0)
        {
            SRscpValue SetPowerSettingsContainer;
            protocol.createContainerValue(&SetPowerSettingsContainer, TAG_EMS_REQ_SET_POWER_SETTINGS);
            if (powersave == 0)
            {
                printf("Switching off power-save\n");
                protocol.appendValue(&SetPowerSettingsContainer, TAG_EMS_POWERSAVE_ENABLED, (unsigned char)0);
            }
            else if (powersave == 1)
            {
                printf("Switching on power-save\n");
                protocol.appendValue(&SetPowerSettingsContainer, TAG_EMS_POWERSAVE_ENABLED, (unsigned char)1);
            }
            protocol.appendValue(&rootValue, SetPowerSettingsContainer);
            protocol.destroyValueData(SetPowerSettingsContainer);
        }

        if (wallboxMode >= 0)
        {
            if (wallboxMode == 0)
            {
                WBchar6[0] = 1;
                printf("Setting wallbox mode: sun\n");
            }
            else if (wallboxMode == 1)
            {
                WBchar6[0] = 2;
                printf("Setting wallbox mode: mix\n");
            }
            SRscpValue WBContainer;
            if (wallboxMode < 2) {
                // WBchar6[4] = 1; // Laden stoppen
                // WBchar6[4] = 0; // Toggle aus
                // WBchar6[0] = 2; // Netzmodus
                // WBchar6[0] = 1; // Sonnenmodus
                // WBchar6[1] = 20; // max. Ladestrom
                // WBchar6[2] = 0; // Status Bit 0: connected, Bit 1: Charging, Bit 2: Start, Bit 3: Charging, Bit 4: Stop, Bit 5: Sonne
                SRscpValue WBExtContainer;
                // SRscpValue WB2Container;
                protocol.createContainerValue(&WBContainer, TAG_WB_REQ_DATA);
                protocol.appendValue(&WBContainer, TAG_WB_INDEX, 0);
                protocol.createContainerValue(&WBExtContainer, TAG_WB_REQ_SET_EXTERN);
                protocol.appendValue(&WBExtContainer, TAG_WB_EXTERN_DATA_LEN, 6);
                protocol.appendValue(&WBExtContainer, TAG_WB_EXTERN_DATA, WBchar6, 6);
                protocol.appendValue(&WBContainer, WBExtContainer);
                protocol.destroyValueData(WBExtContainer);
                
                

                protocol.appendValue(&rootValue, WBContainer);
                protocol.appendValue(&rootValue, TAG_EMS_REQ_SET_WALLBOX_ENFORCE_POWER_ASSIGNMENT, (u_int8_t)wallboxMode);
                // protocol.destroyValueData(WB2Container);
            } else {
                printf("Sending wallbox read request\n");
                protocol.createContainerValue(&WBContainer, TAG_EMS_REQ_GET_WALLBOX_ENFORCE_POWER_ASSIGNMENT);
                // protocol.createContainerValue(&WBContainer, TAG_EMS_REQ_BATTERY_BEFORE_CAR_MODE);
                // protocol.createContainerValue(&WBContainer, TAG_WB_REQ_DATA);
                // protocol.appendValue(&WBContainer, TAG_WB_INDEX, 0);
                // protocol.appendValue(&WBContainer, TAG_WB_REQ_SET_PARAM_1);

                /*
                // protocol.appendValue(&WBContainer, TAG_WB_REQ_PM_MODE);
                protocol.appendValue(&WBContainer, TAG_WB_REQ_MODE);
                protocol.appendValue(&WBContainer, TAG_WB_REQ_PM_MODE);
                protocol.appendValue(&WBContainer, TAG_WB_REQ_PM_DEVICE_STATE);
                // protocol.appendValue(&WBContainer, TAG_WB_REQ_STATUS);
                */
                /*
                protocol.appendValue(&WBContainer, TAG_WB_REQ_PARAM_1);
                protocol.appendValue(&WBContainer, TAG_WB_REQ_EXTERN_DATA_ALG);
                protocol.appendValue(&WBContainer, TAG_WB_REQ_PM_POWER_L1);
                protocol.appendValue(&WBContainer, TAG_WB_REQ_PM_POWER_L2);
                protocol.appendValue(&WBContainer, TAG_WB_REQ_PM_POWER_L3);
                */
                // protocol.appendValue(&WBContainer, TAG_EMS_REQ_BATTERY_TO_CAR_MODE);
                // protocol.createContainerValue(&WBContainer, TAG_EMS_REQ_BATTERY_BEFORE_CAR_MODE);
                protocol.appendValue(&rootValue, WBContainer);
            }
            protocol.destroyValueData(WBContainer);
        }
        iMainRequestSent = 1;
    }

    // create buffer frame to send data to the S10
    protocol.createFrameAsBuffer(frameBuffer, rootValue.data, rootValue.length, true); // true to calculate CRC on for transfer
    // the root value object should be destroyed after the data is copied into the frameBuffer and is not needed anymore
    protocol.destroyValueData(rootValue);

    return 0;
}

int handleResponseValue(RscpProtocol *protocol, SRscpValue *response)
{
    std::vector<SRscpValue> WBData;
    std::vector<SRscpValue> WBData2;
    int iLen = 0;
    // check if any of the response has the error flag set and react accordingly
    if (response->dataType == RSCP::eTypeError)
    {
        // handle error for example access denied errors
        uint32_t uiErrorCode = protocol->getValueAsUInt32(response);
        printf("Tag 0x%08X received error code %u.\n", response->tag, uiErrorCode);
        return -1;
    }

    // printf("Handling response tag: %08X with datatype %08X\n", response->tag, response->dataType);

    // check the SRscpValue TAG to detect which response it is
    switch (response->tag)
    {
    case TAG_RSCP_AUTHENTICATION:
    {
        // It is possible to check the response->dataType value to detect correct data type
        // and call the correct function. If data type is known,
        // the correct function can be called directly like in this case.
        uint8_t ucAccessLevel = protocol->getValueAsUChar8(response);
        if (ucAccessLevel > 0)
        {
            iAuthenticated = 1;
        }
        // printf("RSCP authentitication level %i\n", ucAccessLevel);
        break;
    }
    case TAG_EMS_START_MANUAL_CHARGE:
    {
        if (protocol->getValueAsBool(response))
        {
            printf("Manual charge set.\n");
        }
        else
        {
            printf("Manual charge declined.\n");
        }
        break;
    }
    case TAG_EMS_POWER_PV:
    { // response for TAG_EMS_REQ_POWER_PV
        int32_t iPower = protocol->getValueAsInt32(response);
        printf("EMS PV power is %i W\n", iPower);
        break;
    }
    case TAG_EMS_POWER_BAT:
    { // response for TAG_EMS_REQ_POWER_BAT
        int32_t iPower = protocol->getValueAsInt32(response);
        printf("EMS BAT power is %i W\n", iPower);
        break;
    }
    case TAG_EMS_POWER_HOME:
    { // response for TAG_EMS_REQ_POWER_HOME
        int32_t iPower = protocol->getValueAsInt32(response);
        printf("EMS house power is %i W\n", iPower);
        break;
    }
    case TAG_EMS_POWER_GRID:
    { // response for TAG_EMS_REQ_POWER_GRID
        int32_t iPower = protocol->getValueAsInt32(response);
        printf("EMS grid power is %i W\n", iPower);
        break;
    }
    case TAG_EMS_POWER_ADD:
    { // response for TAG_EMS_REQ_POWER_ADD
        int32_t iPower = protocol->getValueAsInt32(response);
        printf("EMS add power meter power is %i W\n", iPower);
        break;
    }
    case TAG_EMS_BATTERY_TO_CAR_MODE:
    {
        u_int8_t iBat2Car = protocol->getValueAsChar8(response);
        printf("EMS battery to car mode (in sun mode) is %i\n", iBat2Car);
        break;
    }
    case TAG_EMS_BATTERY_BEFORE_CAR_MODE:
    {
        u_int8_t iBat2Car = protocol->getValueAsChar8(response);
        printf("EMS charge priority (0=WB first, 1=<Battery first) is %i\n", iBat2Car);
        break;
    }

    case TAG_EMS_GET_WALLBOX_ENFORCE_POWER_ASSIGNMENT:
    {
        u_int8_t iBatDisEnf = protocol->getValueAsChar8(response);
        printf("Prevent battery discharge through wallbox in mixing mode: %i\n", iBatDisEnf);
        break;
    }
    case TAG_EMS_SET_WALLBOX_ENFORCE_POWER_ASSIGNMENT:
    {
        u_int8_t iBatDisEnf = protocol->getValueAsChar8(response);
        printf("Set prevent battery discharge through wallbox in mixing mode: %i\n", iBatDisEnf);
        break;
    }

    case TAG_EMS_GET_IDLE_PERIODS_2:
    {
        printf("Processing EMS container tag %08X\n", response->tag);
        WBData2 = protocol->getValueAsContainer(response);
        for (size_t j = 0; j < WBData2.size(); ++j)
        {
            if (WBData2[j].dataType == RSCP::eTypeError)
            {
                // handle error for example access denied errors
                uint32_t uiErrorCode = protocol->getValueAsUInt32(&WBData2[j]);
                printf("Tag 0x%08X received error code %u.\n", WBData2[j].tag, uiErrorCode);
                return -1;
            }

            printf("Processing EMS tag %08X", WBData2[j].tag);
            printf(" datatype %08X", WBData2[j].dataType);
            printf(" size %u\n", WBData2[j].length);
        }
        break;
    }

    case TAG_WB_DATA:
    { // resposne for TAG_WB_REQ_DATA
        uint8_t ucWBIndex = 0;
        WBData = protocol->getValueAsContainer(response);
        for (size_t i = 0; i < WBData.size(); ++i)
        {
            if (WBData[i].dataType == RSCP::eTypeError)
            {
                // handle error for example access denied errors
                uint32_t uiErrorCode = protocol->getValueAsUInt32(&WBData[i]);
                printf("Tag 0x%08X received error code %u.\n", WBData[i].tag, uiErrorCode);
                return -1;
            }
            // check each battery sub tag
            switch (WBData[i].tag)
            {
            case TAG_WB_INDEX:
            {
                ucWBIndex = protocol->getValueAsUChar8(&WBData[i]);
                break;
            }

            case TAG_WB_SET_EXTERN:
                /*
                char WBchar6[6];
                memcpy(&WBchar6, &WBData[i].data[0], sizeof(WBchar6));
                printf(" WB_SET_EXTERN\n");
                printf("\n");
                for (size_t x = 0; x < sizeof(WBchar6); ++x)
                {
                    uint8_t y;
                    y = WBchar6[x];
                    printf(" %02X", y);
                }
                printf("\n");
                */
                break;

            case TAG_WB_EXTERN_DATA_ALL:
            case TAG_WB_EXTERN_DATA_SUN:
                WBData2 = protocol->getValueAsContainer(&WBData[i]);
                for (size_t j = 0; j < WBData2.size(); ++j) {
                    if (WBData2[j].dataType == RSCP::eTypeError)
                    {
                        // handle error for example access denied errors
                        uint32_t uiErrorCode = protocol->getValueAsUInt32(&WBData2[j]);
                        printf("Tag 0x%08X received error code %u.\n", WBData2[j].tag, uiErrorCode);
                        return -1;
                    }

                    printf("Processing WB2 tag %08X", WBData2[j].tag);
                    printf(" datatype %08X", WBData2[j].dataType);
                    printf(" size %u\n", WBData2[j].length);

                    // check each battery sub tag
                    uint32_t uiWbExternData=0;
                    switch (WBData2[j].tag) {
                        case TAG_WB_EXTERN_DATA:
                            char WBchar[8];
                            memcpy(&WBchar, &WBData2[j].data[0], sizeof(WBchar));
                            for (size_t x = 0; x < sizeof(WBchar); ++x)
                            {
                                uint8_t y;
                                y = WBchar[x];
                                printf(" %02X", y);
                            }
                            printf("\n");
                            printf("Connected: %u\n", (WBchar[2] & 8) > 0);
                            printf("Charging : %u\n", (WBchar[2] & 32) > 0);
                            printf("Started  : %u\n", (WBchar[2] & 16) > 0);
                            printf("Stopped  : %u\n", (WBchar[2] & 64) > 0);
                            printf("Sonne    : %u\n", (WBchar[2] & 128) > 0);
                            // printf("WB_EXTERN_DATA %08X\n", uiWbExternData);
                            break;
                        default:
                            printf("Unknown WB2 tag %08X", WBData2[j].tag);
                            printf(" datatype %08X\n", WBData2[j].dataType);
                            break;
                    }
                }
                break;

            case TAG_WB_PM_MODE:
            {
                uint8_t val = protocol->getValueAsUChar8(&WBData[i]);
                printf(" WB PM MODE %u\n", iLen);
                break;
            }

            case TAG_WB_MODE:
            {
                uint8_t val2 = protocol->getValueAsUChar8(&WBData[i]);
                printf(" WB MODE %u\n", iLen);
                break;
            }

            case TAG_WB_SET_PARAM_1:
            case TAG_WB_PM_DEVICE_STATE:
            {
                printf("Processing WB container tag %08X\n", WBData[i].tag);
                WBData2 = protocol->getValueAsContainer(&WBData[i]);
                for (size_t j = 0; j < WBData2.size(); ++j)
                {
                    if (WBData2[j].dataType == RSCP::eTypeError)
                    {
                        // handle error for example access denied errors
                        uint32_t uiErrorCode = protocol->getValueAsUInt32(&WBData2[j]);
                        printf("Tag 0x%08X received error code %u.\n", WBData2[j].tag, uiErrorCode);
                        return -1;
                    }

                    printf("Processing WB2 tag %08X", WBData2[j].tag);
                    printf(" datatype %08X", WBData2[j].dataType);
                    printf(" size %u\n", WBData2[j].length);
                }
                break;
            }

            // ...
            default:
                // default behaviour
                printf("Unknown WB tag %08X", WBData[i].tag);
                printf(" datatype %08X\n", WBData[i].dataType);
                /*
                    None      DataType = 0x00
                    Bool      DataType = 0x01
                    Char8     DataType = 0x02
                    UChar8    DataType = 0x03
                    Int16     DataType = 0x04
                    UInt16    DataType = 0x05
                    Int32     DataType = 0x06
                    Uint32    DataType = 0x07
                    Int64     DataType = 0x08
                    Uint64    DataType = 0x09
                    Float32   DataType = 0x0A
                    Double64  DataType = 0x0B
                    Bitfield  DataType = 0x0C
                    CString   DataType = 0x0D
                    Container DataType = 0x0E
                    // 64Bit Sekunden + 32Bit Nanosekunden seit 1970
                    Timestamp DataType = 0x0F
                    ByteArray DataType = 0x10
                    Error     DataType = 0xFF
                */
                break;
            }
        }
        protocol->destroyValueData(WBData);
        protocol->destroyValueData(WBData2);
        break;
    }
    case TAG_BAT_DATA:
    { // response for TAG_BAT_REQ_DATA
        uint8_t ucBatteryIndex = 0;
        std::vector<SRscpValue> batteryData = protocol->getValueAsContainer(response);
        for (size_t i = 0; i < batteryData.size(); ++i)
        {
            if (batteryData[i].dataType == RSCP::eTypeError)
            {
                // handle error for example access denied errors
                uint32_t uiErrorCode = protocol->getValueAsUInt32(&batteryData[i]);
                printf("Tag 0x%08X received error code %u.\n", batteryData[i].tag, uiErrorCode);
                return -1;
            }
            // check each battery sub tag
            switch (batteryData[i].tag)
            {
            case TAG_BAT_INDEX:
            {
                ucBatteryIndex = protocol->getValueAsUChar8(&batteryData[i]);
                break;
            }
            case TAG_BAT_RSOC:
            { // response for TAG_BAT_REQ_RSOC
                float fSOC = protocol->getValueAsFloat32(&batteryData[i]);
                printf("Battery SOC is %0.1f %%\n", fSOC);
                break;
            }
            case TAG_BAT_MODULE_VOLTAGE:
            { // response for TAG_BAT_REQ_MODULE_VOLTAGE
                float fVoltage = protocol->getValueAsFloat32(&batteryData[i]);
                printf("Battery total voltage is %0.1f V\n", fVoltage);
                break;
            }
            case TAG_BAT_CURRENT:
            { // response for TAG_BAT_REQ_CURRENT
                float fVoltage = protocol->getValueAsFloat32(&batteryData[i]);
                printf("Battery current is %0.1f A\n", fVoltage);
                break;
            }
            case TAG_BAT_STATUS_CODE:
            { // response for TAG_BAT_REQ_STATUS_CODE
                uint32_t uiErrorCode = protocol->getValueAsUInt32(&batteryData[i]);
                printf("Battery status code is 0x%08X\n", uiErrorCode);
                break;
            }
            case TAG_BAT_ERROR_CODE:
            { // response for TAG_BAT_REQ_ERROR_CODE
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

    case TAG_EMS_SET_POWER_SETTINGS:
    { // response for TAG_PM_REQ_DATA
        uint8_t ucPMIndex = 0;
        std::vector<SRscpValue> PMData = protocol->getValueAsContainer(response);
        for (size_t i = 0; i < PMData.size(); ++i)
        {
            if (PMData[i].dataType == RSCP::eTypeError)
            {
                // handle error for example access denied errors
                uint32_t uiErrorCode = protocol->getValueAsUInt32(&PMData[i]);
                printf("TAG_EMS_GET_POWER_SETTINGS 0x%08X received error code %u.\n", PMData[i].tag, uiErrorCode);
                return -1;
            }
            // check each PM sub tag
            switch (PMData[i].tag)
            {
            case TAG_PM_INDEX:
            {
                ucPMIndex = protocol->getValueAsUChar8(&PMData[i]);
                break;
            }
            case TAG_EMS_POWER_LIMITS_USED:
            { // response for POWER_LIMITS_USED
                if (protocol->getValueAsBool(&PMData[i]))
                {
                    printf("POWER_LIMITS_USED\n");
                }
                break;
            }
            case TAG_EMS_MAX_CHARGE_POWER:
            { // 101 response for TAG_EMS_MAX_CHARGE_POWER
                uint32_t uPower = protocol->getValueAsUInt32(&PMData[i]);
                printf("MAX_CHARGE_POWER %i W\n", uPower);
                break;
            }
            case TAG_EMS_MAX_DISCHARGE_POWER:
            { // 102 response for TAG_EMS_MAX_DISCHARGE_POWER
                uint32_t uPower = protocol->getValueAsUInt32(&PMData[i]);
                printf("MAX_DISCHARGE_POWER %i W\n", uPower);
                break;
            }
            case TAG_EMS_DISCHARGE_START_POWER:
            { // 103 response for TAG_EMS_DISCHARGE_START_POWER
                uint32_t uPower = protocol->getValueAsUInt32(&PMData[i]);
                printf("DISCHARGE_START_POWER %i W\n", uPower);
                break;
            }
            case TAG_EMS_POWERSAVE_ENABLED:
            { // 104 response for TAG_EMS_POWERSAVE_ENABLED
                if (protocol->getValueAsBool(&PMData[i]))
                {
                    printf("POWERSAVE_ENABLED\n");
                }
                break;
            }
            case TAG_EMS_WEATHER_REGULATED_CHARGE_ENABLED:
            { // 105 resp WEATHER_REGULATED_CHARGE_ENABLED
                if (protocol->getValueAsBool(&PMData[i]))
                {
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

    case TAG_WB_EXTERN_DATA_ALG:
        WBData = protocol->getValueAsContainer(response);
        for (size_t i = 0; i < WBData.size(); ++i)
        {
            if (WBData[i].dataType == RSCP::eTypeError)
            {
                // handle error for example access denied errors
                uint32_t uiErrorCode = protocol->getValueAsUInt32(&WBData[i]);
                printf("Tag 0x%08X received error code %u.\n", WBData[i].tag, uiErrorCode);
                return -1;
            }
            // check each PM sub tag
            switch (WBData[i].tag)
            {
            case TAG_WB_EXTERN_DATA: // response for TAG_RSP_PARAM_1
                char WBchar[8];
                memcpy(&WBchar, &WBData[i].data[0], sizeof(WBchar));
                cWBALG = WBchar[2];
                bWBConnect = (WBchar[2] & 8);
                bWBCharge = (WBchar[2] & 32);
                bWBStart = (WBchar[2] & 16);
                bWBStopped = (WBchar[2] & 64);
                bWBSonne = (WBchar[2] & 128);
                printf(" WB ALG EXTERN_DATA\n");
                printf("\n");
                for (size_t x = 0; x < sizeof(WBchar); ++x)
                {
                    uint8_t y;
                    y = WBchar[x];
                    printf(" %02X", y);
                }
                printf("\n");
                break;

            case TAG_WB_EXTERN_DATA_LEN: // response for TAG_RSP_PARAM_1
                iLen = protocol->getValueAsUChar8(&WBData[i]);
                printf(" WB EXTERN_DATA_LEN %u\n", iLen);
                break;

            default:
                printf("Unknown TAG_WB_EXTERN_DATA_ALG tag %08X", WBData[i].tag);
                printf(" datatype %08X\n", WBData[i].dataType);
                break;
            }

            printf(" length %02X", WBData[i].length);
            printf(" data %02X", WBData[i].data[0]);
            printf("%02X", WBData[i].data[1]);
            printf("%02X", WBData[i].data[2]);
            printf("%02X\n", WBData[i].data[3]);
        }
        protocol->destroyValueData(WBData);
        break;

    // ...
    default:
        // default behavior
        printf("Unknown tag %08X\n", response->tag);
        break;
    }
    return 0;
}

static int processReceiveBuffer(const unsigned char *ucBuffer, int iLength)
{
    RscpProtocol protocol;
    SRscpFrame frame;

    int iResult = protocol.parseFrame(ucBuffer, iLength, &frame);
    if (iResult < 0)
    {
        // check if frame length error occured
        // in that case the full frame length was not received yet
        // and the receive function must get more data
        if (iResult == RSCP::ERR_INVALID_FRAME_LENGTH)
        {
            return 0;
        }
        // otherwise a not recoverable error occured and the connection can be closed
        else
        {
            return iResult;
        }
    }

    int iProcessedBytes = iResult;

    int iNumFrames = frame.data.size();
    // printf("Response has %u frames\n", iNumFrames);

    // process each SRscpValue struct seperately
    for (unsigned int i; i < iNumFrames; i++)
    {
        handleResponseValue(&protocol, &frame.data[i]);
    }

    // destroy frame data and free memory
    protocol.destroyFrameData(frame);

    // returned processed amount of bytes
    return iProcessedBytes;
}

static void receiveLoop(bool &bStopExecution)
{
    //--------------------------------------------------------------------------------------------------------------
    // RSCP Receive Frame Block Data
    //--------------------------------------------------------------------------------------------------------------
    // setup a static dynamic buffer which is dynamically expanded (re-allocated) on demand
    // the data inside this buffer is not released when this function is left
    static int iReceivedBytes = 0;
    static std::vector<uint8_t> vecDynamicBuffer;

    // printf("Receive loop (%u)\n", bStopExecution);

    // check how many RSCP frames are received, must be at least 1
    // multiple frames can only occur in this example if one or more frames are received with a big time delay
    // this should usually not occur but handling this is shown in this example
    int iReceivedRscpFrames = 0;
    while (!bStopExecution && ((iReceivedBytes > 0) || iReceivedRscpFrames == 0))
    {
        // check and expand buffer
        if ((vecDynamicBuffer.size() - iReceivedBytes) < 4096)
        {
            // check maximum size
            if (vecDynamicBuffer.size() > RSCP_MAX_FRAME_LENGTH)
            {
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
        if (iResult < 0)
        {
            // check errno for the error code to detect if this is a timeout or a socket error
            if ((errno == EAGAIN) || (errno == EWOULDBLOCK))
            {
                // receive timed out -> continue with re-sending the initial block
                printf("Response receive timeout (retry)\n");
                break;
            }
            // socket error -> check errno for failure code if needed
            printf("Socket receive error. errno %i\n", errno);
            bStopExecution = true;
            break;
        }
        else if (iResult == 0)
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
            if (iLength == 0)
            {
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
            if (iProcessedBytes < 0)
            {
                // an error occured;
                printf("Error parsing RSCP frame: %i\n", iProcessedBytes);
                // stop execution as the data received is not RSCP data
                bStopExecution = true;
                break;
            }
            else if (iProcessedBytes > 0)
            {
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
            else
            {
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

    while (!bStopExecution)
    {
        //--------------------------------------------------------------------------------------------------------------
        // RSCP Transmit Frame Block Data
        //--------------------------------------------------------------------------------------------------------------
        SRscpFrameBuffer frameBuffer;
        memset(&frameBuffer, 0, sizeof(frameBuffer));

        // create an RSCP frame with requests to some example data
        // printf ("Creating request ...\n");
        createRequest(&frameBuffer);

        // check that frame data was created
        if (frameBuffer.dataLength > 0)
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
            if (iResult < 0)
            {
                printf("Socket send error %i. errno %i\n", iResult, errno);
                bStopExecution = true;
            }
            else
            {
                // go into receive loop and wait for response
                receiveLoop(bStopExecution);
                if (
                    (now + (timeout * 60) < time(NULL)) ||
                    (timeout == -1 && counter > 0))
                {
                    if (iMainRequestSent == 1 || time(NULL) - now > 10)
                    { // max 10s um nach der Auth, den Hauptrequest zu senden
                        bStopExecution = true;
                    }
                }
            }
        }
        // free frame buffer memory
        protocol.destroyFrameData(&frameBuffer);

        // main loop sleep / cycle time before next request
        if (iMainRequestSent == 1 && timeout >= 1)
        {
            sleep(5);
        } // ansonsten direkt nach dem Auth weiter

        counter++;
    }
}

void usage(void)
{
    fprintf(stderr, "\n   Usage: e3dcset [-m mode: 0=auto,1=idle,2=discharge,3=charge,4=grid charge] [-w mode: 0=set sun mode,1=set mix mode,2=read data] [-v charge/discharge value] [-t runtime in minutes] [-s 0=powersave off,1=powersave on] [-p Pfad zur Konfigurationsdatei]\n\n");
    exit(EXIT_FAILURE);
}

void readConfig(void)
{

    FILE *fp;

    fp = fopen(config, "r");

    char var[128], value[128], line[256];

    if (fp)
    {

        while (fgets(line, sizeof(line), fp))
        {

            memset(var, 0, sizeof(var));
            memset(value, 0, sizeof(value));

            if (sscanf(line, "%[^ \t=]%*[\t ]=%*[\t ]%[^\n]", var, value) == 2)
            {

                if (strcmp(var, "MIN_LEISTUNG") == 0)
                    e3dc_config.MIN_LEISTUNG = atoi(value);

                else if (strcmp(var, "MAX_LEISTUNG") == 0)
                    e3dc_config.MAX_LEISTUNG = atoi(value);

                else if (strcmp(var, "MIN_LADUNGSMENGE") == 0)
                    e3dc_config.MIN_LADUNGSMENGE = atoi(value);

                else if (strcmp(var, "MAX_LADUNGSMENGE") == 0)
                    e3dc_config.MAX_LADUNGSMENGE = atoi(value);

                else if (strcmp(var, "server_ip") == 0)
                    strcpy(e3dc_config.server_ip, value);

                else if (strcmp(var, "server_port") == 0)
                    e3dc_config.server_port = atoi(value);

                else if (strcmp(var, "e3dc_user") == 0)
                    strcpy(e3dc_config.e3dc_user, value);

                else if (strcmp(var, "e3dc_password") == 0)
                    strcpy(e3dc_config.e3dc_password, value);

                else if (strcmp(var, "aes_password") == 0)
                    strcpy(e3dc_config.aes_password, value);

                else if (strcmp(var, "debug") == 0)
                    debug = atoi(value);
            }
        }

        DEBUG(" \n");
        DEBUG("----------------------------------------------------------\n");
        DEBUG("Gelesene Parameter aus Konfigurationsdatei %s:\n", config);
        DEBUG("MIN_LEISTUNG=%u\n", e3dc_config.MIN_LEISTUNG);
        DEBUG("MAX_LEISTUNG=%u\n", e3dc_config.MAX_LEISTUNG);
        DEBUG("MIN_LADUNGSMENGE=%u\n", e3dc_config.MIN_LADUNGSMENGE);
        DEBUG("MAX_LADUNGSMENGE=%u\n", e3dc_config.MAX_LADUNGSMENGE);
        DEBUG("server_ip=%s\n", e3dc_config.server_ip);
        DEBUG("server_port=%i\n", e3dc_config.server_port);
        DEBUG("e3dc_user=%s\n", e3dc_config.e3dc_user);
        DEBUG("e3dc_password=%s\n", e3dc_config.e3dc_password);
        DEBUG("aes_password=%s\n", e3dc_config.aes_password);
        DEBUG("----------------------------------------------------------\n");

        fclose(fp);
    }
    else
    {

        printf("Konfigurationsdatei %s wurde nicht gefunden.\n\n", config);
        exit(EXIT_FAILURE);
    }
}

void checkArguments(void)
{

    /*
    if (!leistungAendern && !manuelleSpeicherladung && powerValue == -1){
        fprintf(stderr, "Keine Verbindung mit Server erforderlich\n\n");
        exit(EXIT_FAILURE);
    }
    */
}

void connectToServer(void)
{

    DEBUG("Connecting to server %s:%i\n", e3dc_config.server_ip, e3dc_config.server_port);

    iSocket = SocketConnect(e3dc_config.server_ip, e3dc_config.server_port);

    if (iSocket < 0)
    {
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
        if (iPasswordLength > AES_KEY_SIZE)
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

    if (argc == 1)
    {
        usage();
    }

    int opt;

    while ((opt = getopt(argc, argv, "m:w:p:v:t:s:")) != -1)
    {

        switch (opt)
        {
        case 't':
            timeout = atoi(optarg);
            break;
        case 'm':
            powerMode = atoi(optarg);
            break;
        case 'w':
            wallboxMode = atoi(optarg);
            timeout = -1;
            break;
        case 'v':
            powerValue = atoi(optarg);
            break;
        case 's':
            powersave = atoi(optarg);
            timeout = -1;
            break;
        case 'p':
            config = strdup(optarg);
            break;
        default:
            usage();
        }
    }

    if (optind < argc)
    {
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
