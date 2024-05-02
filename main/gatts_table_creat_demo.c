/*
   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

/****************************************************************************
*
* This file is for a gatt server CTF (capture the flag). 
*
****************************************************************************/


#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_bt.h"
#include "esp_bt_device.h"
#include "driver/gpio.h"

#include "esp_gap_ble_api.h"
#include "esp_gatts_api.h"
#include "esp_bt_main.h"
#include "gatts_table_creat_demo.h"
#include "esp_gatt_common_api.h"

#define GATTS_TABLE_TAG "ESP_GATTS_DEMO"

#define PROFILE_NUM                 1
#define PROFILE_APP_IDX             0
#define ESP_APP_ID                  0x55
#define SVC_INST_ID                 0

#define GATTS_DEMO_CHAR_VAL_LEN_MAX 100
#define PREPARE_BUF_MAX_SIZE        1024
#define CHAR_DECLARATION_SIZE       (sizeof(uint8_t))

#define ADV_CONFIG_FLAG             (1 << 0)
#define SCAN_RSP_CONFIG_FLAG        (1 << 1)
#define FLAG_LEN                    20


#define NUM_FLAGS 20

static const uint16_t FLAG_UUIDS[NUM_FLAGS] = {
    0xffff,
    0xffff,
    0xff03,
    0xff04,
    0xff05,
    0xff06,
    0xff07,
    0xff08,
    0xff0a,
    0xff0b,
    0xff0c,
    0xff0d,
    0xff0f,
    0xff10,
    0xff12,
    0xff13,
    0xff14,
    0xff15,
    0xff16,
    0xff17,
    0xff18
};





static const char     FLAG_HINT_WRITE_FLAG_HERE[]       = "Write Flags Here";
static const char     FLAG_HINT_SIMPLE_READ[]           = "c34cf847ef8f09e4bf4d";
static const char     FLAG_HINT_DEVICE_NAME_MD5[]       = "MD5 of device name (truncated to 20)";
static const char     FLAG_HINT_DEVICE_NAME_ATTR[]      = "e83546b799c408438ccf";
static const char     FLAG_HINT_WRITE_ANY[]             = "write anything here";
static const char     FLAG_HINT_WRITE_ASCII[]           = "write the ASCII value 'DC608' here";
static const char     FLAG_HINT_WRITE_HEX[]             = "write the hex value 0x42 here";
static const char     FLAG_HINT_WRITE_DECIMAL_HANDLE[]  = "write 0xb2 to handle 58";
static const char     FLAG_HINT_WRITE_FUZZING[]         = "brute force my value 00 to ff";
static const char     FLAG_HINT_READ_MANY[]             = "read me 1000 times";
static const char     FLAG_HINT_SINGLE_NOTIFICATION[]   = "listen to me for a single notification";
static const char     FLAG_HINT_SINGLE_INDICATION[]     = "listen to handle 0x0044 for a single indication";
static const char     FLAG_HINT_MULTIPLE_NOTIFICATION[] = "listen to me for multi notifications";
static const char     FLAG_HINT_MULTIPLE_INDICATION[]   = "listen to handle 0x004a for multi indications";
static const char     FLAG_HINT_SPOOF_MAC[]             = "connect with BT MAC address de:ad:be:ef:12:34";
static const char     FLAG_HINT_CHANGE_MTU[]            = "set your connection MTU to 444";
static const char     FLAG_HINT_WRITE_RESPONSE[]        = "write+resp 'DC608'";
static const uint16_t FLAG_UUID_WRITE_RESPONSE          = 0xFF14;
static const char     FLAG_HINT_HIDDEN_NOTIFICATION[]   = "no notifications here! really?";
static const char     FLAG_HINT_MULTIPLE_PROPERTIES[]   = "so many properties!";
static const char     FLAG_HINT_TOKEN[]                 = "unique per device PASSWORD -> auth token";
static const uint16_t FLAG_UUID_TOKEN                   = 0xFF17;

static const char     FLAG_HINT_AUTH[]                  = "authenticated eyes only";
static const uint16_t FLAG_UUID_AUTH                    = 0xFF18;

static const char* FLAG_VALUES[NUM_FLAGS] = {
    "c34cf847ef8f09e4bf4d",
    "820d62f4684a435a43e6",
    "e83546b799c408438ccf",
    "f5a33d0d2795799d2674",
    "4a047f4d288dda3be894",
    "3420a0f90cc7cb9efa45",
    "7c956828d95c6b15117e",
    "066426d6cb787f81ac83",
    "d6969a9b9a2dc376c2b8",
    "d9b6b9a69119bbfd439d",
    "65e1cf33cb453aea0a44",
    "1b386dfc5204c7d8604d",
    "e7ed1d33378dfc23b9dc",
    "4d2aabfafffa3034d105",
    "c632ae9bb70334ff88f8",
    "ac8223cfe2f289f713e8",
    "d7f9d8d5725a1a858064",
    "40f39540960165d4d93d",
    "5f4dcc3b5aa765d61d83",
    "8cb08f5a96f99d63753c"
};

static int flag_status[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static int flag_multi_status[] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}; // For multi-step flags

static uint8_t* local_bd_addr;
static char local_bd_addr_str[13];

static uint8_t adv_config_done       = 0;

uint16_t blectf_handle_table[HRS_IDX_NB];

typedef struct {
    uint8_t                 *prepare_buf;
    int                     prepare_len;
} prepare_type_env_t;

static prepare_type_env_t prepare_write_env;

#define CONFIG_SET_RAW_ADV_DATA
#ifdef CONFIG_SET_RAW_ADV_DATA
static uint8_t raw_adv_data[] = {
        /* flags */
        0x02, 0x01, 0x06,
        /* tx power*/
        0x02, 0x0a, 0xeb,
        /* service uuid */
        0x03, 0x03, 0xFF, 0x00,
        /* device name (first number is the length) */
        0x0E, 0x09, 'D', 'C', '6', '0', '8', '_', 'B', 'L','E','_','L','A','B'

};
static uint8_t raw_scan_rsp_data[] = {
        /* flags */
        0x02, 0x01, 0x06,
        /* tx power */
        0x02, 0x0a, 0xeb,
        /* service uuid */
        0x03, 0x03, 0xFF,0x00
};

#else
static uint8_t service_uuid[16] = {
    /* LSB <--------------------------------------------------------------------------------> MSB */
    //first uuid, 16bit, [12],[13] is the value
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00,
};

/* The length of adv data must be less than 31 bytes */
static esp_ble_adv_data_t adv_data = {
    .set_scan_rsp        = false,
    .include_name        = true,
    .include_txpower     = true,
    .min_interval        = 0x20,
    .max_interval        = 0x40,
    .appearance          = 0x00,
    .manufacturer_len    = 0,    //TEST_MANUFACTURER_DATA_LEN,
    .p_manufacturer_data = NULL, //test_manufacturer,
    .service_data_len    = 0,
    .p_service_data      = NULL,
    .service_uuid_len    = sizeof(service_uuid),
    .p_service_uuid      = service_uuid,
    .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};

// scan response data
static esp_ble_adv_data_t scan_rsp_data = {
    .set_scan_rsp        = true,
    .include_name        = true,
    .include_txpower     = true,
    .min_interval        = 0x20,
    .max_interval        = 0x40,
    .appearance          = 0x00,
    .manufacturer_len    = 0, //TEST_MANUFACTURER_DATA_LEN,
    .p_manufacturer_data = NULL, //&test_manufacturer[0],
    .service_data_len    = 0,
    .p_service_data      = NULL,
    .service_uuid_len    = 16,
    .p_service_uuid      = service_uuid,
    .flag = (ESP_BLE_ADV_FLAG_GEN_DISC | ESP_BLE_ADV_FLAG_BREDR_NOT_SPT),
};
#endif /* CONFIG_SET_RAW_ADV_DATA */

static esp_ble_adv_params_t adv_params = {
    .adv_int_min         = 0x20,
    .adv_int_max         = 0x40,
    .adv_type            = ADV_TYPE_IND,
    .own_addr_type       = BLE_ADDR_TYPE_PUBLIC,
    .channel_map         = ADV_CHNL_ALL,
    .adv_filter_policy   = ADV_FILTER_ALLOW_SCAN_ANY_CON_ANY,
};

struct gatts_profile_inst {
    esp_gatts_cb_t gatts_cb;
    uint16_t gatts_if;
    uint16_t app_id;
    uint16_t conn_id;
    uint16_t service_handle;
    esp_gatt_srvc_id_t service_id;
    uint16_t char_handle;
    esp_bt_uuid_t char_uuid;
    esp_gatt_perm_t perm;
    esp_gatt_char_prop_t property;
    uint16_t descr_handle;
    esp_bt_uuid_t descr_uuid;
};

static void gatts_profile_event_handler(esp_gatts_cb_event_t event,
					esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param);

static void check_flag(const char* writeData);

/* One gatt-based profile one app_id and one gatts_if, this array will store the gatts_if returned by ESP_GATTS_REG_EVT */
static struct gatts_profile_inst blectf_profile_tab[PROFILE_NUM] = {
    [PROFILE_APP_IDX] = {
        .gatts_cb = gatts_profile_event_handler,
        .gatts_if = ESP_GATT_IF_NONE,       /* Not get the gatt_if, so initial is ESP_GATT_IF_NONE */
    },
};

/* Service */
static const uint16_t GATTS_SERVICE_UUID_TEST                   = 0x00FF;
static const uint16_t GATTS_CHAR_UUID_SCORE                     = 0xFF01;
static const uint16_t GATTS_CHAR_UUID_FLAG                      = 0xFF02;

static const uint16_t GATTS_CHAR_UUID_FLAG_SIMPLE_READ          = 0xFF03;
static const uint16_t GATTS_CHAR_UUID_FLAG_MD5                  = 0xFF04;
static const uint16_t GATTS_CHAR_UUID_FLAG_WRITE_ANYTHING       = 0xFF05;
static const uint16_t GATTS_CHAR_UUID_FLAG_WRITE_ASCII          = 0xFF06;
static const uint16_t GATTS_CHAR_UUID_FLAG_WRITE_HEX            = 0xFF07;
static const uint16_t GATTS_CHAR_UUID_FLAG_SIMPLE_WRITE2_READ   = 0xFF08;

static const uint16_t GATTS_CHAR_UUID_FLAG_SIMPLE_WRITE2        = 0xFF09; // KEEP

static const uint16_t GATTS_CHAR_UUID_FLAG_BRUTE_WRITE          = 0xFF0a;
static const uint16_t GATTS_CHAR_UUID_FLAG_READ_ALOT            = 0xFF0b;
static const uint16_t GATTS_CHAR_UUID_FLAG_NOTIFICATION         = 0xFF0c;
static const uint16_t GATTS_CHAR_UUID_FLAG_INDICATE_READ        = 0xFF0d;

static const uint16_t GATTS_CHAR_UUID_FLAG_INDICATE             = 0xFF0e; // KEEP

static const uint16_t GATTS_CHAR_UUID_FLAG_NOTIFICATION_MULTI   = 0xFF0f;
static const uint16_t GATTS_CHAR_UUID_FLAG_INDICATE_MULTI_READ  = 0xFF10;

static const uint16_t GATTS_CHAR_UUID_FLAG_INDICATE_MULTI       = 0xFF11; // KEEP

static const uint16_t GATTS_CHAR_UUID_FLAG_MAC                  = 0xFF12;
static const uint16_t GATTS_CHAR_UUID_FLAG_MTU                  = 0xFF13;
//static const uint16_t GATTS_CHAR_UUID_FLAG_WRITE_RESPONSE       = 0xFF14;
static const uint16_t GATTS_CHAR_UUID_FLAG_HIDDEN_NOTIFY        = 0xFF15;
static const uint16_t GATTS_CHAR_UUID_FLAG_CRAZY                = 0xFF16;
//static const uint16_t GATTS_CHAR_UUID_FLAG_TWITTER              = 0xFF17;

static const uint16_t primary_service_uuid         = ESP_GATT_UUID_PRI_SERVICE;
static const uint16_t character_declaration_uuid   = ESP_GATT_UUID_CHAR_DECLARE;
static const uint16_t character_client_config_uuid = ESP_GATT_UUID_CHAR_CLIENT_CONFIG;
static const uint8_t char_prop_read                = ESP_GATT_CHAR_PROP_BIT_READ;
static const uint8_t char_prop_write               = ESP_GATT_CHAR_PROP_BIT_WRITE;
static const uint8_t char_prop_read_write_notify   = ESP_GATT_CHAR_PROP_BIT_WRITE | ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_NOTIFY;
static const uint8_t char_prop_read_write_indicate   = ESP_GATT_CHAR_PROP_BIT_WRITE |ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_INDICATE;
static const uint8_t char_prop_read_write   = ESP_GATT_CHAR_PROP_BIT_WRITE | ESP_GATT_CHAR_PROP_BIT_READ;
static const uint8_t char_prop_crazy   = ESP_GATT_CHAR_PROP_BIT_WRITE | ESP_GATT_CHAR_PROP_BIT_READ | ESP_GATT_CHAR_PROP_BIT_EXT_PROP | ESP_GATT_CHAR_PROP_BIT_BROADCAST |  ESP_GATT_CHAR_PROP_BIT_NOTIFY ;
//static const uint8_t heart_measurement_ccc[2]      = {0x00, 0x00};
//static const uint8_t char_value[4]                 = {0x11, 0x22, 0x33, 0x44};

// start ctf data vars
static char writeData[100];
static uint8_t score_read_value[14] = {'S', 'c', 'o', 'r', 'e', ':', ' ', '0','/','2','0', ' ', '|', ' '};
static uint8_t score_output[34] = {'S', 'c', 'o', 'r', 'e', ':', ' ', '0','/','2','0', ' ', '|', ' ', '0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0','0'};


int read_alot_counter = 0;
int read_counter = 0;
int score = 0;
static char string_score[10] = "0";
int BLINK_GPIO=2;
int indicate_handle_state = 0;
int send_response=0;
FlagIndex check_send_response=-1;

/* Full Database Description - Used to add attributes into the database */
static const esp_gatts_attr_db_t gatt_db[HRS_IDX_NB] =
{
    // Service Declaration
    [IDX_SVC]        =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&primary_service_uuid, ESP_GATT_PERM_READ,
      sizeof(uint16_t), sizeof(GATTS_SERVICE_UUID_TEST), (uint8_t *)&GATTS_SERVICE_UUID_TEST}},

    /* SCORE Characteristic Declaration */
    [IDX_CHAR_SCORE]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read}},

    [IDX_CHAR_VAL_SCORE]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_SCORE, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(score_output), (uint8_t *)score_output}},
    
    /* FLAG Characteristic Declaration */
    [IDX_CHAR_FLAG]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read_write}},

    /* FLAG Characteristic Value */
    [IDX_CHAR_VAL_FLAG]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_WRITE_FLAG_HERE)-1, (uint8_t *)FLAG_HINT_WRITE_FLAG_HERE}},

    /* FLAG MD5 Characteristic Declaration */
    [IDX_CHAR_FLAG_SIMPLE_READ]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_SIMPLE_READ]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_SIMPLE_READ, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_SIMPLE_READ)-1, (uint8_t *)FLAG_HINT_SIMPLE_READ}},

    /* FLAG MD5 Characteristic Declaration */ 
    [IDX_CHAR_FLAG_MD5]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_MD5]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_MD5, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_DEVICE_NAME_MD5)-1, (uint8_t *)FLAG_HINT_DEVICE_NAME_MD5}},

    /* FLAG WRITE ANYTHING Characteristic Declaration */
    [IDX_CHAR_FLAG_WRITE_ANYTHING]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ|ESP_GATT_PERM_WRITE,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read_write}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_WRITE_ANYTHING]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_WRITE_ANYTHING, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_WRITE_ANY)-1, (uint8_t *)FLAG_HINT_WRITE_ANY}},

    /* FLAG WRITE ASCII Characteristic Declaration */
    [IDX_CHAR_FLAG_WRITE_ASCII]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ|ESP_GATT_PERM_WRITE,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read_write}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_WRITE_ASCII]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_WRITE_ASCII, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_WRITE_ASCII)-1, (uint8_t *)FLAG_HINT_WRITE_ASCII}},

    /* FLAG simple write Characteristic Declaration */
    [IDX_CHAR_FLAG_WRITE_HEX]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ|ESP_GATT_PERM_WRITE,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read_write}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_WRITE_HEX]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_WRITE_HEX, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_WRITE_HEX)-1, (uint8_t *)FLAG_HINT_WRITE_HEX}},

    /* FLAG brute write Characteristic Declaration */
    [IDX_CHAR_FLAG_BRUTE_WRITE]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ|ESP_GATT_PERM_WRITE,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read_write}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_BRUTE_WRITE]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_BRUTE_WRITE, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_WRITE_FUZZING)-1, (uint8_t *)FLAG_HINT_WRITE_FUZZING}},

    /* FLAG read write Characteristic Declaration */
    [IDX_CHAR_FLAG_SIMPLE_WRITE2_READ]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_SIMPLE_WRITE2_READ]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_SIMPLE_WRITE2_READ, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_WRITE_DECIMAL_HANDLE)-1, (uint8_t *)FLAG_HINT_WRITE_DECIMAL_HANDLE}},

    /* FLAG read write Characteristic Declaration */
    [IDX_CHAR_FLAG_SIMPLE_WRITE2]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_write}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_SIMPLE_WRITE2]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_SIMPLE_WRITE2, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_WRITE_DECIMAL_HANDLE)-1, (uint8_t *)FLAG_HINT_WRITE_DECIMAL_HANDLE}},

    /* FLAG read alot Characteristic Declaration */
    [IDX_CHAR_FLAG_READ_ALOT]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_READ_ALOT]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_READ_ALOT, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_READ_MANY)-1, (uint8_t *)FLAG_HINT_READ_MANY}},

    /* Notification flag Characteristic Declaration */
    [IDX_CHAR_FLAG_NOTIFICATION]     =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read_write_notify}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_NOTIFICATION] =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_NOTIFICATION, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_SINGLE_NOTIFICATION)-1, (uint8_t *)FLAG_HINT_SINGLE_NOTIFICATION}},

    /* Client Characteristic Configuration Descriptor */
    [IDX_CHAR_CFG_FLAG_NOTIFICATION]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_client_config_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      sizeof(uint16_t), sizeof(FLAG_HINT_SINGLE_NOTIFICATION)-1, (uint8_t *)FLAG_HINT_SINGLE_NOTIFICATION}},

    /* FLAG indicate read Characteristic Declaration */
    [IDX_CHAR_FLAG_INDICATE_READ]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_INDICATE_READ]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_INDICATE_READ, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_SINGLE_INDICATION)-1, (uint8_t *)FLAG_HINT_SINGLE_INDICATION}},

    
    /* indicate flag Characteristic Declaration */
    [IDX_CHAR_FLAG_INDICATE]     =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read_write_indicate}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_INDICATE] =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_INDICATE, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, 0, (uint8_t *)FLAG_HINT_SINGLE_INDICATION}},

    /* Client Characteristic Configuration Descriptor */
    [IDX_CHAR_CFG_FLAG_INDICATE]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_client_config_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      sizeof(uint16_t), sizeof(FLAG_HINT_SINGLE_INDICATION)-1, (uint8_t *)FLAG_HINT_SINGLE_INDICATION}},

    /* Notification flag Characteristic Declaration */
    [IDX_CHAR_FLAG_NOTIFICATION_MULTI]     =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read_write_notify}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_NOTIFICATION_MULTI] =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_NOTIFICATION_MULTI, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_MULTIPLE_NOTIFICATION)-1, (uint8_t *)FLAG_HINT_MULTIPLE_NOTIFICATION}},

    /* Client Characteristic Configuration Descriptor */
    [IDX_CHAR_CFG_FLAG_NOTIFICATION_MULTI]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_client_config_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      sizeof(uint16_t), sizeof(FLAG_HINT_MULTIPLE_NOTIFICATION)-1, (uint8_t *)FLAG_HINT_MULTIPLE_NOTIFICATION}},

    /* FLAG indicate read Characteristic Declaration */
    [IDX_CHAR_FLAG_INDICATE_MULTI_READ]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_INDICATE_MULTI_READ]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_INDICATE_MULTI_READ, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_MULTIPLE_INDICATION)-1, (uint8_t *)FLAG_HINT_MULTIPLE_INDICATION}},
    
    /* indicate flag Characteristic Declaration */
    [IDX_CHAR_FLAG_INDICATE_MULTI]     =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read_write_indicate}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_INDICATE_MULTI] =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_INDICATE_MULTI, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, 0, (uint8_t *)FLAG_HINT_MULTIPLE_INDICATION}},

    /* Client Characteristic Configuration Descriptor */
    [IDX_CHAR_CFG_FLAG_INDICATE_MULTI]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_client_config_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      sizeof(uint16_t), sizeof(FLAG_HINT_MULTIPLE_INDICATION)-1, (uint8_t *)FLAG_HINT_MULTIPLE_INDICATION}},

    /* FLAG MAC Characteristic Declaration */
    [IDX_CHAR_FLAG_MAC]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_MAC]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_MAC, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_SPOOF_MAC)-1, (uint8_t *)FLAG_HINT_SPOOF_MAC}},

    /* FLAG MTU Characteristic Declaration */
    [IDX_CHAR_FLAG_MTU]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_MTU]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_MTU, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_CHANGE_MTU)-1, (uint8_t *)FLAG_HINT_CHANGE_MTU}},

    /* FLAG write response Characteristic Declaration */
    [IDX_CHAR_FLAG_WRITE_RESPONSE]      =
    {{ESP_GATT_RSP_BY_APP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ|ESP_GATT_PERM_WRITE,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read_write}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_WRITE_RESPONSE]  =
    {{ESP_GATT_RSP_BY_APP}, {ESP_UUID_LEN_16, (uint8_t *)&FLAG_UUID_WRITE_RESPONSE, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_WRITE_RESPONSE)-1, (uint8_t *)FLAG_HINT_WRITE_RESPONSE}},

    /* FLAG hidden notify Characteristic Declaration */
    [IDX_CHAR_FLAG_HIDDEN_NOTIFY]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ|ESP_GATT_PERM_WRITE,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read_write}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_HIDDEN_NOTIFY]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_HIDDEN_NOTIFY, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_HIDDEN_NOTIFICATION)-1, (uint8_t *)FLAG_HINT_HIDDEN_NOTIFICATION}},

    /* FLAG crazy Characteristic Declaration */
    [IDX_CHAR_FLAG_CRAZY]      =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ|ESP_GATT_PERM_WRITE,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_crazy}},

    /* Characteristic Value */
    [IDX_CHAR_VAL_FLAG_CRAZY]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&GATTS_CHAR_UUID_FLAG_CRAZY, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_MULTIPLE_PROPERTIES)-1, (uint8_t *)FLAG_HINT_MULTIPLE_PROPERTIES}},




    /* FLAG TOKEN Characteristic Declaration */
    [MAIN_IDX_CHAR_TOKEN]     =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read_write_notify}},

    /* FLAG TOKEN Characteristic Value */
    [MAIN_IDX_CHAR_TOKEN_VAL] =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&FLAG_UUID_TOKEN, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_TOKEN)-1, (uint8_t *)FLAG_HINT_TOKEN}},

    /* Client Characteristic Configuration Descriptor */
    [MAIN_IDX_CHAR_TOKEN_CFG]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_client_config_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      sizeof(uint16_t), sizeof(FLAG_HINT_TOKEN)-1, (uint8_t *)FLAG_HINT_TOKEN}},


    /* FLAG AUTH Characteristic Declaration */
    [MAIN_IDX_CHAR_AUTH]     =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_declaration_uuid, ESP_GATT_PERM_READ,
      CHAR_DECLARATION_SIZE, CHAR_DECLARATION_SIZE, (uint8_t *)&char_prop_read_write_notify}},

    /* FLAG AUTH Characteristic Value */
    [MAIN_IDX_CHAR_AUTH_VAL] =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&FLAG_UUID_AUTH, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      GATTS_DEMO_CHAR_VAL_LEN_MAX, sizeof(FLAG_HINT_AUTH)-1, (uint8_t *)FLAG_HINT_AUTH}},

    /* Client Characteristic Configuration Descriptor */
    [MAIN_IDX_CHAR_AUTH_CFG]  =
    {{ESP_GATT_AUTO_RSP}, {ESP_UUID_LEN_16, (uint8_t *)&character_client_config_uuid, ESP_GATT_PERM_READ | ESP_GATT_PERM_WRITE,
      sizeof(uint16_t), sizeof(FLAG_HINT_AUTH)-1, (uint8_t *)FLAG_HINT_AUTH}},

};

static void set_score()
{
    //set scores
    score = 0;
    for (int i = 0 ; i < NUM_FLAGS ; ++i)
    {
        score += flag_status[i];
    }
    
    itoa(score, string_score, 10);
    for (int i = 0 ; i < strlen(string_score) ; ++i)
    {
        if (strlen(string_score) == 1){
            score_read_value[7] = ' ';
        }
        score_read_value[6+i] = string_score[i];
    }

    /* SCORE Characteristic Value */
    // Copy score_read_value to combined_array
    for (int i = 0; i < sizeof(score_read_value); i++) {
        score_output[i] = score_read_value[i];
    }

    // Append status to combined_array
    for (int i = 0; i < NUM_FLAGS; i++) {
        score_output[i + sizeof(score_read_value)] = flag_status[i] + '0';
    }

    esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_SCORE]+1, sizeof score_output, score_output);
}

static void gap_event_handler(esp_gap_ble_cb_event_t event, esp_ble_gap_cb_param_t *param)
{
    switch (event) {
    #ifdef CONFIG_SET_RAW_ADV_DATA
        case ESP_GAP_BLE_ADV_DATA_RAW_SET_COMPLETE_EVT:
            adv_config_done &= (~ADV_CONFIG_FLAG);
            if (adv_config_done == 0){
                esp_ble_gap_start_advertising(&adv_params);
            }
            break;
        case ESP_GAP_BLE_SCAN_RSP_DATA_RAW_SET_COMPLETE_EVT:
            adv_config_done &= (~SCAN_RSP_CONFIG_FLAG);
            if (adv_config_done == 0){
                esp_ble_gap_start_advertising(&adv_params);
            }
            break;
    #else
        case ESP_GAP_BLE_ADV_DATA_SET_COMPLETE_EVT:
            adv_config_done &= (~ADV_CONFIG_FLAG);
            if (adv_config_done == 0){
                esp_ble_gap_start_advertising(&adv_params);
            }
            break;
        case ESP_GAP_BLE_SCAN_RSP_DATA_SET_COMPLETE_EVT:
            adv_config_done &= (~SCAN_RSP_CONFIG_FLAG);
            if (adv_config_done == 0){
                esp_ble_gap_start_advertising(&adv_params);
            }
            break;
    #endif
        case ESP_GAP_BLE_ADV_START_COMPLETE_EVT:
            /* advertising start complete event to indicate advertising start successfully or failed */
            if (param->adv_start_cmpl.status != ESP_BT_STATUS_SUCCESS) {
                ESP_LOGE(GATTS_TABLE_TAG, "advertising start failed");
            }else{
                ESP_LOGI(GATTS_TABLE_TAG, "advertising start successfully");
            }
            break;
        case ESP_GAP_BLE_ADV_STOP_COMPLETE_EVT:
            if (param->adv_stop_cmpl.status != ESP_BT_STATUS_SUCCESS) {
                ESP_LOGE(GATTS_TABLE_TAG, "Advertising stop failed");
            }
            else {
                ESP_LOGI(GATTS_TABLE_TAG, "Stop adv successfully\n");
            }
            break;
        case ESP_GAP_BLE_UPDATE_CONN_PARAMS_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "update connetion params status = %d, min_int = %d, max_int = %d,conn_int = %d,latency = %d, timeout = %d",
                  param->update_conn_params.status,
                  param->update_conn_params.min_int,
                  param->update_conn_params.max_int,
                  param->update_conn_params.conn_int,
                  param->update_conn_params.latency,
                  param->update_conn_params.timeout);
            break;
        default:
            break;
    }
}

void example_prepare_write_event_env(esp_gatt_if_t gatts_if, prepare_type_env_t *prepare_write_env, esp_ble_gatts_cb_param_t *param)
{
    ESP_LOGI(GATTS_TABLE_TAG, "prepare write, handle = %d, value len = %d", param->write.handle, param->write.len);
    esp_gatt_status_t status = ESP_GATT_OK;
    if (prepare_write_env->prepare_buf == NULL) {
        prepare_write_env->prepare_buf = (uint8_t *)malloc(PREPARE_BUF_MAX_SIZE * sizeof(uint8_t));
        prepare_write_env->prepare_len = 0;
        if (prepare_write_env->prepare_buf == NULL) {
            ESP_LOGE(GATTS_TABLE_TAG, "%s, Gatt_server prep no mem", __func__);
            status = ESP_GATT_NO_RESOURCES;
        }
    } else {
        if(param->write.offset > PREPARE_BUF_MAX_SIZE) {
            status = ESP_GATT_INVALID_OFFSET;
        } else if ((param->write.offset + param->write.len) > PREPARE_BUF_MAX_SIZE) {
            status = ESP_GATT_INVALID_ATTR_LEN;
        }
    }
    /*send response when param->write.need_rsp is true */
    if (param->write.need_rsp){
        esp_gatt_rsp_t *gatt_rsp = (esp_gatt_rsp_t *)malloc(sizeof(esp_gatt_rsp_t));
        if (gatt_rsp != NULL){
            gatt_rsp->attr_value.len = param->write.len;
            gatt_rsp->attr_value.handle = param->write.handle;
            gatt_rsp->attr_value.offset = param->write.offset;
            gatt_rsp->attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE;
            memcpy(gatt_rsp->attr_value.value, param->write.value, param->write.len);
            esp_err_t response_err = esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, status, gatt_rsp);
            if (response_err != ESP_OK){
               ESP_LOGE(GATTS_TABLE_TAG, "Send response error");
            }
            free(gatt_rsp);
        }else{
            ESP_LOGE(GATTS_TABLE_TAG, "%s, malloc failed", __func__);
        }
    }
    if (status != ESP_GATT_OK){
        return;
    }
    memcpy(prepare_write_env->prepare_buf + param->write.offset,
           param->write.value,
           param->write.len);
    prepare_write_env->prepare_len += param->write.len;

}

void example_exec_write_event_env(prepare_type_env_t *prepare_write_env, esp_ble_gatts_cb_param_t *param){
    if (param->exec_write.exec_write_flag == ESP_GATT_PREP_WRITE_EXEC && prepare_write_env->prepare_buf){
        esp_log_buffer_hex(GATTS_TABLE_TAG, prepare_write_env->prepare_buf, prepare_write_env->prepare_len);
    }else{
        ESP_LOGI(GATTS_TABLE_TAG,"ESP_GATT_PREP_WRITE_CANCEL");
    }
    if (prepare_write_env->prepare_buf) {
        free(prepare_write_env->prepare_buf);
        prepare_write_env->prepare_buf = NULL;
    }
    prepare_write_env->prepare_len = 0;
}

static void gatts_profile_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param)
{
    switch (event) {
        case ESP_GATTS_REG_EVT:{
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_REG_EVT");
            esp_err_t set_dev_name_ret = esp_ble_gap_set_device_name(FLAG_HINT_DEVICE_NAME_ATTR);
            if (set_dev_name_ret){
                ESP_LOGE(GATTS_TABLE_TAG, "set device name failed, error code = %x", set_dev_name_ret);
            }
    #ifdef CONFIG_SET_RAW_ADV_DATA
            esp_err_t raw_adv_ret = esp_ble_gap_config_adv_data_raw(raw_adv_data, sizeof(raw_adv_data));
            if (raw_adv_ret){
                ESP_LOGE(GATTS_TABLE_TAG, "config raw adv data failed, error code = %x ", raw_adv_ret);
            }
            adv_config_done |= ADV_CONFIG_FLAG;
            esp_err_t raw_scan_ret = esp_ble_gap_config_scan_rsp_data_raw(raw_scan_rsp_data, sizeof(raw_scan_rsp_data));
            if (raw_scan_ret){
                ESP_LOGE(GATTS_TABLE_TAG, "config raw scan rsp data failed, error code = %x", raw_scan_ret);
            }
            adv_config_done |= SCAN_RSP_CONFIG_FLAG;
    #else
            //config adv data
            esp_err_t ret = esp_ble_gap_config_adv_data(&adv_data);
            if (ret){
                ESP_LOGE(GATTS_TABLE_TAG, "config adv data failed, error code = %x", ret);
            }
            adv_config_done |= ADV_CONFIG_FLAG;
            //config scan response data
            ret = esp_ble_gap_config_adv_data(&scan_rsp_data);
            if (ret){
                ESP_LOGE(GATTS_TABLE_TAG, "config scan response data failed, error code = %x", ret);
            }
            adv_config_done |= SCAN_RSP_CONFIG_FLAG;
    #endif
            esp_err_t create_attr_ret = esp_ble_gatts_create_attr_tab(gatt_db, gatts_if, HRS_IDX_NB, SVC_INST_ID);
            if (create_attr_ret){
                ESP_LOGE(GATTS_TABLE_TAG, "create attr table failed, error code = %x", create_attr_ret);
            }
        }
       	    break;
        case ESP_GATTS_READ_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_READ_EVT");
            read_counter += 1;
            //set gpio
            esp_rom_gpio_pad_select_gpio(BLINK_GPIO);
            /* Set the GPIO as a push/pull output */
            gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);
            gpio_set_level(BLINK_GPIO, 1);
            if (read_counter > 1000){
                esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_READ_ALOT]+1, FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_READ_MANY]);
            }

            if (param->read.handle == blectf_handle_table[IDX_CHAR_FLAG_WRITE_RESPONSE]+1){
                ESP_LOGI(GATTS_TABLE_TAG,"In WRITE RESPONSE check - item=%d, flag=%d, multi=%d", FLAG_WRITE_RESPONSE, flag_status[FLAG_WRITE_RESPONSE], flag_multi_status[FLAG_WRITE_RESPONSE]);

                // add an ascii value write check to this one
                esp_gatt_rsp_t *rsp = (esp_gatt_rsp_t *)malloc(sizeof(esp_gatt_rsp_t));
                if (flag_status[FLAG_WRITE_RESPONSE] || flag_multi_status[FLAG_WRITE_RESPONSE]){
                    ESP_LOGI(GATTS_TABLE_TAG,"In WRITE RESPONSE - MAIN - flag=%d, multi=%d", flag_status[FLAG_WRITE_RESPONSE], flag_multi_status[FLAG_WRITE_RESPONSE]);

                    rsp->attr_value.len = FLAG_LEN;
                    rsp->attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE;
                    memcpy(rsp->attr_value.value, (uint8_t *)FLAG_VALUES[FLAG_WRITE_RESPONSE], FLAG_LEN);
                }else{
                    ESP_LOGI(GATTS_TABLE_TAG,"In WRITE RESPONSE - ELSE - flag=%d, multi=%d", flag_status[FLAG_WRITE_RESPONSE], flag_multi_status[FLAG_WRITE_RESPONSE]);
                    rsp->attr_value.len = sizeof(FLAG_HINT_WRITE_RESPONSE)-1;
                    rsp->attr_value.auth_req = ESP_GATT_AUTH_REQ_NONE;
                    memcpy(rsp->attr_value.value, (uint8_t *)FLAG_HINT_WRITE_RESPONSE, sizeof(FLAG_HINT_WRITE_RESPONSE)-1);
                }

                esp_ble_gatts_send_response(gatts_if, param->read.conn_id, param->read.trans_id, ESP_GATT_OK, rsp);
            }

       	    break;
        case ESP_GATTS_WRITE_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_WRITE_EVT");

            if (!param->write.is_prep){
                ESP_LOGI(GATTS_TABLE_TAG, "GATT_WRITE_EVT, handle = %d, value len = %d, value :", param->write.handle, param->write.len);
                esp_log_buffer_hex(GATTS_TABLE_TAG, param->write.value, param->write.len);

                // store write data for flag checking
                memset(writeData, 0, sizeof writeData);
                memcpy(writeData, param->write.value, FLAG_LEN); 

                // any write
                if (blectf_handle_table[IDX_CHAR_FLAG_WRITE_ANYTHING]+1 == param->write.handle)
                {
                    esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_WRITE_ANYTHING]+1, FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_WRITE_ANY]);
                }

                // hex ascii
                if (blectf_handle_table[IDX_CHAR_FLAG_WRITE_ASCII]+1 == param->write.handle)
                {
                    if (strcmp(writeData,"DC608") == 0){
                        esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_WRITE_ASCII]+1, FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_WRITE_ASCII]);
                    }
                    else
                    {
                        esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_WRITE_ASCII]+1, sizeof(FLAG_WRITE_ASCII)-1, (uint8_t *)FLAG_WRITE_ASCII);
                    }
                }

                // hex write
                if (blectf_handle_table[IDX_CHAR_FLAG_WRITE_HEX]+1 == param->write.handle)
                {
                    uint16_t descr_value = param->write.value[1]<<8 |param->write.value[0];
                    if (descr_value == 0x0042){
                        esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_WRITE_HEX]+1, FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_WRITE_HEX]);
                    }
                    else
                    {
                        esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_WRITE_HEX]+1, sizeof(FLAG_WRITE_HEX)-1, (uint8_t *)FLAG_WRITE_HEX);
                    }
                }
                // brute write
                if (blectf_handle_table[IDX_CHAR_FLAG_BRUTE_WRITE]+1 == param->write.handle)
                {
                    uint16_t descr_value = param->write.value[1]<<8 |param->write.value[0];
                    if (descr_value == 0x00D4 || flag_status[FLAG_WRITE_FUZZING]){
                        esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_BRUTE_WRITE]+1, FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_WRITE_FUZZING]);
                    }
                    else
                    {
                        esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_BRUTE_WRITE]+1, sizeof(FLAG_HINT_WRITE_FUZZING)-1, (uint8_t *)FLAG_HINT_WRITE_FUZZING);
                    }
                }
                // read write
                if (blectf_handle_table[IDX_CHAR_FLAG_SIMPLE_WRITE2]+1 == param->write.handle)
                {
                    uint16_t descr_value = param->write.value[1]<<8 |param->write.value[0];
                    if (descr_value == 0x00B2 || flag_status[FLAG_WRITE_DECIMAL_HANDLE]){
                        esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_SIMPLE_WRITE2_READ]+1, FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_WRITE_DECIMAL_HANDLE]);
                    }
                    else
                    {
                        esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_SIMPLE_WRITE2_READ]+1, sizeof(FLAG_HINT_WRITE_DECIMAL_HANDLE)-1, (uint8_t *)FLAG_HINT_WRITE_DECIMAL_HANDLE);
                    }
                }
                // notify single response flag
                if (blectf_handle_table[IDX_CHAR_FLAG_NOTIFICATION]+1 == param->write.handle)
                {
                    ESP_LOGI(GATTS_TABLE_TAG, "IDX_CHAR_FLAG_NOTIFICATION"); //: %s\n", writeData);

                    esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_NOTIFICATION]+1, sizeof(FLAG_HINT_SINGLE_NOTIFICATION)-1, (uint8_t *)FLAG_HINT_SINGLE_NOTIFICATION);
                    esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, blectf_handle_table[IDX_CHAR_VAL_FLAG_NOTIFICATION], FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_SINGLE_NOTIFICATION], false);
                }

                // indicate single response flag flag
                if (blectf_handle_table[IDX_CHAR_FLAG_INDICATE]+1 == param->write.handle)
                {
                    esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, blectf_handle_table[IDX_CHAR_VAL_FLAG_INDICATE], FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_SINGLE_INDICATION], true);
                }

                // notify multi response flag
                if (blectf_handle_table[IDX_CHAR_FLAG_NOTIFICATION_MULTI]+1 == param->write.handle)
                {
                    indicate_handle_state = blectf_handle_table[IDX_CHAR_FLAG_NOTIFICATION_MULTI]; 
                    char notify_data[FLAG_LEN] = "Nothing to see here!";
                    esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_NOTIFICATION_MULTI]+1, sizeof(FLAG_HINT_MULTIPLE_NOTIFICATION)-1, (uint8_t *)FLAG_HINT_MULTIPLE_NOTIFICATION);
                    esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, blectf_handle_table[IDX_CHAR_VAL_FLAG_NOTIFICATION_MULTI], sizeof(notify_data), (uint8_t *)notify_data, false);
                }

                // indicate multi response flag flag
                if (blectf_handle_table[IDX_CHAR_FLAG_INDICATE_MULTI]+1 == param->write.handle)
                {
                    indicate_handle_state = blectf_handle_table[IDX_CHAR_FLAG_INDICATE_MULTI]; 
                    char indicate_data[FLAG_LEN] = "Nothing to see here!";
                    esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, blectf_handle_table[IDX_CHAR_VAL_FLAG_INDICATE_MULTI], sizeof(indicate_data), (uint8_t *)indicate_data, true);
                }
                // write response
                if (blectf_handle_table[IDX_CHAR_FLAG_WRITE_RESPONSE]+1 == param->write.handle)
                {
                    if (strcmp(writeData,"DC608") == 0){
                        check_send_response=FLAG_WRITE_RESPONSE;
                        
                        ESP_LOGI(GATTS_TABLE_TAG, "Multi-step successful for: %#04x\n", FLAG_UUID_WRITE_RESPONSE);
                        ESP_LOGI(GATTS_TABLE_TAG, "Setting check_send_response: %d\n", FLAG_WRITE_RESPONSE);

                        // we dont have to do send_response here it will hit the catchall
                    } else {
                        ESP_LOGI(GATTS_TABLE_TAG, "Wrong value for: %#04x\n", FLAG_UUID_WRITE_RESPONSE);
                    }
                }
                // notify hidden notify flag
                if (blectf_handle_table[IDX_CHAR_FLAG_HIDDEN_NOTIFY]+1 == param->write.handle)
                {
                    indicate_handle_state = blectf_handle_table[IDX_CHAR_FLAG_HIDDEN_NOTIFY]; 
                    esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_HIDDEN_NOTIFY]+1, sizeof(FLAG_HINT_HIDDEN_NOTIFICATION)-1, (uint8_t *)FLAG_HINT_HIDDEN_NOTIFICATION);
                    esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, blectf_handle_table[IDX_CHAR_VAL_FLAG_HIDDEN_NOTIFY], FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_HIDDEN_NOTIFICATION], false);
                }

                // so many properties
                if (blectf_handle_table[IDX_CHAR_FLAG_CRAZY]+1 == param->write.handle)
                {
                    char part_1[11];
                    strncpy(part_1, FLAG_VALUES[FLAG_MULTIPLE_PROPERTIES], 10);
                    part_1[10] = '\0';

                    char part_2[11];
                    strncpy(part_2, FLAG_VALUES[FLAG_MULTIPLE_PROPERTIES] + 10, 10);
                    part_2[10] = '\0';

                    esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_CRAZY]+1, 10, (uint8_t *)part_1);
                    esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, blectf_handle_table[IDX_CHAR_VAL_FLAG_CRAZY], sizeof(part_2), (uint8_t *)part_2, false);
                }


                // FLAG TOKEN
                if (blectf_handle_table[MAIN_IDX_CHAR_TOKEN]+1 == param->write.handle)
                {
                    ESP_LOGI(GATTS_TABLE_TAG, "MAIN_IDX_CHAR_TOKEN: %s\n", writeData);

                    if (strcmp(writeData,local_bd_addr_str) == 0){
                        ESP_LOGI(GATTS_TABLE_TAG, "Correct password!");
                        esp_ble_gatts_set_attr_value(blectf_handle_table[MAIN_IDX_CHAR_TOKEN]+1, sizeof(FLAG_HINT_TOKEN)-1, (uint8_t *)FLAG_HINT_TOKEN);
                        esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, blectf_handle_table[MAIN_IDX_CHAR_TOKEN_VAL], FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_TOKEN], false);
                    } else {
                        ESP_LOGI(GATTS_TABLE_TAG, "Wrong password! - %s\n", local_bd_addr_str);
                        esp_ble_gatts_set_attr_value(blectf_handle_table[MAIN_IDX_CHAR_TOKEN]+1, sizeof(FLAG_HINT_TOKEN)-1, (uint8_t *)FLAG_HINT_TOKEN);
                        // esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, blectf_handle_table[MAIN_IDX_CHAR_TOKEN_VAL], FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_TOKEN], false);                        
                    }
                }

                // FLAG AUTH
                if (blectf_handle_table[MAIN_IDX_CHAR_AUTH]+1 == param->write.handle)
                {
                    ESP_LOGI(GATTS_TABLE_TAG, "MAIN_IDX_CHAR_AUTH: %s\n", writeData);

                    if (strcmp(writeData,FLAG_VALUES[FLAG_TOKEN]) == 0){
                        ESP_LOGI(GATTS_TABLE_TAG, "Correct password!");
                        esp_ble_gatts_set_attr_value(blectf_handle_table[MAIN_IDX_CHAR_AUTH]+1, sizeof(FLAG_HINT_AUTH)-1, (uint8_t *)FLAG_HINT_AUTH);
                        esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, blectf_handle_table[MAIN_IDX_CHAR_TOKEN_VAL], FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_AUTH], false);
                    } else {
                        ESP_LOGI(GATTS_TABLE_TAG, "Wrong password! - %s\n", FLAG_VALUES[FLAG_TOKEN]);
                        esp_ble_gatts_set_attr_value(blectf_handle_table[MAIN_IDX_CHAR_AUTH]+1, sizeof(FLAG_HINT_AUTH)-1, (uint8_t *)FLAG_HINT_AUTH);
                    }
                }


                //handle flags
                if (blectf_handle_table[IDX_CHAR_FLAG]+1 == param->write.handle)
                {
                    // make sure flag read value stays static
                    esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG]+1, sizeof FLAG_HINT_WRITE_FLAG_HERE, (uint8_t *)FLAG_HINT_WRITE_FLAG_HERE);

                    ESP_LOGI(GATTS_TABLE_TAG, "About to call check_flag: %s\n", writeData);

                    ESP_LOGI(GATTS_TABLE_TAG, "Inside check_flag");

                    for (int i = 0; i < NUM_FLAGS; i++) {
                        if (strcmp(FLAG_VALUES[i], writeData) == 0) {
                            flag_status[i] = 1;
                            ESP_LOGI(GATTS_TABLE_TAG, "Flag captured for: %#04x\n", FLAG_UUIDS[i]);
                            set_score();
                            return;
                        }
                    }

                    ESP_LOGI(GATTS_TABLE_TAG, "Flag ignored: %s\n", writeData);
                }
                /* send response when param->write.need_rsp is true*/
                //if (param->write.need_rsp && send_response == 0){
                if (param->write.need_rsp){
                    ESP_LOGI(GATTS_TABLE_TAG, "CATCH ALL SEND RESPONSE TRIGGERED");
                    esp_ble_gatts_send_response(gatts_if, param->write.conn_id, param->write.trans_id, ESP_GATT_OK, NULL);
                }
            }
            else{
                /* handle prepare write */
                ESP_LOGI(GATTS_TABLE_TAG, "PREPARE WRITE TRIGGERED");
                example_prepare_write_event_env(gatts_if, &prepare_write_env, param);
            }
      	    break;
        case ESP_GATTS_EXEC_WRITE_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_EXEC_WRITE_EVT");
            example_exec_write_event_env(&prepare_write_env, param);
            break;
        case ESP_GATTS_MTU_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_MTU_EVT, MTU %d", param->mtu.mtu);
            if (param->mtu.mtu == 444) {
                esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_MTU]+1, 20, (uint8_t *)FLAG_VALUES[FLAG_CHANGE_MTU]);
            }
            break;
        case ESP_GATTS_CONF_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_CONF_EVT, status = %d", param->conf.status);
            // notify multi
            if (indicate_handle_state == blectf_handle_table[IDX_CHAR_FLAG_NOTIFICATION_MULTI]){
                // delay was added cause with none, this crashed the server
                vTaskDelay(100);
                esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, blectf_handle_table[IDX_CHAR_VAL_FLAG_NOTIFICATION_MULTI], FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_MULTIPLE_NOTIFICATION], false);
            }
            // indicate multi
            if (indicate_handle_state == blectf_handle_table[IDX_CHAR_FLAG_INDICATE_MULTI]){
                esp_ble_gatts_send_indicate(gatts_if, param->write.conn_id, blectf_handle_table[IDX_CHAR_VAL_FLAG_INDICATE_MULTI], FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_MULTIPLE_INDICATION], true);
            }
            break;
        case ESP_GATTS_START_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "SERVICE_START_EVT, status %d, service_handle %d", param->start.status, param->start.service_handle);
            break;
        case ESP_GATTS_CONNECT_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_CONNECT_EVT, conn_id = %d", param->connect.conn_id);
            esp_log_buffer_hex(GATTS_TABLE_TAG, param->connect.remote_bda, 6);
            uint8_t match_mac[8] = {0xde,0xad,0xbe,0xef,0x12,0x34};
            if (match_mac[0] == param->connect.remote_bda[0] &&
                match_mac[1] == param->connect.remote_bda[1] &&
                match_mac[2] == param->connect.remote_bda[2] &&
                match_mac[3] == param->connect.remote_bda[3] &&
                match_mac[4] == param->connect.remote_bda[4] &&
                match_mac[5] == param->connect.remote_bda[5]){
                ESP_LOGI(GATTS_TABLE_TAG, "THIS IS THE MAC YOU ARE LOOKING FOR");
                esp_ble_gatts_set_attr_value(blectf_handle_table[IDX_CHAR_FLAG_MAC]+1, FLAG_LEN, (uint8_t *)FLAG_VALUES[FLAG_SPOOF_MAC]);
            }


            esp_ble_conn_update_params_t conn_params = {0};
            memcpy(conn_params.bda, param->connect.remote_bda, sizeof(esp_bd_addr_t));
            /* For the IOS system, please reference the apple official documents about the ble connection parameters restrictions. */
            conn_params.latency = 0;
            conn_params.max_int = 0x20;    // max_int = 0x20*1.25ms = 40ms
            conn_params.min_int = 0x10;    // min_int = 0x10*1.25ms = 20ms
            conn_params.timeout = 400;    // timeout = 400*10ms = 4000ms
            //start sent the update connection parameters to the peer device.
            esp_ble_gap_update_conn_params(&conn_params);
            break;
        case ESP_GATTS_DISCONNECT_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_DISCONNECT_EVT, reason = %d", param->disconnect.reason);
            indicate_handle_state=0;
            esp_ble_gap_start_advertising(&adv_params);
            break;
        case ESP_GATTS_CREAT_ATTR_TAB_EVT:{
            if (param->add_attr_tab.status != ESP_GATT_OK){
                ESP_LOGE(GATTS_TABLE_TAG, "create attribute table failed, error code=0x%x", param->add_attr_tab.status);
            }
            else if (param->add_attr_tab.num_handle != HRS_IDX_NB){
                ESP_LOGE(GATTS_TABLE_TAG, "create attribute table abnormally, num_handle (%d) \
                        doesn't equal to HRS_IDX_NB(%d)", param->add_attr_tab.num_handle, HRS_IDX_NB);
            }
            else {
                ESP_LOGI(GATTS_TABLE_TAG, "create attribute table successfully, the number handle = %d\n",param->add_attr_tab.num_handle);
                memcpy(blectf_handle_table, param->add_attr_tab.handles, sizeof(blectf_handle_table));
                esp_ble_gatts_start_service(blectf_handle_table[IDX_SVC]);
            }
            break;
        }
        case ESP_GATTS_STOP_EVT:
        case ESP_GATTS_OPEN_EVT:
        case ESP_GATTS_CANCEL_OPEN_EVT:
        case ESP_GATTS_CLOSE_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_CLOSE_EVT");
            break;
        case ESP_GATTS_LISTEN_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_LISTEN_EVT");
            break;
        case ESP_GATTS_CONGEST_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_CONGEST_EVT");
            break;
        case ESP_GATTS_UNREG_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_UNREG_EVT");
            break;
        case ESP_GATTS_DELETE_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_DELETE_EVT");
            break;
        case ESP_GATTS_RESPONSE_EVT:
            ESP_LOGI(GATTS_TABLE_TAG, "ESP_GATTS_RESPONSE_EVT");
            ESP_LOGI(GATTS_TABLE_TAG, "check_send_response = %d", check_send_response);
            //TODO: change the following to set a read value instead of doing a notify
            if (check_send_response >= 0){
                ESP_LOGI(GATTS_TABLE_TAG, "check_send_response = %d, flag_multi=1", check_send_response);
                ESP_LOGI(GATTS_TABLE_TAG, "flag_multi_status[check_send_response] = %d", flag_multi_status[check_send_response] );

                flag_multi_status[check_send_response] = 1;
                check_send_response = -1;

                ESP_LOGI(GATTS_TABLE_TAG, "check_send_response = %d, flag_multi=1", check_send_response);
                ESP_LOGI(GATTS_TABLE_TAG, "flag_multi_status[check_send_response] = %d", flag_multi_status[check_send_response] );
            }
            
            break;
        default:
            break;
    }
}

static void check_flag(const char* writeData) {
    ESP_LOGI(GATTS_TABLE_TAG, "Inside check_flag");

    for (int i = 0; i < NUM_FLAGS; i++) {
        if (strcmp(FLAG_VALUES[i], writeData) == 0) {
            flag_status[i] = 1;
            ESP_LOGI(GATTS_TABLE_TAG, "Flag captured for: %#04x\n", FLAG_UUIDS[i]);
            set_score();
            return;
        }
    }

    ESP_LOGI(GATTS_TABLE_TAG, "Flag ignored: %s\n", writeData);
}

static void gatts_event_handler(esp_gatts_cb_event_t event, esp_gatt_if_t gatts_if, esp_ble_gatts_cb_param_t *param)
{

    /* If event is register event, store the gatts_if for each profile */
    if (event == ESP_GATTS_REG_EVT) {
        if (param->reg.status == ESP_GATT_OK) {
            blectf_profile_tab[PROFILE_APP_IDX].gatts_if = gatts_if;
        } else {
            ESP_LOGE(GATTS_TABLE_TAG, "reg app failed, app_id %04x, status %d",
                    param->reg.app_id,
                    param->reg.status);
            return;
        }
    }
    do {
        int idx;
        for (idx = 0; idx < PROFILE_NUM; idx++) {
            /* ESP_GATT_IF_NONE, not specify a certain gatt_if, need to call every profile cb function */
            if (gatts_if == ESP_GATT_IF_NONE || gatts_if == blectf_profile_tab[idx].gatts_if) {
                if (blectf_profile_tab[idx].gatts_cb) {
                    blectf_profile_tab[idx].gatts_cb(event, gatts_if, param);
                }
            }
        }
    } while (0);
}

void app_main()
{
    esp_err_t ret;

    //uint8_t new_mac[8] = {0xDE,0xAD,0xBE,0xEF,0xBE,0xEF};
    //esp_base_mac_addr_set(new_mac);
    
    /* Initialize NVS. */
    ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );

    ESP_ERROR_CHECK(esp_bt_controller_mem_release(ESP_BT_MODE_CLASSIC_BT));

    ESP_LOGI(GATTS_TABLE_TAG, "Starting Program");

    esp_bt_controller_config_t bt_cfg = BT_CONTROLLER_INIT_CONFIG_DEFAULT();
    ret = esp_bt_controller_init(&bt_cfg);
    if (ret) {
        ESP_LOGE(GATTS_TABLE_TAG, "%s enable controller failed", __func__);
        return;
    }

    ret = esp_bt_controller_enable(ESP_BT_MODE_BLE);
    if (ret) {
        ESP_LOGE(GATTS_TABLE_TAG, "%s enable controller failed", __func__);
        return;
    }

    ret = esp_bluedroid_init();
    if (ret) {
        ESP_LOGE(GATTS_TABLE_TAG, "%s init bluetooth failed", __func__);
        return;
    }

    ret = esp_bluedroid_enable();
    if (ret) {
        ESP_LOGE(GATTS_TABLE_TAG, "%s enable bluetooth failed", __func__);
        return;
    }

    ret = esp_ble_gatts_register_callback(gatts_event_handler);
    if (ret){
        ESP_LOGE(GATTS_TABLE_TAG, "gatts register error, error code = %x", ret);
        return;
    }

    ret = esp_ble_gap_register_callback(gap_event_handler);
    if (ret){
        ESP_LOGE(GATTS_TABLE_TAG, "gap register error, error code = %x", ret);
        return;
    }

    ret = esp_ble_gatts_app_register(ESP_APP_ID);
    if (ret){
        ESP_LOGE(GATTS_TABLE_TAG, "gatts app register error, error code = %x", ret);
        return;
    }

    esp_err_t local_mtu_ret = esp_ble_gatt_set_local_mtu(500);
    if (local_mtu_ret){
        ESP_LOGE(GATTS_TABLE_TAG, "set local  MTU failed, error code = %x", local_mtu_ret);
    }

    local_bd_addr = esp_bt_dev_get_address();

    sprintf(local_bd_addr_str, "%02X%02X%02X%02X%02X%02X", local_bd_addr[0],local_bd_addr[1],local_bd_addr[2],local_bd_addr[3],local_bd_addr[4],local_bd_addr[5]);
    ESP_LOGI(GATTS_TABLE_TAG, "Local Address: %s", local_bd_addr_str);
}
