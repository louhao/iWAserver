
#ifndef __iWA_H__
#define __iWA_H__

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <memory.h>
#include <string.h>

#include <pthread.h>
#include <semaphore.h>

#include <my_global.h>
#include <mysql.h>

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

#include "bn/bn.h"
#include "bn/sha1.h"

#include "log4c.h"

#include "iWA_Config.h"

#include "iwa_authserver.pb-c.h"
#include "iwa_gameserver.pb-c.h"





typedef signed char        iWAint8;
typedef unsigned char    iWAuint8;
typedef signed short       iWAint16;
typedef unsigned short   iWAuint16;
typedef signed int          iWAint32;
typedef unsigned int       iWAuint32;
typedef unsigned int       iWAbool;




#define iWA_Std_malloc     malloc
#define iWA_Std_free        free
#define iWA_Std_memset   memset
#define iWA_Std_memcpy  memcpy
#define iWA_Std_memcmp  memcmp
#define iWA_Std_strlen      strlen
#define iWA_Std_strcpy      strcpy
#define iWA_Std_strcmp      strcmp
#define iWA_Std_strcat      strcat
#define iWA_Std_atoi          atoi 
#define iWA_Std_sprintf          sprintf 
#define iWA_Std_exit            exit


#define iWA_Exit           iWA_Std_exit
#define iWA_Malloc(s)       iWA_Memory_Alloc(s)
#define iWA_Free(p)         iWA_Memory_Free(p)
#define iWA_Realloc(p, s)   iWA_Memory_Realloc(p, s)

/* 
    [Assert]       Check Internal Coding Error 
    [Fatal]         Run Into Error Case, Unrecoverable, App Abort      
    [Error]         Run Into Error Case, Recoverable, App Keep Working
    [Warn]         RunTime Log, Something Maybe On Guard
    [Notice]        RunTime Log, Routine
    [Info]          DebugTime Info, Normally
    [Debug]       DebugTime Info, Temporary
*/

#define iWA_Assert        assert
#define iWA_Fatal(fmt , args...)    do{iWA_Log_TraceEx(__FILE__, __LINE__, __FUNCTION__, LOG4C_PRIORITY_FATAL, fmt, ##args);iWA_Exit(1);}while(0)
#define iWA_Error(fmt , args...)    iWA_Log_TraceEx(__FILE__, __LINE__, __FUNCTION__, LOG4C_PRIORITY_ERROR, fmt, ##args)
#define iWA_Warn(fmt , args...)    iWA_Log_Trace(LOG4C_PRIORITY_WARN, fmt, ##args)
#define iWA_Notice(fmt , args...)    iWA_Log_Trace(LOG4C_PRIORITY_NOTICE, fmt, ##args)
#define iWA_Info(fmt , args...)    iWA_Log_Trace(LOG4C_PRIORITY_INFO, fmt, ##args)
#define iWA_Debug(fmt , args...)    iWA_Log_Trace(LOG4C_PRIORITY_DEBUG, fmt, ##args)
#define iWA_Dump(p, l)                 iWA_Log_Dump(p, l)

enum
{
    iWAenum_AUTH_CMD_REG            = 0x00,
    iWAenum_AUTH_CMD_LOGON        = 0x01,
    iWAenum_AUTH_CMD_PROOF    = 0x02,
    iWAenum_AUTH_CMD_SERVER_LIST       = 0x03,
};

enum
{
    iWAenum_GAME_CMD_AUTH_CHANLLEGE        = 0x00,
    iWAenum_GAME_CMD_AUTH_SEESION            = 0x01,
    iWAenum_GAME_CMD_AUTH_RESPONSE          = 0x02,
    iWAenum_GAME_CMD_CHAR_ENUM       = 0x03,
    iWAenum_GAME_CMD_CHAR_CREATE       = 0x04,
    iWAenum_GAME_CMD_CHAR_DELETE       = 0x05,
    iWAenum_GAME_CMD_PLAYER_LOGIN       = 0x06,    
};


enum
{
    iWAenum_WORLD_MSG_AUTH                                =  0x00, 
    iWAenum_WORLD_MSG_CHAR_ENUM,
    iWAenum_WORLD_MSG_CHAR_CREATE,
    iWAenum_WORLD_MSG_CHAR_DELETE
};

enum
{
    iWAenum_WORLD_STATUS_OK                    =  0x00, 
    iWAenum_WORLD_STATUS_FAIL
};

enum
{
    iWAenum_CHARACTER_RACE_DOULUO    = 0,
    iWAenum_CHARACTER_RACE_GUISHA,
    iWAenum_CHARACTER_RACE_LINGZUN,
    iWAenum_CHARACTER_RACE_WUHUANG
};

enum
{
    iWAenum_CHARACTER_NATION_HAOTIAN    = 0,
    iWAenum_CHARACTER_NATION_WUCHEN,
    iWAenum_CHARACTER_NATION_CANGHAI
};


enum
{
    iWAenum_AUTH_MSG_AUTH_OK                                         = 0x00,
    iWAenum_AUTH_MSG_AUTH_CONNECT_ERROR                   = 0x01,
    iWAenum_AUTH_MSG_AUTH_INVALID_USERNAME                = 0x02,
    iWAenum_AUTH_MSG_AUTH_INVALID_PASSWORD              = 0x03,
    iWAenum_AUTH_MSG_AUTH_SERVER_LIST                         = 0x04,

    iWAenum_AUTH_MSG_REG_OK                                          = 0x10,
    iWAenum_AUTH_MSG_REG_CONNECT_ERROR                     = 0x11,    
    iWAenum_AUTH_MSG_REG_USERNAME_EXIST                    = 0x12,    
    iWAenum_AUTH_MSG_REG_CREATE_FAIL                           = 0x13,        
};

enum
{
    iWAenum_AUTH_SERVER_STATUS_NEW,
    iWAenum_AUTH_SERVER_STATUS_HOT,
    iWAenum_AUTH_SERVER_STATUS_MAINTAIN,
};

#define iWAmacro_AUTH_SERVER_NAME_SIZE          (32)
#define iWAmacro_AUTH_SERVER_ADDRESS_SIZE    (20)
#define iWAmacro_AUTH_SERVER_HIT_SIZE             (32)

#define iWAmacro_WORLD_CHARACTER_NAME_SIZE     (32)
//#define iWAmacro_WORLD_CHARACTER_RACE_SIZE     (20)
//#define iWAmacro_WORLD_CHARACTER_NATION_SIZE   (20)

typedef struct
{
    iWAuint8     region;
    iWAuint8     status;
    iWAuint8     name[iWAmacro_AUTH_SERVER_NAME_SIZE];
    iWAuint8     hit[iWAmacro_AUTH_SERVER_HIT_SIZE];
    iWAuint8     address[iWAmacro_AUTH_SERVER_ADDRESS_SIZE];
    iWAuint16   port;
    iWAuint16   character_num;
    iWAuint16   character_grade;    
    iWAuint8     character_race;
    iWAuint8     character_nation;    
    iWAuint8     character_name[iWAmacro_WORLD_CHARACTER_NAME_SIZE];
}iWAstruct_Auth_Server;

typedef struct
{
    iWAuint8     cid[8];
    iWAuint8     name[iWAmacro_WORLD_CHARACTER_NAME_SIZE];
    iWAuint16   grade;    
    iWAuint8     race;
    iWAuint8     nation;
}iWAstruct_Character;


#define iWAmacro_MYSQL_HOST_LENGTH_MAX    (32)
#define iWAmacro_MYSQL_USER_LENGTH_MAX    (16)
#define iWAmacro_MYSQL_PWD_LENGTH_MAX    (20)
#define iWAmacro_MYSQL_DBNAME_LENGTH_MAX    (16)


typedef struct
{
    MYSQL *conn;
    iWAint8 host[iWAmacro_MYSQL_HOST_LENGTH_MAX];
    iWAuint16 port;
    iWAint8 user[iWAmacro_MYSQL_USER_LENGTH_MAX];
    iWAint8 pwd[iWAmacro_MYSQL_PWD_LENGTH_MAX];
    iWAint8 name[iWAmacro_MYSQL_DBNAME_LENGTH_MAX];
}iWAstruct_Mysql_Database;

typedef struct
{
    MYSQL_RES *res;
    iWAuint32 num;
    MYSQL_ROW row;
}iWAstruct_Mysql_QueryResult;

#define iWAmacro_AUTHSERVER_ACCOUNTNAME_LENGTH  (32)
#define iWAmacro_GAMESERVER_SEESION_KEY_SIZE     (90)

typedef struct
{
    iWAbool f_used;
    struct bufferevent *bev;
    iWAint8 account[iWAmacro_AUTHSERVER_ACCOUNTNAME_LENGTH];
    iWAuint32 UID;
    BIGNUM N, g, s, v, b, B;
    iWAbool f_simple_auth;
}iWAstruct_AuthSession_Session;


typedef struct
{
    iWAbool f_used;
    struct bufferevent *bev;
    iWAuint32 server_seed;
    iWAint8 account[iWAmacro_AUTHSERVER_ACCOUNTNAME_LENGTH];
    iWAuint32 UID, CID;
    iWAuint8 key[iWAmacro_GAMESERVER_SEESION_KEY_SIZE];
    iWAuint16 key_size;
    iWAbool auth_pass;
    iWAuint8 send_i, send_j, recv_i, recv_j;
}iWAstruct_GameSession_Session;


extern iWAstruct_Mysql_Database *iWA_Global_DatabaseAccount;
extern iWAstruct_Mysql_Database *iWA_Global_DatabaseGame;


extern iWAuint32 iWA_Memory_Count(void);
extern void* iWA_Memory_Alloc(iWAuint32 size);
extern void iWA_Memory_Free(void* p);
extern void *iWA_Memory_Realloc(void *p, iWAuint32 size);      /*only match to mem.c of openssl, not be called really */

extern void iWA_Net_WritePacketUint16(iWAuint8 *packet, iWAuint16 data);
extern void iWA_Net_WritePacketUint32(iWAuint8 *packet, iWAuint32 data);
extern iWAuint16 iWA_Net_ReadPacketUint16(iWAuint8 *packet);
extern iWAuint32 iWA_Net_ReadPacketUint32(iWAuint8 *packet);
extern iWAuint32 iWA_Net_WritePacketBigNumber(iWAuint8 *packet, BIGNUM *bn);   /* return write byte num */
extern void iWA_Net_ReadPacketBigNumber(iWAuint8 *packet, iWAuint32 len, BIGNUM *bn);
extern iWAuint32 iWA_Net_ReadPacketAsciiString(iWAuint8 *packet, iWAuint8 *str_buf, iWAuint32 buf_size);  /* return packet read length, include tail '\0' */
extern void iWA_Auth_TestBn(void);


extern void iWA_Crypto_Sha1ResultBigNumber(SHA1Context *sha_ctx, BIGNUM *result);
extern void iWA_Crypto_Sha1Interleave(SHA1Context *sha_ctx, BIGNUM *result, BIGNUM *input);
extern void iWA_Crypto_Sha1InputBigNumber(SHA1Context *sha_ctx, BIGNUM *bn);
extern void iWA_Crypto_Sha1InputUint32(SHA1Context *sha_ctx, iWAuint32 i);
extern void iWA_Crypto_Sha1HashBigNumbers(SHA1Context *sha_ctx, BIGNUM *result, BIGNUM *bn0, ...);

#if 0
extern iWAbool iWA_AuthServer_Init(void);
extern void iWA_AuthServer_BuffereventReadCb(struct bufferevent *bev);
extern void iWA_AuthServer_HandlePacketQueue(void);
#endif
extern iWAint32 iWA_AuthServer_Main(void);


extern iWAstruct_Mysql_Database* iWA_Mysql_DatabaseNew(void);
extern iWAbool iWA_Mysql_DatabaseOpen(iWAstruct_Mysql_Database* db);
extern iWAbool iWA_Mysql_DatabaseQuery(iWAstruct_Mysql_Database* db, iWAint8* sql);
extern iWAstruct_Mysql_QueryResult* iWA_Mysql_DatabaseStoreResult(iWAstruct_Mysql_Database *db);
extern void iWA_Mysql_DatabaseFreeResult(iWAstruct_Mysql_QueryResult *result);
extern void iWA_Mysql_DatabaseNextRow(iWAstruct_Mysql_QueryResult *result);
extern iWAuint32 iWA_Mysql_DatabaseInsertId(iWAstruct_Mysql_Database *db);
extern void iWA_Mysql_DatabaseClose(iWAstruct_Mysql_Database* db);

extern iWAstruct_AuthSession_Session* iWA_AuthSession_AllocSession(struct bufferevent *bev);
extern void iWA_AuthSession_FreeSession(struct bufferevent *bev);
extern iWAstruct_AuthSession_Session* iWA_AuthSession_GetSession(struct bufferevent *bev);

extern iWAstruct_GameSession_Session* iWA_GameSession_AllocSession(struct bufferevent *bev);
extern void iWA_GameSession_FreeSession(struct bufferevent *bev);
extern iWAstruct_GameSession_Session* iWA_GameSession_GetSession(struct bufferevent *bev);


extern void iWA_Config_Init(iWAint8 *inifile);
extern iWAbool iWA_Config_GetString(iWAint8 *section, iWAint8 *key, iWAint8 *buf, iWAuint32 buf_len);
extern iWAbool iWA_Config_GetInteger(iWAint8 *section, iWAint8 *key, iWAint32 *value);

extern void iWA_Log_Init(void);
extern void iWA_Log_Trace(int priority, const char *fmt , ...);
extern void iWA_Log_TraceEx(const char *file, int line, const char *fun, int priority, const char *fmt , ...);
extern void iWA_Log_Dump(iWAuint8 *p, iWAint32 len);
extern void iWA_Log_Test(void);


#endif         /* __iWA_H__ */

