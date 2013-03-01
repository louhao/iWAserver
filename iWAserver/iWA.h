
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

#include "iwaserver.pb-c.h"




#define iWAmarco_MALLOC_DEBUG_OPTION             1

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
#define iWA_Std_strlen      strlen
#define iWA_Std_strcpy      strcpy
#define iWA_Std_strcmp      strcmp
#define iWA_Std_atoi          atoi 
#define iWA_Std_sprintf          sprintf 

enum
{
    iWAenum_AUTH_CMD_LOGON        = 0x00,
    iWAenum_AUTH_CMD_REG            = 0x01,
    iWAenum_AUTH_CMD_PROOF    = 0x02,
    iWAenum_AUTH_CMD_SERVER_LIST       = 0x03,
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
    iWAuint8     guid[8];
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

extern iWAstruct_Mysql_Database *iWA_Global_DatabaseAccount;



extern void iWA_Log(const iWAint8 *pszFormat, ...);
extern void iWA_Dump(iWAuint8 *p, iWAint32 len);
extern iWAuint32 iWA_MemCount(void);
extern void iWA_Mprint(void);
extern void* iWA_Malloc(iWAuint32 size);
extern void iWA_Free(void* p);
extern void *iWA_Realloc(void *p, iWAuint32 size);      /*only match to mem.c of openssl, not be called really */

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


extern iWAbool iWA_AuthServer_Init(void);
extern void iWA_AuthServer_BuffereventReadCb(struct bufferevent *bev);
extern void iWA_AuthServer_HandlePacketQueue(void);

extern iWAstruct_Mysql_Database* iWA_Mysql_DatabaseNew(void);
extern iWAbool iWA_Mysql_DatabaseOpen(iWAstruct_Mysql_Database* db);
extern iWAbool iWA_Mysql_DatabaseQuery(iWAstruct_Mysql_Database* db, iWAint8* sql);
extern iWAstruct_Mysql_QueryResult* iWA_Mysql_DatabaseStoreResult(iWAstruct_Mysql_Database *db);
extern void iWA_Mysql_DatabaseFreeResult(iWAstruct_Mysql_QueryResult *result);
extern void iWA_Mysql_DatabaseNextRow(iWAstruct_Mysql_QueryResult *result);
extern void iWA_Mysql_DatabaseClose(iWAstruct_Mysql_Database* db);

extern iWAint16 iWA_AuthSession_SessionNew(struct bufferevent *bev);
extern void iWA_AuthSession_SessionEnd(struct bufferevent *bev);
extern iWAint16 iWA_AuthSession_SessionId(struct bufferevent *bev);
extern struct bufferevent* iWA_AuthSession_SessionBev(iWAint16 id);


extern int iWA_Event_SendPacket(unsigned char *pkt, int len);



#endif         /* __iWA_H__ */

