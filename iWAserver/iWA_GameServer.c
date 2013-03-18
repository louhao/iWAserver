
#ifndef WIN32
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#include <sys/socket.h>
#endif


#include "iWA.h"


#define iWAmacro_GAMESERVER_LISTEN_PORT     (3728)
#define iWAmacro_GAMESERVER_LISTEN_BACKLOG  (32)

#define iWAmacro_GAMESERVER_PACKET_HEADER_SIZE    (4)


typedef struct
{
    void *next;
    iWAstruct_GameSession_Session* session;
    iWAuint16 type;
    iWAuint16 len;
    iWAuint8 data[4];
}iWAstruct_GameServer_Packet;

static struct event *timer_event;
static struct timeval timer_interval;

static iWAstruct_GameServer_Packet *packet_queue_header = NULL;
static iWAstruct_GameServer_Packet *packet_queue_tail = NULL;
static iWAuint8 send_packet_buf[1024];


static iWAbool server_init(void);
static void listen_event_cb(evutil_socket_t listener, iWAint16 event, void *arg);
static void timer_event_cb(iWAint32 fd, iWAint16 event, void *argc);
static void bufevent_read_cb(struct bufferevent *bev, void *arg);
static void bufevent_write_cb(struct bufferevent *bev, void *arg);
static void bufevent_error_cb(struct bufferevent *bev, iWAint16 event, void *arg);
static iWAbool write_data_bufferevent(iWAstruct_GameSession_Session *session, iWAuint8 *data, iWAuint32 len);
static void write_auth_chanllege_server_packet(iWAstruct_GameSession_Session *session);
static void handle_auth_session_client_packet(iWAstruct_GameServer_Packet *pkt);
static void handle_char_enum_client_packet(iWAstruct_GameServer_Packet *pkt);
static void handle_char_create_client_packet(iWAstruct_GameServer_Packet *pkt);
static void handle_char_delete_client_packet(iWAstruct_GameServer_Packet *pkt);
static void handle_player_login_client_packet(iWAstruct_GameServer_Packet *pkt);





static iWAbool check_packet_length(iWAstruct_GameSession_Session *session, iWAuint8* header, iWAuint32 length)
{
    iWAuint32 t;
    iWAuint8 x;
    iWAuint16 packet_len, packet_type;
    iWAuint8 recv_i, recv_j;
    iWAbool length_enough;

    iWA_Assert(session != NULL);
    iWA_Assert(header != NULL);

    iWA_Debug("check_packet_length()");

    if(session->auth_pass)
    {
    iWA_Dump(header, iWAmacro_GAMESERVER_PACKET_HEADER_SIZE);

        recv_i = session->recv_i;
        recv_j = session->recv_j;
        for(t = 0; t < iWAmacro_GAMESERVER_PACKET_HEADER_SIZE; t++)
        {
            recv_i %= session->key_size;
            x = (header[t] - recv_j) ^ session->key[recv_i];
            ++recv_i;
            recv_j = header[t];
            header[t] = x;
        
        }

    iWA_Dump(header, iWAmacro_GAMESERVER_PACKET_HEADER_SIZE);
    }
    

    packet_len = iWA_Net_ReadPacketUint16(header);
    length_enough = (length >= (packet_len + iWAmacro_GAMESERVER_PACKET_HEADER_SIZE));

    if(session->auth_pass && length_enough)
    {
        session->recv_i = recv_i;
        session->recv_j = recv_j;
    }

    return length_enough;
}



static void encrypt_packet_header(iWAstruct_GameSession_Session *session, iWAuint8* header)
{
    iWAuint32 t;
    iWAuint8 x;

    iWA_Assert(session != NULL);
    iWA_Assert(header != NULL);
    
    iWA_Debug("encrypt_packet_header()");
    iWA_Dump(header, iWAmacro_GAMESERVER_PACKET_HEADER_SIZE);

    for(t = 0; t < iWAmacro_GAMESERVER_PACKET_HEADER_SIZE; t++)
    {
        session->send_i %= session->key_size;
        x = (header[t] ^ session->key[session->send_i]) + session->send_j;
        ++session->send_i;
        header[t] = session->send_j = x;
    }

    iWA_Dump(header, iWAmacro_GAMESERVER_PACKET_HEADER_SIZE);
}


static iWAbool write_data_bufferevent(iWAstruct_GameSession_Session *session, iWAuint8 *data, iWAuint32 len)
{
    iWA_Info("write_data_bufferevent()");

    iWA_Assert(session != NULL);
    iWA_Assert(data != NULL);

    return !bufferevent_write(session->bev, data, len);
}

static void write_auth_chanllege_server_packet(iWAstruct_GameSession_Session *session)
{
    IWAserverGame__AuthChallengeServer chan;
    BIGNUM  ss;
    iWAuint8 buf[4];
    iWAint32 len;

    iWA_Info("write_auth_chanllege_server_packet()");

    iWA_Assert(session != NULL);

    BN_init(&ss);
    BN_rand(&ss, 4*8, 0, 1);
    iWA_Net_WritePacketBigNumber(buf, &ss);
    session->server_seed = iWA_Net_ReadPacketUint32(buf);

    i_waserver_game__auth_challenge_server__init(&chan);
    chan.seed = session->server_seed;
    len = i_waserver_game__auth_challenge_server__pack(&chan, send_packet_buf+4);
    iWA_Net_WritePacketUint16(send_packet_buf, len);
    iWA_Net_WritePacketUint16(send_packet_buf+2, iWAenum_GAME_CMD_AUTH_CHANLLEGE);

    write_data_bufferevent(session, send_packet_buf, len+4);
}


static void handle_auth_session_client_packet(iWAstruct_GameServer_Packet *pkt)
{
    IWAserverGame__AuthSessionClient *sess;
    IWAserverGame__AuthResponseServer rsp;
    iWAstruct_GameSession_Session* session;
    iWAstruct_Mysql_QueryResult *result = NULL;
    SHA1Context *sha_ctx;
    iWAint32 len;
    iWAint8 sql[100];
    iWAint32 reval = I_WASERVER_GAME__RESULT_CODE__UNKNOWN_ERROR;
    BIGNUM K, D, *I;
    iWAuint8 digest[SHA1HashSize+1];
    
    iWA_Info("handle_auth_session_client_packet()");

    session = pkt->session;
    session->auth_pass = 0;

    /* unpack message */
    sess = i_waserver_game__auth_session_client__unpack(NULL, pkt->len, pkt->data);
    if(sess == NULL)
    {
        reval = I_WASERVER_GAME__RESULT_CODE__UNPACK_MESSAGE_ERROR;
        goto do_response_and_free;
    }
    
    /* record account name */
    iWA_Std_strcpy(session->account, sess->username);

    /* query seesion-key from account-db */
    iWA_Std_sprintf(sql, "select UID, sessionkey from users where username = '%s';", sess->username);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, sql))
    {
        reval = I_WASERVER_GAME__RESULT_CODE__AUTH_RESPONSE_DB_QUERY_ERROR;    
        goto do_response_and_free;
    }
    
    result = iWA_Mysql_DatabaseStoreResult(iWA_Global_DatabaseAccount);
    if(result == NULL)
    {
        reval = I_WASERVER_GAME__RESULT_CODE__AUTH_RESPONSE_DB_QUERY_ERROR;
        goto do_response_and_free;
    }
    if(result->row == NULL)     
    {
        reval = I_WASERVER_GAME__RESULT_CODE__AUTH_RESPONSE_ACCOUNT_NOEXIST;
        goto do_response_and_free;
    }
    
    /* record UID, session-key */
    I = &K;
    BN_init(&K);
    BN_hex2bn(&I, result->row[1]);
    session->key_size = iWA_Net_WritePacketBigNumber(session->key, &K);
    session->UID = iWA_Std_atoi(result->row[0]);

    /* calculate hash value D = Hash(account, 0, client_seed, server_seed, K) */
    BN_init(&D);
    sha_ctx = (SHA1Context*)iWA_Malloc(sizeof(SHA1Context));
    SHA1Reset(sha_ctx);
    SHA1Input(sha_ctx, session->account, iWA_Std_strlen(session->account));  
    iWA_Crypto_Sha1InputUint32(sha_ctx, 0);  /* input t=0 */
    iWA_Crypto_Sha1InputUint32(sha_ctx, sess->seed);  
    iWA_Crypto_Sha1InputUint32(sha_ctx, session->server_seed);  
    iWA_Crypto_Sha1InputBigNumber(sha_ctx, &K);  
    iWA_Crypto_Sha1ResultBigNumber(sha_ctx, &D);

    iWA_Net_WritePacketBigNumber(digest, &D);

    /* compare D value */
    if(!iWA_Std_memcmp(digest, sess->d.data, SHA1HashSize))
    {
        session->auth_pass = 1;
        reval = I_WASERVER_GAME__RESULT_CODE__SUCCESS;
    }
    else
    {
        reval = I_WASERVER_GAME__RESULT_CODE__AUTH_RESPONSE_HASH_CHECK_ERROR;
    }
    
do_response_and_free:

    /* write response packet */
    i_waserver_game__auth_response_server__init(&rsp);
    rsp.result = reval;
    len = i_waserver_game__auth_response_server__pack(&rsp, send_packet_buf+4);
    iWA_Net_WritePacketUint16(send_packet_buf, len);
    iWA_Net_WritePacketUint16(send_packet_buf+2, iWAenum_GAME_CMD_AUTH_RESPONSE);
    write_data_bufferevent(session, send_packet_buf, len+4);

    /* do free */
    if(sess != NULL)    i_waserver_game__auth_session_client__free_unpacked(sess, NULL);
    if(result != NULL)  iWA_Mysql_DatabaseFreeResult(result);
}


static void handle_char_enum_client_packet(iWAstruct_GameServer_Packet *pkt)
{
    iWAstruct_GameSession_Session* session;
    iWAint8 sql[100];
    iWAstruct_Mysql_QueryResult *result = NULL;
    iWAint8 **row;
    IWAserverGame__CharEnumServer   char_enum;
    IWAserverGame__Character *chr;
    iWAuint32 i, len = 0;

    
    iWA_Info("handle_char_enum_client_packet()");

    session = pkt->session;

    /* init iWAstruct_GameSession_Session */
    i_waserver_game__char_enum_server__init(&char_enum);
    char_enum.n_characters = 0;

    /* query character info */
    iWA_Std_sprintf(sql, "select CID, name, grade, race, nation from characters where UID = %d;", session->UID);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseGame, sql))   goto do_response_and_free;

    result = iWA_Mysql_DatabaseStoreResult(iWA_Global_DatabaseGame);
    if(result == NULL)   goto do_response_and_free;

    /* fill character info */
    if(result->num > 0) 
        char_enum.characters = (IWAserverGame__Character**)iWA_Malloc(sizeof(IWAserverGame__Character*) * (result->num));

    while(result->row)
    {
        row = result->row;
        chr = (IWAserverGame__Character*)iWA_Malloc(sizeof(IWAserverGame__Character));

        i_waserver_game__character__init(chr);
        chr->cid = iWA_Std_atoi(row[0]);
        chr->name = row[1];
        chr->grade = iWA_Std_atoi(row[2]);
        chr->race = iWA_Std_atoi(row[3]);
        chr->nation = iWA_Std_atoi(row[4]);

        char_enum.characters[char_enum.n_characters++] = chr;
        iWA_Mysql_DatabaseNextRow(result);
    }

    char_enum.char_num = char_enum.n_characters;

do_response_and_free:

    /* write response packet */
    len = i_waserver_game__char_enum_server__pack(&char_enum, send_packet_buf+4);
    iWA_Net_WritePacketUint16(send_packet_buf, len);
    iWA_Net_WritePacketUint16(send_packet_buf+2, iWAenum_GAME_CMD_CHAR_ENUM);
    encrypt_packet_header(session, send_packet_buf);
    write_data_bufferevent(session, send_packet_buf, len+4);

    /* free sql result */
    if(result != NULL)  iWA_Mysql_DatabaseFreeResult(result);

    /* free IWAserverGame__Character */
    if(char_enum.characters != NULL)
    {
        for(i = 0; i < char_enum.n_characters; i++)
        {
            if(char_enum.characters[i] != NULL)    iWA_Free((void*)char_enum.characters[i]);
        }

        iWA_Free((void*)char_enum.characters);
    }
}

static void handle_char_create_client_packet(iWAstruct_GameServer_Packet *pkt)
{
    IWAserverGame__CharCreateClient *char_create;
    IWAserverGame__CharCreateServer rsp;
    iWAstruct_GameSession_Session* session;
    iWAuint32 insert_id;
    iWAint32 len;
    iWAint8 sql[100];
    iWAint32 reval = I_WASERVER_GAME__RESULT_CODE__UNKNOWN_ERROR;
    
    iWA_Info("handle_char_create_client_packet()");

    session = pkt->session;

    /* unpack message */
    char_create = i_waserver_game__char_create_client__unpack(NULL, pkt->len, pkt->data);
    if(char_create == NULL)
    {
        reval = I_WASERVER_GAME__RESULT_CODE__UNPACK_MESSAGE_ERROR;
        goto do_response_and_free;
    }

    if(char_create->name == NULL || char_create->name[0] == 0x00)
    {
        reval = I_WASERVER_GAME__RESULT_CODE__CHAR_CREATE_ILLEGAL_NAME;
        goto do_response_and_free;
    }
    
    /* insert character into game-db */
    iWA_Std_sprintf(sql, "insert into characters (UID, name, grade, race, nation) values (%d, '%s', %d, %d, %d);", 
                            session->UID, char_create->name, 1, char_create->race, char_create->nation);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseGame, sql))
    {
        reval = I_WASERVER_GAME__RESULT_CODE__CHAR_CREATE_DB_INSERT_ERROR;
        goto do_response_and_free;
    }
    
    insert_id = iWA_Mysql_DatabaseInsertId(iWA_Global_DatabaseGame);
    if(insert_id == 0)
    {
        reval = I_WASERVER_GAME__RESULT_CODE__CHAR_CREATE_DB_INSERT_ERROR;
        goto do_response_and_free;
    }

    reval = I_WASERVER_GAME__RESULT_CODE__SUCCESS;
    
do_response_and_free:

    /* write response packet */
    i_waserver_game__char_create_server__init(&rsp);
    rsp.result = reval;
    rsp.cid = insert_id;
    len = i_waserver_game__char_create_server__pack(&rsp, send_packet_buf+4);
    iWA_Net_WritePacketUint16(send_packet_buf, len);
    iWA_Net_WritePacketUint16(send_packet_buf+2, iWAenum_GAME_CMD_CHAR_CREATE);
    encrypt_packet_header(session, send_packet_buf);
    write_data_bufferevent(session, send_packet_buf, len+4);

    /* do free */
    if(char_create!= NULL)    i_waserver_game__char_create_client__free_unpacked(char_create, NULL);
}

static void handle_char_delete_client_packet(iWAstruct_GameServer_Packet *pkt)
{
    IWAserverGame__CharDeleteClient *char_delete;
    IWAserverGame__CharDeleteServer rsp;
    iWAstruct_GameSession_Session* session;
    iWAint32 len;
    iWAint8 sql[100];
    iWAint32 reval = I_WASERVER_GAME__RESULT_CODE__UNKNOWN_ERROR;
    
    iWA_Info("handle_char_delete_client_packet()");

    session = pkt->session;

    /* unpack message */
    char_delete = i_waserver_game__char_delete_client__unpack(NULL, pkt->len, pkt->data);
    if(char_delete == NULL)
    {
        reval = I_WASERVER_GAME__RESULT_CODE__UNPACK_MESSAGE_ERROR;
        goto do_response_and_free;
    }
    
    /* delete character from game-db */
    iWA_Std_sprintf(sql, "delete from characters where CID = %d;", char_delete->cid);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseGame, sql))
    {
        reval = I_WASERVER_GAME__RESULT_CODE__CHAR_DELETE_DB_DELETE_ERROR;
        goto do_response_and_free;
    }

    reval = I_WASERVER_GAME__RESULT_CODE__SUCCESS;
    
do_response_and_free:

    /* write response packet */
    i_waserver_game__char_delete_server__init(&rsp);
    rsp.result = reval;
    len = i_waserver_game__char_delete_server__pack(&rsp, send_packet_buf+4);
    iWA_Net_WritePacketUint16(send_packet_buf, len);
    iWA_Net_WritePacketUint16(send_packet_buf+2, iWAenum_GAME_CMD_CHAR_DELETE);
    encrypt_packet_header(session, send_packet_buf);
    write_data_bufferevent(session, send_packet_buf, len+4);

    /* do free */
    if(char_delete!= NULL)    i_waserver_game__char_delete_client__free_unpacked(char_delete, NULL);
}

static void handle_player_login_client_packet(iWAstruct_GameServer_Packet *pkt)
{
    IWAserverGame__PlayerLoginClient *player_login;
    iWAstruct_GameSession_Session* session;
    
    iWA_Info("handle_player_login_client_packet()");

    session = pkt->session;

    /* unpack message */
    player_login = i_waserver_game__player_login_client__unpack(NULL, pkt->len, pkt->data);
    if(player_login == NULL)    return;

    pkt->session->CID = player_login->cid;

    i_waserver_game__player_login_client__free_unpacked(player_login, NULL);
}

static iWAbool server_init(void)
{

    iWA_Log_Init();

    iWA_Info("server_init()");

    /* set gameserver.ini filename */
    iWA_Config_Init(iWAmacro_CONFIG_GAMESERVER_INI_FILENAME);

    /* init AccountDB connection */
    iWA_Global_DatabaseAccount = iWA_Mysql_DatabaseNew();

    if(!iWA_Config_GetString("AccountDB", "AccountDBServerHost", iWA_Global_DatabaseAccount->host, iWAmacro_MYSQL_HOST_LENGTH_MAX))
        iWA_Std_strcpy(iWA_Global_DatabaseAccount->host, iWAmacro_CONFIG_ACCOUNT_DB_SERVER_HOST_DEFAULT);

    if(!iWA_Config_GetInteger("AccountDB", "AccountDBServerPort", &iWA_Global_DatabaseAccount->port))
        iWA_Global_DatabaseAccount->port = iWAmacro_CONFIG_ACCOUNT_DB_SERVER_PORT_DEFAULT;

    if(!iWA_Config_GetString("AccountDB", "AccountDBServerUsername", iWA_Global_DatabaseAccount->user, iWAmacro_MYSQL_USER_LENGTH_MAX))
        iWA_Std_strcpy(iWA_Global_DatabaseAccount->user, iWAmacro_CONFIG_ACCOUNT_DB_SERVER_USERNAME_DEFAULT);

    if(!iWA_Config_GetString("AccountDB", "AccountDBServerPassword", iWA_Global_DatabaseAccount->pwd, iWAmacro_MYSQL_PWD_LENGTH_MAX))
        iWA_Std_strcpy(iWA_Global_DatabaseAccount->pwd, iWAmacro_CONFIG_ACCOUNT_DB_SERVER_PASSWORD_DEFAULT);    

    if(!iWA_Config_GetString("AccountDB", "AccountDBName", iWA_Global_DatabaseAccount->name, iWAmacro_MYSQL_DBNAME_LENGTH_MAX))
        iWA_Std_strcpy(iWA_Global_DatabaseAccount->name, iWAmacro_CONFIG_ACCOUNT_DB_NAME_DEFAULT);

    if(!iWA_Mysql_DatabaseOpen(iWA_Global_DatabaseAccount))
    {
        iWA_Error("open iWA_Global_DatabaseAccount error");
        return 0;
    }
    
    /* init GameDB connection */
    iWA_Global_DatabaseGame = iWA_Mysql_DatabaseNew();

    if(!iWA_Config_GetString("GameDB", "GameDBServerHost", iWA_Global_DatabaseGame->host, iWAmacro_MYSQL_HOST_LENGTH_MAX))
        iWA_Std_strcpy(iWA_Global_DatabaseGame->host, iWAmacro_CONFIG_GAME_DB_SERVER_HOST_DEFAULT);

    if(!iWA_Config_GetInteger("GameDB", "GameDBServerPort", &iWA_Global_DatabaseGame->port))
        iWA_Global_DatabaseGame->port = iWAmacro_CONFIG_GAME_DB_SERVER_PORT_DEFAULT;

    if(!iWA_Config_GetString("GameDB", "GameDBServerUsername", iWA_Global_DatabaseGame->user, iWAmacro_MYSQL_USER_LENGTH_MAX))
        iWA_Std_strcpy(iWA_Global_DatabaseGame->user, iWAmacro_CONFIG_GAME_DB_SERVER_USERNAME_DEFAULT);

    if(!iWA_Config_GetString("GameDB", "GameDBServerPassword", iWA_Global_DatabaseGame->pwd, iWAmacro_MYSQL_PWD_LENGTH_MAX))
        iWA_Std_strcpy(iWA_Global_DatabaseGame->pwd, iWAmacro_CONFIG_GAME_DB_SERVER_PASSWORD_DEFAULT);    

    if(!iWA_Config_GetString("GameDB", "GameDBName", iWA_Global_DatabaseGame->name, iWAmacro_MYSQL_DBNAME_LENGTH_MAX))
        iWA_Std_strcpy(iWA_Global_DatabaseGame->name, iWAmacro_CONFIG_GAME_DB_NAME_DEFAULT);
    
    if(!iWA_Mysql_DatabaseOpen(iWA_Global_DatabaseGame))
    {
        iWA_Error("open iWA_Global_DatabaseGame error");
        return 0;
    }
    
    return 1;
}


static void listen_event_cb(evutil_socket_t listener, iWAint16 event, void *arg)
{
    struct event_base *base = (struct event_base *)arg;
    evutil_socket_t fd;
    struct sockaddr_in sin;
    iWAint32 slen;
    struct bufferevent *bev;
    iWAstruct_GameSession_Session *sess;

    iWA_Info("listen_event_cb()");
    
    fd = accept(listener, (struct sockaddr *)&sin, &slen);

    if (fd < 0) 
    {
        iWA_Error("accept() fd < 0");
        return;
    }
    
    if (fd > FD_SETSIZE) {
        iWA_Error("accept() fd > FD_SETSIZE");
        return;
    }
    
    iWA_Info("ACCEPT: fd = %u\n", fd);
    
    bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if(bev == NULL)
    {
        iWA_Error("bufferevent_socket_new() error");
        return;
    }
    
    bufferevent_setcb(bev, bufevent_read_cb, bufevent_write_cb, bufevent_error_cb, arg);
    bufferevent_enable(bev, EV_READ|EV_WRITE|EV_PERSIST);

    sess = iWA_GameSession_AllocSession(bev);
    if(sess != NULL)    write_auth_chanllege_server_packet(sess);
}

static void timer_event_cb(iWAint32 fd, iWAint16 event, void *argc)
{
    iWAstruct_GameServer_Packet *pkt;

    while(packet_queue_header != NULL)
    {
        pkt = packet_queue_header;

        iWA_Assert(pkt->session != NULL);

        if(pkt->type == iWAenum_GAME_CMD_AUTH_SEESION || pkt->session->auth_pass)  
        {
            switch(pkt->type)
            {
                case iWAenum_GAME_CMD_AUTH_SEESION:
                    handle_auth_session_client_packet(pkt);
                    break;                
                case iWAenum_GAME_CMD_CHAR_ENUM:
                    handle_char_enum_client_packet(pkt);
                    break;         
                case iWAenum_GAME_CMD_CHAR_CREATE:
                    handle_char_create_client_packet(pkt);
                    break;
                case iWAenum_GAME_CMD_CHAR_DELETE:
                    handle_char_delete_client_packet(pkt);
                    break;
                case iWAenum_GAME_CMD_PLAYER_LOGIN:
                    handle_player_login_client_packet(pkt);
                    break;
                default:
                    iWA_Warn("unkonwn type packet");
                    break;
            }
        }
        
        packet_queue_header = pkt->next;
        iWA_Free(pkt);
        if(packet_queue_header == NULL)     packet_queue_tail = NULL;
    }

    event_add(timer_event, &timer_interval);
}



static void bufevent_read_cb(struct bufferevent *bev, void *arg)
{
    iWAuint8 header[iWAmacro_GAMESERVER_PACKET_HEADER_SIZE];
    struct evbuffer *evb;
    iWAuint32 evb_len;
    iWAuint16 packet_len, packet_type;
    iWAstruct_GameServer_Packet *packet;
    iWAstruct_GameSession_Session* session;

    iWA_Info("bufevent_read_cb()");

    if(bev == NULL)
    {
        iWA_Error("bufevent_read_cb() : bev==NULL");
        return;
    }

    evb = bufferevent_get_input(bev);
    if(evb == NULL)     
    {
        iWA_Error("bufferevent_get_input() error");
        return;
    }

    evb_len = evbuffer_get_length(evb);
    if(evb_len < iWAmacro_GAMESERVER_PACKET_HEADER_SIZE)    return;
    if(evbuffer_copyout(evb, header, iWAmacro_GAMESERVER_PACKET_HEADER_SIZE) < iWAmacro_GAMESERVER_PACKET_HEADER_SIZE)  return;

    session = iWA_GameSession_GetSession(bev);
    if(session == NULL)
    {
        iWA_Error("iWA_GameSession_GetSession() return NULL");
        return;
    }
    
    if(!check_packet_length(session, header, evb_len))   return;

    packet_len = iWA_Net_ReadPacketUint16(header);
    packet_type = iWA_Net_ReadPacketUint16(header+2);

    packet = (iWAstruct_GameServer_Packet*)iWA_Malloc(packet_len <= 4 ? sizeof(iWAstruct_GameServer_Packet) : sizeof(iWAstruct_GameServer_Packet) + packet_len - 4);
    packet->next = NULL;
    packet->session = session;
    packet->len = packet_len;
    packet->type = packet_type;

    if(evbuffer_drain(evb, iWAmacro_GAMESERVER_PACKET_HEADER_SIZE) < 0)     return;
    if(evbuffer_remove(evb, packet->data, packet_len) != packet_len)    return;

    iWA_Info("extract packet, type=0x%02x", packet_type);

    if(packet_queue_header == NULL)
        packet_queue_header = packet;
    else
        packet_queue_tail->next = packet;
        
    packet_queue_tail = packet;
}

static void bufevent_write_cb(struct bufferevent *bev, void *arg)  
{
    iWA_Info("bufevent_write_cb()");
}

static void bufevent_error_cb(struct bufferevent *bev, iWAint16 event, void *arg)
{
    evutil_socket_t fd = bufferevent_getfd(bev);
    
    iWA_Info("bufevent_error_cb()");
    
    if (event & BEV_EVENT_TIMEOUT) 
    {
        iWA_Info("Timed out"); //if bufferevent_set_timeouts() called
    }
    else if (event & BEV_EVENT_EOF) 
    {
        iWA_Info("connection closed");
    }
    else if (event & BEV_EVENT_ERROR) 
    {
        iWA_Info("some other error");
    }
    
    bufferevent_free(bev);

    iWA_GameSession_FreeSession(bev);
}


iWAint32 iWA_GameServer_Main(void)
{
    evutil_socket_t listener;
    struct sockaddr_in sin;
    struct event_base *base;
    struct event *listen_event;

#ifdef WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    if(!server_init())  iWA_Fatal("server_init error");

    iWA_Info("iWA_GameServer_Main()");

    listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener > 0);
    evutil_make_listen_socket_reuseable(listener);


    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(iWAmacro_GAMESERVER_LISTEN_PORT);

    if (bind(listener, (struct sockaddr *)&sin, sizeof(sin)) < 0)   iWA_Fatal("socket bind error");

    if (listen(listener, iWAmacro_GAMESERVER_LISTEN_BACKLOG) < 0)    iWA_Fatal("socket listen error");

    iWA_Notice("GameServer Listening ...");

    evutil_make_socket_nonblocking(listener);

    base = event_base_new();
    if(base == NULL)    iWA_Fatal("event_base_new error");

    listen_event = event_new(base, listener, EV_READ|EV_PERSIST, listen_event_cb, (void*)base);
    if(listen_event == NULL)    iWA_Fatal("new listen_event error");
    event_add(listen_event, NULL);

    timer_interval.tv_sec=5; 
    timer_interval.tv_usec=0;
    timer_event = event_new(base, -1, 0, timer_event_cb, NULL);
    if(timer_event == NULL)  iWA_Fatal("new timer_event error");
    event_add(timer_event, &timer_interval);
    
    event_base_dispatch(base);

    iWA_Notice("GameServer End");
    
    return 0;
}


