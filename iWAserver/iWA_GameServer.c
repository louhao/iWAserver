
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



typedef struct
{
    iWAuint32 SID;
    pthread_t  thread;
    struct event *timer_event;
    struct timeval timer_interval;
    iWAstruct_GameServer_Packet *packet_queue_header;
    iWAstruct_GameServer_Packet *packet_queue_tail;
    iWAuint8 send_packet_buf[1024];
}iWAstruct_GameServer_InfoBlock;

static iWAstruct_GameServer_InfoBlock server_info_block = {0};

#if 0
static struct event *timer_event;
static struct timeval timer_interval;

static iWAstruct_GameServer_Packet *packet_queue_header = NULL;
static iWAstruct_GameServer_Packet *packet_queue_tail = NULL;
static iWAuint8 send_packet_buf[1024];
#endif

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

    //iWA_Debug("check_packet_length()");

    if(session->status == iWAenum_GAMESERVER_SESSION_STATUS_AUTHED)
    {
    //iWA_Dump(header, iWAmacro_GAMESERVER_PACKET_HEADER_SIZE);

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

    //iWA_Dump(header, iWAmacro_GAMESERVER_PACKET_HEADER_SIZE);
    }
    

    packet_len = iWA_Net_ReadPacketUint16(header);
    length_enough = (length >= (packet_len + iWAmacro_GAMESERVER_PACKET_HEADER_SIZE));

    if(session->status == iWAenum_GAMESERVER_SESSION_STATUS_AUTHED && length_enough)
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
    
    //iWA_Debug("encrypt_packet_header()");
    //iWA_Dump(header, iWAmacro_GAMESERVER_PACKET_HEADER_SIZE);

    for(t = 0; t < iWAmacro_GAMESERVER_PACKET_HEADER_SIZE; t++)
    {
        session->send_i %= session->key_size;
        x = (header[t] ^ session->key[session->send_i]) + session->send_j;
        ++session->send_i;
        header[t] = session->send_j = x;
    }

    //iWA_Dump(header, iWAmacro_GAMESERVER_PACKET_HEADER_SIZE);
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
    iWAuint8 *pkg = server_info_block.send_packet_buf;

    iWA_Info("write_auth_chanllege_server_packet()");

    iWA_Assert(session != NULL);

    BN_init(&ss);
    BN_rand(&ss, 4*8, 0, 1);
    iWA_Net_WritePacketBigNumber(buf, &ss);
    session->server_seed = iWA_Net_ReadPacketUint32(buf);

    i_waserver_game__auth_challenge_server__init(&chan);
    chan.seed = session->server_seed;
    len = i_waserver_game__auth_challenge_server__pack(&chan, pkg+4);
    iWA_Net_WritePacketUint16(pkg, len);
    iWA_Net_WritePacketUint16(pkg+2, iWAenum_GAME_CMD_AUTH_CHANLLEGE);

    write_data_bufferevent(session, pkg, len+4);
}


static void handle_auth_session_client_packet(iWAstruct_GameServer_Packet *pkt)
{
    IWAserverGame__AuthSessionClient *sess;
    IWAserverGame__AuthResponseServer rsp;
    iWAstruct_GameSession_Session* session;
    iWAstruct_Mysql_QueryResult *result = NULL;
    SHA1Context *sha_ctx;
    iWAint32 len;
    iWAint32 reval = I_WASERVER_GAME__RESULT_CODE__UNKNOWN_ERROR;
    BIGNUM K, D, *I;
    iWAuint8 digest[SHA1HashSize+1];
    iWAuint8 *pkg = server_info_block.send_packet_buf;
    
    iWA_Info("handle_auth_session_client_packet()");

    session = pkt->session;
    session->status = iWAenum_GAMESERVER_SESSION_STATUS_UNAUTH;

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
    iWA_Std_sprintf(session->sql, "select UID, sessionkey from users where username = '%s';", sess->username);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, session->sql))
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
        reval = I_WASERVER_GAME__RESULT_CODE__SUCCESS;
        session->status = iWAenum_GAMESERVER_SESSION_STATUS_AUTHED;
    }
    else
    {
        reval = I_WASERVER_GAME__RESULT_CODE__AUTH_RESPONSE_HASH_CHECK_ERROR;
    }
    
do_response_and_free:

    /* write response packet */
    i_waserver_game__auth_response_server__init(&rsp);
    rsp.result = reval;
    len = i_waserver_game__auth_response_server__pack(&rsp, pkg+4);
    iWA_Net_WritePacketUint16(pkg, len);
    iWA_Net_WritePacketUint16(pkg+2, iWAenum_GAME_CMD_AUTH_RESPONSE);
    write_data_bufferevent(session, pkg, len+4);

    /* do free */
    if(sess != NULL)    i_waserver_game__auth_session_client__free_unpacked(sess, NULL);
    if(result != NULL)  iWA_Mysql_DatabaseFreeResult(result);
}


static void handle_char_enum_client_packet(iWAstruct_GameServer_Packet *pkt)
{
    iWAstruct_GameSession_Session* session;
    iWAstruct_Mysql_QueryResult *result = NULL;
    iWAint8 **row;
    IWAserverGame__CharEnumServer   char_enum;
    IWAserverGame__Character *chr;
    iWAuint32 i, len = 0;
    iWAuint8 *pkg = server_info_block.send_packet_buf;
    iWAint32 reval = I_WASERVER_GAME__RESULT_CODE__UNKNOWN_ERROR;

    
    iWA_Info("handle_char_enum_client_packet()");

    session = pkt->session;

    /* init iWAstruct_GameSession_Session */
    i_waserver_game__char_enum_server__init(&char_enum);

    /* query character info */
    iWA_Std_sprintf(session->sql, "select CID, name, grade, race, nation from characters where UID = %d;", session->UID);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseGame, session->sql))
    {
        reval = I_WASERVER_GAME__RESULT_CODE__CHAR_ENUM_DB_QUERY_ERROR;
        goto do_response_and_free;
    }
    
    result = iWA_Mysql_DatabaseStoreResult(iWA_Global_DatabaseGame);
    if(result == NULL)
    {
        reval = I_WASERVER_GAME__RESULT_CODE__CHAR_ENUM_DB_QUERY_ERROR;
        goto do_response_and_free;
    }
    
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

    reval = I_WASERVER_GAME__RESULT_CODE__SUCCESS;

do_response_and_free:

    /* write response packet */
    char_enum.result = reval;
    len = i_waserver_game__char_enum_server__pack(&char_enum, pkg+4);
    iWA_Net_WritePacketUint16(pkg, len);
    iWA_Net_WritePacketUint16(pkg+2, iWAenum_GAME_CMD_CHAR_ENUM);
    encrypt_packet_header(session, pkg);
    write_data_bufferevent(session, pkg, len+4);

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
    iWAint32 reval = I_WASERVER_GAME__RESULT_CODE__UNKNOWN_ERROR;
    iWAuint8 *pkg = server_info_block.send_packet_buf;
    iWAstruct_Mysql_QueryResult *result = NULL;

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
        reval = I_WASERVER_GAME__RESULT_CODE__CHAR_CREATE_NAME_EMPTY;
        goto do_response_and_free;
    }

    /* check if character name already exists */
    iWA_Std_sprintf(session->sql, "select CID from characters where name = '%s';", char_create->name);

    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseGame, session->sql))
    {
        reval = I_WASERVER_GAME__RESULT_CODE__CHAR_CREATE_DB_QUERY_ERROR;
        goto do_response_and_free;
    }

    result = iWA_Mysql_DatabaseStoreResult(iWA_Global_DatabaseGame);
    if(result == NULL)
    {
        reval = I_WASERVER_GAME__RESULT_CODE__CHAR_CREATE_DB_QUERY_ERROR;
        goto do_response_and_free;
    }
    if(result->num > 0)
    {
        reval = I_WASERVER_GAME__RESULT_CODE__CHAR_CREATE_NAME_ALREADY_EXISTS;
        goto do_response_and_free;
    }    
    
    /* insert character into game-db */
    iWA_Std_sprintf(session->sql, "insert into characters (UID, name, grade, race, nation) values (%d, '%s', %d, %d, %d);", 
                            session->UID, char_create->name, 1, char_create->race, char_create->nation);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseGame, session->sql))
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

    /* insert character into account-db */
    iWA_Std_sprintf(session->sql, "insert into characters (SID, UID, CID, name, grade, race, nation) values (%d, %d, %d, '%s', %d, %d, %d);", 
                            server_info_block.SID, session->UID, insert_id, char_create->name, 1, char_create->race, char_create->nation);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, session->sql))
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
    len = i_waserver_game__char_create_server__pack(&rsp, pkg+4);
    iWA_Net_WritePacketUint16(pkg, len);
    iWA_Net_WritePacketUint16(pkg+2, iWAenum_GAME_CMD_CHAR_CREATE);
    encrypt_packet_header(session, pkg);
    write_data_bufferevent(session, pkg, len+4);

    /* do free */
    if(char_create!= NULL)    i_waserver_game__char_create_client__free_unpacked(char_create, NULL);
    if(result != NULL)  iWA_Mysql_DatabaseFreeResult(result);
}

static void handle_char_delete_client_packet(iWAstruct_GameServer_Packet *pkt)
{
    IWAserverGame__CharDeleteClient *char_delete;
    IWAserverGame__CharDeleteServer rsp;
    iWAstruct_GameSession_Session* session;
    iWAint32 len;
    iWAint32 reval = I_WASERVER_GAME__RESULT_CODE__UNKNOWN_ERROR;
    iWAuint8 *pkg = server_info_block.send_packet_buf;
    
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
    iWA_Std_sprintf(session->sql, "delete from characters where CID = %d;", char_delete->cid);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseGame, session->sql))
    {
        reval = I_WASERVER_GAME__RESULT_CODE__CHAR_DELETE_DB_DELETE_ERROR;
        goto do_response_and_free;
    }

    /* delete character from account-db */
    iWA_Std_sprintf(session->sql, "delete from characters where SID = %d and UID = %d and CID = %d;", server_info_block.SID, session->UID, char_delete->cid);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, session->sql))
    {
        reval = I_WASERVER_GAME__RESULT_CODE__CHAR_DELETE_DB_DELETE_ERROR;
        goto do_response_and_free;
    }
    

    reval = I_WASERVER_GAME__RESULT_CODE__SUCCESS;
    
do_response_and_free:

    /* write response packet */
    i_waserver_game__char_delete_server__init(&rsp);
    rsp.result = reval;
    len = i_waserver_game__char_delete_server__pack(&rsp, pkg+4);
    iWA_Net_WritePacketUint16(pkg, len);
    iWA_Net_WritePacketUint16(pkg+2, iWAenum_GAME_CMD_CHAR_DELETE);
    encrypt_packet_header(session, pkg);
    write_data_bufferevent(session, pkg, len+4);

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
    iWAstruct_Mysql_QueryResult *result;

    iWA_Info("game server init");

    /* query server info */
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseGame, "select SID from server_info;"))
    {
        iWA_Error("query server info error");
        return 0;
    }

    result = iWA_Mysql_DatabaseStoreResult(iWA_Global_DatabaseGame);
    if(result == NULL)
    {
        iWA_Error("server info is NULL");
        return 0;
    }
    
    server_info_block.SID = iWA_Std_atoi(result->row[0]);
    
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

    while(server_info_block.packet_queue_header != NULL)
    {
        pkt = server_info_block.packet_queue_header;

        iWA_Assert(pkt->session != NULL);

        if(pkt->type == iWAenum_GAME_CMD_AUTH_SEESION || pkt->session->status == iWAenum_GAMESERVER_SESSION_STATUS_AUTHED)  
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
        
        server_info_block.packet_queue_header = pkt->next;
        iWA_Free(pkt);
        if(server_info_block.packet_queue_header == NULL)     server_info_block.packet_queue_tail = NULL;
    }

    event_add(server_info_block.timer_event, &server_info_block.timer_interval);
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

    if(server_info_block.packet_queue_header == NULL)
        server_info_block.packet_queue_header = packet;
    else
        server_info_block.packet_queue_tail->next = packet;
        
    server_info_block.packet_queue_tail = packet;
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




static void* gameserver_thread(void *data)
{
    evutil_socket_t listener;
    struct sockaddr_in sin;
    struct event_base *base;
    struct event *listen_event;

#ifdef WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    iWA_Info("gameserver_thread()");

    if(!server_init())  iWA_Fatal("game server init error");

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

    server_info_block.timer_interval.tv_sec = 0; 
    server_info_block.timer_interval.tv_usec = 500;
    server_info_block.timer_event = event_new(base, -1, 0, timer_event_cb, NULL);
    if(server_info_block.timer_event == NULL)  iWA_Fatal("new timer_event error");
    event_add(server_info_block.timer_event, &server_info_block.timer_interval);
    
    event_base_dispatch(base);

    iWA_Notice("GameServer End");
    
    return 0;
}


void iWA_GameServer_Main(void)
{
    iWA_Info("iWA_GameServer_Main()");

    iWA_Std_memset((void*)&server_info_block, 0, sizeof(iWAstruct_GameServer_InfoBlock));

    pthread_create(&server_info_block.thread, NULL, gameserver_thread, NULL);
}


