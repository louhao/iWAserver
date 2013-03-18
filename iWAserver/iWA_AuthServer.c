
#ifndef WIN32
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#include <sys/socket.h>
#endif


#include "iWA.h"


#define iWAmacro_AUTHSERVER_LISTEN_PORT     (3724)
#define iWAmacro_AUTHSERVER_LISTEN_BACKLOG  (32)

#define iWAmacro_AUTHSERVER_PACKET_HEADER_SIZE    (4)


typedef struct
{
    void *next;
    iWAstruct_AuthSession_Session* session;
    iWAuint16 type;
    iWAuint16 len;
    iWAuint8 data[4];
}iWAstruct_AuthServer_Packet;

static struct event *timer_event;
static struct timeval timer_interval;

static iWAstruct_AuthServer_Packet *packet_queue_header = NULL;
static iWAstruct_AuthServer_Packet *packet_queue_tail = NULL;
static iWAuint8 send_packet_buf[1024];
static iWAint8 bn_to_hex_buf[512];

static iWAbool server_init(void);
static void listen_event_cb(evutil_socket_t listener, iWAint16 event, void *arg);
static void timer_event_cb(iWAint32 fd, iWAint16 event, void *argc);
static void bufevent_read_cb(struct bufferevent *bev, void *arg);
static void bufevent_write_cb(struct bufferevent *bev, void *arg);
static void bufevent_error_cb(struct bufferevent *bev, iWAint16 event, void *arg);
static void handle_logon_client_packet(iWAstruct_AuthServer_Packet *pkt);
static void handle_reg_client_packet(iWAstruct_AuthServer_Packet *pkt);
static void handle_server_list_client_packet(iWAstruct_AuthServer_Packet *pkt);
static iWAbool write_data_bufferevent(iWAstruct_AuthSession_Session * session, iWAuint8 *data, iWAuint32 len);
static iWAuint32 write_server_list_packet(iWAuint8 *buf);
static void handle_proof_client_packet(iWAstruct_AuthServer_Packet *pkt);


static iWAint8* bn_to_hex(BIGNUM *bn)   /* BN_bn2hex NOT release memory, using this alternative */
{
    iWAint32 i,j,v,z=0;
    iWAint8 *p;
    static const iWAint8 hex[]="0123456789ABCDEF";
    iWAint32 len;

    p = bn_to_hex_buf;
    
    if (bn->neg)    *(p++) = '-';
    if (BN_is_zero(bn))     *(p++) = '0';
    
    for (i = bn->top - 1; i >= 0; i--)
    {
        for (j = BN_BITS2 - 8; j >= 0; j -= 8)
        {
            /* strip leading zeros */
            v = ((iWAint32)(bn->d[i] >> j)) & 0xff;
            
            if (z || (v != 0))
            {
                *(p++) = hex[v >> 4];
                *(p++) = hex[v & 0x0f];
                z = 1;
            }
        }
    }

    *p = 0x00;

    return bn_to_hex_buf;
}


static iWAbool write_data_bufferevent(iWAstruct_AuthSession_Session * session, iWAuint8 *data, iWAuint32 len)
{
    iWA_Info("write_data_bufferevent()");

    iWA_Assert(session != NULL);
    iWA_Assert(data != NULL);

    return !bufferevent_write(session->bev, data, len);
}


static iWAuint32 write_server_list_packet(iWAuint8 *buf)
{
    IWAserverAuth__ServerListServer list;
    iWAint8 *sql = "select sid, region, status, name, hit, address, port from servers where valid = 1;";
    iWAstruct_Mysql_QueryResult *result;
    iWAint8 **row;
    IWAserverAuth__ServerListServer__Server *server;
    iWAuint32 i, len = 0;

    iWA_Info("write_server_list_packet()");

    if(buf == NULL)    return 0;

    /* query server info */
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, sql))   return 0;

    result = iWA_Mysql_DatabaseStoreResult(iWA_Global_DatabaseAccount);
    if(!result)     return 0;

    /* fill IWAserverAuth__ServerListServer */
    i_waserver_auth__server_list_server__init(&list);
    list.n_servers = 0;
    if(result->num > 0)
        list.servers = (IWAserverAuth__ServerListServer__Server**)iWA_Malloc(sizeof(IWAserverAuth__ServerListServer__Server*) * (result->num));

    while(result->row)
    {
        row = result->row;
        server = (IWAserverAuth__ServerListServer__Server*)iWA_Malloc(sizeof(IWAserverAuth__ServerListServer__Server));

        i_waserver_auth__server_list_server__server__init(server);
        server->sid = iWA_Std_atoi(row[0]);
        server->region = iWA_Std_atoi(row[1]);
        server->status = iWA_Std_atoi(row[2]);
        server->name = row[3];
        server->hit = row[4];
        server->address = row[5];
        server->port = iWA_Std_atoi(row[6]);

        list.servers[list.n_servers++] = server;
        iWA_Mysql_DatabaseNextRow(result);
    }

    list.num = list.n_servers;

    /* encode to buf */
    len = i_waserver_auth__server_list_server__pack(&list, buf);

do_free:

    /* free IWAserverAuth__ServerListServer */
    if(list.servers != NULL)
    {
        for(i = 0; i < list.n_servers; i++)
        {
            if(list.servers[i] != NULL)    iWA_Free((void*)list.servers[i]);
        }

        iWA_Free((void*)list.servers);
    }

    /* free sql result */
    if(result != NULL)  iWA_Mysql_DatabaseFreeResult(result);

    return len;
}

static void handle_reg_client_packet(iWAstruct_AuthServer_Packet *pkt)
{
    IWAserverAuth__LogRegClient *reg;
    IWAserverAuth__LogRegServer rsp;
    iWAint32 len;
    iWAint8 sql[250];
    iWAint32 reval = I_WASERVER_AUTH__RESULT_CODE__UNKNOWN_ERROR;

    iWA_Info("handle_reg_client_packet()");

    reg = i_waserver_auth__log_reg_client__unpack(NULL, pkt->len, pkt->data);
    if(reg == NULL)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__UNPACK_MESSAGE_ERROR;
        goto do_response_and_free;
    }

    if(reg->username == NULL || reg->username[0] == 0x00)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__REG_USERNAME_EMPTY;
        goto do_response_and_free;        
    }

    if(reg->password_hash == NULL || reg->password_hash[0] == 0x00)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__REG_PASSWORD_EMPTY;
        goto do_response_and_free;        
    }
    
    iWA_Std_sprintf(sql, "insert into users (username, password, sessionkey) values ('%s', '%s', '00000000000000000000000000000000000000000000000000000000000000000000000000000000');", reg->username, reg->password_hash);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, sql))
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__REG_DB_INSERT_ERROR;
        goto do_response_and_free;
    }

    reval = I_WASERVER_AUTH__RESULT_CODE__SUCCESS;

do_response_and_free:

    /* write response packet */
    i_waserver_auth__log_reg_server__init(&rsp);
    rsp.result = reval;
    len = i_waserver_auth__log_reg_server__pack(&rsp, send_packet_buf+4);
    iWA_Net_WritePacketUint16(send_packet_buf, len);
    iWA_Net_WritePacketUint16(send_packet_buf+2, iWAenum_AUTH_CMD_REG);
    write_data_bufferevent(pkt->session, send_packet_buf, len+4);

    /* do free */
    if(reg != NULL)  i_waserver_auth__log_reg_client__free_unpacked(reg, NULL);
}


static void handle_logon_client_packet(iWAstruct_AuthServer_Packet *pkt)
{
    IWAserverAuth__LogRegClient *logon;
    IWAserverAuth__LogRegServer rsp;
    iWAstruct_AuthSession_Session* session;
    iWAstruct_Mysql_QueryResult *result = NULL;
    iWAint32 len;
    iWAint8 sql[100];
    iWAint32 reval = I_WASERVER_AUTH__RESULT_CODE__UNKNOWN_ERROR;
    iWAint8 *password_hash;
    BIGNUM p, x, g_mod;
    BIGNUM *p_bn, bn1, bn2, bn3;
    SHA1Context sha_ctx;
    BN_CTX *bn_ctx;
    iWAuint8  B_bin[80], g_bin[5], N_bin[80], s_bin[40];
    
    iWA_Info("handle_logon_client_packet()");

    session = pkt->session;

    logon = i_waserver_auth__log_reg_client__unpack(NULL, pkt->len, pkt->data);
    if(logon == NULL)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__UNPACK_MESSAGE_ERROR;
        goto do_response_and_free;
    }

    if(logon->username == NULL || logon->username[0] == 0x00)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__LOGON_USERNAME_EMPTY;
        goto do_response_and_free;        
    }
    
    iWA_Std_sprintf(sql, "select UID, password from users where username = '%s';", logon->username);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, sql))
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__LOGON_DB_QUERY_ERROR;    
        goto do_response_and_free;
    }

    result = iWA_Mysql_DatabaseStoreResult(iWA_Global_DatabaseAccount);
    if(result == NULL)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__LOGON_DB_QUERY_ERROR;
        goto do_response_and_free;
    }
    if(result->row == NULL)     
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__LOGON_ACCOUNT_NOEXIST;
        goto do_response_and_free;
    }

    iWA_Std_strcpy(session->account, logon->username);
    session->UID = iWA_Std_atoi(result->row[0]);
    password_hash = result->row[1];

    /* calculate v, B value */
    bn_ctx = BN_CTX_new();
    BN_init(&p);
    BN_init(&x);
    BN_init(&g_mod);
    BN_init(&bn1);
    BN_init(&bn2);
    BN_init(&bn3);
    BN_init(&session->s);
    BN_init(&session->v);
    BN_init(&session->N);
    BN_init(&session->g);
    BN_init(&session->b);
    BN_init(&session->B);
     
    /* s = random(32bytes) */
    BN_rand(&session->s, 32*8, 0, 1);
#if 0    
    p_bn = &session->s;
    BN_hex2bn(&p_bn, "98790A0C0151E9D7BD04C43BC8BDC0D4D70676129C0B565621EA407D10FFE7A5");
#endif

    /* x = H(s, password_hash) */
    p_bn = &p;
    BN_hex2bn(&p_bn, password_hash);
    iWA_Crypto_Sha1HashBigNumbers(&sha_ctx, &x, &session->s, &p, NULL);

    /* v = (g^x) % N */
    p_bn = &session->g;
    BN_hex2bn(&p_bn, "7");
    p_bn = &session->N;
    BN_hex2bn(&p_bn, "894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7");
    BN_mod_exp(&session->v, &session->g, &x, &session->N, bn_ctx);

    /* b = random(19bytes) */
    BN_rand(&session->b, 19*8, 0, 1);
#if 0
    p_bn = &session->b;
    BN_hex2bn(&p_bn, "A6E9E4CAD212DEB90ACD1B0616D637FD719785");
#endif


    /* g_mod = (g^b) % N */
    BN_mod_exp(&g_mod, &session->g, &session->b, &session->N, bn_ctx);

    /* B = (v*3 + g_mod) % N */
    p_bn = &bn1;
    BN_hex2bn(&p_bn, "3");
    BN_mul(&bn2, &session->v, &bn1, bn_ctx);
    BN_add(&bn3, &bn2, &g_mod);
    BN_mod(&session->B, &bn3, &session->N, bn_ctx);

    BN_CTX_free(bn_ctx);  

    reval = I_WASERVER_AUTH__RESULT_CODE__SUCCESS;

    iWA_Debug("password_hash : %s", password_hash);
    iWA_Debug("p : %s", bn_to_hex(&p));
    iWA_Debug("s : %s", bn_to_hex(&session->s));
    iWA_Debug("x : %s", bn_to_hex(&x));
    iWA_Debug("g : %s", bn_to_hex(&session->g));
    iWA_Debug("N : %s", bn_to_hex(&session->N));
    iWA_Debug("v : %s", bn_to_hex(&session->v));
    iWA_Debug("b : %s", bn_to_hex(&session->b));
    iWA_Debug("g_mod : %s", bn_to_hex(&g_mod));
    iWA_Debug("B : %s", bn_to_hex(&session->B));

    if(!iWA_Std_strcmp(logon->gamename, "iWA"))     session->f_simple_auth = 1;


do_response_and_free:

    /* write response packet */
    i_waserver_auth__log_reg_server__init(&rsp);
    rsp.result = reval;
    rsp.has_b = 1;
    rsp.b.len = iWA_Net_WritePacketBigNumber(B_bin, &session->B); 
    rsp.b.data = B_bin;
    rsp.has_g = 1;
    rsp.g.len = iWA_Net_WritePacketBigNumber(g_bin, &session->g); 
    rsp.g.data = g_bin;
    rsp.has_n = 1;
    rsp.n.len = iWA_Net_WritePacketBigNumber(N_bin, &session->N); 
    rsp.n.data = N_bin; 
    rsp.has_s = 1;
    rsp.s.len = iWA_Net_WritePacketBigNumber(s_bin, &session->s); 
    rsp.s.data = s_bin;
    
    len = i_waserver_auth__log_reg_server__pack(&rsp, send_packet_buf+4);
    iWA_Net_WritePacketUint16(send_packet_buf, len);
    iWA_Net_WritePacketUint16(send_packet_buf+2, iWAenum_AUTH_CMD_LOGON);
    write_data_bufferevent(pkt->session, send_packet_buf, len+4);

    /* do free */
    if(logon != NULL)    i_waserver_auth__log_reg_client__free_unpacked(logon, NULL);
    if(result != NULL)  iWA_Mysql_DatabaseFreeResult(result);
}

static void handle_proof_client_packet(iWAstruct_AuthServer_Packet *pkt)
{
    IWAserverAuth__ProofClient *proof;
    IWAserverAuth__ProofServer rsp;
    iWAint32 i, len;
    iWAint32 reval = I_WASERVER_AUTH__RESULT_CODE__UNKNOWN_ERROR;
    iWAstruct_AuthSession_Session* session;
    BIGNUM A, M1, u, S, K, I, M;
    BIGNUM bn1, bn2, *p_bn;
    SHA1Context sha_ctx;
    BN_CTX *bn_ctx;
    iWAint8 sql[150];
    
    iWA_Info("handle_proof_client_packet()");

    session = pkt->session;

    proof = i_waserver_auth__proof_client__unpack(NULL, pkt->len, pkt->data);
    if(proof == NULL)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__UNPACK_MESSAGE_ERROR;
        goto do_response_and_free;
    }

    /* calculate M, compare with M1 */
    bn_ctx = BN_CTX_new();
    BN_init(&A);
    BN_init(&M1);
    BN_init(&u);
    BN_init(&S);
    BN_init(&K);
    BN_init(&I);    
    BN_init(&M);    
    BN_init(&bn1);
    BN_init(&bn2);


    /* read A, M1 */
    if(proof->a.data == NULL || proof->a.len <= 0)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__PROOF_AVALUE_INCORRECT;    
        goto do_response_and_free;
    }

    iWA_Net_ReadPacketBigNumber(proof->a.data, proof->a.len, &A);

    if(proof->m1.data == NULL || proof->m1.len <= 0)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__PROOF_M1VALUE_INCORRECT;    
        goto do_response_and_free;    
    }
    
    iWA_Net_ReadPacketBigNumber(proof->m1.data, proof->m1.len, &M1);

    /* u = H(A, B) */
    iWA_Crypto_Sha1HashBigNumbers(&sha_ctx, &u, &A, &session->B, NULL);

    /* S = ((A*v^u) ^ b) % N */
    BN_mod_exp(&bn1, &session->v, &u, &session->N, bn_ctx);       /* bn1 = (v ^ u) % N */
    BN_mul(&bn2, &A, &bn1, bn_ctx);      /* bn2 = A * bn1 */
    BN_mod_exp(&S, &bn2, &session->b, &session->N, bn_ctx);       /* S = (bn2 ^ b) % N */

    /* K = H_interleave(S) */
    iWA_Crypto_Sha1Interleave(&sha_ctx, &K, &S);

    /* I = H(username)  */
    SHA1Reset(&sha_ctx);
    SHA1Input(&sha_ctx, session->account, iWA_Std_strlen(session->account));  
    iWA_Crypto_Sha1ResultBigNumber(&sha_ctx, &I);

    /* M = H(H(N) xor H(g), I, s, A, B, K) */
    iWA_Crypto_Sha1HashBigNumbers(&sha_ctx, &bn1, &session->N, NULL);  /* bn1 = H(N) */
    iWA_Crypto_Sha1HashBigNumbers(&sha_ctx, &bn2, &session->g, NULL);  /* bn2 = H(g) */
    for(i = 0; i < bn1.top; i++)   bn1.d[i] ^= bn2.d[i];  /* bn1 = bn1 xor bn2 */
    iWA_Crypto_Sha1HashBigNumbers(&sha_ctx, &M, &bn1, &I, &session->s, &A, &session->B , &K, NULL);  /* M = H(bn1, I, s, A, B, K) */

    BN_CTX_free(bn_ctx);  

    /* compare M and M1 */
    if(!BN_cmp(&M, &M1) || session->f_simple_auth)
    {
        if(session->f_simple_auth)
        {
            p_bn = &K;
            BN_hex2bn(&p_bn, "D10FDB0FB4FDC4893290764BEDE4500631EB2E3FCCBDE656A710E8A6FA6736933E9C63562D895729");
        }  
    
        /* M == M1, store K value to DB */
        iWA_Std_sprintf(sql, "update users set sessionkey = '%s' where username = '%s';", bn_to_hex(&K), session->account);
        
        if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, sql))
            reval = I_WASERVER_AUTH__RESULT_CODE__LOGON_DB_QUERY_ERROR;    
        else
            reval = I_WASERVER_AUTH__RESULT_CODE__SUCCESS;
    }
    else    /* M != M1 */
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__PROOF_MVALUE_UNMATCH;
    }

    iWA_Debug("A : %s", bn_to_hex(&A));
    iWA_Debug("M1 : %s", bn_to_hex(&M1));
    iWA_Debug("B : %s", bn_to_hex(&session->B));
    iWA_Debug("u : %s", bn_to_hex(&u));
    iWA_Debug("v : %s", bn_to_hex(&session->v));
    iWA_Debug("b : %s", bn_to_hex(&session->b));
    iWA_Debug("N : %s", bn_to_hex(&session->N));
    iWA_Debug("S : %s", bn_to_hex(&S));
    iWA_Debug("K : %s", bn_to_hex(&K));
    iWA_Debug("I : %s", bn_to_hex(&I));
    iWA_Debug("s : %s", bn_to_hex(&session->s));
    iWA_Debug("M : %s", bn_to_hex(&M));

do_response_and_free:

    i_waserver_auth__proof_server__init(&rsp);
    rsp.result = reval;
    len = i_waserver_auth__proof_server__pack(&rsp, send_packet_buf+4);
    iWA_Net_WritePacketUint16(send_packet_buf, len);
    iWA_Net_WritePacketUint16(send_packet_buf+2, iWAenum_AUTH_CMD_PROOF);
    write_data_bufferevent(pkt->session, send_packet_buf, len+4);

    i_waserver_auth__proof_client__free_unpacked(proof, NULL);
}


static void handle_server_list_client_packet(iWAstruct_AuthServer_Packet *pkt)
{
    iWAuint32 len;

    iWA_Info("handle_server_list_client_packet()");

    len = write_server_list_packet(send_packet_buf+4);
    if(len == 0)    
    {
        iWA_Info("write_server_list_packet fail");
        return;
    }
    
    iWA_Net_WritePacketUint16(send_packet_buf, len);
    iWA_Net_WritePacketUint16(send_packet_buf+2, iWAenum_AUTH_CMD_SERVER_LIST);

    write_data_bufferevent(pkt->session, send_packet_buf, len+4);
}

#if 0
static iWAbool server_init(void)
{
    iWA_Info("server_init()");

    iWA_Global_DatabaseAccount = iWA_Mysql_DatabaseNew();
    if(iWA_Global_DatabaseAccount == NULL)  return 0;

    iWA_Std_strcpy(iWA_Global_DatabaseAccount->host, "localhost");
    iWA_Global_DatabaseAccount->port = 3306;
    iWA_Std_strcpy(iWA_Global_DatabaseAccount->user, "root");
    iWA_Std_strcpy(iWA_Global_DatabaseAccount->pwd, "");
    iWA_Std_strcpy(iWA_Global_DatabaseAccount->name, "iWAaccount");
    
    if(!iWA_Mysql_DatabaseOpen(iWA_Global_DatabaseAccount)) return 0;

    return 1;
}
#endif

static iWAbool server_init(void)
{
    iWA_Log_Init();

    iWA_Info("server_init()");

    /* set gameserver.ini filename */
    iWA_Config_Init(iWAmacro_CONFIG_AUTHSERVER_INI_FILENAME);

    /* init AccountDB connect */
    iWA_Global_DatabaseAccount = iWA_Mysql_DatabaseNew();
    iWA_Assert(iWA_Global_DatabaseAccount != NULL);

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

    iWA_Assert(iWA_Mysql_DatabaseOpen(iWA_Global_DatabaseAccount));

    return 1;
}



static void listen_event_cb(evutil_socket_t listener, iWAint16 event, void *arg)
{
    struct event_base *base = (struct event_base *)arg;
    evutil_socket_t fd;
    struct sockaddr_in sin;
    iWAint32 slen;
    struct bufferevent *bev;

    iWA_Info("listen_event_cb()");
    
    fd = accept(listener, (struct sockaddr *)&sin, &slen);

    if (fd < 0) 
    {
        iWA_Info("accept error");
        return;
    }
    
    if (fd > FD_SETSIZE) {
        iWA_Info("fd > FD_SETSIZE\n");
        return;
    }
    
    iWA_Info("ACCEPT: fd = %u\n", fd);
    
    bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, bufevent_read_cb, bufevent_write_cb, bufevent_error_cb, arg);
    bufferevent_enable(bev, EV_READ|EV_WRITE|EV_PERSIST);

    iWA_AuthSession_AllocSession(bev);
}

static void timer_event_cb(iWAint32 fd, iWAint16 event, void *argc)
{
    iWAstruct_AuthServer_Packet *pkt;

    while(packet_queue_header != NULL)
    {
        pkt = packet_queue_header;

        iWA_Assert(pkt->session != NULL);

        /* !!!!!!!!!  should check seesion status */

        switch(pkt->type)
        {
            case iWAenum_AUTH_CMD_REG:
                handle_reg_client_packet(pkt);
                break;  
            case iWAenum_AUTH_CMD_LOGON:
                handle_logon_client_packet(pkt);
                break;
            case iWAenum_AUTH_CMD_PROOF:
                handle_proof_client_packet(pkt);
                break;           
            case iWAenum_AUTH_CMD_SERVER_LIST:
                handle_server_list_client_packet(pkt);
                break;                  
            default:
                iWA_Info("unkonwn type packet");
                break;
        }

        packet_queue_header = pkt->next;
        iWA_Free(pkt);
        if(packet_queue_header == NULL)     packet_queue_tail = NULL;
    }

    event_add(timer_event, &timer_interval);
}




static void bufevent_read_cb(struct bufferevent *bev, void *arg)
{
    iWAuint8 header[iWAmacro_AUTHSERVER_PACKET_HEADER_SIZE];
    struct evbuffer *evb;
    iWAuint32 evb_len;
    iWAuint16 packet_len, packet_type;
    iWAstruct_AuthServer_Packet *packet;

    iWA_Info("bufevent_read_cb()");

    evb = bufferevent_get_input(bev);
    if(evb == NULL)     return;

    evb_len = evbuffer_get_length(evb);
    if(evb_len < iWAmacro_AUTHSERVER_PACKET_HEADER_SIZE)    return;

    if(evbuffer_copyout(evb, header, iWAmacro_AUTHSERVER_PACKET_HEADER_SIZE) < iWAmacro_AUTHSERVER_PACKET_HEADER_SIZE)  return;

    packet_len = iWA_Net_ReadPacketUint16(header);
    packet_type = iWA_Net_ReadPacketUint16(header+2);

    if(evb_len < packet_len + 4)    return;

    packet = (iWAstruct_AuthServer_Packet*)iWA_Malloc(packet_len <= 4 ? sizeof(iWAstruct_AuthServer_Packet) : sizeof(iWAstruct_AuthServer_Packet) + packet_len - 4);

    packet->next = NULL;
    packet->session = iWA_AuthSession_GetSession(bev);
    packet->len = packet_len;
    packet->type = packet_type;

    if(evbuffer_drain(evb, iWAmacro_AUTHSERVER_PACKET_HEADER_SIZE) < 0)     return;
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

    iWA_AuthSession_FreeSession(bev);
}


iWAint32 iWA_AuthServer_Main(void)
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

    iWA_Info("iWA_AuthServer_Main()");

    listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener > 0);
    evutil_make_listen_socket_reuseable(listener);


    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(iWAmacro_AUTHSERVER_LISTEN_PORT);

    if (bind(listener, (struct sockaddr *)&sin, sizeof(sin)) < 0) 
    {
        iWA_Info("bind error");
        return -2;
    }

    if (listen(listener, iWAmacro_AUTHSERVER_LISTEN_BACKLOG) < 0) 
    {
        iWA_Info("listen error");
        return -3;
    }

    iWA_Info ("AuthServer Listening...");

    evutil_make_socket_nonblocking(listener);

    base = event_base_new();
    if(base == NULL)
    {
        iWA_Info("event_base_new error");
        return -4;
    }

    listen_event = event_new(base, listener, EV_READ|EV_PERSIST, listen_event_cb, (void*)base);
    if(listen_event != NULL)
    {
        event_add(listen_event, NULL);
    }
    else
    {
        iWA_Info("new listen_event error");
        return -5;
    }

    timer_interval.tv_sec=5; 
    timer_interval.tv_usec=0;
    timer_event = event_new(base, -1, 0, timer_event_cb, NULL);
    if(timer_event != NULL)
    {
        event_add(timer_event, &timer_interval);
    }
    else
    {
        iWA_Info("new timer_event error");
        return -6;
    }
    
    event_base_dispatch(base);

    iWA_Info("AuthServer End");
    
    return 0;
}


