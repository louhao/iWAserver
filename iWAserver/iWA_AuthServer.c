
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


typedef struct
{
    pthread_t  thread;
    struct event *timer_event;
    struct timeval timer_interval;
    iWAstruct_AuthServer_Packet *packet_queue_header;
    iWAstruct_AuthServer_Packet *packet_queue_tail;
    iWAuint8 send_packet_buf[1024];
    iWAint8 bn_to_hex_buf[512];
}iWAstruct_AuthServer_InfoBlock;

static iWAstruct_AuthServer_InfoBlock server_info_block = {0};


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
static void handle_proof_client_packet(iWAstruct_AuthServer_Packet *pkt);


static iWAint8* bn_to_hex(BIGNUM *bn)   /* BN_bn2hex NOT release memory, using this alternative */
{
    iWAint32 i,j,v,z=0;
    iWAint8 *p;
    static const iWAint8 hex[]="0123456789ABCDEF";
    iWAint32 len;

    p = server_info_block.bn_to_hex_buf;
    
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

    return server_info_block.bn_to_hex_buf;
}


static iWAbool write_data_bufferevent(iWAstruct_AuthSession_Session * session, iWAuint8 *data, iWAuint32 len)
{
    iWA_Info("write_data_bufferevent()");

    iWA_Assert(session != NULL);
    iWA_Assert(data != NULL);

    return !bufferevent_write(session->bev, data, len);
}




static void handle_reg_client_packet(iWAstruct_AuthServer_Packet *pkt)
{
    IWAserverAuth__LogRegClient *reg;
    IWAserverAuth__LogRegServer rsp;
    iWAint32 len;
    iWAint32 reval = I_WASERVER_AUTH__RESULT_CODE__UNKNOWN_ERROR;
    iWAuint8 *pkg = server_info_block.send_packet_buf;
    iWAstruct_AuthSession_Session* session;
    iWAstruct_Mysql_QueryResult *result = NULL;

    iWA_Info("handle_reg_client_packet()");

    session = pkt->session;
    session->status = iWAenum_AUTHSERVER_SESSION_STATUS_UNLOGON;

    /* unpack message */
    reg = i_waserver_auth__log_reg_client__unpack(NULL, pkt->len, pkt->data);
    if(reg == NULL)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__UNPACK_MESSAGE_ERROR;
        goto do_response_and_free;
    }

    /* check username */
    if(reg->username == NULL || reg->username[0] == 0x00)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__REG_USERNAME_EMPTY;
        goto do_response_and_free;        
    }

    /* check password_hash */
    if(reg->password_hash == NULL || reg->password_hash[0] == 0x00)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__REG_PASSWORD_EMPTY;
        goto do_response_and_free;        
    }

    /* check if username already exists */
    iWA_Std_sprintf(session->sql, "select username from users where username = '%s';", reg->username);

    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, session->sql))
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__REG_DB_QUERY_ERROR;
        goto do_response_and_free;
    }
    
    result = iWA_Mysql_DatabaseStoreResult(iWA_Global_DatabaseAccount);
    if(result == NULL)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__REG_DB_QUERY_ERROR;
        goto do_response_and_free;
    }
    if(result->num > 0)
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__REG_USERNAME_ALREADY_EXISTS;
        goto do_response_and_free;
    }    

    /* insert into account-db */    
    iWA_Std_sprintf(session->sql, "insert into users (username, password, sessionkey) values ('%s', '%s', '00000000000000000000000000000000000000000000000000000000000000000000000000000000');", reg->username, reg->password_hash);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, session->sql))
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__REG_DB_INSERT_ERROR;
        goto do_response_and_free;
    }

    reval = I_WASERVER_AUTH__RESULT_CODE__SUCCESS;

do_response_and_free:

    /* write response packet */
    i_waserver_auth__log_reg_server__init(&rsp);
    rsp.result = reval;
    len = i_waserver_auth__log_reg_server__pack(&rsp, pkg+4);
    iWA_Net_WritePacketUint16(pkg, len);
    iWA_Net_WritePacketUint16(pkg+2, iWAenum_AUTH_CMD_REG);
    write_data_bufferevent(pkt->session, pkg, len+4);

    /* do free */
    if(reg != NULL)  i_waserver_auth__log_reg_client__free_unpacked(reg, NULL);
    if(result != NULL)  iWA_Mysql_DatabaseFreeResult(result);
}


static void handle_logon_client_packet(iWAstruct_AuthServer_Packet *pkt)
{
    IWAserverAuth__LogRegClient *logon;
    IWAserverAuth__LogRegServer rsp;
    iWAstruct_AuthSession_Session* session;
    iWAstruct_Mysql_QueryResult *result = NULL;
    iWAint32 len;
    iWAint32 reval = I_WASERVER_AUTH__RESULT_CODE__UNKNOWN_ERROR;
    iWAint8 *password_hash;
    BIGNUM p, x, g_mod;
    BIGNUM *p_bn, bn1, bn2, bn3;
    SHA1Context sha_ctx;
    BN_CTX *bn_ctx;
    iWAuint8  B_bin[80], g_bin[5], N_bin[80], s_bin[40];
    iWAuint8 *pkg = server_info_block.send_packet_buf;
    
    iWA_Info("handle_logon_client_packet()");

    session = pkt->session;
    session->status = iWAenum_AUTHSERVER_SESSION_STATUS_UNLOGON;

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
    
    iWA_Std_sprintf(session->sql, "select UID, password from users where username = '%s';", logon->username);
    
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, session->sql))
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
    session->status = iWAenum_AUTHSERVER_SESSION_STATUS_LOGONING;

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
    
    len = i_waserver_auth__log_reg_server__pack(&rsp, pkg+4);
    iWA_Net_WritePacketUint16(pkg, len);
    iWA_Net_WritePacketUint16(pkg+2, iWAenum_AUTH_CMD_LOGON);
    write_data_bufferevent(pkt->session, pkg, len+4);

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
    iWAuint8 *pkg = server_info_block.send_packet_buf;

    iWA_Info("handle_proof_client_packet()");

    session = pkt->session;
    session->status = iWAenum_AUTHSERVER_SESSION_STATUS_UNLOGON;

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
        iWA_Std_sprintf(session->sql, "update users set sessionkey = '%s' where username = '%s';", bn_to_hex(&K), session->account);
        
        if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, session->sql))
        {
            reval = I_WASERVER_AUTH__RESULT_CODE__LOGON_DB_QUERY_ERROR;    
        }
        else
        {
            reval = I_WASERVER_AUTH__RESULT_CODE__SUCCESS;
            session->status = iWAenum_AUTHSERVER_SESSION_STATUS_LOGONED;

        }
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

    /* write response packet */
    i_waserver_auth__proof_server__init(&rsp);
    rsp.result = reval;
    len = i_waserver_auth__proof_server__pack(&rsp, pkg+4);
    iWA_Net_WritePacketUint16(pkg, len);
    iWA_Net_WritePacketUint16(pkg+2, iWAenum_AUTH_CMD_PROOF);
    write_data_bufferevent(pkt->session, pkg, len+4);

    /* do free */
    i_waserver_auth__proof_client__free_unpacked(proof, NULL);
}


static void handle_server_list_client_packet(iWAstruct_AuthServer_Packet *pkt)
{
    iWAstruct_AuthSession_Session* session;
    IWAserverAuth__ServerListServer list;
    iWAstruct_Mysql_QueryResult *result, *result_chr;
    iWAint8 **row;
    IWAserverAuth__ServerListServer__Server *server;
    IWAserverAuth__ServerListServer__Server__Character *chr;
    iWAuint32 i, j, len = 0;
    iWAuint8 *pkg = server_info_block.send_packet_buf;
    iWAint32 reval = I_WASERVER_AUTH__RESULT_CODE__UNKNOWN_ERROR;

    iWA_Info("handle_server_list_client_packet()");

    session = pkt->session;

    /* query server info */
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, "select sid, region, status, name, hit, address, port from servers where valid = 1;"))   
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__SERVER_LIST_DB_QUERY_ERROR;    
        goto do_response_and_free;
    }

    /* init IWAserverAuth__ServerListServer */
    i_waserver_auth__server_list_server__init(&list);

    /* get server list result */
    result = iWA_Mysql_DatabaseStoreResult(iWA_Global_DatabaseAccount);
    if(result == NULL) 
    {
        reval = I_WASERVER_AUTH__RESULT_CODE__SERVER_LIST_DB_QUERY_ERROR;
        goto do_response_and_free;
    }

    /* alloc server list */
    if(result->num > 0)
        list.servers = (IWAserverAuth__ServerListServer__Server**)iWA_Malloc(sizeof(IWAserverAuth__ServerListServer__Server*) * (result->num));

    /* fill server list */
    while(result->row != NULL)
    {
        /* alloc server */
        server = (IWAserverAuth__ServerListServer__Server*)iWA_Malloc(sizeof(IWAserverAuth__ServerListServer__Server));

        /* fill server info */
        i_waserver_auth__server_list_server__server__init(server);
        row = result->row;
        server->sid = iWA_Std_atoi(row[0]);
        server->region = iWA_Std_atoi(row[1]);
        server->status = iWA_Std_atoi(row[2]);
        server->name = row[3];
        server->hit = row[4];
        server->address = row[5];
        server->port = iWA_Std_atoi(row[6]);

        /* query character info */
        iWA_Std_sprintf(session->sql, "select CID, name, grade, race, nation from characters where SID = %d and UID = %d;", server->sid, session->UID);
        if(iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, session->sql))   
        {
            result_chr = iWA_Mysql_DatabaseStoreResult(iWA_Global_DatabaseAccount);
            if(result_chr != NULL)
            {
                /* alloc character list */
                if(result_chr->num > 0)
                    server->characters = (IWAserverAuth__ServerListServer__Server__Character**)
                                                    iWA_Malloc(sizeof(IWAserverAuth__ServerListServer__Server__Character*)*(result_chr->num));

                /* fill character list */
                while(result_chr->row != NULL)
                {
                    /* alloc character */
                    chr = (IWAserverAuth__ServerListServer__Server__Character*)iWA_Malloc(sizeof(IWAserverAuth__ServerListServer__Server__Character));

                    /* fill character */
                    i_waserver_auth__server_list_server__server__character__init(chr);
                    row = result_chr->row;
                    chr->cid = iWA_Std_atoi(row[0]);
                    chr->name = (iWAint8*)iWA_Malloc(iWA_Std_strlen(row[1]) + 1);
                    iWA_Std_strcpy(chr->name, row[1]);
                    chr->grade = iWA_Std_atoi(row[2]);
                    chr->race = iWA_Std_atoi(row[3]);
                    chr->nation = iWA_Std_atoi(row[4]);
                    
                    /* add character to list */
                    server->characters[server->n_characters++] = chr;

                    /* next character row */
                    iWA_Mysql_DatabaseNextRow(result_chr);
                }

                /* free result_chr*/
                iWA_Mysql_DatabaseFreeResult(result_chr);
            }
        }

        /* add server to list */
        list.servers[list.n_servers++] = server;

        /* next server row */
        iWA_Mysql_DatabaseNextRow(result);
    }

    reval = I_WASERVER_AUTH__RESULT_CODE__SUCCESS;

do_response_and_free:

    /* write response packet */
    list.result =reval;
    len = i_waserver_auth__server_list_server__pack(&list, pkg+4);
    iWA_Net_WritePacketUint16(pkg, len);
    iWA_Net_WritePacketUint16(pkg+2, iWAenum_AUTH_CMD_SERVER_LIST);
    write_data_bufferevent(pkt->session, pkg, len+4);

    /* do free */
    if(list.servers != NULL)
    {
        for(i = 0; i < list.n_servers; i++)
        {
            if(list.servers[i] == NULL)     continue;
    
            for(j = 0; j < list.servers[i]->n_characters; j++)
            {
                if(list.servers[i]->characters[j] != NULL)   
                {
                    iWA_Free((void*)list.servers[i]->characters[j]->name);
                    iWA_Free((void*)list.servers[i]->characters[j]);
                }
            }
            
            iWA_Free((void*)list.servers[i]);
        }

        iWA_Free((void*)list.servers);
    }

    if(result != NULL)  iWA_Mysql_DatabaseFreeResult(result);
}


static iWAbool server_init(void)
{
    iWA_Info("auth server init");

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

    while(server_info_block.packet_queue_header != NULL)
    {
        pkt = server_info_block.packet_queue_header;

        iWA_Assert(pkt->session != NULL);

        switch(pkt->type)
        {
            case iWAenum_AUTH_CMD_REG:
                handle_reg_client_packet(pkt);
                break;  
            case iWAenum_AUTH_CMD_LOGON:
                handle_logon_client_packet(pkt);
                break;
            case iWAenum_AUTH_CMD_PROOF:
                if(pkt->session->status == iWAenum_AUTHSERVER_SESSION_STATUS_LOGONING)     handle_proof_client_packet(pkt);
                break;           
            case iWAenum_AUTH_CMD_SERVER_LIST:
                if(pkt->session->status == iWAenum_AUTHSERVER_SESSION_STATUS_LOGONED)     handle_server_list_client_packet(pkt);
                break;                  
            default:
                iWA_Info("unkonwn type packet");
                break;
        }

        server_info_block.packet_queue_header = pkt->next;
        iWA_Free(pkt);
        if(server_info_block.packet_queue_header == NULL)     server_info_block.packet_queue_tail = NULL;
    }

    event_add(server_info_block.timer_event, &server_info_block.timer_interval);
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

    iWA_AuthSession_FreeSession(bev);
}


static void* authserver_thread(void *data)
{
    evutil_socket_t listener;
    struct sockaddr_in sin;
    struct event_base *base;
    struct event *listen_event;

#ifdef WIN32
    WSADATA wsa_data;
    WSAStartup(0x0201, &wsa_data);
#endif

    iWA_Info("authserver_thread()");

    if(!server_init())  iWA_Fatal("auth server init error");

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

    iWA_Info("AuthServer Listening...");

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

    server_info_block.timer_interval.tv_sec = 0; 
    server_info_block.timer_interval.tv_usec = 500;
    server_info_block.timer_event = event_new(base, -1, 0, timer_event_cb, NULL);
    if(server_info_block.timer_event != NULL)
    {
        event_add(server_info_block.timer_event, &server_info_block.timer_interval);
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

void iWA_AuthServer_Main(void)
{
    iWA_Info("iWA_AuthServer_Main()");

    iWA_Std_memset((void*)&server_info_block, 0, sizeof(iWAstruct_AuthServer_InfoBlock));

    pthread_create(&server_info_block.thread, NULL, authserver_thread, NULL);
}

