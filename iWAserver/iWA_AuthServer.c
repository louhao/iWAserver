



#include "iWA.h"


#define iWAmacro_AUTHSERVER_PACKET_HEADER_SIZE    (4)


typedef struct
{
    void *next;
    iWAint16 session;
    iWAuint16 type;
    iWAuint16 len;
    iWAuint8 data[4];
}iWAstruct_AuthServer_Packet;

static iWAstruct_AuthServer_Packet *packet_queue_header = NULL;
static iWAstruct_AuthServer_Packet *packet_queue_tail = NULL;
static iWAuint8 send_packet_buf[1024];


static void handle_logon_client_packet(iWAstruct_AuthServer_Packet *pkt);
static void handle_reg_client_packet(iWAstruct_AuthServer_Packet *pkt);


iWAbool iWA_AuthServer_Init(void)
{
    iWA_Log("iWA_AuthServer_Init()");

    iWA_Global_DatabaseAccount = iWA_Mysql_DatabaseNew();
    if(iWA_Global_DatabaseAccount == NULL)  return 0;

    iWA_Std_strcpy(iWA_Global_DatabaseAccount->host, "localhost");
    iWA_Std_strcpy(iWA_Global_DatabaseAccount->user, "root");
    iWA_Std_strcpy(iWA_Global_DatabaseAccount->pwd, "");
    iWA_Std_strcpy(iWA_Global_DatabaseAccount->name, "iWAaccount");
    
    if(!iWA_Mysql_DatabaseOpen(iWA_Global_DatabaseAccount)) return 0;

    return 1;
}




void iWA_AuthServer_BuffereventReadCb(struct bufferevent *bev)
{

    iWAuint8 header[iWAmacro_AUTHSERVER_PACKET_HEADER_SIZE];
    struct evbuffer *evb;
    iWAuint32 evb_len;
    iWAuint16 packet_len, packet_type;
    iWAstruct_AuthServer_Packet *packet;

    iWA_Log("iWA_AuthServer_BuffereventReadCb()");

    evb = bufferevent_get_input(bev);
    if(evb == NULL)     return;

    evb_len = evbuffer_get_length(evb);
    if(evb_len < iWAmacro_AUTHSERVER_PACKET_HEADER_SIZE)    return;

    if(evbuffer_copyout(evb, header, iWAmacro_AUTHSERVER_PACKET_HEADER_SIZE) < iWAmacro_AUTHSERVER_PACKET_HEADER_SIZE)  return;

    packet_len = iWA_Net_ReadPacketUint16(header);
    packet_type = iWA_Net_ReadPacketUint16(header+2);

    if(evb_len < packet_len + 4)    return;

    packet = (iWAstruct_AuthServer_Packet*)iWA_Malloc(packet_len <= 4 ? sizeof(iWAstruct_AuthServer_Packet) : sizeof(iWAstruct_AuthServer_Packet) + packet_len - 4);
    if(packet == NULL)  return;

    packet->next = NULL;
    packet->session = iWA_AuthSession_SessionId(bev);
    packet->len = packet_len;
    packet->type = packet_type;

    if(evbuffer_drain(evb, iWAmacro_AUTHSERVER_PACKET_HEADER_SIZE) < 0)     return;
    if(evbuffer_remove(evb, packet->data, packet_len) != packet_len)    return;

    iWA_Log("extract packet, type=0x%02x", packet_type);

    if(packet_queue_header == NULL)
        packet_queue_header = packet;
    else
        packet_queue_tail->next = packet;
        
    packet_queue_tail = packet;
}


static iWAbool write_data_bufferevent(iWAint16 session, iWAuint8 *data, iWAuint32 len)
{
    struct bufferevent *bev;

    iWA_Log("write_data_bufferevent()");

    bev = iWA_AuthSession_SessionBev(session);

    if(bev == NULL)     return 0;

    return !bufferevent_write(bev, data, len);
}

static iWAbool insert_account_info(iWAint8 *user, iWAint8 *pwd)
{
    iWAint8 sql[200];

    if(user == NULL || pwd == NULL)     return 0;

    iWA_Std_sprintf(sql, "insert into user (username, password) values ('%s', '%s');", user, pwd);

    iWA_Log("insert_account_info: %s", sql);
    
    return iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, sql);
}

static iWAuint32 write_server_list_packet(iWAuint8 *buf)
{
    IWAserverAuth__ServerListServer list;
    iWAint8 *sql = "select region, status, name, hit, address, port from server where valid = 1;";
    iWAstruct_Mysql_QueryResult *result;
    iWAint8 **row;
    IWAserverAuth__ServerListServer__Server *server;
    iWAuint32 i, len = 0;

    iWA_Log("write_server_list_packet()");

    if(buf == NULL)    return 0;

    /* query server info */
    if(!iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, sql))   return 0;

    result = iWA_Mysql_DatabaseStoreResult(iWA_Global_DatabaseAccount);
    if(!result)     return 0;

    /* fill IWAserverAuth__ServerListServer */
    i_waserver_auth__server_list_server__init(&list);
    list.n_servers = 0;
    list.servers = (IWAserverAuth__ServerListServer__Server**)iWA_Malloc(sizeof(IWAserverAuth__ServerListServer__Server*) * (result->num));
    if(list.servers == NULL)    goto do_free;
    memset((void*)list.servers, 0, sizeof(IWAserverAuth__ServerListServer__Server*) * (result->num));

    while(result->row)
    {
        row = result->row;
        server = (IWAserverAuth__ServerListServer__Server*)iWA_Malloc(sizeof(IWAserverAuth__ServerListServer__Server));
        if(server == NULL)  goto do_free;

        i_waserver_auth__server_list_server__server__init(server);
        server->region = iWA_Std_atoi(row[0]);
        server->status = iWA_Std_atoi(row[1]);
        server->name = row[2];
        server->hit = row[3];
        server->address = row[4];
        server->port = iWA_Std_atoi(row[5]);

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
    iWA_Mysql_DatabaseFreeResult(result);

    return len;
}

static void handle_logon_client_packet(iWAstruct_AuthServer_Packet *pkt)
{
    IWAserverAuth__LogRegClient *logon;
    IWAserverAuth__LogRegServer rsp;
    iWAint32 len;

    iWA_Log("handle_logon_client_packet()");

    logon = i_waserver_auth__log_reg_client__unpack(NULL, pkt->len, pkt->data);

#if 0
{
    iWAint8 sql[200];

    iWA_Std_sprintf(sql, "select username, password from user where username = '%s';", logon->username);

    iWA_Log("%s", sql);
    
    if(iWA_Mysql_DatabaseQuery(iWA_Global_DatabaseAccount, sql))
    {
        iWAstruct_Mysql_QueryResult *result = iWA_Mysql_DatabaseStoreResult(iWA_Global_DatabaseAccount);
        
        iWA_Mysql_DatabaseFreeResult(result);
    }
}
#endif



    i_waserver_auth__log_reg_client__free_unpacked(logon, NULL);

    i_waserver_auth__log_reg_server__init(&rsp);
    rsp.result = I_WASERVER_AUTH__LOG_REG_SERVER__RESULT_CODE__OK;
    len = i_waserver_auth__log_reg_server__pack(&rsp, send_packet_buf+4);
    iWA_Net_WritePacketUint16(send_packet_buf, len);
    iWA_Net_WritePacketUint16(send_packet_buf+2, iWAenum_AUTH_CMD_LOGON);

    write_data_bufferevent(pkt->session, send_packet_buf, len+4);

    
}

static void handle_reg_client_packet(iWAstruct_AuthServer_Packet *pkt)
{
    IWAserverAuth__LogRegClient *logon;
    IWAserverAuth__LogRegServer rsp;
    iWAint32 len;

    iWA_Log("handle_reg_client_packet()");

    logon = i_waserver_auth__log_reg_client__unpack(NULL, pkt->len, pkt->data);

    insert_account_info(logon->username, logon->password);

    i_waserver_auth__log_reg_client__free_unpacked(logon, NULL);


    i_waserver_auth__log_reg_server__init(&rsp);
    rsp.result = I_WASERVER_AUTH__LOG_REG_SERVER__RESULT_CODE__OK;
    len = i_waserver_auth__log_reg_server__pack(&rsp, send_packet_buf+4);
    iWA_Net_WritePacketUint16(send_packet_buf, len);
    iWA_Net_WritePacketUint16(send_packet_buf+2, iWAenum_AUTH_CMD_REG);

    write_data_bufferevent(pkt->session, send_packet_buf, len+4);
}

static void handle_proof_client_packet(iWAstruct_AuthServer_Packet *pkt)
{
    IWAserverAuth__ProofClient *proof;
    IWAserverAuth__ProofServer rsp;
    iWAint32 len;

    iWA_Log("handle_proof_client_packet()");

    proof = i_waserver_auth__proof_client__unpack(NULL, pkt->len, pkt->data);

    i_waserver_auth__proof_client__free_unpacked(proof, NULL);


    i_waserver_auth__proof_server__init(&rsp);
    rsp.result = I_WASERVER_AUTH__PROOF_SERVER__RESULT_CODE__OK;
    len = i_waserver_auth__proof_server__pack(&rsp, send_packet_buf+4);
    iWA_Net_WritePacketUint16(send_packet_buf, len);
    iWA_Net_WritePacketUint16(send_packet_buf+2, iWAenum_AUTH_CMD_PROOF);

    write_data_bufferevent(pkt->session, send_packet_buf, len+4);
}


static void handle_server_list_client_packet(iWAstruct_AuthServer_Packet *pkt)
{
    iWAuint32 len;

    iWA_Log("handle_server_list_client_packet()");

    len = write_server_list_packet(send_packet_buf+4);
    if(len == 0)    
    {
        iWA_Log("write_server_list_packet fail");
        return;
    }
    
    iWA_Net_WritePacketUint16(send_packet_buf, len);
    iWA_Net_WritePacketUint16(send_packet_buf+2, iWAenum_AUTH_CMD_SERVER_LIST);

    write_data_bufferevent(pkt->session, send_packet_buf, len+4);
}

void iWA_AuthServer_HandlePacketQueue(void)
{
    iWAstruct_AuthServer_Packet *pkt;
    IWAserverAuth__LogRegClient *logon;


    iWA_Log("iWA_AuthServer_HandlePacketQueue()");

    while(packet_queue_header != NULL)
    {
        pkt = packet_queue_header;

        switch(pkt->type)
        {
            case iWAenum_AUTH_CMD_LOGON:
                handle_logon_client_packet(pkt);
                break;
            case iWAenum_AUTH_CMD_REG:
                handle_reg_client_packet(pkt);
                break;                
            case iWAenum_AUTH_CMD_PROOF:
                handle_proof_client_packet(pkt);
                break;           
            case iWAenum_AUTH_CMD_SERVER_LIST:
                handle_server_list_client_packet(pkt);
                break;                  
            default:
                iWA_Log("unkonwn type packet");
                break;
        }

        packet_queue_header = pkt->next;
        iWA_Free(pkt);
        if(packet_queue_header == NULL)     packet_queue_tail = NULL;
    }
}



