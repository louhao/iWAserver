

#include "iWA.h"





iWAstruct_Mysql_Database* iWA_Mysql_DatabaseNew(void)
{
    iWAstruct_Mysql_Database* db;
    
    iWA_Log("iWA_Mysql_DatabaseNew()");

    db = (iWAstruct_Mysql_Database*)iWA_Malloc(sizeof(iWAstruct_Mysql_Database));
    if(db == NULL)
    {
        iWA_Log("alloc error");
        return NULL;
    }

    return db;
}

 
iWAbool iWA_Mysql_DatabaseOpen(iWAstruct_Mysql_Database* db)
{
    iWAint32 ret;
    iWAint8 arq = 1;

    iWA_Log("iWA_Mysql_DatabaseOpen()");
    iWA_Log("MySQL client version: %s\n", mysql_get_client_info());

    if(db == NULL)  return 0;

    db->conn = mysql_init(NULL);
    if (db->conn == NULL) 
    {
        iWA_Log("mysql_init() error");
        return 0;
    }

    ret = mysql_options(db->conn, MYSQL_OPT_RECONNECT, &arq);
    if(ret != 0)
    {
        iWA_Log("mysql_options error %d", ret);
        return 0;
    }  

    
    if (mysql_real_connect(db->conn, db->host, db->user, db->pwd, NULL, 0, NULL, 0) == NULL) 
    {
        iWA_Log("mysql_real_connect error %u: %s", mysql_errno(db->conn), mysql_error(db->conn));
        return 0;
    }
    
    ret = mysql_select_db(db->conn, db->name);
    if(ret != 0)
    {
        iWA_Log("mysql_select_db error %d", ret);

        mysql_close(db->conn);
        return 0;
    }  

    ret = mysql_query(db->conn,"set character set utf8");
    if(ret != 0)
    {
        iWA_Log("set character set utf8 error %d", ret);

        mysql_close(db->conn);
        return 0;
    }  

    return 1;
}


iWAbool iWA_Mysql_DatabaseQuery(iWAstruct_Mysql_Database* db, iWAint8* sql)
{
    iWAint32 ret;
    iWAint8 arq = 1;

    if(db == NULL || sql == NULL)  return 0;

    iWA_Log("iWA_Mysql_DatabaseQuery(%s)", sql);

    ret = mysql_query(db->conn, sql);
    if(ret != 0)
    {
        iWA_Log("mysql_query error %d", ret);
        return 0;
    }  

    return 1;
}


iWAstruct_Mysql_QueryResult* iWA_Mysql_DatabaseStoreResult(iWAstruct_Mysql_Database *db)
{
    MYSQL_RES *res;
    iWAstruct_Mysql_QueryResult *result;
    
    iWA_Log("iWA_Mysql_DatabaseStoreResult()");

    if(db == NULL)  return NULL;

    res = mysql_store_result(db->conn);
    if(res == NULL)     return NULL;

    result = (iWAstruct_Mysql_QueryResult*)iWA_Malloc(sizeof(iWAstruct_Mysql_QueryResult));
    if(result == NULL)
    {
        mysql_free_result(res);
        return NULL;
    }

    iWA_Std_memset(result, 0, sizeof(iWAstruct_Mysql_QueryResult));
    result->res = res;
    result->num = (iWAuint32)mysql_num_rows(res);
    if(result->num > 0) result->row = mysql_fetch_row(res);

    return result;
}

void iWA_Mysql_DatabaseFreeResult(iWAstruct_Mysql_QueryResult *result)
{
    iWA_Log("iWA_Mysql_DatabaseFreeResult()");

    if(result == NULL)  return;

    if(result->res != NULL)     mysql_free_result(result->res);
    iWA_Free((void*)result);
}

void iWA_Mysql_DatabaseNextRow(iWAstruct_Mysql_QueryResult *result)
{
    if(result == NULL || result->res == NULL)   return;
    
    result->row = mysql_fetch_row(result->res);
}


void iWA_Mysql_DatabaseClose(iWAstruct_Mysql_Database* db)
{
    iWA_Log("iWA_Mysql_DatabaseClose()");

    if(db == NULL)  return;

    mysql_close(db->conn);  
    iWA_Free((void*)db);
}





