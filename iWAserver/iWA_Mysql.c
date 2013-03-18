

#include "iWA.h"





iWAstruct_Mysql_Database* iWA_Mysql_DatabaseNew(void)
{
    iWA_Info("iWA_Mysql_DatabaseNew()");

    return (iWAstruct_Mysql_Database*)iWA_Malloc(sizeof(iWAstruct_Mysql_Database));
}

 
iWAbool iWA_Mysql_DatabaseOpen(iWAstruct_Mysql_Database* db)
{
    iWAint32 ret;
    iWAint8 arq = 1;

    iWA_Info("iWA_Mysql_DatabaseOpen()");
    iWA_Notice("MySQL client version: %s\n", mysql_get_client_info());

    iWA_Assert(db != NULL);

    db->conn = mysql_init(NULL);
    if (db->conn == NULL)   
    {
        iWA_Error("mysql_init() error");
        return 0;
    }

    ret = mysql_options(db->conn, MYSQL_OPT_RECONNECT, &arq);
    if(ret != 0)    
    {
        iWA_Error("mysql_options error %d", ret);
        return 0;
    }
    
    if (mysql_real_connect(db->conn, db->host, db->user, db->pwd, db->name, db->port, NULL, 0) == NULL) 
    {
        iWA_Error("mysql_real_connect error %u: %s", mysql_errno(db->conn), mysql_error(db->conn));
        return 0;
    }
    
    #if 0
    ret = mysql_select_db(db->conn, db->name);
    if(ret != 0)    
    {
        iWA_Error("mysql_select_db error %d", ret);
        return 0;
    }
    #endif
    

    ret = mysql_query(db->conn,"set character set utf8");
    if(ret != 0)    
    {
        iWA_Error("set character set utf8 error %d", ret);
        return 0;
    }
    
    return 1;
}


iWAbool iWA_Mysql_DatabaseQuery(iWAstruct_Mysql_Database* db, iWAint8* sql)
{
    iWAint32 ret;
    iWAint8 arq = 1;

    iWA_Assert(db != NULL);
    iWA_Assert(sql != NULL);

    iWA_Info("iWA_Mysql_DatabaseQuery(%s)", sql);

    ret = mysql_query(db->conn, sql);
    if(ret != 0)
    {
        iWA_Error("mysql_query error %d", ret);
        return 0;
    }  

    return 1;
}


iWAstruct_Mysql_QueryResult* iWA_Mysql_DatabaseStoreResult(iWAstruct_Mysql_Database *db)
{
    MYSQL_RES *res;
    iWAstruct_Mysql_QueryResult *result;
    
    iWA_Info("iWA_Mysql_DatabaseStoreResult()");

    iWA_Assert(db != NULL);

    res = mysql_store_result(db->conn);
    if(res == NULL)     return NULL;

    result = (iWAstruct_Mysql_QueryResult*)iWA_Malloc(sizeof(iWAstruct_Mysql_QueryResult));

    result->res = res;
    result->num = (iWAuint32)mysql_num_rows(res);
    if(result->num > 0) result->row = mysql_fetch_row(res);

    return result;
}

void iWA_Mysql_DatabaseFreeResult(iWAstruct_Mysql_QueryResult *result)
{
    iWA_Info("iWA_Mysql_DatabaseFreeResult()");

    if(result == NULL)  return;

    if(result->res != NULL)     mysql_free_result(result->res);
    iWA_Free((void*)result);
}

void iWA_Mysql_DatabaseNextRow(iWAstruct_Mysql_QueryResult *result)
{
    iWA_Info("iWA_Mysql_DatabaseNextRow()");

    iWA_Assert(result != NULL);
    iWA_Assert(result->res != NULL);
    
    result->row = mysql_fetch_row(result->res);
}



iWAuint32 iWA_Mysql_DatabaseInsertId(iWAstruct_Mysql_Database *db)
{
    iWA_Info("iWA_Mysql_DatabaseInsertId()");

    iWA_Assert(db != NULL);

    return mysql_insert_id(db->conn);
}

void iWA_Mysql_DatabaseClose(iWAstruct_Mysql_Database* db)
{
    iWA_Info("iWA_Mysql_DatabaseClose()");

    iWA_Assert(db != NULL);

    mysql_close(db->conn);  
    iWA_Free((void*)db);
}





