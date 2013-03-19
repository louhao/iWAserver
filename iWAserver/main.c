//
//  main.c
//  iWAserver
//
//  Created by louhao on 13-1-25.
//  Copyright (c) 2013年 louhao. All rights reserved.
//

/*
 This exmple program provides a trivial server program that listens for TCP
 connections on port 9995.  When they arrive, it writes a short message to
 each client connection, and closes each connection once it is flushed.
 
 Where possible, it exits cleanly in response to a SIGINT (ctrl-c).
 */


#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>

#include "iWA.h"




int main(int argc, char *argv[])
{
    iWA_Log_Init();

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

    iWA_AuthServer_Main();
    iWA_GameServer_Main();

    
    while(1) sleep(10);

    return 1;
}















