
#include "iWA.h"



#define iWAmacro_GAMESESSION_SESSION_NUM_MAX   (256)

static iWAstruct_GameSession_Session sessions[iWAmacro_GAMESESSION_SESSION_NUM_MAX] = {0};


iWAstruct_GameSession_Session* iWA_GameSession_AllocSession(struct bufferevent *bev)
{
    iWAint32 i;

    iWA_Info("iWA_GameSession_AllocSession()");

    iWA_Assert(bev != NULL);

    for(i = 0; i < iWAmacro_GAMESESSION_SESSION_NUM_MAX; i++)
    {
        if(sessions[i].f_used)    continue;

        iWA_Std_memset(&sessions[i], 0, sizeof(iWAstruct_GameSession_Session));
        
        sessions[i].f_used = 1;
        sessions[i].bev = bev;
        sessions[i].status = iWAenum_GAMESERVER_SESSION_STATUS_UNAUTH;
        
        return &sessions[i];
    }

    iWA_Error("Alloc Game Session Error");

    return NULL;
}

void iWA_GameSession_FreeSession(struct bufferevent *bev)
{
    iWAint32 i;

    iWA_Info("iWA_GameSession_FreeSession()");

    iWA_Assert(bev != NULL);

    for(i = 0; i < iWAmacro_GAMESESSION_SESSION_NUM_MAX; i++)
    {
        if(sessions[i].f_used && sessions[i].bev == bev)
        {
            sessions[i].f_used = 0;            
            return;
        }
    }
}

iWAstruct_GameSession_Session* iWA_GameSession_GetSession(struct bufferevent *bev)
{
    iWAint32 i;

    iWA_Info("iWA_GameSession_GetSession()");

    iWA_Assert(bev != NULL);

    for(i = 0; i < iWAmacro_GAMESESSION_SESSION_NUM_MAX; i++)
    {
        if(sessions[i].f_used && sessions[i].bev == bev)  return &sessions[i];
    }

    return NULL;
}





