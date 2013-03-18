
#include "iWA.h"



#define iWAmacro_AUTHSESSION_SESSION_NUM_MAX   (256)

static iWAstruct_AuthSession_Session sessions[iWAmacro_AUTHSESSION_SESSION_NUM_MAX] = {0};


iWAstruct_AuthSession_Session* iWA_AuthSession_AllocSession(struct bufferevent *bev)
{
    iWAint32 i;

    iWA_Info("iWA_AuthSession_AllocSession()");

    iWA_Assert(bev != NULL);

    for(i = 0; i < iWAmacro_AUTHSESSION_SESSION_NUM_MAX; i++)
    {
        if(sessions[i].f_used)    continue;

        iWA_Std_memset(&sessions[i], 0, sizeof(iWAstruct_AuthSession_Session));
        
        sessions[i].f_used = 1;
        sessions[i].bev = bev;

        return &sessions[i];
    }

    iWA_Error("Alloc Auth Session Error");

    return NULL;
}


void iWA_AuthSession_FreeSession(struct bufferevent *bev)
{
    iWAint32 i;

    iWA_Info("iWA_AuthSession_FreeSession()");

    iWA_Assert(bev != NULL);

    for(i = 0; i < iWAmacro_AUTHSESSION_SESSION_NUM_MAX; i++)
    {
        if(sessions[i].f_used && sessions[i].bev == bev)
        {
            sessions[i].f_used = 0;  
            
            return;
        }
    }
}


iWAstruct_AuthSession_Session* iWA_AuthSession_GetSession(struct bufferevent *bev)
{
    iWAint32 i;

    iWA_Info("iWA_AuthSession_GetSession()");

    iWA_Assert(bev != NULL);

    for(i = 0; i < iWAmacro_AUTHSESSION_SESSION_NUM_MAX; i++)
    {
        if(sessions[i].f_used && sessions[i].bev == bev)  return &sessions[i];
    }

    return NULL;
}

struct bufferevent* iWA_AuthSession_SessionBev(iWAint16 id)
{
    iWA_Info("iWA_AuthSession_SessionBev()");

    if(id < 0 || id >= iWAmacro_AUTHSESSION_SESSION_NUM_MAX)  return NULL;

    if(!sessions[id].f_used)    return NULL;

    return sessions[id].bev;
}










