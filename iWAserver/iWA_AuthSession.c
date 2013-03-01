
#include "iWA.h"

typedef struct
{
    iWAbool f_used;
    struct bufferevent *bev;
}iWAstruct_AuthSession_Session;

#define iWAmacro_AUTHSESSION_SESSION_NUM_MAX   (256)

static iWAstruct_AuthSession_Session sessions[iWAmacro_AUTHSESSION_SESSION_NUM_MAX] = {0};





iWAint16 iWA_AuthSession_SessionNew(struct bufferevent *bev)
{
    iWAint32 i;

    iWA_Log("iWA_AuthSession_SessionNew()");

    if(bev == NULL)  return -1;

    for(i = 0; i < iWAmacro_AUTHSESSION_SESSION_NUM_MAX; i++)
    {
        if(sessions[i].f_used)    continue;
        
        sessions[i].f_used = 1;
        sessions[i].bev = bev;

        return i;
    }

    return -1;
}

void iWA_AuthSession_SessionEnd(struct bufferevent *bev)
{
    iWAint32 i;

    iWA_Log("iWA_AuthSession_SessionEnd()");

    if(bev == NULL)  return;

    for(i = 0; i < iWAmacro_AUTHSESSION_SESSION_NUM_MAX; i++)
    {
        if(sessions[i].f_used && sessions[i].bev == bev)
        {
            sessions[i].f_used = 0;
            sessions[i].bev = NULL;     
            
            return;
        }
    }
}

iWAint16 iWA_AuthSession_SessionId(struct bufferevent *bev)
{
    iWAint32 i;

    iWA_Log("iWA_AuthSession_SessionId()");

    if(bev == NULL)  return -1;

    for(i = 0; i < iWAmacro_AUTHSESSION_SESSION_NUM_MAX; i++)
    {
        if(sessions[i].f_used && sessions[i].bev == bev)  return i;
    }

    return -1;
}

struct bufferevent* iWA_AuthSession_SessionBev(iWAint16 id)
{
    iWA_Log("iWA_AuthSession_SessionBev()");

    if(id < 0 || id >= iWAmacro_AUTHSESSION_SESSION_NUM_MAX)  return NULL;

    if(!sessions[id].f_used)    return NULL;

    return sessions[id].bev;
}



