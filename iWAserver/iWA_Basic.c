

#include "iWA.h"


void iWA_Log(const iWAint8* pszFormat, ...)
{
#define iWA_LOG_BUF_LENGTH   (256)

    iWAint8 buf[iWA_LOG_BUF_LENGTH];

    va_list args;
    va_start(args, pszFormat);        
    vsnprintf(buf, iWA_LOG_BUF_LENGTH, pszFormat, args);
    va_end(args);

#ifndef ANDROID    
    fprintf(stderr, "[iAW]  %s\n",  buf);
#else
    __android_log_print(3, "iWA debug info",  buf);
#endif  
}

void iWA_Dump(iWAuint8 *p, iWAint32 len)
{
#define iWA_DUMP_LINE_LENGTH         (8)

    iWAint32 i;
    iWAint8 c[20];
    iWAint8 c_buf[2*iWA_DUMP_LINE_LENGTH+2];
    iWAint8 buf[6*iWA_DUMP_LINE_LENGTH+2];

    if(!p || len == 0)	return;

    iWA_Log("[iWA_Dump 0x%08x, %d]", p, len);

    for(i = 0; i < len; i++)
    {
        if(i % iWA_DUMP_LINE_LENGTH == 0)	
        {
            c_buf[0] = 0;
            buf[0] = 0;
        }

        if(*p == '%')
        {
            c[0] = '%';
            c[1] = '%';
            c[2] = 0;
        }
    	 else if(*p >= 0x20 && *p <= 0x7e)
    	 {
            sprintf(c, "%c", *p);
        }
        else
        {
            sprintf(c, ".");
        }
        strcat(c_buf, c);

    	 
        sprintf(c, "0x%02x, ", *p++);
        strcat(buf, c);

    	 if(i % iWA_DUMP_LINE_LENGTH == iWA_DUMP_LINE_LENGTH - 1)  
        {
    	    iWA_Log(c_buf);
    	    iWA_Log(buf);    	    
        }    	    
    }

    if(len % iWA_DUMP_LINE_LENGTH != 0)   
    {
        iWA_Log(c_buf);
        iWA_Log(buf);    	    
    }
}






#if iWAmarco_MALLOC_DEBUG_OPTION

static iWAuint32 malloc_count = 0;

iWAuint32 iWA_MemCount(void)
{
    return malloc_count;
}

void iWA_Mprint(void)
{
    iWA_Log("mem count : %d", malloc_count);
}

#else

void iWA_Mprint(void) {}

#endif

void* iWA_Malloc(iWAuint32 size)
{
#if !iWAmarco_MALLOC_DEBUG_OPTION

    return (void*)iWA_Std_malloc(size);

#else

    iWAuint32 ss = size + 16; /* add header for storing size and alignment to 16 bytes */
    iWAuint8* pp = (iWAuint8*)iWA_Std_malloc(ss);

    if(pp != NULL)   /* store mem block size at head */
    {
        pp[0] = (iWAuint8)ss;
        pp[1] = (iWAuint8)(ss >> 8);
        pp[2] = (iWAuint8)(ss >> 16);
        pp[3] = (iWAuint8)(ss >> 24);
        
        malloc_count += ss;
        pp += 16;

        // iWA_Log("iWA_Malloc %d", ss);         
    }    

    return (void*)pp;
    
#endif
}

void iWA_Free(void* p)
{
#if !iWAmarco_MALLOC_DEBUG_OPTION

    if(p != NULL)   iWA_Std_free(p);

#else

    iWAuint32 ss;  
    iWAuint8* pp = (iWAuint8*)p;

    if(pp == NULL)   return;

    /* read size */
    pp -= 16;  
    ss = (iWAuint32)pp[0] |((iWAuint32)pp[1] << 8) | ((iWAuint32)pp[2] << 16) | ((iWAuint32)pp[3] << 24);
    
    malloc_count -= ss;

    iWA_Std_free((void*)pp);

    // iWA_Log("iWA_Free %d", ss);

#endif    
}


void *iWA_Realloc(void *p, iWAuint32 size)      /*only match to mem.c of openssl, not be called really */
{
    iWA_Log("iWA_Realloc %d", size);

    return realloc(p, size);
}















