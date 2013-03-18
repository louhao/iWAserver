

#include "iWA.h"

static iWAuint32 malloc_count = 0;

iWAuint32 iWA_Memory_Count(void)
{
    return malloc_count;
}

void* iWA_Memory_Alloc(iWAuint32 size)
{
#if !iWAmarco_CONFIG_MALLOC_DEBUG_OPTION

    iWAuint8* pp = (iWAuint8*)iWA_Std_malloc(size);

    if(pp == NULL)  iWA_Fatal("Memory Alloc %d Bytes Fail", size);

#else

    iWAuint32 ss = size + 16; /* add header for storing size and alignment to 16 bytes */
    iWAuint8* pp = (iWAuint8*)iWA_Std_malloc(ss);

    if(pp == NULL)  iWA_Fatal("Memory Alloc %d Bytes Fail", ss);

    pp[0] = (iWAuint8)ss;
    pp[1] = (iWAuint8)(ss >> 8);
    pp[2] = (iWAuint8)(ss >> 16);
    pp[3] = (iWAuint8)(ss >> 24);
    
    malloc_count += ss;
    pp += 16;

#endif

    iWA_Std_memset(pp, 0, size);

    // iWA_Debug("iWA_Memory_Alloc %d", ss);         

    return (void*)pp;
}

void iWA_Memory_Free(void* p)
{
#if !iWAmarco_CONFIG_MALLOC_DEBUG_OPTION

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

    // iWA_Debug("iWA_Free %d", ss);

#endif    
}


void *iWA_Memory_Realloc(void *p, iWAuint32 size)      /*only match to mem.c of openssl, not be called really */
{
    //iWA_Debug("iWA_Memory_Realloc() %d", size);

    return realloc(p, size);
}















