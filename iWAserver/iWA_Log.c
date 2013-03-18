
#include "iWA.h"




static log4c_category_t* category;

void iWA_Log_Init(void)
{
    log4c_init();

    category = log4c_category_get("iWA"); 

    //iWA_Log_Test();
}


void iWA_Log_Trace(int priority, const char *fmt , ...)  
{  
    va_list ap;  
      
    iWA_Assert(category != NULL);  
  
    va_start(ap, fmt);  
    log4c_category_vlog(category, priority , fmt , ap);  
    va_end(ap);  
}  

void iWA_Log_TraceEx(const char *file, int line, const char *fun, int priority, const char *fmt , ...)  
{  
    char new_fmt[1024];  
    const char *head_fmt = "[file:%s, line:%d, function:%s]";   
    va_list ap;  
    int n;  
      
    iWA_Assert(category != NULL);  
    n = iWA_Std_sprintf(new_fmt, head_fmt , file , line , fun);  
    iWA_Std_strcat(new_fmt + n , fmt);  
  
    va_start(ap , fmt);  
    log4c_category_vlog(category, priority, new_fmt , ap);  
    va_end(ap);  
}  


void iWA_Log_Dump(iWAuint8 *p, iWAint32 len)  
{
#define iWA_DUMP_LINE_LENGTH         (8)

    iWAint32 i;
    iWAint8 c[20];
    iWAint8 c_buf[2*iWA_DUMP_LINE_LENGTH+2];
    iWAint8 buf[6*iWA_DUMP_LINE_LENGTH+2];

    if(!p || len == 0)	return;

    iWA_Debug("[iWA_Dump 0x%08x, %d]", p, len);

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
    	    iWA_Debug(c_buf);
    	    iWA_Debug(buf);    	    
        }    	    
    }

    if(len % iWA_DUMP_LINE_LENGTH != 0)   
    {
        iWA_Debug(c_buf);
        iWA_Debug(buf);    	    
    }
}

void iWA_Log_Test(void)
{
    iWAint16 i = 0;
    iWAuint8 buf[256];

    for(i = 0; i < sizeof(buf); i++)    buf[i] = i;

    iWA_Dump(buf, i);
    i = 0;
    
    iWA_Debug("%d. [Debug] DebugTime Info, Temporary", ++i);
    iWA_Info("%d. [Info] DebugTime Info, Normally", ++i);
    iWA_Notice("%d. [Notice] RunTime Log, Routine", ++i);
    iWA_Warn("%d. [Warn] RunTime Log, Something Maybe On Guard", ++i);
    iWA_Error("%d. [Error] Run Into Error Case, Recoverable, App Keep Working", ++i);
    iWA_Fatal("%d. [Fatal] Run Into Error Case, Unrecoverable, App Abort", ++i);
    iWA_Assert(i == 0);
}

#if 0
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
#endif


