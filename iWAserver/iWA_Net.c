

#include "iWA.h"


void iWA_Net_WritePacketUint16(iWAuint8 *packet, iWAuint16 data)
{
    packet[0] = (iWAuint8)data;
    packet[1] = (iWAuint8)(data >> 8);
}

void iWA_Net_WritePacketUint32(iWAuint8 *packet, iWAuint32 data)
{
    packet[0] = (iWAuint8)data;
    packet[1] = (iWAuint8)(data >> 8);
    packet[2] = (iWAuint8)(data >> 16);
    packet[3] = (iWAuint8)(data >> 24);
}

iWAuint16 iWA_Net_ReadPacketUint16(iWAuint8 *packet)
{
    return  (iWAuint16)packet[0] |((iWAuint16)packet[1] << 8);
}

iWAuint32 iWA_Net_ReadPacketUint32(iWAuint8 *packet)
{
    return  (iWAuint32)packet[0] |((iWAuint32)packet[1] << 8) | ((iWAuint32)packet[2] << 16) | ((iWAuint32)packet[3] << 24);
}

/* return write byte num */
iWAuint32 iWA_Net_WritePacketBigNumber(iWAuint8 *packet, BIGNUM *bn)
{
    iWAuint32 len;
    iWAuint32 a,b;
    iWAuint8 c;    

    if(bn == NULL)  return 0;

    /* convert */
    len = BN_bn2bin(bn, packet);

    /* should do reverse */
    for(a = 0, b = len-1; a < len/2; a++, b--)
    {
        c = packet[a];
        packet[a] = packet[b];
        packet[b] = c;
    }  

    return len;
}

void iWA_Net_ReadPacketBigNumber(iWAuint8 *packet, iWAuint32 len, BIGNUM *bn)
{
#define iWAmacro_AUTH_READ_PACKET_BIGNUMBER_SIZE        (128)

    iWAuint8 bn_bin[iWAmacro_AUTH_READ_PACKET_BIGNUMBER_SIZE];   /* support maxium 1024 bits BN */
    iWAint32 i, j;

    if(len == 0 || len > iWAmacro_AUTH_READ_PACKET_BIGNUMBER_SIZE || bn == NULL)    return;

    for(i = 0, j = len-1; i < len; i++, j--)    bn_bin[i] = packet[j];    
    BN_bin2bn(bn_bin, len, bn);     
}

/* return packet read length, include tail '\0' */
iWAuint32 iWA_Net_ReadPacketAsciiString(iWAuint8 *packet, iWAuint8 *str_buf, iWAuint32 buf_size)
{
    iWAuint32 i = 0;
    
    if(str_buf == NULL || buf_size == 0)    return 0;

    while(packet[i] != 0x00 && i < buf_size)
    {
        str_buf[i] = packet[i];
        i++;
    }

    if(i >= buf_size)
        str_buf[buf_size - 1] = 0x00;
    else
        str_buf[i] = 0x00;

    return (i + 1);
}



