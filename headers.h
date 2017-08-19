#ifndef HEADERS_H
#define HEADERS_H
//LIBRARIES
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/if_ether.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <sys/time.h>
#include <stdlib.h>
#include <postgresql/libpq-fe.h>
#include <time.h>

/*GLOBALS*/
////STRUCTS

//Generic request/response basic structure
typedef struct genif
{
  //Owned addresses
  unsigned char mac[6];
  unsigned char ip[4];
  //Target addresses (same device not obligatory, i.e, global IP vs. local MAC)
  unsigned char tgt_mac[6];
  unsigned char tgt_ip[4];
  //Local Gateway information and subnet mask
  unsigned char gateway_mac[6];
  unsigned char gateway_ip[4];
  unsigned char subn[4];
} genif;

struct pingdata
{
  genif * s_echo;
  int socket_id;
  int index_sd;
};

struct pping_ip
{
  unsigned char * IP[4];
};

////FUNCTIONS

//Format
//Arrow Prompt
static void arrow(){fputs("-> ",stdout);}
//Remove Whitespace

char * RWS(char * str,char rmch)
{
  char * nstr;
  size_t length = strlen(str);
  int nowsp=0, lngt = (int)length;
  while(str[nowsp]!=rmch)nowsp++;
  nstr=malloc((size_t)nowsp);
  if(nowsp==length) return str;
  else memcpy(nstr,str,nowsp);
  return nstr;
}
//Concatenate Three Strings
static char * coolcat(char * head,char * info,char * tail)
{
  size_t tsize = strlen(head)+strlen(RWS(info,' '))+strlen(tail)+1;
  char * srcat = malloc(tsize+1);
  memcpy(srcat,head,tsize+1);
  strcat(srcat,info);
  strcat(srcat,tail);
  return srcat;
}
//Get Gateway
char * getGW()
{
  FILE *fp;
  int i;
  char * gw = malloc(16);
  fp=popen("route | grep 'default' | awk '{print $2}'", "r");
  fgets(gw,16,fp);
  return gw;
}
//Checksum
unsigned int checksum(unsigned char * bc, int lngth)
{
  int accum=0;
  for(int i=0;i<lngth;i++)
    {
      accum=accum+((bc[i*2])<<8|bc[i*2+1]);
      if(accum>65535)accum=(accum&65535)+((accum&65536)>>16);
    }
  return 0xFFFF^accum;
}

////Variables
//MAC
const u_char BROADCAST[] =     {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
const u_char EMPTYMAC[] =      {0x00,0x00,0x00,0x00,0x00,0x00};
const u_char IP_ETH[] =        {0x08,0x00};
const u_char ARP_ETH[] =       {0x08,0x06};
//ARP
const u_char HW_TYPE[] =       {0x00,0x01};
const u_char OPCODE_REQ[] =    {0x00,0x01};
const u_char OPCODE_REP[] =    {0x00,0x02};
const u_char HW_LG_ADD[] =     {0x06,0x04};
//IP
const u_char IP_PROTO[] =      {0x08,0x00};
const u_char IP_ID[] =         {0x00,0x00};
const u_char V_LNGTH[] =       {0x45};
const u_char DIFF_SERV[] =     {0x00};
const u_char T_SIZE_ECHO[] =   {0x00,0x48};
const u_char F_OFFSET[] =      {0x40,0x00};
const u_char TTL_PROT[] =      {0x40,0x01};
const u_char INIT_CHKSM[] =    {0x00,0x00};
//ICMP
const u_char ICMP_REQ[] =      {0x08,0x00};
const u_char ICMP_RES[] =      {0x00,0x00};
const u_char ICMP_TTL[] =      {0x0b};
const u_char ICMP_URN[] =      {0x03,0x00};
const u_char REQ_ID_SQ[] =     {0x00,0x00,0x00,0x00};
const u_char TIMESTAMP[] =     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
const u_char PING_MSG[] =      {
  0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,
  0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,
  0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,
  0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,
  0x60,0x61,0x62,0x63};

//LOCAL HEADERS
#include "socket.h"
#include "packet.h"
#include "control.h"

#endif
