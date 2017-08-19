
#include "../libs/headers.h"

int main(int argc, char * argv[])
{  
  genif s_arp,defended;
  int packet_socket,index;
  char defendedIP[16];
  unsigned char pdataS[1514],pdataR[1514];
  packet_socket = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
  if(packet_socket==-1) printf("\n[Error al abrir el socket]\n");
  else
    {
      printf("\n[Éxito al abrir el socket]\n");
      if(index=socketData(packet_socket,&s_arp))
	{
	  /*GET SOCKET INFO*/
	  fmtpSocketInfo(s_arp);
	  /*ARP SCANNER (WITH DB)*/
	  arp_scanner(&s_arp,pdataS,pdataR,packet_socket,index);
	  /*ARP SINGLE REQUEST*/
	  //tgt_arp(&s_arp,pdataS,pdataR,packet_socket,index,'u');
	  /*ARP TRANSPARENT SERVER*/
	  puts("Defender IP");
	  scanf("%[^\n]",defendedIP);
	  IP_d(defended.ip,defendedIP,'m');
	  memcpy(&defended.mac,getMACfromDB(defendedIP),6);
	  while(1)
	    {
	      if(recvpdata_timeout_attacker(packet_socket,pdataR,&s_arp))
		{
		  ARP_Gresponse(pdataS,&defended);
		  sendpdata(pdataS,packet_socket,index,42);
		}
	    }
	}
      
    }
  close(packet_socket);
  return 0;
}
