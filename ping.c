#include "../libs/headers.h"
#define SZPDATA 1514

int main(int argc, char * argv[])
{
  if(argc!=3){printf("[Dos argumentos]\n\n");return 0;}
  if(atoi(argv[1])>255){printf("Límite: 255\n\n");return 0;}
  srand(time(NULL));
  genif s_echo;
  struct pingdata pingst;
  int packet_socket,index,ping_iter;
  unsigned char pdataS[SZPDATA],pdataR[SZPDATA];
  packet_socket = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
  if(packet_socket==-1) printf("\n[Error al abrir el socket]\n");
  else
    {
      printf("\n[Éxito al abrir el socket]\n");
      if(index=socketData(packet_socket,&s_echo))//Check socket
	{
	  fmtpSocketInfo(s_echo); //Print socket info
	  tgt_arp(&s_echo,pdataS,pdataR,packet_socket,index,'g'); //Get gateway
	  IP_d(s_echo.tgt_ip,argv[2],'m');
	  
	  pingst.s_echo = &s_echo;
	  pingst.socket_id = packet_socket;
	  pingst.index_sd = index;
	    
	  pingTool(&pingst,pdataS,pdataR,atoi(argv[1]));
	}
    }
  close(packet_socket);
  return 1;
}
