#ifndef PACKETC_H
#define PACKETC_H
#define SZPDATA 1514

void printpdata(unsigned char *, int);
void insDIR(PGresult *,PGconn *,char *,char *);
int DBConnection(PGconn *);
void ARP_Gresponse(unsigned char * pdata,genif * s_arp)
{
  //MAC Header
  memcpy(pdata+0,BROADCAST,6);
  memcpy(pdata+6,s_arp->mac,6);
  memcpy(pdata+12,ARP_ETH,2);
  //ARP Request
  memcpy(pdata+14,HW_TYPE,2);
  memcpy(pdata+16,IP_PROTO,2);
  memcpy(pdata+18,HW_LG_ADD,2);
  memcpy(pdata+20,OPCODE_REQ,2);
  memcpy(pdata+22,s_arp->mac,6);
  memcpy(pdata+28,s_arp->ip,4);
  memcpy(pdata+32,s_arp->mac,6);
  memcpy(pdata+38,s_arp->ip,4);
}

void ARP_Erequest(unsigned char * pdata,genif * s_arp,char opt)
{
  //MAC Header
  memcpy(pdata+0,BROADCAST,6);
  memcpy(pdata+6,s_arp->mac,6);
  memcpy(pdata+12,ARP_ETH,2);
  //ARP Request
  memcpy(pdata+14,HW_TYPE,2);        //Hardware Type
  memcpy(pdata+16,IP_PROTO,2);       //IP Protocol
  memcpy(pdata+18,HW_LG_ADD,2);      //Hardware Size, Logic Size
  memcpy(pdata+20,OPCODE_REQ,2);     //OPCode
  memcpy(pdata+22,s_arp->mac,6);     //Mac Origin
  memcpy(pdata+28,s_arp->ip,4);      //IP Origin
  memcpy(pdata+32,EMPTYMAC,6);       //Mac Destination
  if(opt=='u')                       //IP Destination
    memcpy(pdata+38,s_arp->tgt_ip,4);  
  else if(opt=='g')                  //Gateway for PING purposes
    memcpy(pdata+38,s_arp->gateway_ip,4);
}

void ECHO_Erequest(unsigned char * pdata,genif * s_echo)
{
  //MAC Header
  memcpy(pdata+0,s_echo->gateway_mac,6);
  memcpy(pdata+6,s_echo->mac,6);
  memcpy(pdata+12,IP_ETH,2);
  //IP Header
  memcpy(pdata+14,V_LNGTH,1);          //Version & Internet Header Length
  memcpy(pdata+15,DIFF_SERV,1);        //Differentiated Services
  memcpy(pdata+16,T_SIZE_ECHO,2);      //Total Datagram Size
  memcpy(pdata+18,IP_ID,2);            //IP Identifier
  memcpy(pdata+20,F_OFFSET,2);         //Do not Fragment
  memcpy(pdata+22,TTL_PROT,2);         //Time To Live
  memcpy(pdata+24,INIT_CHKSM,2);       //Checksum
  memcpy(pdata+26,s_echo->ip,4);       //Source IP
  memcpy(pdata+30,s_echo->tgt_ip,4);   //Target IP
  //ICMP Header
  memcpy(pdata+34,ICMP_REQ,2);         //ICMP Request - No options
  memcpy(pdata+36,INIT_CHKSM,2);       //Initial Checksum
  memcpy(pdata+38,REQ_ID_SQ,4);        //Identifier set to 0
  memcpy(pdata+42,PING_MSG,sizeof(PING_MSG));
}

int sendpdata(unsigned char * pdata,int ds,int index, int size)
{
  int tam;
  struct sockaddr_ll interfaz;
  //printpdata(pdata,60);
  memset(&interfaz,0x00,sizeof(interfaz));
  interfaz.sll_family=PF_PACKET;
  interfaz.sll_protocol=htons(ETH_P_ALL);
  interfaz.sll_ifindex=index;
  tam=sendto(ds,pdata,size,0,(struct sockaddr *)&interfaz,sizeof(interfaz));
  if(tam==-1){perror("\nError al enviar"); return 1;}
  return 0;
}

void arp_recvpdata(int ds, unsigned char * pdata,genif * s_arp,char opt)
{
  int tam;
  
  while(1)
    {
      if((tam = recvfrom(ds,pdata,1514,0,NULL,0))==-1)perror("\nError al recibir");
      else if(!memcmp(pdata+0,s_arp->mac,6)&&!memcmp(pdata+12,ARP_ETH,2)&&
	      !memcmp(pdata+20,OPCODE_REP,2))
	{
	  if(!memcmp(pdata+28,s_arp->tgt_ip,4))
	    {memcpy(s_arp->tgt_mac,pdata+6,6);print32bit(s_arp->tgt_mac);}
	  else if (!memcmp(pdata+28,s_arp->gateway_ip,4))
	    {memcpy(s_arp->gateway_mac,pdata+6,6);}
	  if(opt=='g')
	    {printf("\nPuerta de enlace: ~ ");print32bit(s_arp->gateway_mac);puts("\n");}
	  break;
	}
    }
}

int echo_recvpdata(int ds, unsigned char * pdata,genif * s_echo, short * ttl)
{
  int tam;
  struct timeval start, end;
  long mtime=0, seconds, miliseconds;
  gettimeofday(&start,NULL);
  while(mtime<3000)
    {
      tam = recvfrom(ds,pdata,1514,0,NULL,0);
      if(tam==-1);
      else if(!memcmp(pdata+0,s_echo->mac,6)&&!memcmp(pdata+6,s_echo->gateway_mac,6)&&
	      !memcmp(pdata+12,IP_ETH,2))
	{
	  gettimeofday(&end,NULL);
	  seconds = end.tv_sec - start.tv_sec;
	  miliseconds = end.tv_usec - start.tv_usec;
	  mtime = (seconds*1000 + miliseconds/1000.0) +0.5;

	  if(!memcmp(pdata+34,ICMP_TTL,1))
	    {printf("\n%d\t",*ttl);print16bit(pdata+26);puts("\t\tOK");}
	  if(!memcmp(pdata+34,ICMP_RES,2))
	    {printf("\n%d\t",*ttl);print16bit(pdata+26);printf("\t\tAlcanzado t=%dms\n",mtime);return 0;}
	  if(!memcmp(pdata+34,ICMP_URN,2)&&*ttl>0)
	    {printf("\n%d\t",*ttl);print16bit(pdata+26);puts("\t\tRed Inalcanzable");}
	  return 1;
	}
    }
  return 1;
}
int pathping_recvpdata(int ds, unsigned char * pdata,genif * s_echo, int ttl,struct pping_ip * ips)
{
  int tam;
  struct timeval start, end;
  long mtime=0, seconds, miliseconds;
  gettimeofday(&start,NULL);
  while(mtime<3000)
    {
      if((tam = recvfrom(ds,pdata,1514,0,NULL,0))==-1)perror("\nError al recibir");
      else if(!memcmp(pdata+0,s_echo->mac,6)&&!memcmp(pdata+6,s_echo->gateway_mac,6)&&
	      !memcmp(pdata+12,IP_ETH,2))
	{
	  gettimeofday(&end,NULL);
	  seconds = end.tv_sec - start.tv_sec;
	  miliseconds = end.tv_usec - start.tv_usec;
	  mtime = (seconds*1000 + miliseconds/1000.0) +0.5;
	  
	  if(!memcmp(pdata+34,ICMP_TTL,1))
	    {printf("\n%d\t",ttl);print16bit(pdata+26);puts("\t\tOK");}
	  if(!memcmp(pdata+34,ICMP_RES,2))
	    {printf("\n%d\t",ttl);print16bit(pdata+26);printf("\t\tAlcanzado t=%dms\n",mtime);return 0;}
	  if(!memcmp(pdata+34,ICMP_URN,2))
	    {printf("\n%d\t",ttl);print16bit(pdata+26);puts("\t\tRed Inalcanzable");return 0;}
	  return 1;
	}
    }
}

void arp_recvpdata_timeout(int ds, unsigned char * pdata,genif * s_arp)
{
  PGconn * conn;
  PGresult * res;
  
  int tam,flag=0;
  struct timeval start, end;
  long mtime=0, seconds, miliseconds;
  conn = PQconnectdb("dbname=chatdb host=localhost user=e_chat password=echat");
  gettimeofday(&start,NULL);
  while(mtime<200)
    {
      tam = recvfrom(ds,pdata,1514,MSG_DONTWAIT,NULL,0);
      if(!memcmp(pdata+0,s_arp->mac,6)&&
	 !memcmp(pdata+28,s_arp->tgt_ip,4)&&
	 !memcmp(pdata+20,OPCODE_REP,2)&&
	 !memcmp(pdata+12,ARP_ETH,2))
	{
	  flag=1;
	  //printpdata(pdata,60);
	}
      gettimeofday(&end,NULL);

      seconds = end.tv_sec - start.tv_sec;
      miliseconds = end.tv_usec - start.tv_usec;

      mtime = (seconds*1000 + miliseconds/1000.0) +0.5;
      if(flag==1)
	{
	  unsigned char _mac[]={pdata[22],pdata[23],pdata[24],pdata[25],pdata[26],pdata[27],'\0'};
	  unsigned char _ip[]={pdata[28],pdata[29],pdata[30],pdata[31],'\0'};
	  unsigned char macstr[32];
	  unsigned char ipstr[32];

	  sprintf(macstr,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
		  _mac[0],_mac[1],_mac[2],_mac[3],_mac[4],_mac[5]);
	  sprintf(ipstr,"%d.%d.%d.%d",_ip[0],_ip[1],_ip[2],_ip[3]);
	  res = PQexec(conn,coolcat("insert into d_address(macdir,ipdir) values ('",
				    coolcat(RWS(macstr,' '),"','",RWS(ipstr,' ')),
				    "')"));
	  puts("");print32bit(_mac);
	  puts("");print16bit(_ip);
	  if (PQresultStatus(res) != PGRES_COMMAND_OK)perror(PQresultErrorMessage(res));
	  PQclear(res);
	  flag = 0;
	  break;
	}
    }
  PQfinish(conn);
}
int recvpdata_timeout_attacker(int ds, unsigned char * pdata,genif * s_arp)
{
  genif defendTerm;
  unsigned char ipstr[32];
  int tam,flag=0,rec_count;
  struct timeval start, end;
  long mtime=0, seconds, miliseconds;
  
  gettimeofday(&start,NULL);
  while(mtime<100)
    {
      tam = recvfrom(ds,pdata,1514,MSG_DONTWAIT,NULL,0);
      if(!memcmp(pdata+0,BROADCAST,6)&&!memcmp(pdata+28,s_arp->ip,4)&&
	 memcmp(pdata+6,s_arp->mac,2)&&!memcmp(pdata+12,ARP_ETH,2))
	{flag=1;}
      
      gettimeofday(&end,NULL);

      seconds = end.tv_sec - start.tv_sec;
      miliseconds = end.tv_usec - start.tv_usec;

      mtime = (seconds*1000 + miliseconds/1000.0) +0.5;
      if(flag==1)return 1;
    }
  //  PQfinish(conn);
}

void setTTL(unsigned char * pdata,short i)
{
  *(pdata+22) = (unsigned char)((i >> 0) & 0xff);
}

void pingCounter(unsigned char * pdata,unsigned short val)
{
  unsigned short pid = rand()%65535;
  if(val<65536)
    {
      *(pdata+40) = (unsigned char)((val >> 8) & 0xff);
      *(pdata+41) = (unsigned char)((val >> 0) & 0xff);
    }
}

void generateChecksum(unsigned char * pdata,genif * s_echo,unsigned short ttl,unsigned short iter)
{
  unsigned char chksm[2];
  unsigned short cs_ip,cs_icmp;
  unsigned short icmp_id = rand()%65535;
  unsigned short ip_id = rand()%65535;
  
  memset(pdata,0x00,SZPDATA);
  ECHO_Erequest(pdata,s_echo);
  //IP  
  *(pdata+18) = (unsigned char)((ip_id >> 8) & 0xff);
  *(pdata+19) = (unsigned char)((ip_id >> 0) & 0xff);
  setTTL(pdata,ttl);
  cs_ip=checksum(pdata+14,10);
  chksm[0] = (unsigned char)((cs_ip >> 8) & 0xff);
  chksm[1] = (unsigned char)((cs_ip >> 0) & 0xff);
  memcpy(pdata+24,chksm,2);
  //ICMP
  *(pdata+38) = (unsigned char)((icmp_id >> 8) & 0xff);
  *(pdata+39) = (unsigned char)((icmp_id >> 0) & 0xff);
  pingCounter(pdata,iter);
  cs_icmp=checksum(pdata+34,26);
  chksm[0] = (unsigned char)((cs_icmp >> 8) & 0xff);
  chksm[1] = (unsigned char)((cs_icmp >> 0) & 0xff);
  memcpy(pdata+36,chksm,2);
  //printpdata(pdata,86);
}

void pingTool(struct pingdata * ping,unsigned char * pdataS, unsigned char * pdataR, int iter)
{
  printf("ID\tIP\t\t\tInfo\n-------------------------------------------------|");
  for(short i=1;i<=iter;i++)
    {
      generateChecksum(pdataS,ping->s_echo,64,i);
      sendpdata(pdataS,ping->socket_id,ping->index_sd,86);
      echo_recvpdata(ping->socket_id,pdataR,ping->s_echo,&i);
    }
  puts("-------------------------------------------------|");
  puts("");
}

void tracertTool(struct pingdata * ping,unsigned char * pdataS, unsigned char * pdataR, int iter)
{
  char reached = 1;
  printf("TTL\tIP\t\t\tInfo\n-------------------------------------------------|");
  for(short i=1;i<iter;i++)
    {
      generateChecksum(pdataS,ping->s_echo,i,1);
      sendpdata(pdataS,ping->socket_id,ping->index_sd,86);
      if(!echo_recvpdata(ping->socket_id,pdataR,ping->s_echo,&i)){reached=1;break;}
      reached=0;
    }
  puts("-------------------------------------------------|");
  if(!reached)printf("[!]\t \t Intentos agotados");
  puts("");
}

void pathPing(struct pingdata * ping,unsigned char * pdataS, unsigned char * pdataR, int iter)
{
  struct pping_ip * ips;
  char reached = 1;
  printf("TTL\tIP\t\t\tInfo\n-------------------------------------------------|");
  for(short i=1;i<iter;i++)
    {
      generateChecksum(pdataS,ping->s_echo,i,1);
      sendpdata(pdataS,ping->socket_id,ping->index_sd,86);
      if(!echo_recvpdata(ping->socket_id,pdataR,ping->s_echo,&i)){reached=1;break;}
      reached=0;
    }
  puts("-------------------------------------------------|");
  if(!reached)printf("[!]\t \t Intentos agotados");
  puts("");
}

#endif
