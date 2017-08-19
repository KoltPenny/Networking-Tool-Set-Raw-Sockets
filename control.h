#ifndef CTRL_H
#define CTRL_H

//PACKET PRINTING CONTROL
void printpdata(unsigned char * paq, int len)
{
  int i;
  if(len==0)printf("\n!!- Logitud es cero -!!");
  else
  for(i=0;i<len;i++)
    {
      if(i%16==0) printf("\n");
      printf("%.2x ",paq[i]);
    }
  printf("\n");
}
//IP PARSER CONTROL
void IP_d(unsigned char * mip,char * msg,char opt)
{
  struct in_addr sip;
  unsigned char ip[16], * tgtip;
  switch(opt)
    {
    case 'u':
      printf("%s",msg);
      fgets(ip,16,stdin);
      inet_aton(ip,&sip);
      break;
    case 'g':
      tgtip = getGW();                             //Gets Gateway for PING
      inet_aton(tgtip,&sip);
      break;
    case 'm':
      inet_aton(msg,&sip);
      break;
    }
  memcpy(mip,(unsigned char*)&sip.s_addr,4);
}

//UNIQUE ADDRESS RESOLUTION CONTROL
void tgt_arp(genif * s_arp,unsigned char * pdataS,
	     unsigned char * pdataR,int packet_socket,int index,char opt)
{
  if(opt=='u') IP_d(s_arp->tgt_ip,"\nIP Destino: ",opt);
  else if(opt=='g');
  ARP_Erequest(pdataS,s_arp,opt);
  sendpdata(pdataS,packet_socket,index,60);
  arp_recvpdata(packet_socket,pdataR,s_arp,opt);
}

/* void tgt_echo(genif * s_arp,unsigned char * pdataS, */
/* 	      unsigned char * pdataR,int packet_socket,int index) */
/* { */
/*   ECHO_Erequest(pdataS,s_arp,NULL,'u'); */
/*   sendpdata(pdataS,packet_socket,index,98); */
/*   echo_recvpdata(packet_socket,pdataR,s_arp); */
/* } */

//ITERATOR ADDRESS RESOLUTION CONTROL
void arp_scanner(genif * s_arp,unsigned char * pdataS,
		 unsigned char * pdataR,int packet_socket,int index)
{
  PGconn * conn;
  PGresult * res;
  int it;
  conn = PQconnectdb("dbname=chatdb host=localhost user=e_chat password=echat");
  printf("\nClearing DB...");
  res = PQexec(conn,"delete from d_address");
  if (PQresultStatus(res) != PGRES_COMMAND_OK)perror(PQresultErrorMessage(res));
  memcpy(s_arp->tgt_ip,s_arp->ip,4);
  printf("\nObteniendo terminales disponibles...\n");
  for(it = 1;it<255;it++)
    {
      s_arp->tgt_ip[3]=it;
      ARP_Erequest(pdataS,s_arp,'u');
      if(sendpdata(pdataS,packet_socket,index,60))break;
      arp_recvpdata_timeout(packet_socket,pdataR,s_arp);
      //printpdata(pdataR,60);
    }
  printf("Listo!\n");
}
//DATABASE CONTROL

//Database Connection Control
int DBConnection(PGconn * conn)
{
  conn = PQconnectdb("dbname=chatdb host=localhost user=e_chat password=echat");
  if (PQstatus(conn) == CONNECTION_BAD)
    {
      printf("Error al conectar la base de datos\n");
      return 0;
    }
  return 1;
}

//Execute Query
int QueryExec(PGresult * res, PGconn * conn,char * query)
{
  res = PQexec(conn,query);
  if (PQresultStatus(res) != PGRES_TUPLES_OK) return 0;
  return 1;
}

//DB FUNCTIONS

//Directions Insertion
void insDIR(PGresult * res,PGconn * conn,char * _MAC,char * _IP)
{
  QueryExec(res,conn,
	    coolcat("insert into d_address(macdir,ipdir) values(",
		    coolcat(_MAC,",",_IP),
		    ");"));
}

unsigned char * getMACfromDB(char * defendedIP)
{
  PGconn * conn;
  PGresult * res;
  int tuples;
  char aux[255];
  unsigned char * retmac = malloc(sizeof(unsigned char)*6);
  sprintf(aux,"select macdir from d_address where ipdir='%s';",RWS(defendedIP,'\0'));
  conn = PQconnectdb("dbname=chatdb host=localhost user=e_chat password=echat");
  DBConnection(conn);
  res = PQexec(conn,aux);
  if (PQresultStatus(res) != PGRES_TUPLES_OK)
    {
      perror(PQresultErrorMessage(res));
      return 0;
    }
  tuples = PQntuples(res);
  sscanf(PQgetvalue(res,0,0),"%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	 &retmac[0],&retmac[1],&retmac[2],&retmac[3],&retmac[4],&retmac[5]);
  return retmac;
  PQclear(res);
  PQfinish(conn);
}

#endif
