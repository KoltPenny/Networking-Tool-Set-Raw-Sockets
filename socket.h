#ifndef SOCKETC_H
#define SOCKETC_H

void IP_d(unsigned char *,char *,char);

int socketData(int ds,genif * s_arp)
{
  int index, it;
  struct ifreq interfaz;
  printf("\nInserte nombre de la interfaz:\n");arrow();
  scanf("%s",interfaz.ifr_name);
  getchar();
  if(ioctl(ds,SIOCGIFINDEX,&interfaz)==-1)
    perror("\n[Error al obtener índice]\n");
  else
    {
      index = interfaz.ifr_ifindex;
      if(ioctl(ds,SIOCGIFHWADDR,&interfaz)==-1){perror("\n[Error al obtener MAC]\n"); return 0;}
      else memcpy(s_arp->mac,interfaz.ifr_hwaddr.sa_data,6);
      if(ioctl(ds,SIOCGIFNETMASK,&interfaz)==-1)
	{perror("\n[Error al obtener Máscara de subred]\n");return 0;}
      else memcpy(s_arp->subn,interfaz.ifr_netmask.sa_data+2,4);
      if(ioctl(ds,SIOCGIFADDR,&interfaz)==-1){perror("\n[Error al obtener IP]\n");return 0;}
      else memcpy(s_arp->ip,interfaz.ifr_addr.sa_data+2,4);
    }
  IP_d(s_arp->gateway_ip,NULL,'g');
  return index;
}

void print32bit(unsigned char * ADDR)
{
  printf("%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",ADDR[0],ADDR[1],ADDR[2],ADDR[3],ADDR[4],ADDR[5]);
}

void print16bit(unsigned char * ADDR)
{
  printf("%d.%d.%d.%d",ADDR[0],ADDR[1],ADDR[2],ADDR[3]);
}

void fmtpSocketInfo(genif s_arp)
{
  printf("\n");
  printf("[  MAC ] ~ "); print32bit(s_arp.mac);
  printf("\n[Subred] ~ "); print16bit(s_arp.subn);
  printf("\n[  IP  ] ~ "); print16bit(s_arp.ip);
  printf("\n[  GW  ] ~ "); print16bit(s_arp.gateway_ip);
  puts("");
}
#endif
