#include <pcap.h>
#include <stdio.h>
#include <net/ethernet.h> //ethernet header
#include <netinet/ip.h>   //ip header
#include <netinet/tcp.h>  //tcp header
#include <arpa/inet.h>    //inet_ntoa()

struct ether_header *ethh;
struct ip *iph;
struct tcphdr *tcph;
struct udphdr *udph;

void callback(u_char* handle, const struct pcap_pkthdr* header, const u_char* packet);
void usage()
{
  printf("sysntax : pcap_test <interface>\n");
  printf("sample@linux~$ ./pcap_test wlan0\n");
}

int main(int argc, char* argv[])
{
  // usage error check!
  if(argc != 2)
  {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];  // errbuf
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);  // packet descripter
  
  dev = pcap_lookupdev(errbuf);

  // device error check!
  if(handle == NULL)
  {
    fprintf(stderr,"Couldn't open device : %s : %s\n",dev,errbuf);
    return -1;
  }
  printf("dev : %s\n",dev);

  pcap_loop(handle,0,callback,NULL);
  return 0;
}
void callback(u_char* handle, const struct pcap_pkthdr* header, const u_char* packet)
{
  // Ethernet header
  int i;
  ethh = (struct ether_header *)packet;
  printf("============== Ethernet ==============\n");
  printf("[Dst Mac address] : ");
  for(i = 0; i < 6; i++)
  {
     printf("%02x", packet[i]);
     if (i != 5)
      printf(":");
  }
  printf("\n");
  printf("[Src Mac address] : ");
  for(i = 6; i < 12; i++)
  {
     printf("%02x", packet[i]);
     if (i != 11)
      printf(":");
  }
  printf("\n");

  // IP header
  packet += sizeof(struct ether_header); //sizeof(struct eth); 
  iph = (struct ip *)packet;
  printf("================= IP =================\n");
  printf("[Src IP address] : %s\n",inet_ntoa(iph -> ip_src));	//inet_ntoa() -> number to string
  printf("[Dst IP address] : %s\n",inet_ntoa(iph -> ip_dst));

  // TCP header
  packet += 20; //(iph -> ip_hl * 4);		// packet length (total length -> 5 * 4 = 20)
  tcph = (struct tcphdr *)packet;
  printf("================ TCP ================\n");
  printf("[Src Port] : %d\n" , ntohs(tcph -> th_sport));	//ntohs() -> network to host type : short
  printf("[Dst Port] : %d\n" , ntohs(tcph -> th_dport));	// short : 2 byte

  // Packet Data
  packet += (tcph -> th_off);
  printf("================ Data ================\n");
  for(i = 0; i < 14; i++)
  {
    printf("%02x", *(packet++));
    if(i % 14 == 0 && i != 0)
       printf("\n");
  }
  printf("\n\n\n");
}
