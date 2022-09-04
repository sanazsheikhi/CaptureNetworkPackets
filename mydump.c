#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> 
#include<string.h> 
#include<errno.h>
#include<time.h> 

#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip.h>

typedef int bool;
#define true 1
#define false 0
 
void process_packet(char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ether_type(const u_char*);
void print_ether_timestamp(const struct timeval);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *, const struct pcap_pkthdr *  , int, char *);
void print_udp_packet(const u_char * ,const struct pcap_pkthdr *,int, char *);
void print_icmp_packet(const u_char *,const struct pcap_pkthdr * , int, char *);
void PrintData (const u_char * , int);
void print_payload(const u_char *, int);
void print_hex_ascii_line(const u_char *, int , int);
bool  payloadSearch(u_char *,int, char *);


FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;
int main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	int c, err = 0, iflag = 0, rflag = 0; 
	char *device , *file;
        char *search = "";
	char BPF_expression[1000];
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;      /* hold compiled program*/
	bpf_u_int32 maskp;          /* subnet mask               */
	bpf_u_int32 netp;           /* ip                        */
	static char usage[] = "usage: %s [-i interface] [-r file] [-s string] expression\n";
	pcap_t *handle; //Handle of the device that shall be sniffed

	while ((c = getopt(argc, argv, "i:r:s:")) != -1)
		switch (c) {
		case 'i':
			device = optarg;
			iflag = 1;
			break;
		case 'r':
			file = optarg;
			rflag = 1;
			break;
		case 's':
			search = optarg;
			break;
		case '?':
			err = 1;
			break;
		}
	if (err) {
		fprintf(stderr, usage, argv[0]);
		exit(1);
	}

	memset(BPF_expression,'\0',1000);
	if (optind < argc)	/* these are the arguments after the command-line options */
		for (; optind < argc; optind++){
			sprintf(BPF_expression + strlen(BPF_expression),argv[optind]);
			sprintf(BPF_expression + strlen(BPF_expression)," ");
		}

	if (iflag && rflag){
		printf("Choose either -i or -r for packet source.\n");
		exit(0);
		}

	else if(!iflag && rflag){
		handle = pcap_open_offline(file, errbuf);
  		if (handle == NULL) {
		printf("pcap_open_offline() failed: %s", errbuf);
	      	exit(0);
		}	
	}
	else if(!iflag && !rflag){
		device = pcap_lookupdev(errbuf);
       		if(device == NULL){
		 printf("%s\n",errbuf); 
		exit(0);
		}
		iflag = 1;
	}
	if(iflag && device != NULL){
	    printf("Opening device %s for sniffing ...\n" , device);
	    handle = pcap_open_live(device,BUFSIZ,1,-1,errbuf);
	    if (handle == NULL) 
            	{
			fprintf(stderr, "Couldn't open device %s : %s\n" , device, errbuf);
		        exit(1);
   		 }
	}
	if(BPF_expression){
	        pcap_lookupnet(device,&netp,&maskp,errbuf);
		if(pcap_compile(handle,&fp,BPF_expression,0,netp) == -1){
			fprintf(stderr,"Error calling pcap_compile\n"); 
			exit(1);
			}

        /* set the compiled program as the filter */
        if(pcap_setfilter(handle,&fp) == -1)
        { fprintf(stderr,"Error setting filter\n"); exit(1); }
    }
	logfile=fopen("log.txt","w");
	if(logfile==NULL) 
        	printf("Unable to create file.");
     
	//Put the device in sniff loop
	pcap_loop(handle , -1 , process_packet ,search);
//        pcap_loop(handle , -1 , process_packet , NULL); 
	return 0;     
   }
 
void process_packet(char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = header->len;
    char *search = args;//(char *) args;
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            print_icmp_packet( buffer,header , size, search);
            break;
         
        case 2:  //IGMP Protocol
            ++igmp;
            break;
         
        case 6:  //TCP Protocol
            ++tcp;
            print_tcp_packet(buffer, header , size, search);
            break;
         
        case 17: //UDP Protocol
            ++udp;
            print_udp_packet(buffer, header , size, search);
            break;
         
        default: //Some Other Protocol like ARP etc.
            ++others;
	    printf("\nip header protocol is unknown (others) for some packets...\n");
            break;
    }
}
void print_ether_type(const u_char* packet)
{
     struct ether_header *eptr;  /* net/ethernet.h */

    /* Ether header */
    eptr = (struct ether_header *) packet;

    /* Define ether type */
    if (ntohs (eptr->ether_type) == ETHERTYPE_IP)
    {
        fprintf(logfile,"\nEther type : IP\n");
    }else  if (ntohs (eptr->ether_type) == ETHERTYPE_ARP)
    {
        fprintf(logfile,"\nEther type : ARP\n");
    }else  if (ntohs (eptr->ether_type) == ETHERTYPE_REVARP)
    {
        fprintf(logfile,"\nEther type : RARP\n");
    }else {
        fprintf(logfile,"\nEther type not defined\n");
    }
}

void print_ethernet_header(const u_char *Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;
     
    print_ether_type(Buffer);     
	
    fprintf(logfile , "\n");
    fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);    
}
 
void print_ip_header(const u_char * Buffer, int Size )
{
    print_ethernet_header(Buffer , Size);
   
    unsigned short iphdrlen;
         
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;
     
    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
     
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;
     
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile , "   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    fprintf(logfile , "   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
}
 
void print_tcp_packet(const u_char * Buffer,const struct pcap_pkthdr *header, int Size, char *search)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;
     
    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
             
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    
  
  if (search != NULL  && payloadSearch(Buffer + header_size, Size - header_size, search) || search == NULL)
{


    fprintf(logfile , "\n\n***********************TCP Packet*************************\n");  
    print_ether_timestamp(header->ts);     
    print_ip_header(Buffer,header->len);
         
    fprintf(logfile , "\n");
    fprintf(logfile , "TCP Header\n");
    fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);
    fprintf(logfile , "\n");
    fprintf(logfile , "                        DATA Dump                         ");
    fprintf(logfile , "\n");
         
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile , "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);

    fprintf(logfile , "Data Payload\n");    
    PrintData(Buffer + header_size , Size - header_size);
    fprintf(logfile , "\n###########################################################");
}
}
 
void print_udp_packet(const u_char *Buffer,const struct pcap_pkthdr *header, int Size, char *search)
{
     
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
     
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
     

 if (search != NULL  && payloadSearch(Buffer + header_size, Size - header_size, search) || search == NULL)
{

    fprintf(logfile , "\n\n***********************UDP Packet*************************\n");
    print_ether_timestamp(header->ts);     
    print_ip_header(Buffer,header->len);           
     
    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));
     
    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer , iphdrlen);
         
    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);
    // test sanaz     
    fprintf(logfile , "Data Payload\n");    
     
    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , Size - header_size);
    payloadSearch(Buffer + header_size, Size - header_size, search);
    fprintf(logfile , "\n###########################################################");
}
}
 
void print_icmp_packet(const u_char * Buffer,const struct pcap_pkthdr *header, int Size, char *search)
{
    unsigned short iphdrlen;
     
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;
     
    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));
     
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

 if (search != NULL  && payloadSearch(Buffer + header_size, Size - header_size, search) || search == NULL)
{

     
    fprintf(logfile , "\n\n***********************ICMP Packet*************************\n"); 
    print_ether_timestamp(header->ts);     
    print_ip_header(Buffer , header->len);
             
    fprintf(logfile , "\n");
         
    fprintf(logfile , "ICMP Header\n");
    fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));
             
    if((unsigned int)(icmph->type) == 11)
    {
        fprintf(logfile , "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == ICMP_ECHOREPLY)
    {
        fprintf(logfile , "  (ICMP Echo Reply)\n");
    }
     
    fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
    fprintf(logfile , "\n");
 
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);
         
    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);
    fprintf(logfile , "Data Payload\n");    
    PrintData(Buffer + header_size , Size - header_size);
    payloadSearch(Buffer + header_size, Size - header_size, search);
    
     fprintf(logfile , "\n###########################################################");
}
}
 
void PrintData (const u_char * data , int Size)
{
    int i , j;
    char tmp[2 * Size + 1];
    int index = 0;
    char p;
    unsigned char *d = malloc(2*Size+1);
memcpy(d,data,Size);

    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile , "         ");

            for(j=i-16 ; j<i ; j++)
            {
                if(d[j]>=32 && d[j]<=128)
                 {  
		    fprintf(logfile , "%c",d[j]); //if its a number or alphabet
         	}
                else {
			fprintf(logfile , "."); //otherwise print a dot
			}
            }
            fprintf(logfile , "\n");
        } 
         
        if(i%16==0) {
		fprintf(logfile , "   ");

//	}
//	    int d1 = (unsigned int)d[i];
            fprintf(logfile , " %02X",(unsigned int)d[i]);

/*            fprintf(logfile , " %c",d[i]);
	     sprintf(&tmp[index],"%c",d[i]);
             index++;
*/
  }         
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
              fprintf(logfile , "   "); //extra spaces
            }
             
            fprintf(logfile , "         ");

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(d[j]>=32 && d[j]<=128) 
                {
		   p = (unsigned char)d[j];
                  fprintf(logfile , "%c",p);
                }
                else
                {
                  fprintf(logfile , ".");
                }
            }
             
            fprintf(logfile ,  "\n" );
        }
    }
	fprintf(logfile,"%s\n",tmp);
	free(d);
}

void print_ether_timestamp(const struct timeval ts)
{
	time_t nowtime;
	struct tm *nowtm;
	char tmbuf[64], buf[64];

	gettimeofday(&ts, NULL);
	nowtime = ts.tv_sec;
	nowtm = localtime(&nowtime);
	strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
	fprintf(logfile,"\nPacket Date/Time : %s.%06ld \n",tmbuf,ts.tv_usec);
}
 bool payloadSearch(u_char *data, int Size, char *search)
{
    int i , j;
    char tmp[2 * Size + 1];
    int index = 0;
    char p;
    unsigned char *d = malloc(2*Size+1);
    memcpy(d,data,Size);

    for(i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
	    sprintf(&tmp[index],"%c"," ");
            index++;

            for(j=i-16 ; j<i ; j++)
            {
                if(d[j]>=32 && d[j]<=128){
		    sprintf(&tmp[index],"%c",d[j]);
		    index++;
         	}
                else {
			sprintf(&tmp[index],"%c",".");
                        index++;
			}
            }
	    sprintf(&tmp[index],"%c","\n");
            index++;
        } 
         
        if(i%16==0) {
		sprintf(&tmp[index],"%c"," ");
                index++;

//	}
	    sprintf(&tmp[index],"%02d",(unsigned int)d[i]);
            index++;

  }         
        if( i==Size-1)  //print the last spaces
        {
            for(j=0;j<15-i%16;j++) 
            {
	      sprintf(&tmp[index],"%c"," ");
	      index++;

            }
             
	    sprintf(&tmp[index],"%c"," ");
	    index++;

            for(j=i-i%16 ; j<=i ; j++)
            {
                if(d[j]>=32 && d[j]<=128) 
                {
		   p = (unsigned char)d[j];
		  sprintf(&tmp[index],"%c",p);
                  index++;
                }
                else
                {
		  sprintf(&tmp[index],"%c",".");
                  index++;
                }
            }
             
	    sprintf(&tmp[index],"%c","\n");
            index++;
        }
    }
	free(d);
	if (tmp && search){
	if(strstr(tmp,search))
		return true;
	else{
		return false;
	}
	}
      return false;
   }


