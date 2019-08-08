
#define APP_NAME		"sniffex"
#define APP_DESC		"Sniffer example using libpcap"
#define APP_COPYRIGHT	"Copyright (c) 2005 The Tcpdump Group"
#define APP_DISCLAIMER	"THERE IS ABSOLUTELY NO WARRANTY FOR THIS PROGRAM."

#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <time.h>
#include <unistd.h>
#include <sys/inotify.h>
#include <pthread.h>
#include <search.h>


/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN	6
 // compare char arrays

#define ServerPort 8080
#define ServerHostName  "SAFEiitb"
#define MAX_devices 100 

#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )
/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};
struct data 
{
	int tcpbytes , nHttpreq , nHttpres ;
	char tcpS[26] ; 
	char tcpR[26] ; 

};
// client struct 

struct client 
{
	char* ip ; 
	char* mac ; 
	char* c_mac ;  
	int state ; // state and substate.
	int tcpbytes , nHttpreq , nHttpres ; 
	int q_port ; 
	int seq_start ; 
	int transaction ; 
	struct data state_data[7] ; 
	
};
struct student
{
	int Rollno  ; 
	int Devices[MAX_devices] ; 
	int noD ; 
	//char* PrevDev[MAX_devices] ; 
};
struct s_pm
{
	char* mac ; 
	char* rollno ; 
};
struct device
{

	char* ip  ; 
	struct client* C ; 
} ; 

//// My IP address
void* map1 = 0 ; 
char* my_ip  ; 
struct client* clients;
struct client* prevclients;
struct student* students ;  
int nClients = 0 ;
int pClients = 0 ; 
int MaxClients = 100 ; 
int MaxStudents = 200 ; 
//// Data Info
int Sn[8] ; 
//// compare strings
char cmpstr( char* a , char* c , int x)
{
	char equal = 't' ; 
	for( int i = 0 ; i <  x ;i++)
	{
	if( a[i] == c[i] ) continue ; 
	else equal = 'f' ; 
}
     return equal ; 
} 
/////
/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
/// functions for structs
void clear_dev(int pos)
{
	clients[pos].ip = NULL ; 
	clients[pos].c_mac = NULL ; 	
	for(int i = 0 ; i < 7 ; i++)
	{
		clients[pos].state_data[i].tcpbytes = 0 ; 
		clients[pos].state_data[i].nHttpres = 0 ; 
		clients[pos].state_data[i].nHttpreq = 0 ;
	}
}

/// initialize clients
void initialize_clients()
{
	for(int i = 0 ; i < MaxClients ; i++)
	{
		clients[i].state =  -1 ;  
		for(int k = 0 ; k < 7 ; k++)
		{
			clients[i].state_data[k].nHttpreq = 0 ; 
			clients[i].state_data[k].nHttpres = 0 ;
			clients[i].state_data[k].tcpbytes = 0 ; 			 			
		}
	}

}
/// initialize students
void initialize_students()
{
	for(int i = 0 ; i < MaxStudents ; i++)
	{
		students[i].Rollno = i + 1 ; 
		students[i].noD = 0 ; 		
	}
}
/// get line from csv
char* getfield(char* line, int num)
{
    char* tok;
    for (tok = strtok(line, "\t");
            tok && *tok;
            tok = strtok(NULL, "\t\n"))
    {
        if (!--num)
            return tok;
    }
    return NULL;
}

void fields_of_log(char* A[] , char* Message)
{
	int t = 0 ;
        for(int i = 0 ; i < 5 ; i++)
        {
        	int a = 0   ; 
 
        	while(a != 3)
        	{
        		if(*(Message + t) == '"')
        		{
        			a++ ; 
        		}
        		t++ ; 
        	}
        	int j = t ;
        	int len = 0 ;  
        	while(*(Message + t) != '"')
        	{
        		t++ ; 
        		len++ ; 
        	}
        	t++ ; 
        	A[i] =  malloc((len + 1)* sizeof(char)); 
        	for(int k = 0 ; k < len ; k++)
        	{
        		A[i][k] = *(Message + j + k) ; 
        	}
        	A[i][len] = '\0' ; 
        	printf("field %d is %s\n" , i , A[i]) ; 
        }
} 
int compar(const void *l, const void *r)
{
    const struct s_pm *lm = l;
    const struct s_pm *lr = r;
    return  strcmp(lm->mac , lr->mac);

}
void prelookup()
{
	FILE* stream = fopen("/home/rahul/Desktop/Project/x.csv", "r");
	 char line[1024];
   //	for(int j = 0 ; j < i ; j++) fgets(line, 1024 , stream) ;  
    while (fgets(line, 1024, stream))
    {
    	char* tmp = strdup(line);
        char* Message = getfield(tmp, 3);
        char* A[5] ; 
        
		int state_im = (int) (Message[0] - '0') + 5 ;  
        fields_of_log(A , Message) ;
        char * name = getfield(tmp , 2) ; 
        char* roll_num = getfield(tmp , 1) ;
       	struct s_pm* a = malloc(sizeof(struct s_pm)) ; 
       	a -> mac = malloc(17) ; 
       	a -> rollno = malloc(17) ; 
       	strcpy(a -> mac ,A[3]) ; 
       	strcpy(a -> rollno ,roll_num) ; 
        struct s_pm* ret = *(struct s_pm**)tsearch(a , &map1 , compar) ;
        if(ret != 0) printf("Successfully placed under %s , %s\n" , a -> mac,  a -> rollno); 
		if(ret == a )
		{
			 printf("Newly Placed\n");
			 for(int i = 0 ; i < nClients ; i++)
        {
        	if(cmpstr(clients[i].mac , A[3] , 17) == 't')
        	{
        		v = i ; 
        	}
        }
		if(v == -1)
        {
        	printf("Adding this device\n");
        	prevclients[pClients].mac = malloc(18) ; 
        	prevclients[pClients].ip = malloc(11) ; 
			strcpy(prevclients[pClients].mac ,  A[3]) ;  
			strcpy(prevclients[pClients].ip , A[2]) ;
			prevclients[pClients].state = state_im ;
		//	Sn[state_im - 1]++ ; 
			v = pClients ;  
			pClients++  ; 			
		}
		}
	}
}
void print_summary()
{
	int S[8] ;
	for(int i = 0 ; i < 8 ; i++) S[i] = 0 ;  
	// printing the clients.
	for(int i = 0 ; i < nClients ; i++)
	{
		//printf("client %d IP %s\n", i + 1 , clients[i].ip);
		printf("client %d MAC %s\n", i + 1 , clients[i].mac);
		printf("client %d State : %d\n", i + 1 , clients[i].state);		
		if(clients[i].state != -1)
		S[clients[i].state]++ ; 
	}

	// printing the students vs the clients.
	for(int i = 0 ; i < MaxStudents ; i++)
	{
		
		if(students[i].noD > 0)
		{
			printf("Student id :%d \n" , i );
		printf("No of devices connected used: %d\n" , students[i].noD);
			printf("They are : \n");
			for(int j = 0 ; j < students[i].noD ; j++)
			{
				int Device_no = students[i].Devices[j] ; 
				printf("MAC address : %s \n" , clients[Device_no].mac);
				printf("State: %d\n" , clients[Device_no].state);
			}
		}
	}
	printf("data = '[");
	for(int i = 0 ; i < 7 ; i++)
	{
		printf("{\"label\": \"state%d\" , \"y\" : %d},", i + 1 ,  S[i]);
	}
	printf("{\"label\": \"state%d\" , \"y\" : %d}", 8 ,  S[7]);
	printf("]'\n");

}
int sL = 0; 
int stop = 1 ; 
void lookupcsv()
{
	 
	FILE* stream = fopen("/home/rahul/Desktop/Project/a/y.csv", "r");

    char line[1024];
   printf("starting from line: %d\n" , sL) ; 
   // int x = 0 ; 
   // int state = 1 ;  
   for(int j = 0 ; j < sL ; j++) fgets(line, 1024, stream) ;  
    while (fgets(line, 1024, stream))
    {	
    	// if(state)
    	// {
    	// x++ ; 
    	// if(x <= sL) {   continue ; }
    	// else {state = 0 ;}
    	// }
    	sL++  ;     
        char* tmp = strdup(line);
        char* Message = getfield(tmp, 3);
        char* A[5] ; 
        int state_im = (int) (Message[0] - '0') + 5 ; 
        fields_of_log(A , Message) ;
        char * name = getfield(tmp , 2) ; 
        char* roll_num = getfield(tmp , 1) ; 
        int v = -1 ; 
        if(Message[0]  == '4')
        {
        	printf("stop is changed\n");
        	print_summary() ; stop = 0 ; 
        	continue ;  
        }
        printf("%s\n", roll_num ); 
        int id = (int)(*(roll_num + 12) - '0') * 100 + (int)(*(roll_num + 13) - '0') * 100
		 			+ (int) (*(roll_num + 14) - '0')  ;
		printf("Updating the student with id , %d\n", id );
        int nd = students[id].noD ;
		
        // this can be optimised with a hash map
		for(int i = 0 ; i < nClients ; i++)
        {
        	if(cmpstr(clients[i].mac , A[3] , 17) == 't')
        	{
        		v = i ; 
        	}
        }
		if(v == -1)
        {
        	printf("Adding this device\n");
        	clients[nClients].mac = malloc(18) ; 
        	clients[nClients].ip = malloc(11) ; 
			strcpy(clients[nClients].mac ,  A[3]) ;  
			strcpy(clients[nClients].ip , A[2]) ;
			clients[nClients].state = state_im ;
		//	Sn[state_im - 1]++ ; 
			v = nClients ;  
			nClients++  ; 			
		}
		 else
		 {
		 	// update the clients state. and connect the client to student
			// if(clients[v].state != state_im )
			// 	{Sn[state_im -1]++ ; Sn[clients[v].state]-- ; }
			 	
			 	clients[v].state = state_im ;
		 
		}
		// add this device to the student, in any case. 
		char already_there = '0' ; 
		for(int i = 0 ; i < nd ; i++)
        {
        	// look whether the mac is already present.
        	if( students[id].Devices[i] == v) 
        		{ already_there = '1' ; break ; }
        
        }
        if((already_there) == '0')
        {
        		students[id].Devices[nd] = v  ; 
		 		students[id].noD = nd + 1;  
        }  
        // NOTE strtok clobbers tmp
        free(tmp);
    }
}
/// Main function
/// when captured packet.
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const char *payload;                    /* Packet payload */
	int radio_len; 
	/// ethernet fields
	char *eth_s , *eth_d ;
	int IE_type , IE_subtype ; 

	eth_s = malloc(18) ; 
	eth_d = malloc(18) ;
	eth_s[17] = '\0' ; 
	eth_d[17] = '\0' ; 
    printf("\nPacket number %d:\n", count);
	
	count++;
	
	// header len
	radio_len = (unsigned int) *(packet + 2) ; 

	//// get the IE header
	const char* IE_header = packet + radio_len ; 
	IE_type = (*(IE_header) >> 2) & 0x3 ;
	IE_subtype = (*(IE_header) >> 4) & 0xF ;  
	int len = 0 ;  

	if(IE_type == 0) 
	{
		len = 24 ; // 24bytes in case of magement.
	strcpy(eth_d  , ether_ntoa((const struct ether_addr *)(IE_header + 4) )) ;
	strcpy(eth_s , ether_ntoa((const struct ether_addr *)(IE_header + 10))) ;
	printf("Management Packet\n");	
	}
	else if(IE_type == 1)
	{
		strcpy(eth_d  , ether_ntoa((const struct ether_addr *)(IE_header + 4) )) ;
		//strcpy(eth_s , ether_ntoa((const struct ether_addr *)(IE_header + 10))) ;
		len = 10 ; 
		printf("Control Packet\n");
	//	printf("Ignored\n");
		return ; 
	}
	else if(IE_type == 2)
	{
		printf("Data Packet\n");
		strcpy(eth_d  , ether_ntoa((const struct ether_addr *)(IE_header + 4) )) ;
		strcpy(eth_s , ether_ntoa((const struct ether_addr *)(IE_header + 10))) ;	
		switch(IE_subtype)
		{
			case 0: 
				len = 24 ; 
				printf("pure data\n");

				break ;  
			case 8:
				len = 26 ; 
				printf("Qos Data\n");	
				break ; 
			default : 
					printf("Unknown\n");
		}
	}
	else if (IE_type == 3)
	{
		printf("Dont know what these are\n");
		return ; 
	}
	
	//////////////
	
		printf("Types : %d , %d\n", IE_type , IE_subtype);
		printf("Destination Address %s\n", eth_d);
		printf("Source Address %s\n", eth_s);		
	////
	// for each packet, make an object or find a object of the source mac.
	char found1 = 'f' , found2 = 'f'  ; 
	int source = -1 , dest = -1 ; 
	char* broadcast = malloc(18) ; 
	broadcast = "ff:ff:ff:ff:ff:ff" ; 	
	if(cmpstr(eth_s , broadcast , 17) == 't') found1 = 't' ; 
	if(cmpstr(eth_d , broadcast, 17) == 't') found2 = 't' ; 	


	for(int i = 0 ; i < nClients ; i++)
	{
		//printf("Checking with %s\n", clients[i].mac );
		if(found1 == 't' && found2 == 't') break ;
		
		if(cmpstr(clients[i].mac, eth_s, 17) == 't')
		{	found1 = 't' ;
			source = i ;
		//	printf("source found at %d\n", i); 
		} 
		if(cmpstr(clients[i].mac, eth_d, 17) == 't')
		{	found2 = 't' ;
			dest = i ; 
		//	printf("destination found at %d\n", i); 
		} 
	}

	//printf("After packet analysis %c , %c : nClienst is %d\n", found1 , found2, nClients );
	if(found1 == 't')
	{
	//	printf("Known source :%s , id is %d\n" , eth_s , source);
	}
	else
	{
		printf("%s\n", eth_s );
			if(nClients > MaxClients - 1)
		{
			printf("Got_a packet from a new guy, but limit reached \n");
		}
		else { 
			clients[nClients].mac = malloc(18)  ;
			strcpy(clients[nClients].mac , eth_s) ; 
			source = nClients ; 
			nClients++ ; 
			printf("Unknown Guy , added %s \n" , eth_s);
		}
	}
	if(found2 == 't')
	{

		printf("Known destination :%s , id is %d\n" , eth_d , dest );
	}
	else
	{
		if(nClients > MaxClients - 1)
		{
			printf("Got_a packet from a new guy, but limit reached \n");
		}
		else{
			printf("%s\n", eth_d );
			clients[nClients].mac = malloc(18)  ;
			strcpy(clients[nClients].mac , eth_d) ; 
			dest = nClients ; 
			nClients++ ; 
			printf("Unknown Guy , added %s \n" , eth_d);
		}
		
	}
	////////////////////////////////
	//update(clients , s1 , d1, IE_type, IE_subtype, IE_header ) ;
	// Ip data
	if(IE_type == 0 && IE_subtype == 0)
	{
		/// irrespective of the state.
		if(source == -1) return ;
		clear_dev(source) ; 
		// if(clients[source].state != 0 )
		// 	Sn[0]++ ; 
		clients[source].state = 0 ; 
		printf("Association request Sent from client\n");
		return ;  		
	}
	else if (IE_type == 0 && IE_subtype == 1)
	{
		// clearing the device.
		if(dest == -1) return ; 
		clear_dev(dest) ;
		// if(clients[source].state != 1)
		// 	Sn[1]++ ;  
		clients[dest].state = 1 ;  			
		printf("Association response Sent to client\n"); 
		clients[dest].c_mac = malloc(18) ; 
		strcpy(clients[dest].c_mac , ether_ntoa((const struct ether_addr *)(IE_header + 10))) ; 
		return ;
		 
	} 
	const char* LLC = IE_header + len ; 
	int IPtype = ((unsigned int)*(LLC  + 6)) * 256 + ((unsigned int)*(LLC  + 7)) ;  

	if(IPtype != 2048)
	{
		printf("Type is %d , %d\n",IPtype , (int)*(LLC + 7) );
		return ; 
	}
	/// IP data
	const struct sniff_ip *ip;              /* The IP header */
	ip = (struct sniff_ip*) (LLC + 8) ; 
	const char* IP = LLC + 8 ;
	const char* TCP ;  
	int protocol = -1;
	int ip_type  = -1; 
	char* query ;
	char* ip_s , *ip_d ; 
	int s_port , d_port ; 
	ip_s = malloc(11) ; 
	ip_d = malloc(11) ;  
	int hlen = 4*IP_HL(ip)   ;// each word is of 4 bytes.
	strcpy(ip_s , inet_ntoa(ip->ip_src)) ; 
	strcpy(ip_d , inet_ntoa(ip->ip_dst)) ; 
	printf("source ip: %s , dest ip: %s\n", ip_s , ip_d );
	//printf("head len %d\n", hlen);
	protocol = (int) ip -> ip_p ;
	printf("protocol %d\n" , protocol);
	clients[dest].ip = malloc(11) ; 
	clients[source].ip = malloc(11) ; 	
	strcpy(clients[dest].ip , ip_d ) ; 
	strcpy(clients[source].ip , ip_s ) ; 	
	if(protocol == 17 )
	{
		printf("UDP packet\n");
		const char* UDP = IP + hlen ; 
		int UDPlen = ((unsigned char) *(UDP + 4)) * 256 +  (unsigned char) *(UDP + 5) ; 
		s_port = ((unsigned char)*UDP) * 256 + ((unsigned char) *(UDP + 1)) ;
		printf("source port elements %d , %d\n",((unsigned char)*UDP) ,  ((unsigned char) *(UDP + 1)));
		d_port = ((unsigned char)*(UDP + 2)) * 256 + ((unsigned char) *(UDP + 3)) ;	
		printf("source port: %d , dest port: %d\n" , s_port , d_port) ;
		if(s_port == 68 && d_port == 67)
		{
			printf("DHCP Request\n");
			ip_type = 1 ; 
		}
		else if(s_port == 67 && d_port == 68)
		{
			printf("DHCP Response\n");
			ip_type = 2 ; 
		}
		else if (d_port == 53)
		{
			
			const char* DNS = UDP + 8 ; 
			printf("DNS request\n") ;
			int nQ = ((int)*(DNS + 4)) * 256 + (int) * (DNS + 5) ; 
			printf(" %d Question\n" , nQ);
			if (nQ != 1)
			{
				printf("too many , dropping the packet\n");
				return ; 
			}
			/// printing the query
			int querylen = UDPlen - 24  ;
			query = malloc(querylen - 1) ;
			for(int i = 0 ; i < querylen - 2 ; i++ )
			{
				if( ((int)*(DNS + 13 + i ))   >= 48)
				query[i] = (char) *(DNS + 13 + i)  ;
				else query[i] = '.' ; 
			} 
			printf("%s\n", query);
			if(cmpstr(query , ServerHostName , 8 ) == 't')
			{
				printf("found dns required\n");
				clients[source].transaction = ((int)*(DNS)) * 256 + ((int)*(DNS + 1) ) ;  
				ip_type = 3 ;
			} 
			ip_type = 3 ;
		}
		else if (s_port == 53)
		{
			ip_type = 4 ; 
			const char* DNS = UDP + 8 ;
			printf("DNS response\n");
			int transaction = ((int)*(DNS)) * 256 + ((int)*(DNS + 1) )  ; 
			printf("transaction: %d\n", transaction );
		}  
	}
	else if (protocol == 6)
	{
		ip_type = 5 ; 
		printf("TCP packet\n"); 
		const struct sniff_tcp *tcp = (struct sniff_tcp * )(IP + hlen);            /* The TCP header */
		TCP = IP + hlen ;
		s_port = ntohs(tcp->th_sport) ; 
		d_port = ntohs(tcp->th_dport) ;
		printf("   Src port: %d\n", s_port);
		printf("   Dst port: %d\n", d_port); 

	}
	int S0 = clients[source].state ; 
	int S1 = clients[dest].state ;
	if(ip_type == 1)
	{
		//DHCP request ; 
		if(dest != -1)
		{
			if(S1 <= 2 ) 
			{
			// 	if(clients[dest].state != 2 )
			// Sn[2]++ ; 
				clients[dest].state = 2 ; 				
			}
		}
	}
	else if(ip_type == 2)
	{
		if(source != -1)
		{
			if(S0 <= 3 ) 
			{
				// if(clients[source].state != 3 )
				// Sn[3]++ ; 
				clients[source].state = 3 ; 		
			}
		}	
	}
	else if(ip_type == 3)
	{
		if(dest != -1)
		{
			if(S1 <= 4 )
			{
				// if(clients[dest].state != 4)
				// Sn[4]++ ; 
				clients[dest].state = 4 ;  			
			}
		}
	}
	else if(ip_type = 4)
	{
		if(source != -1)
		{
			if(S0 <= 5) 
			{
				// if(S0 != 5)
				// Sn[5]++ ; 
				clients[source].state = 5 ; 
			}
		}
	}
	else if(ip_type == 5)
	{
		if(d_port == ServerPort)
		{
			// server contacted.
			clients[source].state =  6 ;  
			clients[source].q_port = s_port ; 
		}
		if( d_port == clients[dest].q_port && s_port == ServerPort )
	{
		 unsigned long int segLen = (((int)*(TCP + 4) * 256 +
	  	(int) *(TCP + 5)) * 256 + (int) *(TCP + 6)) * 256 + (int) *(TCP + 7) ;
		if(((int) *(TCP + 13)) == 18)
		{
			clients[dest].seq_start = segLen ; 
			clients[dest].nHttpreq++ ;
			clients[dest].state_data[S1].nHttpreq++ ; 
		}
		else if (((int) * (TCP + 13)) == 17)
		{
			clients[dest].nHttpres++ ;  
			clients[dest].state_data[S1].nHttpres++ ;
			clients[dest].state_data[S1].tcpbytes +=  segLen - clients[dest].seq_start ; 
			clients[dest].tcpbytes += segLen - clients[dest].seq_start ; 
		}

	}
}
return ; 	
}


void* f()
{
  int length, i = 0;
  int fd;
  int wd;
  char buffer[EVENT_BUF_LEN];

  /*creating the INOTIFY instance*/
 
  
	 fd = inotify_init();

  /*checking for error*/
  if ( fd < 0 ) {
    perror( "inotify_init" );
  }

  /*adding the “/tmp” directory into watch list. Here, the suggestion is to validate the existence of the directory before adding into monitoring list.*/
  wd = inotify_add_watch( fd, "/home/rahul/Desktop/Project/a", IN_MODIFY | IN_CREATE | IN_DELETE );
 	printf("stop value is %d\n",stop );
  while(stop)
  {
  /*read to determine the event change happens on “/tmp” directory. Actually this read blocks until the change event occurs*/ 
	  	i = 0 ;  
	  length = read( fd, buffer, EVENT_BUF_LEN ); 

	  /*checking for error*/
	  if ( length < 0 ) {
	    perror( "read" );
	  }  

		/*actually read return the list of change events happens. Here, read the change event one by one and process it accordingly.*/
	  while ( i < length ) {   
	    struct inotify_event *event = ( struct inotify_event * ) &buffer[ i ];     if ( event->len ) {
	      if ( event->mask & IN_CREATE ) {
	        if ( event->mask & IN_ISDIR ) {
	          printf( "New directory %s created.\n", event->name );
	        }
	        else {
	          printf( "New file %s created.\n", event->name );
	         // lookupcsv() ; 
	        }
	      }
	      else if ( event->mask & IN_DELETE ) {
	        if ( event->mask & IN_ISDIR ) {
	          printf( "Directory %s deleted.\n", event->name );
	        }
	        else {
	          printf( "File %s deleted.\n", event->name );
	        }
	      }
	    else if ( event->mask & IN_MODIFY ) {
	        if ( event->mask & IN_ISDIR ) {
	          printf( "The directory %s was modified.\n", event->name );
	        }
	        else {    
	          printf( "The file %s was modified.\n", event->name );
	          lookupcsv() ; 
	        }
	      }

	    }
	    i += EVENT_SIZE + event->len;
	   
  }
}
  /*removing the “/tmp” directory from the watch list.*/
   inotify_rm_watch( fd, wd );

  /*closing the INOTIFY instance*/
   close( fd );
return NULL; 
}
void* Packet_capture(void* handle)
{
	pcap_t* h = (pcap_t*) handle ; 
	int num_packets = 1 ; 
	while(stop)
	pcap_loop(h, num_packets, got_packet, NULL);
	/// function to incorporate csv files.
	//lookupcsv() ; 

}
int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */
	my_ip = malloc(11) ; 
	//int numberClients = 100 ; 
	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */
	int num_packets = 1;			/* number of packets to capture */
	if (argc == 2) {
		dev = argv[1];
	}
	else if (argc > 2) {
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		//print_app_usage();
		exit(EXIT_FAILURE);
	}
	else {
	pcap_if_t *d;
    int status = pcap_findalldevs(&d, errbuf);
    if(status != 0) {
        printf("%s\n", errbuf);
        return 1;
    }
   	while(d != NULL)
   	{
    if( d -> name[0] != 'm') 
    {
    	d = d-> next ; 
    	continue ; 
    }
 	for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) { 
            if(a->addr->sa_family == AF_INET)

               strcpy(my_ip , inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr)) ;  
        }
         printf("%s \n" , my_ip) ; 
    	 break ;
    }
       	if(d == NULL )
    	{
    		printf("Unable to find monitor interface\n");
    		exit(EXIT_FAILURE) ; 
    	} 
     dev = (char * ) d->name ; 
	}
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}
	int can = pcap_can_set_rfmon(handle) ; 
	if ( can != 1)
	{
		printf("Unable to set monitor mode\n ") ; 
	}
	else
	{
		int status = pcap_set_rfmon(handle , 1) ;  
		printf("Monitor mode set\n"); 
	}
	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_IEEE802_11_RADIO) {
		fprintf(stderr, "%s is not wifi\n", dev);
		exit(EXIT_FAILURE);
	}
	clients = malloc(MaxClients * sizeof(struct client) ) ;
	prevclients = malloc(MaxClients * sizeof(struct client) ) ; 
	students = malloc(MaxStudents * sizeof(struct student)) ; 
	//
	initialize_students() ; 
	initialize_clients() ; 
	prelookup() ; 
	// monitor the csv
	pthread_t tid1 , tid2;
 	pthread_create(&tid1, NULL, f, NULL);
 	pthread_create(&tid2, NULL, Packet_capture, (void* )handle);
	while(stop) ; 
	print_summary() ; 
	printf("\nNumber of clients: %d\n", nClients );
	/* cleanup */
	{
		int status = pcap_set_rfmon(handle , 0) ;  
		if(status != PCAP_ERROR_ACTIVATED)
		{
			printf("Monitor mode off\n"); 
		}
	}
	//pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}

