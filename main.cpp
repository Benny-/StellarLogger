#include "pcap.h"

#include <iostream>
#include <tcpmib.h>
#include <io.h>

#include "tcphdr.h"

// Magic value a tcp package starts for the score board.
u_char StellarMagic[] = {
'\x10','\x0','\x0','\x0','\x0','\x0','\x0','\x0','\xdd','\x1','\x0','\x0',
};

/* 4 bytes IP address */
typedef struct ip4_address{
    u_char byte1 : 8;
    u_char byte2 : 8;
    u_char byte3 : 8;
    u_char byte4 : 8;
}ip4_address;

/* IPv4 header */
typedef struct ip4_header
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    u_char  ihl : 4;        // Internet header length (4 bits)
    u_char  ver : 4;        // Version. The constant 4.
#else #elif __BYTE_ORDER == __BIG_ENDIAN
	u_char  ver : 4;        // Version. The constant 4.
	u_char  ihl : 4;        // Internet header length (4 bits)
#endif
    u_char  tos : 8;            // Type of service 
    u_short tlen : 16;           // Total length 
    u_short identification : 16; // Identification
    u_short flags_fo : 16;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl : 8;            // Time to live
    u_char  proto : 8;          // Protocol
    u_short crc : 16;            // Header checksum
    ip4_address  saddr;      // Source address
    ip4_address  daddr;      // Destination address
    u_int   op_pad;        // Option + Padding
} ip4_header;

/* prototype of the packet handler */
void packet_handler(u_char *dumpfile, const struct pcap_pkthdr *header, const u_char *pkt_data);
bool handleIp4( ip4_header*, u_char** data, u_int* data_len );
void parseScoreboard(const struct tm* time, u_char* data, u_int data_len);
void printHex(const u_char* data, SIZE_T len);

pcap_dumper_t *dumpfile = NULL;
int main(int argc, char *argv[])
{
	pcap_if_t *alldevs = NULL;
    pcap_if_t *d;
    int i=0;
	int inum;
	u_int netmask = 0xffffff;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *adhandle;
	struct bpf_program fcode;
	char source[PCAP_BUF_SIZE] = {0}; // Used for reading a wireshark packet log.
	bool input_is_file = false;

	if (_access("stellarlog.pcap", 0) == -1)
	{
		// File does not exist
	}
	else
	{
		std::cout << "Warning: stellarlog.pcap file exist. Please move or remove it. This program cant merge logs." << std::endl;
		getc(stdin);
		return EXIT_FAILURE;
	}


	if(argc > 1)
	{
		input_is_file = true;
		/* Create the source string according to the new WinPcap syntax */
		if ( pcap_createsrcstr( source,         // variable that will keep the source string
						PCAP_SRC_FILE,  // we want to open a file
						NULL,           // remote host
						NULL,           // port on the remote host
						argv[1],        // name of the file we want to open
						errbuf          // error buffer
						) != 0)
		{
			fprintf(stderr,"Error creating a source string\n");
			getc(stdin);
			return EXIT_FAILURE;
		}
	}
	else
	{
		/* Retrieve the device list from the local machine */
		if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, &alldevs, errbuf) == -1)
		{
			fprintf(stderr,"Error in pcap_findalldevs_ex: %s\n", errbuf);
			getc(stdin);
			return EXIT_FAILURE;
		}
    
		/* Print the list */
		for(d= alldevs; d != NULL; d= d->next)
		{
			printf("%d. ", ++i);
			if (d->description)
				printf(" (%s)\n", d->description);
			else
				printf(" (No description available)\n");
		}
    
		if (i == 0)
		{
			printf("\nNo interfaces found! Make sure WinPcap is installed and running.\n");
			getc(stdin);
			return EXIT_FAILURE;
		}

		printf("Enter the interface number (1-%d):",i);
		std::cin >> inum;
		std::cin.get();
    
		if(inum < 1 || inum > i)
		{
			printf("\nInterface number out of range.\n");
			/* Free the device list */
			pcap_freealldevs(alldevs);
			std::cin.get();
			return EXIT_FAILURE;
		}
    
		/* Jump to the selected adapter */
		for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);

		std::cout << "You have selected " << d->description << std::endl;
	}

	/* Open the device */
	if ( (adhandle= pcap_open( input_is_file?source:d->name,          // name of the device. This will be a real network device or a path to a logfile.
								65536,            // portion of the packet to capture
												// 65536 guarantees that the whole packet will be captured on all the link layers
								PCAP_OPENFLAG_NOCAPTURE_LOCAL,
								1000,             // read timeout
								NULL,             // authentication on the remote machine
								errbuf            // error buffer
								) ) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		std::cin.get();
		return EXIT_FAILURE;
	}

	std::cout << "Operating on link layer " << pcap_datalink(adhandle) << std::endl;

	if(input_is_file)
	{
		std::cout << "Not writing to dumpfile." << std::endl;
	}
	else
	{
		std::cout << "Opening dump file" << std::endl;
		dumpfile = pcap_dump_open(adhandle, "stellarlog.pcap");

		if(dumpfile==NULL)
		{
			fprintf(stderr,"\nError opening output dump file\n");
			getc(stdin);
			return EXIT_FAILURE;
		}
	}

    if ( !input_is_file && d->addresses != NULL)
        /* Retrieve the mask of the first address of the interface */
        netmask=((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;

	std::cout << "Making filter" << std::endl;

    if (pcap_compile(adhandle, &fcode, "tcp", 1, netmask) < 0)
    {
        fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
		std::cin.get();
		return EXIT_FAILURE;
    }
    
	std::cout << "Setting filter" << std::endl;

    if (pcap_setfilter(adhandle, &fcode) < 0)
    {
        fprintf(stderr,"\nError setting the filter.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
		std::cin.get();
		return EXIT_FAILURE;
    }

    /* We don't need any more the device list. Free it */
	if(!input_is_file)
		pcap_freealldevs(alldevs);

	std::cout << "Now looking for packages containing magic number." << std::endl;

    /* start the capture */
    pcap_loop(adhandle, 0, packet_handler, NULL);

	pcap_close(adhandle);

	std::cout << "Program has finished" << std::endl;
	std::cin.get();
	return EXIT_SUCCESS;
}

void printHex(const u_char* data, SIZE_T len)
{
	printf("0x");
	for(SIZE_T i = 0; i < len ; i++)
	{
		printf(" %02hhX",*( data +i) );
	}
	printf("\n");
}

void parseScoreboard(const struct tm* time, u_char* stellarHeader, u_int stellarData_len)
{
	u_char* playerHeader = stellarHeader + 0x10;
	SIZE_T playerHeader_len;

	// The "playerHeader > stellarHeader" is there to ensure we stop in case the pointer overflows.
	// This will only happen the data stellarHeader points to is located near the end of the adress space.
	// This error has not been observed.
	while(playerHeader < (stellarHeader+stellarData_len) && playerHeader > stellarHeader)
	{
		u_char* statPointer = playerHeader;			// The stat pointer is a temp adress who goes over every value.
		playerHeader_len = *(SIZE_T*)statPointer;	// Here you see it used to extract header size.
		statPointer += 16;							// Now it points to the next value, player team. ect..

		if(playerHeader_len != 0x48)
		{
			std::cout << "Warning, I dont know what to do with player header with this size: " << playerHeader_len << std::endl;
			std::cout << "Hexidecimal values:" << std::endl;
			printHex(statPointer,playerHeader_len);
			std::cout << "Ignoring header" << std::endl;
			std::cout << std::endl;
		}
		else
		{
			std::cout << "Player team: " << * (u_long*) statPointer << std::endl;
			statPointer += 8;
			std::cout << "Player kills: " << * (u_int*) statPointer << std::endl;
			statPointer += 4;
			std::cout << "Player deaths: " << * (u_int*) statPointer << std::endl;
			statPointer += 4;
			std::cout << "Player assists: " << * (u_int*) statPointer << std::endl;
			statPointer += 4;
			std::cout << "Player destructions: " << * (u_int*) statPointer << std::endl;
			statPointer += 4;
			std::cout << "Player captures: " << * (u_int*) statPointer << std::endl;
			statPointer += 4;
			std::cout << "Player escorts destroyed: " << * (u_int*) statPointer << std::endl;
			statPointer += 4;

			statPointer += 4; // 4 empty bytes. Padding?
			std::cout << "Player name: " << statPointer << std::endl;
			std::cout << std::endl;
		}

		playerHeader = playerHeader + playerHeader_len; // Go to next player's score.
	}

	std::cout << std::endl;
}

bool handleIp4( ip4_header* ip4h, u_char** data, u_int* data_len )
{
	u_int ip_len; // In bytes.
	tcp4hdr* tcph;
	u_int tcp_len; // In bytes.

	ip_len = (ip4h->ihl) * 4;
	
	tcph = (tcp4hdr*) ( ((u_char*)ip4h) + ip_len);
	tcp_len = ntohs( ntohs(tcph->doff) ) * 4;

	// XXX: Tcp a stream based protocol. The thing we are looking for might be segmented. We do not take this into account.

	*data = ((u_char*)tcph) + tcp_len;
	*data_len = ntohs(ip4h->tlen) - tcp_len - ip_len;

	if(*data_len < (sizeof(StellarMagic) - 1))
	{
		// printf("Incomming thing is too small.\n");
	}
	else
	{
		if(memcmp(*data,StellarMagic,(sizeof(StellarMagic) - 1)))
		{
			// printf("Magic value does not match\n");
		}
		else
		{
			printf("Magic value matches!\n");

			printf("Total len (bytes): %hu\n",ntohs(ip4h->tlen));
			printf("Ip4 len (bytes): %u\n",ip_len);
			printf("tcp4 len (bytes): %u\n",tcp_len);
			printf("data len (bytes): %u\n",*data_len);

			printHex(*data, *data_len);

			printf("\n");
			return true;
		}
	}
	return false;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *adhandle, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    struct tm ltime;
    char timestr[80];
    time_t local_tv_sec;

	const u_char* iph;
	u_char* data;
	u_int data_len;
	bool valid_stellar_magic = false;

	/* retireve the position of the ip header */
    iph = (pkt_data +
        14); //length of ethernet header
	
	if( (*iph >> 4) == 4 )
	{
		if (handleIp4( (ip4_header*) iph, &data, &data_len ))
		{
			valid_stellar_magic = true;

			/* convert the timestamp to readable format */
			local_tv_sec = header->ts.tv_sec;
			localtime_s(&ltime, &local_tv_sec);
			// gmtime_s(&ltime, &local_tv_sec);
			strftime( timestr, sizeof timestr, "%d/%m/%Y %H:%M:%S", &ltime);
			printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
			
			if(dumpfile != NULL)
			{
				pcap_dump( (u_char*) dumpfile, header, pkt_data); // Idk why argument is a u_char pointer.
				pcap_dump_flush( dumpfile ); // Our program does not exit gracefully. So we must dump now and then.
			}

			parseScoreboard(&ltime,data,data_len);
		}
	}
	else
	{
		std::cout << "Could not handle a non-ipv4 package. Ignoring." << std::endl;
		printf("IP version: 0x%02hhX\n", *iph >> 4 );
		// TODO: Support ipv6
	}

	if(valid_stellar_magic)
	{

	}
}
