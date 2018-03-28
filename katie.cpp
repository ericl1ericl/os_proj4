#include <iostream>
#include <pcap.h>

using namespace std;

int main() {
	int num = 0;
	int inum = 0;
	int i = 0;

	pcap_if_t *alldevs;  		//TYPE??
	pcap_t *adhandle;		//TYPE??
	struct bpf_program fcode;
	bpf_u_int32 net;		//64? 32?
	bpf_u_int32 mask;		//64? 32?

	char *dev;			//idk what this does.

	pfile = "/afs/nd.edu/coursesp.18/cse/cse30341.01/support/project4/Dataset-Small.pcap";

	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_t * pcap = pcap_open_offline(pfile.c_str(), errbuff);

	struct pcap_pkthdr *header;

	const u_char *data;
	dev = pcap_lookupdev(errbuff);


	if (pcap_lookupnet(dev, &net, &mask, errbuff) == -1) { 	//why -1?
		fprintf(stderr, "can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	u_int packetCount = 0;
	while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0) {
		cout << "test";
		if (pcap_compile(pcap, &fcode, "ip and tcp", 1, net) < 0) {
			fprintf(stderr, "\nC++ is unable to comple the packet filter\n");
			pcap_freealldevs(alldevs);
			return -1;
		}
		if (pcap_setfilter(pcap, &fcode) < 0) {
			fprintf(stderr, "\nThere is an error in the filter.\n");
			pcap_freealldevs(alldevs);
			return -1;
		}

		printf("Packet number %i\n" ++packetCount);
		printf("Packet size: %d bytes\n", header->len);
		if (header->len != header ->caplen) {
			printf("Warnig! Packet size different from capture size: %ld bytes\n", header->len);
		}
	}
	cin >> num;
	return 0;
	



	
