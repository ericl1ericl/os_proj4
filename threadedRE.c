#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "hash.c"
#include "uthash.h"

#define DEF_LEVEL 1
#define DEF_THREADS 1
#define MAX_FILES 10
#define MAX_FILENAME_LENGTH 30

int level = DEF_LEVEL;
int threads = DEF_THREADS;
char filelist[MAX_FILES][MAX_FILENAME_LENGTH + 1];
int numfiles = 0;

// struct to hold previously seen packet contents
// this is what we should probably store in a linked 
// list that's attaached to the hash table

struct PacketHolder{
  int isValid; // 0 if no, 1 if yest
  char data[2400]; // the actual packet data
  uint32_t hash; // hash of th packet contents
  UT_hash_handle hh;
};

// hold all the packets
struct PacketHolder *packets = NULL;

//hash table with chaining



void DumpInformation (FILE *);
void parseHeader(FILE *);
void usage();
void welcome();
void addPacket(uint32_t, char *);

int main(int argc, char * argv[]) {
  FILE *fp;

  // parse command line arguments	
  for (int i = 1; i < argc; i++) {
	// make sure the first argument is -level 
    if (!strcmp(argv[i], "-level")) {
      if (i == (argc - 1)) {
        usage();
        return 1;
      }
      i++;
      level = atoi(argv[i]);
    } else if (!strcmp(argv[i], "-threads")) { // make sure a number of threads is specified 
      if (i == (argc - 1)) {
        usage();
        return 1;
      }
      i++;
      threads = atoi(argv[i]);
    } else { // all inputs specified 
      strcpy(filelist[numfiles], argv[i]);
      numfiles++;
    }
  }
  welcome();
	
  //open the file for reading
	fp = fopen("Dataset-Small.pcap", "r");
	parseHeader(fp);	
	DumpInformation(fp);
	fclose(fp);
	
	return 0;
}

// startup function
void welcome() {
  printf("Welcome to Project 4 - threadedRE by kage\n");
  printf("level: %d\n", level);
  printf("threads: %d\n", threads);
  printf("files: ");
  for (int i = 0; i < numfiles; i++) {
    printf("%s ", filelist[i]);
  }
  printf("\n");
  return; 
}

void usage() {
  printf("usage: threadedRE [-level l] [-threads t] file1 [file2 ...]\n");
  printf("\t-level l: version of program to run (default 1)\n");
  printf("\t-threads t: max number of threads allowed (default 1)\n");
  printf("\t-file1 ... : list of .pcap files to process\n");
  return;
}

void parseHeader(FILE *fp) {
	//jump through 24 bytes of the header of the pcap file
	fseek(fp, 24, SEEK_CUR);
	printf("jumped through the header\n");
}

//fread(pointer to memory, size of element to be read, number of elements, 
//	the pointer to a FILE object)
void DumpInformation (FILE *fp) {
	uint32_t nPacketLength;
	uint32_t newPacketLength = 0;
	char theData[2000];

	while(!feof(fp)) {
		//skip the ts_sec field
		fseek(fp, 4, SEEK_CUR);
	
		//skip the ts_usec field
		fseek(fp, 4, SEEK_CUR);

		//Read the incl_len field --> store in nPacketLength
		fread(&nPacketLength, 4, 1, fp);

		//Skip the orig_len field
		fseek(fp, 4, SEEK_CUR);
		
		//ignore packets less than 128 bytes
		if (nPacketLength < 128) {
			printf("skipped: too small\n");	
			fseek(fp, nPacketLength, SEEK_CUR);
			
		}
		// ignore packets greater than 2400 bytes 
		else if (nPacketLength > 2400) {
			printf("skipped: too large");
			fseek(fp, nPacketLength, SEEK_CUR);
		}
		else {
			printf("Packet length was %d\n", nPacketLength);
			//store in a data structure somehow
			
			//skip the first 52 bytes
			fseek(fp, 52, SEEK_CUR);

			//store the rest of the packet into theData
			newPacketLength = nPacketLength - 52;
			fread(theData, 1, newPacketLength, fp);
			// make a copy of theData
			char compHash[2000];
			strncpy(compHash, theData, sizeof(theData));
			//compute the hash for theData -- 52 bytes through the end of the packet 
			uint32_t b = 0, c = 0;
			hashlittle2(compHash, sizeof(theData), &b, &c);
			// make a packet struct
			
		}	
		//after these loops, start reading the next packet
	}
}


void addPacket(uint32_t hash, char * data) {
  struct PacketHolder * s;
  HASH_FIND_INT(packets, &hash, s); // is the packet already in table
  if (s == NULL) {
    s = (struct PacketHolder *)malloc(sizeof(struct PacketHolder));
    s->hash = hash;
    HASH_ADD_INT(packets, hash, s);
  }
  strcpy(s->data, data); 
}
