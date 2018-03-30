// project 4
// "uthash" used to implement hash map structure in c
// http://troydhanson.github.io/uthash/userguide.html used as basis for uthash interface functions

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "hash.c"
#include "uthash.h"
#include <pthread.h>
#include <unistd.h>

#define DEF_LEVEL 1
#define DEF_THREADS 1
#define MAX_FILES 10
#define MAX_FILENAME_LENGTH 30
#define RAND_SEED 10
#define MAX_PACKETS_IN_TABLE 32000 // TODO CHANGE THIS NUMBER BEFORE TURNING IN


// global variables
int level = DEF_LEVEL;
int threads = DEF_THREADS;
char filelist[MAX_FILES][MAX_FILENAME_LENGTH + 1];
int numfiles = 0;
struct PacketHolder *packets = NULL;
char theData[2000];
uint32_t hashToEvict;
int packetsInTable = 0;

pthread_rwlock_t hashLock = PTHREAD_RWLOCK_INITIALIZER;

struct PacketHolder{
  int isValid; // 0 if no, 1 if yest
  char data[2000]; // the actual packet data
  uint32_t hash; // hash of th packet contents
  UT_hash_handle hh;
};

// buffer/queue struct
typedef struct {
  char buf[BUFSIZ];
  size_t len;
  pthread_mutex_t mutex;
  pthread_cond_t more;
  pthread_cond_t less;
} buffer_t;


// function definitions 
void DumpInformation (FILE *);
void parseHeader(FILE *);
void usage();
void welcome();
void addPacket(uint32_t, char *);
struct PacketHolder * findPacket (uint32_t);
void deletePacket (struct PacketHolder *);
void DONTCALLTHISaddPacket(uint32_t, char *);
struct PacketHolder * DONTCALLTHISfindPacket (uint32_t);
void DONTCALLTHISdeletePacket (struct PacketHolder *);
void parseInput(int, char **);
void printPackets();
void *producer(void *);
void *consumer(void *);
void compHash();

int main(int argc, char * argv[]) {
  FILE *fp;

  // set random seed
  srand((unsigned) RAND_SEED);

  parseInput(argc, argv);

  //open the file for reading
  fp = fopen("Dataset-Small.pcap", "r");
  parseHeader(fp);	
  DumpInformation(fp);
  fclose(fp);

  buffer_t buffer = {
    .len = 0,
    .mutex = PTHREAD_MUTEX_INITIALIZER,
    .more = PTHREAD_COND_INITIALIZER,
    .less = PTHREAD_COND_INITIALIZER
  };

  pthread_t prod;
  pthread_t cons;
  pthread_create(&prod, NULL, producer, (void*)&buffer);
  pthread_create(&cons, NULL, consumer, (void*)&buffer);

  pthread_join(prod, NULL);
  pthread_join(cons, NULL);

  //printPackets();

  return 0;
}

void parseInput(int argc, char * argv[]) {
  // parse command line arguments	
  for (int i = 1; i < argc; i++) {
    // make sure the first argument is -level 
    if (!strcmp(argv[i], "-level")) {
      if (i == (argc - 1)) {
        usage();
        exit( EXIT_FAILURE );
      }
      i++;
      if ((atoi(argv[i]) != 1) && (atoi(argv[i]) != 2)) {
        usage();
        exit( EXIT_FAILURE );
      } else {
        level = atoi(argv[i]);
      }
    } else if (!strcmp(argv[i], "-threads")) { // make sure a number of threads is specified 
      if (i == (argc - 1)) {
        usage();
        exit( EXIT_FAILURE );
      }
      i++;
      if ((atoi(argv[i]) <= 0) || (atoi(argv[i]) > 25)) {
        usage();
        exit( EXIT_FAILURE );
      } else {
        threads = atoi(argv[i]);
      }
    } else { // all inputs specified 
      strcpy(filelist[numfiles], argv[i]);
      numfiles++;
    }
  }
  welcome();
  return;
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

void *producer(void *arg) {
  buffer_t *buffer = (buffer_t*) arg;
  while (1) {
    pthread_mutex_lock(&buffer->mutex);
    if(buffer->len == BUFSIZ) {
      pthread_cond_wait(&buffer->more, &buffer->mutex);
    }
    int t = rand();
    printf("Produced: %d\n", t);
    buffer->buf[buffer->len] = t;
    ++buffer->len;
    pthread_cond_signal(&buffer->less);
    pthread_mutex_unlock(&buffer->mutex);
  }
  return NULL;
}

void *consumer(void *arg) {
  buffer_t *buffer = (buffer_t*) arg;
  while(1) {
    pthread_mutex_lock(&buffer->mutex);
    while(buffer->len == 0) {
      pthread_cond_wait(&buffer->less, &buffer->mutex);
    }
    --buffer->len;
    printf("Consumed: %d\n", buffer->buf[buffer->len]);
    pthread_cond_signal(&buffer->more);
    pthread_mutex_unlock(&buffer->mutex);
  }
  return NULL;
}


//fread(pointer to memory, size of element to be read, number of elements, 
//	the pointer to a FILE object)
void DumpInformation (FILE *fp) {
  uint32_t nPacketLength;
  uint32_t newPacketLength = 0;

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
      //printf("skipped: too small\n");	
      fseek(fp, nPacketLength, SEEK_CUR);
    }
    // ignore packets greater than 2400 bytes 
    else if (nPacketLength > 2400) {
      //printf("skipped: too large");
      fseek(fp, nPacketLength, SEEK_CUR);
    }
    else {
      //printf("Packet length was %d\n", nPacketLength);
      //store in a data structure somehow

      //skip the first 52 bytes
      fseek(fp, 52, SEEK_CUR);

      //store the rest of the packet into theData
      newPacketLength = nPacketLength - 52;
      fread(theData, 1, newPacketLength, fp);
    }
    // TODO: add data to the queue
  }
}

// consumers start here 
// TODO: need to add a function that checks for redundancy
void compHash(){
  // make a copy of theData
  char compHash[2000];
  strncpy(compHash, theData, sizeof(theData));

  //compute the hash for theData -- 52 bytes through the end of the packet 
  uint32_t b = 0, c = 0;
  hashlittle2(compHash, sizeof(theData), &b, &c);

  // add packet to hash table
  addPacket(b, &compHash[0]);
}

void chooseHashToEvict(uint32_t hash) {
  int roll = rand() % 6;
  if (!packetsInTable) { // if this is the first entry, it is automatically the packet that will be evicted
    hashToEvict = hash;
  } else if (!roll) { // if roll == 0 (1/6 chance) update packet to evict
    hashToEvict = hash;
  }
}

void addPacket(uint32_t hash, char * data) {
  pthread_rwlock_wrlock(&hashLock);
  DONTCALLTHISaddPacket(hash, data);
  pthread_rwlock_unlock(&hashLock);
}

struct PacketHolder * findPacket (uint32_t hash) {
  pthread_rwlock_rdlock(&hashLock);
  struct PacketHolder * s = DONTCALLTHISfindPacket(hash);
  pthread_rwlock_unlock(&hashLock);
  return s;
}

void deletePacket (struct PacketHolder *packet) {
  pthread_rwlock_wrlock(&hashLock);
  DONTCALLTHISdeletePacket(packet);
  pthread_rwlock_unlock(&hashLock);
}

void DONTCALLTHISaddPacket(uint32_t hash, char * data) {
  struct PacketHolder * s;
  chooseHashToEvict(hash);
  HASH_FIND_INT(packets, &hash, s); // is the packet already in table
  if (s == NULL) {
    if (packetsInTable >= MAX_PACKETS_IN_TABLE) {
      DONTCALLTHISdeletePacket(DONTCALLTHISfindPacket(hashToEvict));  
    }
    s = (struct PacketHolder *)malloc(sizeof(struct PacketHolder));
    s->hash = hash;
    HASH_ADD_INT(packets, hash, s);
  }
  strcpy(s->data, data); 
  packetsInTable++; // increment count of packets in hash table
}


struct PacketHolder * DONTCALLTHISfindPacket (uint32_t hash) {
  struct PacketHolder *s;
  HASH_FIND_INT(packets, &hash, s);  // s: output pointer
  return s;
}

void DONTCALLTHISdeletePacket (struct PacketHolder *packet) {
  HASH_DEL(packets, packet);  // packet: pointer to delete
  free(packet);
  packetsInTable--; // decrement count of packets in table
}

void printPackets() {
  struct PacketHolder *s;

  for(s = packets; s != NULL; s=(struct PacketHolder *)(s->hh.next)) {
    printf("hash %d: data size %ld\n", s->hash, sizeof(s->data));
  }
}

