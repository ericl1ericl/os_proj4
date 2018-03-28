#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define DEF_LEVEL 1
#define DEF_THREADS 1
#define MAX_FILES 10
#define MAX_FILENAME_LENGTH 30

int level = DEF_LEVEL;
int threads = DEF_THREADS;
char filelist[MAX_FILES][MAX_FILENAME_LENGTH + 1];
int numfiles = 0;

void usage() {
  printf("usage: threadedRE [-level l] [-threads t] file1 [file2 ...]\n");
  printf("\t-level l: version of program to run (default 1)\n");
  printf("\t-threads t: max number of threads allowed (default 1)\n");
  printf("\t-file1 ... : list of .pcap files to process\n");
  return;
}

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

int main (int argc, char * argv[]) {
  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-level")) {
      if (i == (argc - 1)) {
        usage();
        return 1;
      }
      i++;
      level = atoi(argv[i]);
    } else if (!strcmp(argv[i], "-threads")) {
      if (i == (argc - 1)) {
        usage();
        return 1;
      }
      i++;
      threads = atoi(argv[i]);
    } else {
      strcpy(filelist[numfiles], argv[i]);
      numfiles++;
    }
  }
  welcome();
  return 0;
}
