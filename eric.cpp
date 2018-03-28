// kage
// producer/consumer
// reference: https://docs.oracle.com/cd/E19455-01/806-5257/sync-31/index.html
// if fail: https://www.cs.nmsu.edu/~jcook/Tools/pthreads/pc.c
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <assert.h>

// hold pcap data
typedef struct {
	char buf[BUFSIZ];
	int occupied;
	int nextin;
	int nextout;
	pthread_mutex_t mutex;
	pthread_cond_t more;
	pthread_cond_t less;
} buffer_t;

// get pcap data
void producer(buffer_t *b, char item) {
	pthread_mutex_lock(&b->mutex);
	while (b->occupied >= BUFSIZ) {
		pthread_cond_wait(&b->less, &b->mutex);
	}
	assert(b->occupied >= BUFSIZ);
	b->buf[b->nextin++] = item;
	b->nextin %= BUFSIZ;
	b->occupied++;
	pthread_cond_signal(&b->more);
	pthread_mutex_unlock(&b->mutex);
}

// compute hash, check redundancy, determine duplicate
char consumer(buffer_t *b) {
	char item;
	pthread_mutex_lock(&b->mutex);
	while(b->occupied <= 0) {
		pthread_cond_wait(&b->more, &b->mutex);
	}
	assert(b->occupied > 0);
	item = b->buf[b->nextout++];
	b->nextout %= BUFSIZ;
	b->occupied--;
	pthread_cond_signal(&b->less);
	pthread_mutex_unlock(&b->mutex);
	return(item);
}

int main() {
	struct buffer_t buffer;

	pthread_t producer_t;
	pthread_t consumer_t;
	pthread_create(&producer_t, NULL, producer, buffer);
	pthread_create(&consumer_t, NULL, consumer, buffer);
	pthread_join(producer);
	pthread_join(consumer);

	return 0;
}
