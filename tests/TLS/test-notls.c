#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define BUF_SIZE 128
#define NUM_THREADS 2

// GLOBAL DATA
unsigned int current = 0;
char global_buf[BUF_SIZE];
pthread_mutex_t lock;

int get_current(void){
	return current;
}


void *do_thread_stuff(void *args){
	pthread_mutex_lock(&lock);
		char* gs;
		asm ("movl %%gs:0, %0"
			:"=r" (gs)
			:
			:);
		printf("gs segment address: %p\n", gs);
		get_current();
	pthread_mutex_unlock(&lock);
	return NULL;
}

int main(void){
	int x;
	pthread_t threads[NUM_THREADS];
	for (x = 0; x < NUM_THREADS; x++){
		pthread_create(&threads[x], NULL, &do_thread_stuff, NULL);
	}
	for (x = 0; x < NUM_THREADS; x++){
		pthread_join(threads[x], NULL);
	}
	return 0;
}


