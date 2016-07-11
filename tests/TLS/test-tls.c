#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define BUF_SIZE 128
#define NUM_THREADS 2

// THREAD DATA
__thread int my_num; //.tbss
__thread char thread_buf[BUF_SIZE];
//__thread int *my_num_prt = &my_num; // reloc! (not possible)
__thread char *str = "rodata?"; // str in .rodata, ptr in .tdata (all point to same string)

// GLOBAL DATA
unsigned int current = 0;
char global_buf[BUF_SIZE];
pthread_mutex_t lock;

int get_my_num(void){
	return my_num;
}


void *do_thread_stuff(void *args){
	pthread_mutex_lock(&lock);
		my_num = current++;
		printf("my_num %d @ %p\n", my_num, &my_num);
		printf("str      @ %p\n", &str);
		// the memset is critical. need to make sure the thread data
		// doesnt overwrite the thread bookkeeping data
		// if it does, we should get a segfault
		memset(thread_buf, 0x41, BUF_SIZE);
	pthread_mutex_unlock(&lock);
	return NULL;
}

int main(void){
	printf("This is the ptr in .tdata: 0x%p\n", &str);
	int x;
	int *main_ptr  = &my_num;
	printf("in main &my_num=0x%p\n", &my_num);
	pthread_t threads[NUM_THREADS];
	for (x = 0; x < NUM_THREADS; x++){
		pthread_create(&threads[x], NULL, &do_thread_stuff, NULL);
	}
	for (x = 0; x < NUM_THREADS; x++){
		pthread_join(threads[x], NULL);
	}
	return 0;
}


