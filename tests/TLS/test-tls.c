#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>


__thread int my_num; //.tbss
//__thread int *my_num_prt = &my_num; // reloc!
__thread char *str = "rodata?"; // str in .rodata, ptr in .tdata (all point to same string)
unsigned int current = 0;

int get_errno(void){
	return my_num;
}


void *do_thread_stuff(void *args){
	my_num = current++;
	printf("%d: 0x%p\n", my_num, &my_num);
	return NULL;
}

int main(void){
	printf("This is the ptr in .tdata: 0x%p\n", str);
	int num_threads = 5;
	int x;
	int *main_ptr  = &my_num;
	printf("in main &my_num=0x%p\n", &my_num);
	pthread_t threads[5];
	for (x = 0; x < num_threads; x++){
		pthread_create(&threads[x], NULL, &do_thread_stuff, NULL);
	}
	for (x = 0; x < num_threads; x++){
		pthread_join(threads[x], NULL);
	}
	return 0;
}


