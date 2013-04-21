#include <sys/types.h>  /* Primitive System Data Types */ 
#include <sys/time.h>
#include <sys/syscall.h>
#include <time.h>
#include <errno.h>      /* Errors */
#include <stdio.h>      /* Input/Output */
#include <stdlib.h>     /* General Utilities */
#include <pthread.h>    /* POSIX Threads */
#include <string.h>     /* String handling */

 static __inline__ unsigned long long  getticks(void);
int main()
{
   char ch, source_file[20], target_file[20];
   FILE *source, *target;
 
   printf("Enter name of file to copy\n");
   gets(source_file);
 unsigned long long start=getticks();
   source = fopen(source_file, "r");
 
   if( source == NULL )
   {
      printf("Press any key to exit...\n");
      exit(EXIT_FAILURE);
   }
 
   printf("Enter name of target file\n");
   gets(target_file);
 
   target = fopen(target_file, "w");
 
   if( target == NULL )
   {
      fclose(source);
      printf("Press any key to exit...\n");
      exit(EXIT_FAILURE);
   }
 
   while( ( ch = fgetc(source) ) != EOF )
      fputc(ch, target);
 
   printf("File copied successfully.\n");
 
   fclose(source);
   fclose(target);
 printf("%lld\n",getticks()-start);
   return 0;
}

static __inline__ unsigned long long getticks(void)
{
     unsigned a, d;
     asm volatile("cpuid"); 
      asm volatile("rdtsc" : "=a" (a), "=d" (d));
    unsigned long long ret= (((unsigned long long)a) | (((unsigned long long)d) << 32));
	return ret;
}
