#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include<conio.h>
extern int xor_do_crypt(FILE* fp1, int action, char* key_str){
	if(action<0)//pass through aka don't touch
	{
	return 0;
	}
	int val1;
	int write_at=0;
	int read_at=0;
	int count=0;
	int passlength=strlen(key_str);

	if(fp1==NULL)
	{
	printf("Cannot open source file");
	exit(0);
	}
	
	
	while((val1=fgetc(fp1))!=EOF)
	{
	//if(val1=='\n')
	//break;
	//printf("t");
	read_at=ftell(fp1);
	fseek(fp1,write_at,SEEK_SET);
	fputc(val1^key_str[count%passlength],fp1);
	write_at=ftell(fp1);
	fseek(fp1,read_at,SEEK_SET);
	count++;
	}
	printf("Success!");
	//fclose(fp1);

return 0;
}



/*int main(int argc, char *argv[])
{
FILE *fp1;
if(argc!=3)
	{
	printf("arg missing");
	exit(0);
	}
	
	fp1=fopen(argv[1],"r+");
char pass[32];
strncpy(pass,argv[2],32);
xor_encrypt(fp1,0,pass);



/*int a=100;
int b=1;
//int c='c';
char c= a^b;
printf("a:%d, b:%d, c:%c",a,b,c);
return 0;*/

/*char pass[4];
strncpy(pass,"pass",4);*/
	/*FILE *fp1;
	int val1;
	int write_at=0;
	int read_at=0;
	if(argc!=2)
	{
	printf("arg missing");
	exit(0);
	}
	
	fp1=fopen(argv[1],"r+");

	if(fp1==NULL)
	{
	printf("Cannot open source file");
	exit(0);
	}
	
	while((val1=fgetc(fp1))!=EOF)
	{
	if(val1=='\n')
	break;
	printf("t");
	read_at=ftell(fp1);
	fseek(fp1,write_at,SEEK_SET);
	fputc('A'+val1-'a',fp1);
	write_at=ftell(fp1);
	fseek(fp1,read_at,SEEK_SET);
	}
	printf("Success!");
	fclose(fp1);

return 0;*/
//}

