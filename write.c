    #include <unistd.h>  
    #include <stdio.h>  
    #include <fcntl.h>  
    #include <sys/types.h>  
    #include <sys/stat.h>  
    #include <string.h>  
    #include <signal.h>  
      
    #define FIFO "/var/run/ififo"  
    int main(void)  
    {  
        int fd;  
        char buf[128];  
      
        if(mkfifo(FIFO, 0666))  
        {  
            perror("Mkfifo error");  
        }  
        printf("open for writing ... \n");  
        // fd=open(FIFO,O_WRONLY);// 阻塞  
        fd=open(FIFO,O_WRONLY);// 如果写端设置成非阻塞，不能先于读端运行，否则 open失败  
        printf("opened... \n");  
        if(fd<0)  
        {  
            perror("Failed to open fifo:");  
            return -1;  
        }
          
        while(1)  
        {  
            fgets(buf,128,stdin);//标准输入内容  
            write(fd,buf,strlen(buf));//把缓存写入  
            if(strncmp(buf,"exit",4)==0)  
            {  
                break;  
            }  
        }  
        close(fd);  
        unlink(FIFO);     
        return 0;  
    }  