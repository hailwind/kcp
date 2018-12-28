    #include <unistd.h>  
    #include <stdio.h>  
    #include <fcntl.h>  
    #include <sys/types.h>  
    #include <sys/stat.h>  
    #include <string.h>  
      
    #define FIFO "/var/run/ififo"  
      
    int main(void)  
    {  
        int fd;  
        char buf[128];  
        if(mkfifo(FIFO, 0666))//创建管道文件  
        {  
             perror("Mkfifo error");  
        }  
        printf("open for reading... \n");  
    //  fd=open(FIFO,O_RDONLY);//阻塞  
        fd=open(FIFO,O_RDONLY);//非阻塞  
        /* 
        1：open(fifo, O_RDONLY);  
               open(fifo, O_WRONLY); 
                不管先运行哪个，都会等另一个进程把对应连接打开时候才open结束 
                  reader 的 open会等到writer的open  运行起来才open结束, 
                  反之亦然 
            2：open(fifo, O_RDONLY|O_NONBLOCK );  就不等待writer打开文件了 
            3：open(fifo , O_WRONLY|O_NONBLOCK)： 
             如果没有reader打开该管道文件的话，就直接报错，退出进程 
             用perror去抓信息，得到的会是No such device or address 
            得先运行reader 
        */  
        printf("opened ... \n");  
        if(fd<0)  
        {  
            perror("Failed to open fifo:");  
            return -1;  
        }  
      
        while(1)  
        {  
            int count;  
            count=read(fd,buf,127);  
            //要用底层io。read()会返回实际读到的字节数  
            if(count>0)  
            {  
                buf[count]=0;//结束符，也可以='\0';  
                printf("fifoReader receive a string:%s\n",buf);  
            }
            if(strncmp(buf,"exit",4)==0)  
            {  
                break;  
            }  
        }  
        close(fd);    
        return 0;  
    }  