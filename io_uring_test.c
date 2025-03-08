/*
Revised implementation of io_uring 
*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <linux/io_uring.h>

//one level is fine -- don't worry about it 
#define QUEUE_DEPTH 1 

#define read_barrier()  __asm__ __volatile__("fence r, r"::);
#define write_barrier() __asm__ __volatile__("fence w, w"::);

struct app_io_sq_ring {
    unsigned *head;
    unsigned *tail;
    unsigned *ring_mask;
    unsigned *ring_entries;
    unsigned *flags;
    unsigned *array;
};

struct app_io_cq_ring {
    unsigned *head;
    unsigned *tail;
    unsigned *ring_mask;
    unsigned *ring_entries;
    struct io_uring_cqe *cqes;
};

struct submitter {
    int ring_fd;
    struct app_io_sq_ring sq_ring; //why not make this a pointer? 
    struct io_uring_sqe *sqes; //array of sq entries?
    struct app_io_cq_ring cq_ring;
};

//the two syscall wrapper functions 
//Copied straight from mini_liburing?
int io_uring_setup(unsigned entries, struct io_uring_params *p)
{
    return (int) syscall(__NR_io_uring_setup, entries, p);
}

int io_uring_enter(int ring_fd, unsigned int to_submit,
                          unsigned int min_complete, unsigned int flags)
{
    return (int) syscall(__NR_io_uring_enter, ring_fd, to_submit, min_complete,
                   flags, NULL, 0);
}


int app_setup_uring(struct submitter *s) {
    struct app_io_sq_ring *sring = &s->sq_ring;
    struct app_io_cq_ring *cring = &s->cq_ring;
    struct io_uring_params p;
    void *sq_ptr, *cq_ptr;

    /*
     * We need to pass in the io_uring_params structure to the io_uring_setup()
     * call zeroed out. We could set any flags if we need to, but for this
     * example, we don't.
     * */
    memset(&p, 0, sizeof(p));
    s->ring_fd = io_uring_setup(QUEUE_DEPTH, &p);
    if (s->ring_fd < 0) {
        perror("io_uring_setup");
        return 1;
    }

    /*
     * io_uring communication happens via 2 shared kernel-user space ring buffers,
     * which can be jointly mapped with a single mmap() call in recent kernels. 
     * While the completion queue is directly manipulated, the submission queue 
     * has an indirection array in between. We map that in as well.
     * */

    int sring_sz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
    int cring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);

    /* In kernel version 5.4 and above, it is possible to map the submission and 
     * completion buffers with a single mmap() call. Rather than check for kernel 
     * versions, the recommended way is to just check the features field of the 
     * io_uring_params structure, which is a bit mask. If the 
     * IORING_FEAT_SINGLE_MMAP is set, then we can do away with the second mmap()
     * call to map the completion ring.
     * */
    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        if (cring_sz > sring_sz) {
            sring_sz = cring_sz;
        }
        cring_sz = sring_sz;
    }

    /* Map in the submission and completion queue ring buffers.
     * Older kernels only map in the submission queue, though.
     * */
    sq_ptr = mmap(0, sring_sz, PROT_READ | PROT_WRITE, 
            MAP_SHARED | MAP_POPULATE,
            s->ring_fd, IORING_OFF_SQ_RING);
    if (sq_ptr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    if (p.features & IORING_FEAT_SINGLE_MMAP) {
        cq_ptr = sq_ptr;
    } else {
        /* Map in the completion queue ring buffer in older kernels separately */
        cq_ptr = mmap(0, cring_sz, PROT_READ | PROT_WRITE, 
                MAP_SHARED | MAP_POPULATE,
                s->ring_fd, IORING_OFF_CQ_RING);
        if (cq_ptr == MAP_FAILED) {
            perror("mmap");
            return 1;
        }
    }
    /* Save useful fields in a global app_io_sq_ring struct for later
     * easy reference */
    sring->head = sq_ptr + p.sq_off.head;
    sring->tail = sq_ptr + p.sq_off.tail;
    sring->ring_mask = sq_ptr + p.sq_off.ring_mask;
    sring->ring_entries = sq_ptr + p.sq_off.ring_entries;
    sring->flags = sq_ptr + p.sq_off.flags;
    sring->array = sq_ptr + p.sq_off.array;

    /* Map in the submission queue entries array */
    s->sqes = mmap(0, p.sq_entries * sizeof(struct io_uring_sqe),
            PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
            s->ring_fd, IORING_OFF_SQES);
    if (s->sqes == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    /* Save useful fields in a global app_io_cq_ring struct for later
     * easy reference */
    cring->head = cq_ptr + p.cq_off.head;
    cring->tail = cq_ptr + p.cq_off.tail;
    cring->ring_mask = cq_ptr + p.cq_off.ring_mask;
    cring->ring_entries = cq_ptr + p.cq_off.ring_entries;
    cring->cqes = cq_ptr + p.cq_off.cqes;

    return 0;
}
/*until this point no difference to uring_test */


int read_from_cq(struct submitter *s, int* buf, int count) {
    //read up to count amount of retval from complete queue described in submitter
    //Put the return value into buf 
    //return the actual amount read from CQ
    
    /*
    struct definition is in /io_uring_Demo/include/linux/io_uring.h
    struct peng_req{
        unsigned long pg_cmd; 
        unsigned long args[COHORT_MAX_ARGS]; 
        int retval; 
    }
    */
    
    struct peng_req *fi;
    struct app_io_cq_ring *cring = &s->cq_ring;
    struct io_uring_cqe *cqe;
    unsigned head, reaped = 0;
    if(buf == NULL){
        printf("buf is NULL. Abort reading."); 
        return -1; 
    }
    if(count < 0){
        printf("Error, count < 0. Abort reading."); 
        return -1; 
    }
    head = *cring->head;
    int read_amount = 0; 
    do {
        read_barrier();
        /*
         * Remember, this is a ring buffer. If head == tail, it means that the
         * buffer is empty.
         * */
        if (head == *cring->tail)
            break;
        /* Get the entry */
        cqe = &cring->cqes[head & *s->cq_ring.ring_mask]; 
        fi = (struct peng_req*) cqe->user_data;
        if (cqe->res < 0)
            fprintf(stderr, "Error: %s\n", strerror(abs(cqe->res)));
        //lx is unsigned long printed in hexadecimal
        //printf("0x%lx\n", fi->retval);
        buf[read_amount] = fi->retval; 
        head++;
        read_amount += 1; 
    } while (1);

    *cring->head = head;
    write_barrier();
    return read_amount;
}

//this function does 3 functions job in mini_liburing - prepares cmd, presend and submit? 
int submit_to_sq(struct submitter *s, unsigned long cmd, unsigned long* argsToSubmit, int count) {
//submit peng req with pg_cmd = cmd, args = argsToSubmit, count = number of args 
//to submission queue described in submitter

//should we regulate what value cmd could be? 


    if(argsToSubmit == NULL){
        printf("Abort submit_to_sq, argsToSubmit is NULL \n"); 
        return -1;  
    }
    if(count > COHORT_MAX_ARGS){
        printf("Abort submit_to_sq, count exceeds COHORT_MAX_ARGS\n"); 
        return -1;  
    }
    if(count <= 0){
        printf("Abort submit_to_sq, count <= 0 \n"); 
        return -1;  
    }
    struct peng_req *req;
    struct app_io_sq_ring *sring = &(s->sq_ring);

    unsigned index = 0, tail = 0, next_tail = 0;

    //set up the the peng_req to submit 
    req = malloc(sizeof(struct peng_req));
    if (!req) {
        fprintf(stderr, "Unable to allocate memory\n");
        return 1;
    }

    //set up the member variables of req
    req->pg_cmd = cmd; 
    for(int i=0; i<count; i++){
        req->args[i] = argsToSubmit[i]; 
    }
    
    tail = *sring->tail; 
    next_tail = *sring->tail; 
    next_tail++; 
    read_barrier(); 
    index = tail & *s->sq_ring.ring_mask;

    //Puts a new entry into submission queue
    struct io_uring_sqe *sqe = &((s->sqes)[index]); 
    //set up the other parameters of the entry 
    //everything except user_data and addr are not determined by user input yet
    sqe->fd = 0; //No need to be function input
    sqe->flags = 0;  //No need to be function input
    sqe->opcode = IORING_OP_PENGPUSH; //constant
    sqe->addr = (unsigned long) req; //dont worry that this points to the same place as user_data 
    sqe->len = 0; //No need to be function input
    sqe->off = 0; //No need to be function input
    sqe->user_data = (unsigned long long) req; //why user data same pointer as addr
    
    //this part is in io_uring_submit in mini_liburing 
    sring->array[index] = index;
    tail = next_tail;

    /* Update the tail so the kernel can see it. */
    if(*sring->tail != tail) { //why this check? 
        *sring->tail = tail;
        write_barrier();
    }

    int ret =  io_uring_enter(s->ring_fd, 1,1,
        IORING_ENTER_GETEVENTS);
    if(ret < 0) {
        perror("io_uring_enter");
        return 1;
    }

    return 0;
}
//testings 
int main(void) {
    int maxSize = COHORT_MAX_ARGS;
    int exceedSize = maxSize + 1; 
    struct submitter *s;
    unsigned long arr[10];
    int retvals[20]; 
    for (int i=0; i<10; i++){
        arr[i] = 0xc0ffee + i;
    }

    s = malloc(sizeof(*s));
    if (!s) {
        perror("malloc");
        return 1;
    }
    memset(s, 0, sizeof(*s));

    printf("Setting up submitter\n"); 
    if(app_setup_uring(s)) {
        fprintf(stderr, "Unable to setup uring!\n");
        return 1;
    }

    printf("First submission with args count = %d\n", maxSize); 
    if(submit_to_sq(s, RV_CONF_IOMMU, arr, maxSize)) {
        fprintf(stderr, "Error reading file\n");
        return 1;
    }
    printf("Second submission with args count = %d should fail\n", exceedSize); 
    if(submit_to_sq(s, RV_CONF_IOMMU, arr, exceedSize) > 0) {
        fprintf(stderr, "Error submitting > max size file is successful\n");
        return 1;
    }
    printf("Read from cq\n"); 
    int read_amount = read_from_cq(s, retvals, 20); 
//    if(read_amount != maxSize){
//        fprintf(stderr, "Read %d, which is less than expected\n", read_amount);
//  }
    printf("read_amount = %d, Printing what is contained in retvals\n", read_amount); 
    for(int i = 0; i < read_amount; i++){
        printf("0x%lx\n", retvals[i]); 
    }
    printf("End of main\n"); 


    /* read_from_cq(s); */

    return 0;
}
