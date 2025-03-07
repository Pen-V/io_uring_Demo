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


void read_from_cq(struct submitter *s, unsigned long* buf, int* count) {
    //type of buf needs to determined by type of fi->retval
        //chose to be unsigned long * because of %lx in the printf 
    //will read from cq, put retval into buf[count] until ring is empty fails 
    //count will be incremented by how many items are read 
    //*count needs to be a non-negative number 

    //should we always start count from 0? 
    //since count is inputted by user 
    //buf is a pointer, to an array ideally 
    

    struct peng_req *fi;
    struct app_io_cq_ring *cring = &s->cq_ring;
    struct io_uring_cqe *cqe;
    unsigned head, reaped = 0;
    if(count == NULL){
        printf("Count is NULL. Abort reading."); 
        return; 
    }
    if(buf == NULL){
        printf("buf is NULL. Abort reading."); 
        return; 
    }
    if((*count) < 0){
        printf("Error, (*count) < 0. Abort reading."); 
        return; 
    }
    head = *cring->head;
    do {
        read_barrier();
        /*
         * Remember, this is a ring buffer. If head == tail, it means that the
         * buffer is empty.
         * */
        if (head == *cring->tail)
            break;
        /* Get the entry */

        //what is the order of operations in the next line 
        cqe = &cring->cqes[head & *s->cq_ring.ring_mask]; 
        fi = (struct peng_req*) cqe->user_data;
        if (cqe->res < 0)
            fprintf(stderr, "Error: %s\n", strerror(abs(cqe->res)));
        //lx is unsigned long printed in hexadecimal
        //printf("0x%lx\n", fi->retval);
        buf[*count] = fi->retval; 

        head++;
        (*count) += 1; 
    } while (1);

    *cring->head = head;
    write_barrier();
}

// unsigned long read_one_from_cq(struct submitter* s){

// }]

//allow what args to submit and the count? 
//this function does 3 functions job in mini_liburing? prepares cmd, presend and submit? 
int submit_to_sq(struct submitter *s, unsigned long* argsToSubmit, int count) {
//again, type of argsToSubmit need to depend on type of req->args
//need to see where peng_req struct definition is 
//do we want to submit mutliple peng req at the same time? 
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

    struct app_io_sq_ring *sring = &(s->sq_ring); //this order? 

    unsigned index = 0, tail = 0, next_tail = 0;

    //set up the the peng_req to submit 
    req = malloc(sizeof(struct peng_req));
    if (!req) {
        fprintf(stderr, "Unable to allocate memory\n");
        return 1;
    }
    req->pg_cmd = RV_CONF_IOMMU; //does this need to be a function input? 
    //what args should be given in reality? 
    //the user provide that from function call? 
    for(int i=0; i<count; i++){
        req->args[i] = argsToSubmit[i]; 
    }
    
    tail = *sring->tail; 
    next_tail = *sring->tail; 
    next_tail++; 
    read_barrier(); 
    index = tail & *s->sq_ring.ring_mask; //what is the purpose of the mask 

    //this puts a new entry into submission queue? 
    struct io_uring_sqe *sqe = &((s->sqes)[index]); //intended order?
    sqe->fd = 0; //does this need to be a function input? 
    sqe->flags = 0; //does this need to be a function input? 
    sqe->opcode = IORING_OP_PENGPUSH; //constant? 
    sqe->addr = (unsigned long) req;
    sqe->len = 0;//does this need to be a function input? 
    sqe->off = 0;//this is not set in mini_liburing? 
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

int main(void) {
    struct submitter *s;

    unsigned long arr[10];
    for (int i=0; i<10; i++)
        arr[i] = 0xc0ffee;

    s = malloc(sizeof(*s));
    if (!s) {
        perror("malloc");
        return 1;
    }
    memset(s, 0, sizeof(*s));

    if(app_setup_uring(s)) {
        fprintf(stderr, "Unable to setup uring!\n");
        return 1;
    }

    if(submit_to_sq(s, arr, 10)) {
        fprintf(stderr, "Error reading file\n");
        return 1;
    }
    /* read_from_cq(s); */

    return 0;
}
