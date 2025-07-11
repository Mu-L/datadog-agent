#ifndef _STRUCTS_SYSCALLS_H_
#define _STRUCTS_SYSCALLS_H_

#include "constants/custom.h"
#include "bpf.h"
#include "dentry_resolver.h"
#include "filter.h"
#include "events_context.h"
#include "process.h"

struct syscall_monitor_key_t {
    u32 type;
    u32 pid;
};

struct syscall_monitor_entry_t {
    char syscalls[SYSCALL_ENCODING_TABLE_SIZE];
    u64 last_sent;
    u8 dirty;
};

struct syscalls_stats_t {
    s32 count;
    u32 active;
};

struct syscall_table_key_t {
    u64 id;
    u64 syscall_key;
};

struct syscall_cache_t {
    struct policy_t policy;
    u64 type;
    enum SYSCALL_STATE state;
    u8 async;
    u32 ctx_id;
    struct dentry_resolver_input_t resolver;
    s64 retval;
    enum TAIL_CALL_PROG_TYPE prog_type;

    union {
        struct {
            int flags;
            umode_t mode;
            struct dentry *dentry;
            struct file_t file;
            u64 pid_tgid;
        } open;

        struct {
            umode_t mode;
            struct dentry *dentry;
            struct path *path;
            struct file_t file;
        } mkdir;

        struct {
            struct dentry *dentry;
            struct file_t file;
            int flags;
        } unlink;

        struct {
            struct dentry *dentry;
            struct file_t file;
        } rmdir;

        struct {
            struct file_t src_file;
            unsigned long src_inode;
            struct dentry *src_dentry;
            struct dentry *target_dentry;
            struct file_t target_file;
        } rename;

        struct {
            int resource;
            u64 rlim_cur;
            u64 rlim_max;
            u32 pid;
            struct process_context_t target_process;
            struct container_context_t target_container;
        } setrlimit;

        struct {
            struct dentry *dentry;
            struct path *path;
            struct file_t file;
            union {
                umode_t mode;
                struct {
                    uid_t user;
                    gid_t group;
                };
                struct {
                    struct ktimeval atime;
                    struct ktimeval mtime;
                };
            };
        } setattr;

        struct {
            // collected from kernel functions arguments
            struct mount *newmnt;
            struct mount *parent;
            struct dentry *mountpoint_dentry;
            u32 bind_src_mount_id;
            // populated from collected
            const char *fstype;
            struct path_key_t root_key;
            struct path_key_t mountpoint_key;
            dev_t device;
            int clone_mnt_ctr;
            int source;
        } mount;

        struct {
            struct vfsmount *vfs;
        } umount;

        struct {
            struct file_t src_file;
            struct path *src_path;
            struct dentry *src_dentry;
            struct dentry *target_dentry;
            struct file_t target_file;
            enum link_target_dentry_origin target_dentry_origin;
        } link;

        struct {
            struct dentry *dentry;
            struct file_t file;
            const char *name;
            u64 pid_tgid;
        } xattr;

        struct {
            struct dentry *dentry;
            struct file_t file;
            struct args_envs_t args;
            struct args_envs_t envs;
            struct args_envs_parsing_context_t args_envs_ctx;
            struct span_context_t span_context;
            struct linux_binprm_t linux_binprm;
        } exec;

        struct {
            u32 is_thread;
            u32 is_kthread;
        } fork;

        struct {
            struct dentry *dentry;
            struct file_t file;
            u32 event_kind;
            union selinux_write_payload_t payload;
        } selinux;

        struct {
            int cmd;
            u32 map_id;
            u32 prog_id;
            int retval;
            u64 helpers[3];
            union bpf_attr_def *attr;
        } bpf;

        struct {
            u32 request;
            u32 pid;
            u64 addr;
            u32 ns_pid;
        } ptrace;

        struct {
            u64 offset;
            u64 len;
            u64 protection;
            u64 flags;
            struct file_t file;
            struct dentry *dentry;
        } mmap;

        struct {
            u64 vm_start;
            u64 vm_end;
            u64 vm_protection;
            u64 req_protection;
        } mprotect;

        struct {
            struct file_t file;
            struct dentry *dentry;
            char name[MODULE_NAME_LEN];
            u32 loaded_from_memory;
            char args[128];
            u32 args_truncated;
        } init_module;

        struct {
            const char *name;
        } delete_module;

        struct {
            u32 pid;
            u32 type;
            u32 need_target_resolution;
        } signal;

        struct {
            struct file_t file;
            struct dentry *dentry;
            struct pipe_inode_info *pipe_info;
            struct pipe_buffer *bufs;
            u32 file_found;
            u32 pipe_entry_flag;
            u32 pipe_exit_flag;
        } splice;

        struct {
            u64 addr[2];
            u16 family;
            u16 port;
            u16 protocol;
            u64 pid_tgid;
        } bind;

         struct {
            u64 addr[2];
            u16 family;
            u16 port;
            u16 protocol;
            u64 pid_tgid;
        } connect;

         struct {
            u64 addr[2];
            u16 family;
            u16 port;
        } accept;

        struct {
            struct dentry *dentry;
            struct path *path;
            struct file_t file;
        } chdir;

        struct {
            u32 auid;
        } login_uid;

        struct {
            u8 in_flight;
        } stat;

        struct {
            u32 action;
        } sysctl;

        struct {
            short socket_type;
            u16 socket_family;
            unsigned short filter_len;
            u16 socket_protocol;
            int filter_size_to_send;
            int level;
            int optname;
            u32 truncated;
            struct sock_fprog *fprog;
        } setsockopt;
    };
};

#endif
