// SPDX-License-Identifier: Apache-2.0
// Path-selective filesystem mutation enforcement for an exact cgroup target.
#include <vmlinux.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual MIT/GPL";
#define EACCES 13
#define MAY_WRITE 2
#define O_ACCMODE 00000003
#define O_WRONLY 00000001
#define O_RDWR 00000002

enum operation {
    GUARDD_OP_CREATE = 1, GUARDD_OP_LINK, GUARDD_OP_METADATA,
    GUARDD_OP_MOUNT_BYPASS, GUARDD_OP_RENAME, GUARDD_OP_SYMLINK,
    GUARDD_OP_TRUNCATE, GUARDD_OP_UNLINK, GUARDD_OP_WRITE,
    GUARDD_OP_WRITABLE_OPEN,
};
struct target_key { __u64 cgroup_id; };
struct path_key { __u64 generation; __u64 device; __u64 inode; };
struct path_policy { __u32 enabled_operations; __u32 reserved; };
struct denial_event {
    __u64 cgroup_id; __u64 generation; __u64 device; __u64 inode;
    __u32 operation; __s32 error;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, struct target_key);
    __type(value, __u64);
} guarded_targets SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct path_key);
    __type(value, struct path_policy);
} guarded_paths SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} filesystem_denials SEC(".maps");

static __always_inline __u64 governed_generation(void)
{
    struct target_key target = { .cgroup_id = bpf_get_current_cgroup_id() };
    __u64 *generation = bpf_map_lookup_elem(&guarded_targets, &target);
    if (generation)
        return *generation;
    for (__u32 level = 0; level < 64; level++) {
        target.cgroup_id = bpf_get_current_ancestor_cgroup_id(level);
        if (!target.cgroup_id)
            continue;
        generation = bpf_map_lookup_elem(&guarded_targets, &target);
        if (generation)
            return *generation;
    }
    return 0;
}

static __always_inline int deny_inode(struct inode *inode, __u32 operation)
{
    __u64 generation = governed_generation();
    struct path_key key = {};
    struct path_policy *policy;
    struct denial_event *event;
    if (!generation || !inode)
        return 0;
    key.generation = generation;
    key.device = BPF_CORE_READ(inode, i_sb, s_dev);
    key.inode = BPF_CORE_READ(inode, i_ino);
    policy = bpf_map_lookup_elem(&guarded_paths, &key);
    if (!policy || !(policy->enabled_operations & (1U << operation)))
        return 0;
    event = bpf_ringbuf_reserve(&filesystem_denials, sizeof(*event), 0);
    if (event) {
        event->cgroup_id = bpf_get_current_cgroup_id();
        event->generation = key.generation;
        event->device = key.device;
        event->inode = key.inode;
        event->operation = operation;
        event->error = -EACCES;
        bpf_ringbuf_submit(event, 0);
    }
    return -EACCES;
}

static __always_inline int deny_dentry(struct dentry *dentry, __u32 operation)
{
    return deny_inode(BPF_CORE_READ(dentry, d_inode), operation);
}

SEC("lsm/file_open")
int BPF_PROG(deny_writable_open, struct file *file, int ret)
{
    int flags;
    if (ret) return ret;
    flags = BPF_CORE_READ(file, f_flags) & O_ACCMODE;
    return (flags == O_WRONLY || flags == O_RDWR) ?
        deny_inode(BPF_CORE_READ(file, f_inode), GUARDD_OP_WRITABLE_OPEN) : 0;
}
SEC("lsm/file_permission")
int BPF_PROG(deny_write, struct file *file, int mask, int ret)
{
    if (ret) return ret;
    return (mask & MAY_WRITE) ?
        deny_inode(BPF_CORE_READ(file, f_inode), GUARDD_OP_WRITE) : 0;
}
SEC("lsm/path_truncate")
int BPF_PROG(deny_truncate, const struct path *path, int ret)
{
    return ret ? ret : deny_dentry(BPF_CORE_READ(path, dentry), GUARDD_OP_TRUNCATE);
}
SEC("lsm/inode_create")
int BPF_PROG(deny_create, struct inode *dir, struct dentry *dentry,
             umode_t mode, int ret)
{
    return ret ? ret : deny_inode(dir, GUARDD_OP_CREATE);
}
SEC("lsm/inode_mkdir")
int BPF_PROG(deny_mkdir, struct inode *dir, struct dentry *dentry,
             umode_t mode, int ret)
{
    return ret ? ret : deny_inode(dir, GUARDD_OP_CREATE);
}
SEC("lsm/inode_mknod")
int BPF_PROG(deny_mknod, struct inode *dir, struct dentry *dentry,
             umode_t mode, dev_t dev, int ret)
{
    return ret ? ret : deny_inode(dir, GUARDD_OP_CREATE);
}
SEC("lsm/inode_link")
int BPF_PROG(deny_link, struct dentry *old_dentry, struct inode *dir,
             struct dentry *new_dentry, int ret)
{
    int denied;
    if (ret) return ret;
    denied = deny_dentry(old_dentry, GUARDD_OP_LINK);
    return denied ? denied : deny_inode(dir, GUARDD_OP_LINK);
}
SEC("lsm/inode_setattr")
int BPF_PROG(deny_metadata, struct mnt_idmap *idmap, struct dentry *dentry,
             struct iattr *attr, int ret)
{
    return ret ? ret : deny_dentry(dentry, GUARDD_OP_METADATA);
}
SEC("lsm/inode_setxattr")
int BPF_PROG(deny_setxattr, struct mnt_idmap *idmap, struct dentry *dentry,
             const char *name, const void *value, size_t size, int flags, int ret)
{
    return ret ? ret : deny_dentry(dentry, GUARDD_OP_METADATA);
}
SEC("lsm/inode_removexattr")
int BPF_PROG(deny_removexattr, struct mnt_idmap *idmap, struct dentry *dentry,
             const char *name, int ret)
{
    return ret ? ret : deny_dentry(dentry, GUARDD_OP_METADATA);
}
SEC("lsm/inode_rename")
int BPF_PROG(deny_rename, struct inode *old_dir, struct dentry *old_dentry,
             struct inode *new_dir, struct dentry *new_dentry, int ret)
{
    int denied;
    if (ret) return ret;
    denied = deny_inode(old_dir, GUARDD_OP_RENAME);
    if (!denied) denied = deny_dentry(old_dentry, GUARDD_OP_RENAME);
    if (!denied) denied = deny_inode(new_dir, GUARDD_OP_RENAME);
    return denied ? denied : deny_dentry(new_dentry, GUARDD_OP_RENAME);
}
SEC("lsm/inode_symlink")
int BPF_PROG(deny_symlink, struct inode *dir, struct dentry *dentry,
             const char *old_name, int ret)
{
    return ret ? ret : deny_inode(dir, GUARDD_OP_SYMLINK);
}
SEC("lsm/inode_unlink")
int BPF_PROG(deny_unlink, struct inode *dir, struct dentry *dentry, int ret)
{
    int denied;
    if (ret) return ret;
    denied = deny_inode(dir, GUARDD_OP_UNLINK);
    return denied ? denied : deny_dentry(dentry, GUARDD_OP_UNLINK);
}
SEC("lsm/inode_rmdir")
int BPF_PROG(deny_rmdir, struct inode *dir, struct dentry *dentry, int ret)
{
    int denied;
    if (ret) return ret;
    denied = deny_inode(dir, GUARDD_OP_UNLINK);
    return denied ? denied : deny_dentry(dentry, GUARDD_OP_UNLINK);
}
SEC("lsm/sb_mount")
int BPF_PROG(deny_mount_bypass, const char *dev_name, const struct path *path,
             const char *type, unsigned long flags, void *data, int ret)
{
    return ret ? ret :
        deny_dentry(BPF_CORE_READ(path, dentry), GUARDD_OP_MOUNT_BYPASS);
}
