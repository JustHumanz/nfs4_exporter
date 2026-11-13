
#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"
#include "bpf_helpers.h"
#include "nfsd_trace.h"

struct data_t {
    u32 op;
    u32 size;
    u32 addr4;
    u16 prt;
    u32 version;
    char path[MAX_PATH_COMPONENTS][COMPONENT_LEN]; // 16 x 64 = 2048 bytes
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct mount___local {
    struct hlist_node mnt_hash;
    struct mount___local *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;
} __attribute__((preserve_access_index));

static __always_inline void build_path(struct dentry *dentry, struct vfsmount *vfsmnt,
                                        char comp[MAX_PATH_COMPONENTS][COMPONENT_LEN])
{
    u8 n = 0;

    #pragma unroll
    for (int i = 0; i < MAX_PATH_COMPONENTS; i++) {

        #pragma unroll
        for (int j = 0; j < MAX_MOUNT_HOPS; j++) {
            struct dentry *mnt_root = BPF_CORE_READ(vfsmnt, mnt_root);
            if (dentry != mnt_root)
                break;

            struct mount___local *real_mnt =
                (void *)vfsmnt - offsetof(struct mount___local, mnt);
            struct mount___local *parent_mnt;
            struct dentry *mountpoint;
            bpf_core_read(&parent_mnt, sizeof(parent_mnt), &real_mnt->mnt_parent);
            bpf_core_read(&mountpoint, sizeof(mountpoint), &real_mnt->mnt_mountpoint);
            if (parent_mnt == real_mnt)
                break;
            dentry = mountpoint;
            vfsmnt = &parent_mnt->mnt;
        }

        struct dentry *parent = BPF_CORE_READ(dentry, d_parent);
        if (parent == dentry)
            break;

        const unsigned char *name_ptr = BPF_CORE_READ(dentry, d_name.name);

        u8 idx = n & (MAX_PATH_COMPONENTS - 1);
        bpf_probe_read_kernel_str(comp[idx], COMPONENT_LEN, name_ptr);
        n++;

        dentry = parent;
    }
}

static __always_inline int trace_rw(struct pt_regs *ctx, struct svc_rqst *rqstp,
                                     struct svc_export *fh_export, struct dentry *fh_dentry,
                                     const void *buflen, u32 op, u32 version)
{
    struct __kernel_sockaddr_storage remote = {};
    bpf_probe_read_kernel(&remote, sizeof(remote), &rqstp->rq_addr);

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &remote.ss_family);
    if (family != AF_INET)
        return 0;

    struct data_t *data = bpf_ringbuf_reserve(&events, sizeof(*data), 0);
    if (!data)
        return 0;

    volatile u32 *data_words = (volatile u32 *)data;
    #pragma unroll
    for (int i = 0; i < sizeof(*data) / sizeof(u32); i++)
        data_words[i] = 0;
    data->op = op;
    data->version = version;
    bpf_probe_read_kernel(&data->size, sizeof(data->size), buflen);

    struct sockaddr_in *sin = (struct sockaddr_in *)&remote;
    bpf_probe_read_kernel(&data->addr4, sizeof(data->addr4), &sin->sin_addr.s_addr);
    bpf_probe_read_kernel(&data->prt, sizeof(data->prt), &sin->sin_port);

    if (fh_export && fh_dentry) {
        struct vfsmount *vfsmnt = NULL;
        bpf_probe_read_kernel(&vfsmnt, sizeof(vfsmnt), &fh_export->ex_path.mnt);
        if (vfsmnt)
            build_path(fh_dentry, vfsmnt, data->path);
    }

    bpf_printk("NFS OP %d size: %d version: %d\n",
               data->op, data->size, data->version);

    bpf_ringbuf_submit(data, 0);
    return 0;
}
// Wrapper for nfsd_write
SEC("kprobe/nfsd4_write")
int kprobe__nfsd4_write(struct pt_regs *ctx)
{
    struct svc_rqst *rqstp = (struct svc_rqst *)PT_REGS_PARM1(ctx);
    struct nfsd4_compound_state *cstate = (struct nfsd4_compound_state *)PT_REGS_PARM2(ctx);
    struct nfsd4_write *write = (struct nfsd4_write *)PT_REGS_PARM3(ctx);

    struct svc_export *	fh_export = NULL;
    struct dentry *fh_dentry = NULL;
    bpf_probe_read_kernel(&fh_export, sizeof(fh_export), &cstate->current_fh.fh_export);
    bpf_probe_read_kernel(&fh_dentry, sizeof(fh_dentry), &cstate->current_fh.fh_dentry);

    return trace_rw(ctx, rqstp, fh_export, fh_dentry, &write->wr_buflen,OP_WRITE,NFS4_VER);
}

// Wrapper for nfsd_read
SEC("kprobe/nfsd4_read")
int kprobe__nfsd4_read(struct pt_regs *ctx)
{
    struct svc_rqst *rqstp = (struct svc_rqst *)PT_REGS_PARM1(ctx);
    struct nfsd4_compound_state *cstate = (struct nfsd4_compound_state *)PT_REGS_PARM2(ctx);
    void *u = (void *)PT_REGS_PARM3(ctx);
    struct nfsd4_read *read = (struct nfsd4_read *)u;
    
    struct svc_export *fh_export = NULL;
    struct dentry *fh_dentry = NULL;    
    bpf_probe_read_kernel(&fh_export, sizeof(fh_export), &cstate->current_fh.fh_export);
    bpf_probe_read_kernel(&fh_dentry, sizeof(fh_dentry), &cstate->current_fh.fh_dentry);

    return trace_rw(ctx, rqstp, fh_export, fh_dentry, &read->rd_length, OP_READ, NFS4_VER);
}

// NFS 3 support
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u64);
    __type(value, struct svc_rqst *);
} rqstp_map SEC(".maps");

// Wrapper for nfsd3_proc_write
SEC("kprobe/nfsd3_proc_write")
int BPF_KPROBE(kprobe_nfsd3_proc_write, struct svc_rqst *rqstp)
{   
    struct nfsd3_writeres *resp = NULL;
    bpf_probe_read_kernel(&resp, sizeof(resp), &rqstp->rq_resp);
    if (!resp) {
        return 0;
    }
    // Using bitwise shift to differentiate between read and write operations in the map key
    u64 pid_tgid = bpf_get_current_pid_tgid() >> OP_WRITE;
    bpf_map_update_elem(&rqstp_map, &pid_tgid, &rqstp, BPF_ANY);
    return 0;
}

SEC("kretprobe/nfsd3_proc_write")
int BPF_KRETPROBE(kretprobe_nfsd3_proc_write)
{
 
    u64 pid_tgid = bpf_get_current_pid_tgid() >> OP_WRITE;
    struct svc_rqst **rqstp_ptr = bpf_map_lookup_elem(&rqstp_map, &pid_tgid);
    if (!rqstp_ptr) {
        return 0;
    }
    
    struct svc_rqst *rqstp = *rqstp_ptr;
    bpf_map_delete_elem(&rqstp_map, &pid_tgid);

    struct nfsd3_writeres *resp = NULL;
    if (bpf_probe_read_kernel(&resp, sizeof(resp), &rqstp->rq_resp) < 0 || !resp) {
        return 0;
    }

    struct svc_export *fh_export = NULL;
    long res_exp = bpf_probe_read_kernel(&fh_export, sizeof(fh_export), &resp->fh.fh_export);

    // Your conditional check block
    if (!fh_export) {
        bpf_printk("nfsd3_proc_write: fh_export is NULL or read failed, res=%ld fh_export=%llx\n", res_exp, (u64)fh_export);
        return 0;
    } 

    struct dentry *fh_dentry = NULL;
    bpf_probe_read_kernel(&fh_dentry, sizeof(fh_dentry), &fh_export->ex_path.dentry);    
    if (!fh_dentry) {
        bpf_printk("nfsd3_proc_write: fh_dentry is NULL\n");
        return 0;
    }

    return trace_rw((struct pt_regs *)PT_REGS_PARM1(ctx), rqstp, fh_export, fh_dentry, &resp->count, OP_WRITE, NFS3_VER);
}

// Wrapper for nfsd3_proc_read
SEC("kprobe/nfsd3_proc_read")
int BPF_KPROBE(kprobe_nfsd3_proc_read, struct svc_rqst *rqstp)
{   
    struct nfsd3_readres *resp = NULL;
    bpf_probe_read_kernel(&resp, sizeof(resp), &rqstp->rq_resp);
    if (!resp) {
        return 0;
    }
    u64 pid_tgid = bpf_get_current_pid_tgid() >> OP_READ;
    bpf_map_update_elem(&rqstp_map, &pid_tgid, &rqstp, BPF_ANY);
    return 0;
}

SEC("kretprobe/nfsd3_proc_read")
int BPF_KRETPROBE(kretprobe_nfsd3_proc_read)
{
 
    u64 pid_tgid = bpf_get_current_pid_tgid() >> OP_READ;
    struct svc_rqst **rqstp_ptr = bpf_map_lookup_elem(&rqstp_map, &pid_tgid);
    if (!rqstp_ptr) {
        return 0;
    }
    
    struct svc_rqst *rqstp = *rqstp_ptr;
    bpf_map_delete_elem(&rqstp_map, &pid_tgid);

    struct nfsd3_readargs *resp = NULL;
    if (bpf_probe_read_kernel(&resp, sizeof(resp), &rqstp->rq_resp) < 0 || !resp) {
        return 0;
    }

    struct svc_export *fh_export = NULL;
    long res_exp = bpf_probe_read_kernel(&fh_export, sizeof(fh_export), &resp->fh.fh_export);

    // Your conditional check block
    if (!fh_export) {
        bpf_printk("nfsd3_proc_read: fh_export is NULL or read failed, res=%ld fh_export=%llx\n", res_exp, (u64)fh_export);
        return 0;
    } 

    struct dentry *fh_dentry = NULL;
    bpf_probe_read_kernel(&fh_dentry, sizeof(fh_dentry), &fh_export->ex_path.dentry);    
    if (!fh_dentry) {
        bpf_printk("nfsd3_proc_read: fh_dentry is NULL\n");
        return 0;
    }

    return trace_rw((struct pt_regs *)PT_REGS_PARM1(ctx), rqstp, fh_export, fh_dentry, &resp->count, OP_READ, NFS3_VER);
}

/* metadata */
char LICENSE[] SEC("license") = "GPL";
__u32 __version SEC("version") = 1;