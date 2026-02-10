
#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

/* use AF_INET value here to avoid pulling in uapi headers that conflict
 * with vmlinux.h during compilation
 */
#ifndef AF_INET
#define AF_INET 2
#endif

#define NFS4_VER 4
#define NFS3_VER 3
#define OP_WRITE 1
#define OP_READ 0
#define MAX_SECINFO_LIST 8

/* note: we rely on vmlinux.h for kernel type definitions; do not include
 * kernel headers directly to avoid type redefinition conflicts with vmlinux.h
 */

#define NFS4_FHSIZE		128

struct nfsd4_fs_location {
	char *hosts; /* colon separated list of hosts */
	char *path;  /* slash separated list of path components */
};

struct nfsd4_fs_locations {
	uint32_t locations_count;
	struct nfsd4_fs_location *locations;
};

struct svc_export {
	struct cache_head	h;
	struct auth_domain *	ex_client;
	int			ex_flags;
	struct path		ex_path;
};

struct knfsd_fh {
	unsigned int	fh_size;	/*
					 * Points to the current size while
					 * building a new file handle.
					 */
	union {
		char			fh_raw[NFS4_FHSIZE];
		struct {
			u8		fh_version;	/* == 1 */
			u8		fh_auth_type;	/* deprecated */
			u8		fh_fsid_type;
			u8		fh_fileid_type;
			u32		fh_fsid[]; /* flexible-array member */
		};
	};
};


typedef struct svc_fh {
	struct knfsd_fh		fh_handle;	/* FH data */
	int			fh_maxsize;	/* max size for fh_handle */
	struct dentry *		fh_dentry;	/* validated dentry */
	struct svc_export *	fh_export;	/* export pointer */
	bool			fh_want_write;	/* remount protection taken */
	bool			fh_no_wcc;	/* no wcc data needed */
	bool			fh_no_atomic_attr;
						/*
						 * wcc data is not atomic with
						 * operation
						 */
	int			fh_flags;	/* FH flags */
	bool			fh_post_saved;	/* post-op attrs saved */
	bool			fh_pre_saved;	/* pre-op attrs saved */

	/* Pre-op attributes saved when inode is locked */
	__u64			fh_pre_size;	/* size before operation */
	struct timespec64	fh_pre_mtime;	/* mtime before oper */
	struct timespec64	fh_pre_ctime;	/* ctime before oper */
	/*
	 * pre-op nfsv4 change attr: note must check IS_I_VERSION(inode)
	 *  to find out if it is valid.
	 */
	u64			fh_pre_change;

	/* Post-op attributes saved in fh_fill_post_attrs() */
	struct kstat		fh_post_attr;	/* full attrs after operation */
	u64			fh_post_change; /* nfsv4 change; see above */
} svc_fh;

struct nfsd4_compound_state {
	struct svc_fh		current_fh;
};

struct nfsd4_write {
    char           wr_stateid[16]; // stateid_t
    u64            wr_offset;
    u32            wr_stable_how;
    u32            wr_buflen;
};

// For nfsd4_read
struct nfsd4_read {
    char rd_stateid[16];
    u64  rd_offset;
    u32  rd_length;
};

struct nfsd3_readargs {
	struct svc_fh		fh;
	__u64			offset;
	__u32			count;
};

struct nfsd3_writeargs {
	svc_fh			fh;
	__u64			offset;
	__u32			count;
	int			stable;
	__u32			len;
	struct xdr_buf		payload;
};

struct data_t {
    u32 op;       // 0 = read, 1 = write
    u32 size;
    u32 addr4;
    u32 version;
    char path[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline int trace_rw(struct pt_regs *ctx,struct svc_rqst *rqstp, struct svc_export *fh_export,const void *buflen, u32 op, u32 version)
{
    struct data_t data = {};
    struct __kernel_sockaddr_storage remote = {};
    bpf_probe_read_kernel(&remote, sizeof(remote), &rqstp->rq_addr);

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &remote.ss_family);
    if (family == AF_INET) {
        // This is OP for READ or WRITE
        data.op = op;
        data.version = version;
        bpf_probe_read_kernel(&data.size, sizeof(data.size), buflen);

        // Find the client ip addr
        struct sockaddr_in *sin = (struct sockaddr_in *)&remote;
        bpf_probe_read_kernel(&data.addr4, sizeof(data.addr4), &sin->sin_addr.s_addr);

        if (version == 4) {
            // Get the nfs mount path
            struct path expath = {};
            bpf_probe_read_kernel(&expath, sizeof(expath), &fh_export->ex_path);
            struct dentry *de = NULL;
            bpf_probe_read_kernel(&de, sizeof(de), &expath.dentry);
            struct dentry d = {};
            bpf_probe_read_kernel(&d, sizeof(d), de);
            struct qstr q = {};
            bpf_probe_read_kernel(&q, sizeof(q), &d.d_name);
            bpf_probe_read_kernel_str(&data.path, sizeof(data.path), q.name);
        }

        bpf_printk("NFS OP %d size: %d version: %d\n", data.op, data.size, data.version);
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));
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
    bpf_probe_read_kernel(&fh_export, sizeof(fh_export), &cstate->current_fh.fh_export);

    return trace_rw(ctx, rqstp, fh_export, &write->wr_buflen,OP_WRITE,NFS4_VER);
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
    bpf_probe_read_kernel(&fh_export, sizeof(fh_export), &cstate->current_fh.fh_export);
    return trace_rw(ctx, rqstp, fh_export, &read->rd_length, OP_READ, NFS4_VER);
}

// NFS 3 support

// Wrapper for nfsd3_proc_write
SEC("kprobe/nfsd3_proc_write")
int kprobe__nfsd3_proc_write(struct pt_regs *ctx)
{
    __u32 count = 0;
    struct svc_rqst *rqstp = (struct svc_rqst *)PT_REGS_PARM1(ctx);
    struct nfsd3_writeargs *argp = NULL;
    struct svc_export *fh_export = NULL;
    bpf_probe_read_kernel(&argp, sizeof(argp), &rqstp->rq_argp);
    bpf_probe_read_kernel(&count, sizeof(count), &argp->count); 
    bpf_probe_read_kernel(&fh_export, sizeof(fh_export), &argp->fh.fh_export);
    return trace_rw(ctx, rqstp, fh_export, &count, OP_WRITE,NFS3_VER);
    
}

// Wrapper for nfsd3_proc_read
SEC("kprobe/nfsd3_proc_read")
int kprobe__nfsd3_proc_read(struct pt_regs *ctx)
{
    __u32 count = 0;
    struct svc_rqst *rqstp = (struct svc_rqst *)PT_REGS_PARM1(ctx);
    struct nfsd3_readargs *argp = NULL;
    struct svc_export *fh_export = NULL;
    bpf_probe_read_kernel(&argp, sizeof(argp), &rqstp->rq_argp);
    bpf_probe_read_kernel(&count, sizeof(count), &argp->count); 
    bpf_probe_read_kernel(&fh_export, sizeof(fh_export), &argp->fh.fh_export);
    return trace_rw(ctx, rqstp, fh_export, &count, OP_READ,NFS3_VER);
    
}


/* metadata */
char LICENSE[] SEC("license") = "GPL";
__u32 __version SEC("version") = 1;