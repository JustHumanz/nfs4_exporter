
#include "vmlinux.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

/* use AF_INET value here to avoid pulling in uapi headers that conflict
 * with vmlinux.h during compilation
 */
#ifndef AF_INET
#define AF_INET 2
#endif

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
	kuid_t			ex_anon_uid;
	kgid_t			ex_anon_gid;
	int			ex_fsid;
	unsigned char *		ex_uuid; /* 16 byte fsid */
	struct nfsd4_fs_locations ex_fslocs;
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


struct data_t {
    u32 op;       // 0 = read, 1 = write
    u32 size;
    u32 addr4;
    char path[64];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

static __always_inline int trace_rw(struct pt_regs *ctx,struct svc_rqst *rqstp, struct nfsd4_compound_state *cstate,const void *buflen, u32 op)
{
    struct data_t data = {};
    struct __kernel_sockaddr_storage remote = {};
    bpf_probe_read_kernel(&remote, sizeof(remote), &rqstp->rq_addr);

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &remote.ss_family);
    if (family == AF_INET) {
        // This is OP write
        data.op = op;
        bpf_probe_read_kernel(&data.size, sizeof(data.size), buflen);

        // Find the client ip addr
        struct sockaddr_in *sin = (struct sockaddr_in *)&remote;
        bpf_probe_read_kernel(&data.addr4, sizeof(data.addr4), &sin->sin_addr.s_addr);

        // Get the nfs mount path
        struct svc_export *exp = NULL;
        bpf_probe_read_kernel(&exp, sizeof(exp), &cstate->current_fh.fh_export);
        struct path expath = {};
        bpf_probe_read_kernel(&expath, sizeof(expath), &exp->ex_path);
        struct dentry *de = NULL;
        bpf_probe_read_kernel(&de, sizeof(de), &expath.dentry);
        struct dentry d = {};
        bpf_probe_read_kernel(&d, sizeof(d), de);
        struct qstr q = {};
        bpf_probe_read_kernel(&q, sizeof(q), &d.d_name);

        bpf_probe_read_kernel_str(&data.path, sizeof(data.path), q.name);
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
    
    bpf_printk("NFS write");
    return trace_rw(ctx, rqstp, cstate, &write->wr_buflen, 1);    
}

// Wrapper for nfsd_read
SEC("kprobe/nfsd4_read")
int kprobe__nfsd4_read(struct pt_regs *ctx)
{
    struct svc_rqst *rqstp = (struct svc_rqst *)PT_REGS_PARM1(ctx);
    struct nfsd4_compound_state *cstate = (struct nfsd4_compound_state *)PT_REGS_PARM2(ctx);
    void *u = (void *)PT_REGS_PARM3(ctx);
    struct nfsd4_read *read = (struct nfsd4_read *)u;
    
    bpf_printk("NFS read");
    return trace_rw(ctx, rqstp, cstate, &read->rd_length, 0);
}

/* metadata */
char LICENSE[] SEC("license") = "GPL";
__u32 __version SEC("version") = 1;