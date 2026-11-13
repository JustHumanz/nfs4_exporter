#include "vmlinux.h"


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
#define MAX_PATH_COMPONENTS 16
#define COMPONENT_LEN 128
#define MAX_MOUNT_HOPS 8

struct svc_export {
	struct cache_head	h;
	struct auth_domain *	ex_client;
	int			ex_flags;
	struct path		ex_path;
};

typedef struct svc_fh {
    char fh_handle[4 + NFS4_FHSIZE];
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

struct nfsd3_writeres {
	__be32			status;
	struct svc_fh		fh;
	unsigned long		count;
	int			committed;
	__be32			verf[2];
};

struct nfsd3_writeargs {
	svc_fh			fh;
	__u64			offset;
	__u32			count;
	int			stable;
	__u32			len;
	struct xdr_buf		payload;
};


#define rcu_head callback_head

struct nfsd_file {
	struct rhlist_head	nf_rlist;
	void			*nf_inode;
	struct file		*nf_file;
	const struct cred	*nf_cred;
	struct net		*nf_net;
#define NFSD_FILE_HASHED	(0)
#define NFSD_FILE_PENDING	(1)
#define NFSD_FILE_REFERENCED	(2)
#define NFSD_FILE_GC		(3)
#define NFSD_FILE_RECENT	(4)
	unsigned long		nf_flags;
	refcount_t		nf_ref;
	unsigned char		nf_may;

	struct nfsd_file_mark	*nf_mark;
	struct list_head	nf_lru;
	struct list_head	nf_gc;
	struct rcu_head		nf_rcu;
	ktime_t			nf_birthtime;

	u32			nf_dio_mem_align;
	u32			nf_dio_offset_align;
	u32			nf_dio_read_offset_align;
};
