#[repr(C)]
pub enum SyscallSrcFunc {
	UNKNOWN,
	WRITE,
	READ,
	SEND,
	RECV,
	SENDTO,
	RECVFROM,
	SENDMSG,
	RECVMSG,
	SENDMMSG,
	RECVMMSG,
	WRITEV,
	READV,
	SENDFILE
}

/*
struct data_args_t {
	// Represents the function from which this argument group originates.
	enum syscall_src_func source_fn;
	__u32 fd;
	// For send()/recv()/write()/read().
	const char *buf;
	// For sendmsg()/recvmsg()/writev()/readv().
	const struct iovec *iov;
	size_t iovlen;
	union {
		// For sendmmsg()
		unsigned int *msg_len;
		// For clock_gettime()
		struct timespec *timestamp_ptr;
	};
	// Timestamp for enter syscall function.
	__u64 enter_ts;
};

*/

#[repr(C)]
pub struct DataArgT{
    pub syscall_src_func:SyscallSrcFunc,
	pub fd: u32,
    pub buf: *const [u8],
    // iov: *const iovec,
    // union??
    // iov_len: usize,
    pub enter_ts:u64,

}


// 数据流方向
pub enum TrafficDirection {
	EGRESS,
	INGRESS,
}