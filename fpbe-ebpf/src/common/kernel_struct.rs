use core::ffi::c_void;

/*
struct iovec
  {
    void *iov_base;	/* Pointer to data.  */
    size_t iov_len;	/* Length of data.  */
  };

*/
#[repr(C)]
pub struct  iovec{
    iov_base: *const c_void ,
    iov_len: usize,
}
