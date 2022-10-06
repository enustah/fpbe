use aya_bpf::maps::HashMap;
use aya_bpf::macros::map;

use super::socket_trace::DataArgT;


#[map(name = "active_write_args_map")] 
// map<pid,DataArgT>
pub static mut active_write_args_map: HashMap<u64,DataArgT> =HashMap::<u64,DataArgT>::with_max_entries(10240, 0);