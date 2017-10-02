
extern crate libc;
extern crate libloading;

use std::ffi::CString;
use std::ffi::CStr;
use std::str;

pub enum PcapCapInstance {}

pub enum PcapDumper {}

pub enum BpfProgram {}

#[repr(C, packed)]
struct SockAddr {
    sa_family: u16,
    sa_data: [u8; 14]
}

#[repr(C, packed)]
struct PcapAddr {
    next: *mut libc::c_void,
    addr: *mut SockAddr,
    netmask: *mut SockAddr,
    broadaddr: *mut SockAddr,
    dstaddr: *mut SockAddr
}

#[repr(C, packed)]
struct PcapInterface {
    next: *mut libc::c_void,
    name: *mut libc::c_char,
    description: *mut libc::c_char,
    addresses: *mut PcapAddr,
    flags: u32
}

#[repr(C, packed)]
struct PcapPktHdr {

}

// sa_family constants
//#define AF_UNSPEC 0
const AF_UNSPEC: u16 = 0;
//#define AF_UNIX 1 // Unix domain sockets
const AF_UNIX: u16 = 1;
//#define AF_INET 2 // IPv4
const AF_INET: u16 = 2;
//#define AF_INET6 23 // IPv6
const AF_INET6: u16 = 23;
//#define AF_NETLINK 16
const AF_LLC: u16 = 26;
//#define AF_ROUTE AF_NETLINK
//#define AF_PACKET 17// packet family
//#define AF_NETBIOS 17
//#define AF_LLC 26 // linux LLC
//#define AF_BLUETOOTH 32
//#define AF_BRIDGE 7 // multi-proto bridge

// typedef void(*) pcap_handler(u_char *user,
//                              const struct pcap_pkthdr *pkt_header,
//                              const u_char *pkt_data)
extern fn pcap_handler(user: *mut u8,
                      pkt_header: *const PcapPktHdr,
                      pkt_data: *const u8) {
                          println!("callback from pcap function");
                      }

#[cfg(all(target_os = "wn32", target_arch="x86"))]
#[link(name = "wpcap")]

extern "C" {
    // fn SetEnvironmentVariableA(n: *const u8, v: *const u8) -> libc::c_int;
    // static mut rl_prompt: *const libc::c_char;
    // fn pcap_handler(user: *mut u8,
    //                 pcap_pkthdr: *const PcapPktHdr,
    //                 pkt_data: *const u8);

    // pcap_t * pcap_open_live (const char *device,
    //                          int snaplen,
    //                          int promisc,
    //                          int to_ms,
    //                          char *ebuf)
    fn pcap_open_live(device: *const libc::c_char,
                      snaplen: u32,
                      promisc: u32,
                      timeout: u32,
                      error_buf: *mut libc::c_char) -> *mut PcapCapInstance;

    // pcap_t * pcap_open_dead (int linktype, int snaplen)
    fn pcap_open_dead(linktype: int, snaplen: int) -> *mut PcapCapInstance;

    // pcap_t * 	pcap_open_offline (const char *fname, char *errbuf)
    fn pcap_open_offline(fname: *const libc::c_char,
                         errbuf: *mut libc::c_char) -> *mut PcapCapInstance;

    // pcap_dumper_t * 	pcap_dump_open (pcap_t *p, const char *fname)
    fn pcap_dump_open(p: *const libc::c_void,
                      fname: *const libc::c_char) -> *mut PcapCapInstance;

    // int 	pcap_setnonblock (pcap_t *p, int nonblock, char *errbuf)
    fn pcap_setnonblock(p: *mut libc::c_void,
                        nonblock: int,
                        errbuf: *mut libc::c_char) -> libc::c_int;

    // int 	pcap_getnonblock (pcap_t *p, char *errbuf)
    fn pcap_getnonblock(p: *mut PcapCapInstance,
                        errbuf: *mut libc::c_char) -> libc::c_int;

    // int 	pcap_findalldevs (pcap_if_t **alldevsp, char *errbuf)
    fn pcap_findalldevs(alldevsp: *mut *mut PcapInterface,
                        errbuf: *mut libc::c_char) -> libc::c_int;

    // void 	pcap_freealldevs (pcap_if_t *alldevsp)
    fn pcap_freealldevs(alldevsp: *mut PcapInterface);

    // char * 	pcap_lookupdev (char *errbuf)
    fn pcap_lookupdev(errbuf: *mut libc::c_char) -> *mut libc::c_char;

    // int 	pcap_lookupnet (const char *device, bpf_u_int32 *netp, bpf_u_int32 *maskp, char *errbuf)
    fn pcap_lookupnet(device: *const libc::c_char,
                        netp: *mut libc::c_int,
                        maskp: *mut libc::c_int,
                        errbuf: *mut libc::c_char) -> libc::c_int;

    // int 	pcap_dispatch (pcap_t *p, int cnt, pcap_handler callback, u_char *user)
    fn pcap_dispatch(p: *mut PcapCapInstance,
                     callback: extern fn(user: *mut libc::c_char,
                                         pkt_hdr: *const PcapPktHdr,
                                         pkt_data: *const u8),
                     user: *mut u8) -> libc::c_int;

    // int 	pcap_loop (pcap_t *p, int cnt, pcap_handler callback, u_char *user)
    fn pcap_loop(p: *mut PcapCapInstance,
                 cnt: u32,
                 callback: extern fn(user: *mut libc::c_char,
                                         pkt_hdr: *const PcapPktHdr,
                                         pkt_data: *const u8),
                 user: *mut u8) -> libc::c_int;

    // u_char * 	pcap_next (pcap_t *p, struct pcap_pkthdr *h)
    fn pcap_next(p: *mut PcapCapInstance,
                 h: *mut PcapPktHdr) -> *mut u8;

    // int 	pcap_next_ex (pcap_t *p, struct pcap_pkthdr **pkt_header, const u_char **pkt_data)
    fn pcap_next_ex(p: *mut PcapCapInstance,
                    pkt_header: *mut *mut PcapPktHdr,
                    pkt_data: *const *const u8) -> libc::c_int;

    // void 	pcap_breakloop (pcap_t *)
    fn pcap_breakloop(p: *mut PcapCapInstance);

    // int 	pcap_sendpacket (pcap_t *p, u_char *buf, int size)
    fn pcap_sendpacket(p: *mut PcapCapInstance,
                        buf: *mut u8,
                        size: int) -> libc::c_int;

    // void 	pcap_dump (u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
    fn pcap_dump(user: *mut u8,
                    h: *const PcapPktHdr,
                    sp: *mut u8);

    // long 	pcap_dump_ftell (pcap_dumper_t *)
    fn pcap_dump_ftell(save_file: *mut PcapDumper) -> libc::c_int;

    // int 	pcap_compile (pcap_t *p, struct bpf_program *fp, char *str, int optimize, bpf_u_int32 netmask)
    fn pcap_compile(p: *mut PcapCapInstance,
                    fp: *mut BpfProgram,
                    filter_str: *mut libc::c_char,
                    optimize: u32,
                    netmask: u32) -> libc::c_int;

    // int 	pcap_compile_nopcap (int snaplen_arg, int linktype_arg, struct bpf_program *program, char *buf, int optimize, bpf_u_int32 mask)
    fn pcap_compile_nopcap(snaplen_arg: u32,
                            linktype_arg: u32,
                            program: *mut BpfProgram,
                            optimize: u32,
                            mask: u32) -> libc::c_int;

    // int 	pcap_setfilter (pcap_t *p, struct bpf_program *fp)
    fn pcap_setfilter(p: *mut PcapCapInstance,
                        fp: *mut BpfProgram) -> libc::c_int;

    // void 	pcap_freecode (struct bpf_program *fp)
    fn pcap_freecode(fp: *mut BpfProgram);

    // int 	pcap_datalink (pcap_t *p)
    // int 	pcap_list_datalinks (pcap_t *p, int **dlt_buf)
    // int 	pcap_set_datalink (pcap_t *p, int dlt)
    // int 	pcap_datalink_name_to_val (const char *name)
    // const char * 	pcap_datalink_val_to_name (int dlt)
    // const char * 	pcap_datalink_val_to_description (int dlt)
    // int 	pcap_snapshot (pcap_t *p)
    // int 	pcap_is_swapped (pcap_t *p)
    // int 	pcap_major_version (pcap_t *p)
    // int 	pcap_minor_version (pcap_t *p)
    // FILE * 	pcap_file (pcap_t *p)
    // int 	pcap_stats (pcap_t *p, struct pcap_stat *ps)
    // void 	pcap_perror (pcap_t *p, char *prefix)
    // char * 	pcap_geterr (pcap_t *p)
    // char * 	pcap_strerror (int error)
    // const char * 	pcap_lib_version (void)
    // void 	pcap_close (pcap_t *p)
    fn pcap_close(p: *mut PcapCapInstance);

    // FILE * 	pcap_dump_file (pcap_dumper_t *p)
    // int 	pcap_dump_flush (pcap_dumper_t *p)
    // void 	pcap_dump_close (pcap_dumper_t *p)

    // https://www.winpcap.org/docs/docs_40_2/html/group__wpcapfunc.html#gc429cf4f27205111259ff7b02a82eeab
}

type PcapFindAllDevs = unsafe fn (alldevsp: *mut *mut libc::c_void,
                                  errbuf: *mut u8) -> libc::c_int;

// void 	pcap_freealldevs (pcap_if_t *alldevsp)
// fn pcap_freealldevs(alldevsp: *mut PcapInterface);
type PcapFreeAllDevs = unsafe fn (alldevsp: *mut libc::c_void);

pcap_findalldevs: libloading::Symbol<PcapFindAllDevs>;


fn main() {
    println!("PCAP program");

    let lib = libloading::Library::new("C:\\Windows\\System32\\Npcap\\wpcap.dll").unwrap();

    unsafe {
        let pcap_findalldevs: libloading::Symbol<PcapFindAllDevs> = lib.get(b"pcap_findalldevs").unwrap();
        let pcap_freealldevs: libloading::Symbol<PcapFreeAllDevs> = lib.get(b"pcap_freealldevs").unwrap();
        let inum = 0;
        let i = 0;
        let pcap_handle: *mut PcapCapInstance;
        let mut alldevs = 0 as *mut PcapInterface;
        let errbuf_ptr = 0 as *mut u8;
        let errbuf = std::slice::from_raw_parts_mut(errbuf_ptr, 4096);
        let result = pcap_findalldevs(
            (&mut alldevs) as *mut _ as *mut *mut libc::c_void, errbuf_ptr);
        if result == -1 {
            println!("failed to call pcap_findalldevs");
            return;
        }

        let first_dev: &PcapInterface = &*alldevs;
        let first_name = CStr::from_ptr(first_dev.name).to_string_lossy().into_owned();
        let description = CStr::from_ptr(first_dev.description).to_string_lossy().into_owned();
        println!("name: {}", first_name);
        println!("description: {}", description);
        let first_dev_addr: &PcapAddr = &*first_dev.addresses;

        let mut addr_rp = first_dev_addr.addr;
        let mut addr: &SockAddr = &*addr_rp;
        println!("address family: {}", addr.sa_family);
        if addr.sa_family == AF_INET {
            let ip4_addr_str = format!("{}.{}.{}.{}", addr.sa_data[0], addr.sa_data[1], addr.sa_data[2], addr.sa_data[3]);
            println!("address: {}", ip4_addr_str);
        }
        // let mut netmask_rp = first_dev_addr.netmask;
        // let mut bcast_rp = first_dev_addr.broadaddr;
        // let mut bcast: &SockAddr = &*bcast_rp;
        let mut next_addr_rp = first_dev_addr.next as *mut PcapAddr;

        while !next_addr_rp.is_null() {
            let next_addr: &PcapAddr = &*next_addr_rp;
            // address
            addr_rp = next_addr.addr;
            addr = &*addr_rp;
            println!("address family: {}", addr.sa_family);
            if addr.sa_family == AF_INET {
                let ip4_addr_str = format!("{}.{}.{}.{}", addr.sa_data[2], addr.sa_data[3], addr.sa_data[0], addr.sa_data[1]);
                println!("address: {}", ip4_addr_str);
            }
            // netmask
            // netmask_rp = next_addr.netmask;
            // broadcast
            // bcast_rp = next_addr.broadaddr;
            next_addr_rp = next_addr.next as *mut PcapAddr;
        }

        let mut next_dev_rp = first_dev.next as *mut PcapInterface;
        while !next_dev_rp.is_null() {
            let next_dev: &PcapInterface = &*next_dev_rp;
            let next_name = CStr::from_ptr(next_dev.name).to_string_lossy().into_owned();
            let next_description = CStr::from_ptr(next_dev.description).to_string_lossy().into_owned();
            let next_dev_addr: &PcapAddr = &*next_dev.addresses;
            println!("name: {}", next_name);
            println!("description: {}", next_description);

            let next_dev_addr: &PcapAddr = &*next_dev.addresses;
            addr_rp = next_dev_addr.addr;
            addr = &*addr_rp;
            println!("address family: {}", addr.sa_family);
            if addr.sa_family == AF_INET {
                let ip4_addr_str = format!("{}.{}.{}.{}", addr.sa_data[0], addr.sa_data[1], addr.sa_data[2], addr.sa_data[3]);
                println!("address: {}", ip4_addr_str);
            }

            next_addr_rp = next_dev_addr.next as *mut PcapAddr;
            while !next_addr_rp.is_null() {
                let next_addr: &PcapAddr = &*next_addr_rp;
                // address
                addr_rp = next_addr.addr;
                addr = &*addr_rp;
                println!("address family: {}", addr.sa_family);
                if addr.sa_family == AF_INET {
                    let ip4_addr_str = format!("{}.{}.{}.{}", addr.sa_data[2], addr.sa_data[3], addr.sa_data[0], addr.sa_data[1]);
                    println!("address: {}", ip4_addr_str);
                }
                next_addr_rp = next_addr.next as *mut PcapAddr;
            }

            next_dev_rp = next_dev.next as *mut PcapInterface;
        }



        println!("freeing alldevs");
        pcap_freealldevs(alldevs as *mut libc::c_void);
    }

    println!("done");
    return;
}
