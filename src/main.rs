
extern crate libc;
extern crate libloading;

use std::ffi::CString;
use std::ffi::CStr;
use std::str;
use libloading::{Library, Symbol};

#[cfg(windows)] extern create winapi;

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

static LIB_NAME: &'static str = "C:\\Windows\\System32\\Npcap\\wpcap.dll";

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

// #[cfg(all(target_os = "win32", target_arch="x86"))]
// #[link(name = "wpcap")]



type PcapFindAllDevs = unsafe fn (alldevsp: *mut *mut libc::c_void,
                                  errbuf: *mut u8) -> libc::c_int;

// void 	pcap_freealldevs (pcap_if_t *alldevsp)
// fn pcap_freealldevs(alldevsp: *mut PcapInterface);
type PcapFreeAllDevs = unsafe fn (alldevsp: *mut libc::c_void);

// TODO: replace with ctx defn that holds ptrs instead.
// static mut pcap_findalldevs: libloading::Symbol<PcapFindAllDevs> = Nil;
// static mut pcap_freealldevs: libloading::Symbol<PcapFreeAllDevs> = Nil;

// #[derive(Default)]
// pub struct AppContext {
//     pcap_dll: libloading::Library,
//     pcap_findalldevs: Symbol<'static, PcapFindAllDevs>,
//     pcap_freealldevs: Symbol<'static, PcapFreeAllDevs>,
// }

/**
 * Convert a foreign c string to a standard string
 */
fn convert_forn_str(in_str: *const libc::c_char) -> String {
    unsafe {
        return CStr::from_ptr(in_str).to_string_lossy().into_owned();
    }
}

/**
 * Print an IPv4 address byte sequence in dot format
 */
// fn print_ip4_bytes(in_bytes: &[u8]) {
//     let ip4_addr_str = format!("{}.{}.{}.{}", in_bytes[2], in_bytes[3],
//     in_bytes[0], in_bytes[1]);
//     println!("address: {}", ip4_addr_str);
// }

fn ip4_bytes_to_str(in_bytes: &[u8]) -> String {
    let ip4_addr_str = format!("{}.{}.{}.{}", in_bytes[2], in_bytes[3],
    in_bytes[0], in_bytes[1]);
    return ip4_addr_str;
}

fn call_freealldevs(in_alldevs: *mut PcapInterface) {
    let _pcap_dll = Library::new(LIB_NAME).unwrap();
    unsafe {
        let pcap_freealldevs: Symbol<PcapFreeAllDevs> = _pcap_dll.get(b"pcap_freealldevs").unwrap();
        pcap_freealldevs(in_alldevs as *mut libc::c_void);
    }
}

/**
 * Call the unsafe pcap findalldevs
 */
fn call_findalldevs() -> *mut PcapInterface {
    let _pcap_dll = Library::new(LIB_NAME).unwrap();

    unsafe {
        let pcap_findalldevs: Symbol<PcapFindAllDevs> = _pcap_dll.get(b"pcap_findalldevs").unwrap();

        let mut alldevs = 0 as *mut PcapInterface;
        let errbuf_ptr = 0 as *mut u8;
        let errbuf = std::slice::from_raw_parts_mut(errbuf_ptr, 4096);
        let result = pcap_findalldevs(&mut alldevs as *mut _ as *mut *mut libc::c_void, errbuf_ptr);
        if result == -1 {
            println!("failed to call pcap_findalldevs");
            return 0 as *mut PcapInterface;
        }
        return alldevs;
    }
}

/**
 * MAX_KEY_LENGTH 255
 * MAX_VALUE_NAME 16383
 * RegOpenKeyEx(HKEY_LOCAL_MACHINE, TEXT("subkey\\key"), 0, KEY_READ, &hTestKey) == ERROR_SUCCESS
 * TCHAR achKey[MAX_KEY_LENGTH] // buffer for subkey name
 * DWORD cbName // size of name string
 * TCHAR achClass[MAX_PATH] // buffer for class name
 * DWORD cchClassName = MAX_PATH // size of class string
 * DWORD cSubKeys = 0 // number of subkeys
 * DWORD cbMaxSubKey // longest subkey size
 * DWORD cchMaxClass // longest class string
 * DWORD cbMaxValueData // longest value data
 * DWORD cbSecurityDescriptor // size of security descriptor
 * FILETIME ftLastWriteTime // last write time
 * TCHAR achValue[MAX_VALUE_NAME]
 * DWORD cchValue = MAX_VALUE_NAME
 *
 * retCode = RegQueryInfoKey(hKey, achClass, &cchClassName, NULL, &cSubKeys, &cbMaxSubKey, &cchMaxClass, &cValues, &cchMaxValue, &cbMaxValueData, &cbSecurityDescriptor, &ftLastWriteTime);
 *
 * if (cSubKeys)
 * for (i = 0; i < cSubKeys; i++)
 * cbName = MAX_KEY_LENGTH
 *
 * retCode = RegEnumKeyEx(hKey, i, achKey, &cbName, NULL, NULL, NULL, &ftLastWriteTime)
 * if (retCode == ERROR_SUCCESS) _tprintf(TEXT, i+1, achKey)
 *
 * if (cValues)
 * for (i = 0; retCode = ERROR_SUCCESS; i < cValues; i++)
 * cchValue = MAX_VALUE_NAME
 * achValue[0] = '\0'
 * retCode = RegEnumValue(hKey, i, achValue, &cchValue, NULL, NULL, NULL, NULL)
 *
 * RegCloseKey(hTestKey);
 *
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa365915(v=vs.85).aspx
 * ULONG WINAPI GetAdaptersAddresses(
  _In_    ULONG                 Family,
  _In_    ULONG                 Flags,
  _In_    PVOID                 Reserved,
  _Inout_ PIP_ADAPTER_ADDRESSES AdapterAddresses, IP_ADAPTER_ADDRESSES
  _Inout_ PULONG                SizePointer, size of the buffer
  Returns ERROR_SUCCESS or an error code
);
 *
 * https://msdn.microsoft.com/en-us/library/windows/desktop/aa365917(v=vs.85).aspx
 * DWORD GetAdaptersInfo(
  _Out_   PIP_ADAPTER_INFO pAdapterInfo, // IP_ADAPTER_INFO
  _Inout_ PULONG           pOutBufLen // ULONG size
); Returns ERROR_SUCCESS or an error code
 *
 * GetInterfaceInfo: https://msdn.microsoft.com/en-us/library/windows/desktop/aa365947(v=vs.85).aspx
 * DWORD GetInterfaceInfo(
  _Out_   PIP_INTERFACE_INFO pIfTable,
  _Inout_ PULONG             dwOutBufLen
);
 *
 */
#[cfg(windows)]
fn get_net_info_extra() {
    use winapi::advapi32::{RegOpenKeyEx, RegQueryInfoKey, RegEnumKeyEx, RegEnumValue};
    use winapi::iphlpapi::{GetAdaptersAddresses}
    // #define HKEY_LOCAL_MACHINE (( HKEY ) (ULONG_PTR)((LONG)0x80000002) )
    //

}

/**
 * Process network interfaces
 */
fn process_network_interfaces() -> String {
    println!("processing network interfaces");
    let found_name: String;

    unsafe {
        let pcap_handle: *mut PcapCapInstance;

        let alldevs: *mut PcapInterface = call_findalldevs();
        if alldevs.is_null() {
            println!("error retrieving device list");
            return String::from("");
        }

        // Get the First Pcap Device Struct
        let mut curr_dev_ptr = alldevs as *mut PcapInterface;
        while !curr_dev_ptr.is_null() {
            let curr_dev: &PcapInterface = &*curr_dev_ptr;
            println!("device:");
            let name: String = convert_forn_str(curr_dev.name);
            println!("\tname: {}", name);
            let description: String = convert_forn_str(curr_dev.description);
            println!("\tdescription: \"{}\"", description);
            let mut pcap_addr_ptr = curr_dev.addresses as *mut PcapAddr;
            println!("\taddresses:");
            while !pcap_addr_ptr.is_null() {
                let pcap_addr: &PcapAddr = &*pcap_addr_ptr;
                if !pcap_addr.addr.is_null() {
                    let address: &SockAddr = &*pcap_addr.addr;
                    println!("\t\taddress family: {}", address.sa_family);
                    if address.sa_family == AF_INET {
                        let ip4_str = ip4_bytes_to_str(&address.sa_data[0..4]);
                        println!("\t\taddress: {}", ip4_str);
                    }
                } else {
                    println!("\t\taddress is null");
                }
                pcap_addr_ptr = pcap_addr.next as *mut PcapAddr;
            }
            curr_dev_ptr = curr_dev.next as *mut PcapInterface;
        }

        println!("freeing alldevs");
        call_freealldevs(alldevs);
    }

    return String::from("");
}

/**
 * Initialize the app context.
 */
// fn init_app_ctx() -> AppContext {
//     let _pcap_dll = Library::new(LIB_NAME).unwrap();

//     unsafe {
//         let app_ctx: AppContext = AppContext {
//             pcap_dll: _pcap_dll,
//             pcap_findalldevs: std::default,
//             pcap_freealldevs: std::default,
//         };

//         // _pcap_dll.get(b"pcap_findalldevs").unwrap(),
//         //  _pcap_dll.get(b"pcap_freealldevs").unwrap(

//         return app_ctx;
//     }
// }

/**
 * Main function
 */
fn main() {
    println!("PCAP program");

    let found_dev_name = process_network_interfaces();

    println!("found dev name: {}", found_dev_name);

    println!("done");
    return;
}
