/// This pcap implementation is a compatibility implementation that
/// dynamically loads the pcap library and forwards all calls onto the
/// loaded library.  This pcap implementation only provides the required
/// declarations needed to properly compile the pcap-test application.

#ifndef __PCAP_INTERNAL_H__
#define __PCAP_INTERNAL_H__

#include <stdint.h>

#if _WIN32
#include <WinSock2.h>
#else
#error "Define for this platform!"
#endif // _WIN32

#if _WIN32
#ifdef pcap_internal_AS_SHARED_LIB
#ifdef pcap_internal_EXPORTS
#define PCAP_EXPORT __declspec( dllexport )
#else
#define PCAP_EXPORT __declspec( dllimport )
#endif // pcap_internal_EXPORTS
#else
#define PCAP_EXPORT
#endif // pcap_internal_AS_DLL
#else
#error "Define for this platform!"
#endif // _WIN32

#if __cplusplus
extern "C"
{
#endif // __cplusplus

#define DLT_NULL     0
#define DLT_EN10MB   1
#define DLT_EN3MB    2
#define DLT_AX25     3
#define DLT_PRONET   4
#define DLT_CHAOS    5
#define DLT_IEEE802  6
#define DLT_ARCNET   7
#define DLT_SLIP     8
#define DLT_PPP      9
#define DLT_FDDI     10   

#define PCAP_ERRBUF_SIZE 256

typedef struct pcap pcap_t;
typedef struct pcap_if pcap_if_t;
typedef struct pcap_addr pcap_addr_t;

struct pcap_pkthdr
{
   struct timeval ts;
   uint32_t caplen;
   uint32_t len;
};

struct pcap_if
{
   struct pcap_if * next;
   char * name;
   char * description;
   struct pcap_addr * addresses;
   uint32_t flags;
};

#define PCAP_IF_LOOPBACK                           0x00000001
#define PCAP_IF_UP                                 0x00000002
#define PCAP_IF_RUNNING                            0x00000004
#define PCAP_IF_WIRELESS                           0x00000008
#define PCAP_IF_CONNECTION_STATUS                  0x00000030
#define PCAP_IF_CONNECTION_STATUS_UNKNOWN          0x00000000
#define PCAP_IF_CONNECTION_STATUS_CONNECTED        0x00000010
#define PCAP_IF_CONNECTION_STATUS_DISCONNECTED     0x00000020
#define PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE   0x00000030

struct pcap_addr
{
   struct pcap_addr * next;
   struct sockaddr * addr;
   struct sockaddr * netmask;
   struct sockaddr * broadaddr;
   struct sockaddr * dstaddr;
};

struct bpf_program
{
   uint64_t opaque[2];
};

typedef void (*pcap_handler) (
   uint8_t *, /* user defined closure data */
   const struct pcap_pkthdr *, /* packet header associated with data */
   const uint8_t * ); /* packet data including protocol headers */

#define PCAP_ERROR			      -1
#define PCAP_ERROR_NOT_ACTIVATED -3

PCAP_EXPORT void pcap_close(
   pcap_t * capture_instance );
PCAP_EXPORT pcap_t * pcap_open_live(
   const char * device_name,
   int capture_size,
   int promiscuous_mode,
   int read_timeout_ms,
   char * error_buffer );
PCAP_EXPORT int pcap_dispatch(
   pcap_t * capture_instance,
   int max_packets_to_process,
   pcap_handler callback,
   u_char * user_data );
PCAP_EXPORT int pcap_findalldevs(
   pcap_if_t ** interface_list,
   char * error_buffer );
PCAP_EXPORT void pcap_freealldevs(
   pcap_if_t * interface_list );
PCAP_EXPORT void pcap_freecode(
   struct bpf_program * filter_program );
PCAP_EXPORT int pcap_compile(
    pcap_t * capture_instance,
    struct bpf_program * filter_program,
    const char * filter_expression,
    int optimize_filter,
    uint32_t network_mask );
PCAP_EXPORT char * pcap_geterr(
   pcap_t * capture_instance );
PCAP_EXPORT int pcap_setfilter(
   pcap_t * capture_instance, 
   struct bpf_program * filter_program );
PCAP_EXPORT void pcap_breakloop(
   pcap_t * capture_instance );
PCAP_EXPORT int pcap_datalink(
   pcap_t * capture_instance );

#if __cplusplus
}
#endif // __cplusplus

#endif // __PCAP_INTERNAL_H__
