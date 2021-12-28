#include <pcap/pcap.h>

#if _WIN32

#include <ws2def.h>
#include <WinSock2.h>

#elif __linux__

#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/socket.h>

#else

#error "Define for this platform!"

#endif // _WIN32

#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QMenu>
#include <QtWidgets/QPlainTextEdit>
#include <QtWidgets/QSplitter>
#include <QtWidgets/QTreeView>

#include <QtGui/QFont>
#include <QtGui/QCursor>
#include <QtGui/QGuiApplication>

#include <QtCore/QAbstractItemModel>
#include <QtCore/QDebug>
#include <QtCore/QItemSelection>
#include <QtCore/QItemSelectionModel>
#include <QtCore/QMetaType>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QTextStream>
#include <QtCore/QVariant>

#include <Qt>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace osi
{

namespace data_link
{

struct ethernet
{
   uint8_t dest_mac[6];
   uint8_t src_mac[6];
   uint16_t type;
};

struct ethernet_vlan
{
   uint8_t dest_mac[6];
   uint8_t src_mac[6];
   uint16_t vlan_tpid;
   uint16_t vlan_tci;
   uint16_t type;
};

namespace msb
{
static constexpr uint16_t ETHERNET_TYPE_IPV4 { 0x0008 };
static constexpr uint16_t ETHERNET_TYPE_IPV6 { 0xDD86 };
static constexpr uint16_t ETHERNET_TYPE_VLAN { 0x0081 };
} // namespace msb

} // namespace data_link

namespace network
{

struct ipv4
{
   // these two are reversed due to bit ordering
   // of big-endian (network order) to little-endian
   uint8_t header_length : 4;
   uint8_t version : 4;
   uint8_t service_type;
   uint16_t total_length;
   uint16_t fragment_id;
   uint16_t fragment_flags_offset;
   uint8_t time_to_live;
   uint8_t protocol;
   uint16_t header_checksum;
   uint8_t source_ip[4];
   uint8_t destination_ip[4];
};

static constexpr uint8_t PROTOCOL_ICMP { 1 };
static constexpr uint8_t PROTOCOL_TCP { 6 };
static constexpr uint8_t PROTOCOL_UDP { 17 };

static constexpr uint16_t FRAGMENT_OFFSET_BITS { 0x1FFF };
static constexpr uint16_t FRAGMENT_FLAG_BITS { 0xE000 };
static constexpr uint16_t FRAGMENT_FLAG_RESERVED { 0x8000 };
static constexpr uint16_t FRAGMENT_FLAG_DO_NOT_FRAGMENT { 0x4000 };
static constexpr uint16_t FRAGMENT_FLAG_MORE_FRAGMENTS { 0x2000 };

} // namespace network

namespace transport
{

struct tcp
{
   uint16_t src_port;
   uint16_t dst_port;
   uint32_t sequence;
   uint32_t acknowledgement;
   uint8_t reserved1 : 4;
   uint8_t header_length : 4;
   uint8_t terminate_bit : 1;
   uint8_t synchronize_bit : 1;
   uint8_t reset_bit : 1;
   uint8_t push_bit : 1;
   uint8_t acknowledgement_bit : 1;
   uint8_t urgent_bit : 1;
   uint8_t reserved2 : 2;
   uint16_t window_size;
   uint16_t checksum;
   uint16_t urgent_pointer;
   // options are 0 - 40 bytes
   // tcp data follows the options
};

struct icmp
{
   uint8_t type;
   uint8_t code;
   uint16_t checksum;
   // next 32-bits is defined by type and code
};

struct icmp_echo :
   public icmp
{
   uint16_t id;
   uint16_t sequence;
};

struct udp
{
   uint16_t src_port;
   uint16_t dst_port;
   uint16_t total_length;
   uint16_t checksum;
};

} // namespace transport

} // namespace osi

using PacketData =
   std::tuple<
      double, /* time seconds */
      size_t, /* length of packet */
      std::unique_ptr< const char [] >, /* packet data */
      const osi::data_link::ethernet * const, /* ethernet header */
      const osi::network::ipv4 * const, /* ip header */
      const void * const /* ip payload */
   >;

using Packets =
   std::vector< PacketData >;

static const auto qt_meta_type_std_vector_PacketData =
   qRegisterMetaType< std::shared_ptr< Packets > >(
      "std::shared_ptr< Packets >");

// the pcap capture handle that will release all
// the memory created by calling PCAPCloseCapture
using PCAPCapture =
   std::unique_ptr<
      pcap_t,
      void (*) ( pcap_t * const )
   >;

// a utility function to delete the capture handle
// for a particular device.  this is mainly used by
// the PCAPCapture handle.
void PCAPCloseCapture(
   pcap_t * const capture )
{
   if (capture)
   {
      pcap_close( 
         capture);
   }
}

// opens a source on the specified interface
PCAPCapture OpenSource(
   const std::string & device_name )
{
   std::cout
      << "\n"
      << "Capturing packets for device '"
      << device_name
      << "'\n";

   char error[PCAP_ERRBUF_SIZE] { };

   const auto open_handle =
      pcap_open_live(
         device_name.c_str(),
         0x10000, /* maximum bytes to capture */
         1, /* on / off promiscuous mode */
         33, /* packet timeout ms */
         error);

   if (!open_handle)
   {
      std::cerr
         << "Unable to open device '"
         << device_name << "'!  Error: "
         << error
         << "\n";
   }
   else if (*error != '\0')
   {
      std::cout
         << "Warning: "
         << error
         << "\n";
   }

   return {
      open_handle,
      &PCAPCloseCapture
   };
}

std::string IdentifyPacketType(
   const uint16_t type )
{
   std::string stype { "Unknown Type" };

   switch (type)
   {
   case osi::data_link::msb::ETHERNET_TYPE_IPV4:
      stype = "IPv4";
      break;
   case osi::data_link::msb::ETHERNET_TYPE_IPV6:
      stype = "IPv6";
      break;
   case osi::data_link::msb::ETHERNET_TYPE_VLAN:
      stype = "VLAN";
      break;
   }

   return
      stype;
}

std::string FormatMediaAccessControl(
   const uint8_t (&mac)[6] )
{
   std::string smac;

   if (mac)
   {
      char buffer[32];

      std::snprintf(
         buffer,
         sizeof(buffer),
         "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
         mac[0],
         mac[1],
         mac[2],
         mac[3],
         mac[4],
         mac[5]);

      smac.assign(
         buffer);
   }

   return smac;
}

std::string IdentifyProtocol(
   const uint8_t protocol )
{
   std::string sprotocol { "Unknown Protocol" };

   switch (protocol)
   {
   case osi::network::PROTOCOL_ICMP:
      sprotocol = "ICMP";
      break;
   case osi::network::PROTOCOL_TCP:
      sprotocol = "TCP";
      break;
   case osi::network::PROTOCOL_UDP:
      sprotocol = "UDP";
      break;
   }

   return
      sprotocol;
}

std::string InterpretFragmentFlags(
   const uint16_t nbo_fragment_flags_offset )
{
   const uint16_t fragment_flags_offset =
      ntohs(nbo_fragment_flags_offset);

   std::string sflags { "None" };

   if (fragment_flags_offset & osi::network::FRAGMENT_FLAG_BITS)
   {
      sflags.clear();

      const auto AddFlag =
         [ ] (
            const bool flag,
            const char * const flag_name,
            std::string & flags )
         {
            if (flag)
            {
               if (!flags.empty())
               {
                  flags += " and ";
               }

               flags += flag_name;
            }
         };

      AddFlag(
         fragment_flags_offset & osi::network::FRAGMENT_FLAG_RESERVED,
         "Reserved",
         sflags);
      AddFlag(
         fragment_flags_offset & osi::network::FRAGMENT_FLAG_DO_NOT_FRAGMENT,
         "Do Not Fragment",
         sflags);
      AddFlag(
         fragment_flags_offset & osi::network::FRAGMENT_FLAG_MORE_FRAGMENTS,
         "More Fragments",
         sflags);
   }

   return
      sflags;
}

uint32_t CalculateFragmentOffset(
   const uint16_t nbo_fragment_flags_offset )
{
   const uint16_t fragment_flags_offset =
      ntohs(nbo_fragment_flags_offset);

   const uint16_t offset =
      fragment_flags_offset &
      osi::network::FRAGMENT_OFFSET_BITS;
   
   return
      offset * 8;
}

size_t CalculateIPHeaderSize(
   const uint8_t ip_header_size )
{
   return
      ip_header_size * sizeof(uint32_t);
}

std::string FormatIPAddress(
   const uint8_t (&address)[4] )
{
   std::string saddress;

   if (address)
   {
      char buffer[32];

      std::snprintf(
         buffer,
         sizeof(buffer),
         "%u.%u.%u.%u",
         address[0],
         address[1],
         address[2],
         address[3]);

      saddress.assign(
         buffer);
   }

   return
      saddress;
}

// a utility function to continually capture
// data from the capture source
std::vector< PacketData > CapturePackets(
   const PCAPCapture & capture )
{
   std::vector< PacketData >
      packets;

   if (capture)
   {
      const auto packet_handler =
         [ ] (
            uint8_t * user_data,
            const pcap_pkthdr * const packet_header,
            const uint8_t * const  packet_data )
         {
            auto & packets =
               *reinterpret_cast< std::vector< PacketData > * >(
                  user_data);

            const double seconds =
               packet_header->ts.tv_sec +
               std::chrono::duration_cast<
               std::chrono::duration< double, std::ratio< 1, 1 > > >(
                  std::chrono::microseconds{ packet_header->ts.tv_usec }).count();

            auto data =
               std::make_unique< char [] >(
                  packet_header->caplen);

            std::memcpy(
               data.get(),
               packet_data,
               packet_header->caplen);

            const auto ethernet_header =
               reinterpret_cast< const osi::data_link::ethernet * >(
                  data.get());
            const auto ipv4_header =
               reinterpret_cast< const osi::network::ipv4 * >(
                  ethernet_header + 1);

            packets.emplace_back(
               seconds,
               packet_header->caplen,
               std::move(data),
               ethernet_header,
               osi::data_link::msb::ETHERNET_TYPE_IPV4 == ethernet_header->type ?
                  ipv4_header :
                  nullptr,
               reinterpret_cast< const uint8_t * >(ipv4_header) +
               CalculateIPHeaderSize(ipv4_header->header_length));
         };

      pcap_dispatch(
         capture.get(),
         -1,
         packet_handler,
         reinterpret_cast< uint8_t * >(
            &packets));
   }

   return
      packets;
}

// the pcap devices handle that will release all the
// device memory created by calling FindAllDevices
using PCAPDevices =
   std::unique_ptr<
      const pcap_if_t,
      void (*) ( const pcap_if_t * const )
   >;

// a utility function to delete all the pcap devices
// this is mainly used by the PCAPDevices handle
void PCAPFreeAllDevices(
   const pcap_if_t * const devices )
{
   if (devices)
   {
      pcap_freealldevs(
         const_cast< pcap_if_t * >(
            devices));
   }
}

// obtains all of the devices that pcap has found
// and stores them in the pcap devices handle
// this should really return a vector of device
// objects that have a shared pointer to devices
PCAPDevices FindAllDevices( )
{
   PCAPDevices all_devices {
      nullptr,
      &PCAPFreeAllDevices
   };

   pcap_if_t * devices;
   char error[PCAP_ERRBUF_SIZE];

   const int32_t find_result =
      pcap_findalldevs(
         &devices,
         error);

   if (find_result <= PCAP_ERROR)
   {
      std::cerr
         << "Error in pcap_findalldevs: "
         << find_result
         << "\n";
   }
   else if (!devices)
   {
      std::cerr
         << "No capture devices found!\n";
   }
   else
   {
      all_devices.reset(
         devices);
   }
   
   return
      all_devices;
}

// obtains all of the device names and descriptions
// for the devices.  the first member is the name
// of the device.  the second member is the description.
std::vector< std::pair< std::string, std::string > >
GetInterfaceNames(
   const PCAPDevices & devices )
{
   std::vector< std::pair< std::string, std::string > >
      device_names;

   if (devices)
   {
      for (auto current_device { devices.get() };
           current_device;
           current_device = current_device->next)
      {
         device_names.emplace_back(
            current_device->name,
            current_device->description ?
            current_device->description :
            std::string { });
      }
   }

   return
      device_names;
}

// obtains all of the device flags in human readable format
std::vector< std::string >
GetInterfaceFlags(
   const PCAPDevices & devices )
{
   std::vector< std::string >
      device_flags;

   if (devices)
   {
      for (auto current_device { devices.get() };
           current_device;
           current_device = current_device->next)
      {
         std::string flags;

         flags +=
            current_device->flags & PCAP_IF_LOOPBACK ?
            "Is Loopback\n" :
            "Is Not Loopback\n";

         flags +=
            current_device->flags & PCAP_IF_UP ?
            "Is Up\n" :
            "Is Down\n";

         flags +=
            current_device->flags & PCAP_IF_RUNNING ?
            "Is Running\n" :
            "Is Not Running\n";

         flags +=
            current_device->flags & PCAP_IF_WIRELESS ?
            "Is Wireless\n" :
            "Is Not Wireless\n";

         const auto connection_status =
            current_device->flags & PCAP_IF_CONNECTION_STATUS;

         switch (connection_status)
         {
         case PCAP_IF_CONNECTION_STATUS_UNKNOWN:
            flags +=
               "Connection Status Unknown";
            break;

         case PCAP_IF_CONNECTION_STATUS_CONNECTED:
            flags +=
               "Connection Status Connected";
            break;

         case PCAP_IF_CONNECTION_STATUS_DISCONNECTED:
            flags +=
               "Connection Status Disconnected";
            break;

         case PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE:
            flags +=
               "Connection Status Not Applicable";
            break;
         }

         device_flags.emplace_back(
            std::move(flags));
      }
   }

   return
      device_flags;
}

// obtains all of the device addresses in human readable format
// for the specified socket address family
std::string AddressToString(
   const pcap_addr_t * const pcap_address )
{
   std::string addresses;

   if (pcap_address)
   {
      addresses +=
         "Address Family: " +
         (pcap_address->addr ?
            std::to_string(
               pcap_address->addr->sa_family) :
            std::string { "Unknown" }) +
         "\n";

      if (pcap_address->addr)
      {
         switch (pcap_address->addr->sa_family)
         {
         case AF_INET:
            {
               const auto DecodeAddress =
                  [ ] (
                     const sockaddr * addr,
                     std::string prefix )
                  {
                     std::string decoded;

                     if (addr)
                     {
                        const auto addr_in =
                           reinterpret_cast< const sockaddr_in * >(
                              addr);

                        decoded +=
                           std::move(prefix) +
                           inet_ntoa(addr_in->sin_addr) +
                           "\n";
                     }

                     return
                        decoded;
                  };

               addresses +=
                  DecodeAddress(
                     pcap_address->addr,
                     "Addr Address: ");
               addresses +=
                  DecodeAddress(
                     pcap_address->netmask,
                     "Net Mask Address: ");
               addresses +=
                  DecodeAddress(
                     pcap_address->broadaddr,
                     "Broadcast Address: ");
               addresses +=
                  DecodeAddress(
                     pcap_address->dstaddr,
                     "Destination Address: ");
            }

            break;

         case AF_INET6:
            {
               const auto DecodeAddress =
                  [ ] (
                     const sockaddr * addr,
                     std::string prefix )
                  {
                     std::string decoded;

                     if (addr)
                     {
                        char ipv6_address[INET6_ADDRSTRLEN];

                        const auto converted =
                           inet_ntop(
                              AF_INET6,
                              &reinterpret_cast< const sockaddr_in6 * >(
                                 addr)->sin6_addr,
                              ipv6_address,
                              sizeof(ipv6_address));

                        if (!converted)
                        {
                           decoded +=
                              "Unable to convert IPv6 address!\n";
                        }
                        else
                        {
                           decoded.append(
                              converted) +=
                              "\n";
                        }
                     }

                     return
                        decoded;
                  };

               addresses +=
                  DecodeAddress(
                     pcap_address->addr,
                     "Addr Address: ");
               addresses +=
                  DecodeAddress(
                     pcap_address->netmask,
                     "Net Mask Address: ");
               addresses +=
                  DecodeAddress(
                     pcap_address->broadaddr,
                     "Broadcast Address: ");
               addresses +=
                  DecodeAddress(
                     pcap_address->dstaddr,
                     "Destination Address: ");
            }

            break;

         default:
            addresses +=
               "Not decoding address family!\n";

            break;
         }
      }
   }

   return
      addresses;
}

// obtains all of the device addresses in human readable format
std::vector< std::string >
GetInterfaceAddresses(
   const PCAPDevices & devices )
{
   std::vector< std::string >
      device_addresses;

   if (devices)
   {
      for (auto current_device { devices.get() };
           current_device;
           current_device = current_device->next)
      {
         std::string addresses;

         for (const auto * current_address { current_device->addresses };
              current_address;
              current_address = current_address->next)
         {
            addresses +=
               AddressToString(
                  current_address);
         }

         device_addresses.emplace_back(
            std::move(addresses));
      }
   }

   return
      device_addresses;
}

using PCAPFilter =
   std::unique_ptr<
      bpf_program,
      void (*) ( bpf_program * const ) >;

void PCAPFreeFilter(
   bpf_program * const filter )
{
   if (filter)
   {
      pcap_freecode(
         filter);

      delete filter;
   }
}

PCAPFilter CreateAndSetFilter(
   const PCAPCapture & capture )
{
   PCAPFilter filter {
      nullptr,
      &PCAPFreeFilter
   };

   if (capture)
   {
      bpf_program raw_filter;

      auto error =
         pcap_compile(
            capture.get(),
            &raw_filter,
            "(ip and tcp) or (ip and udp) or (ip and icmp)",
            1, /* optimize */
            0 /* no net mask filter */);

      if (error <= PCAP_ERROR)
      {
         std::cerr
            << "Error creating filter: "
            << pcap_geterr(capture.get())
            << "\n";
      }
      else
      {
         filter.reset(
            new bpf_program { raw_filter });

         error =
            pcap_setfilter(
               capture.get(),
               filter.get());

         if (error <= PCAP_ERROR)
         {
            std::cerr
               << "Error setting filter: "
               << pcap_geterr(capture.get())
               << "\n";

            filter.reset();
         }
      }
   }

   return
      filter;
}

class PCAPItemModel :
   public QAbstractItemModel
{
   Q_OBJECT;

public:
   PCAPItemModel(
      PCAPCapture capture,
      QObject * parent );
   virtual ~PCAPItemModel( );

   virtual int32_t columnCount(
      const QModelIndex & parent ) const override;
   virtual int32_t rowCount(
      const QModelIndex & parent ) const override;
   virtual QVariant headerData(
      int32_t section,
      Qt::Orientation orientation,
      int32_t role ) const override;
   virtual QModelIndex parent(
      const QModelIndex & index ) const override;
   virtual QVariant data(
      const QModelIndex & index,
      int32_t role ) const override;
   virtual QModelIndex index(
      int32_t row,
      int32_t column,
      const QModelIndex & parent ) const override;

signals:
   void NewCapturedPackets(
      const std::shared_ptr< Packets > & packets ) const;

public slots:
   void OnClearCapturedData( );

private slots:
   void OnNewCapturedPackets(
      const std::shared_ptr< Packets > & packets );

private:
   std::vector< PacketData > packets_;

   PCAPCapture capture_device_;

   bool quit_capture_;
   std::thread capture_thread_;

};

PCAPItemModel::PCAPItemModel(
   PCAPCapture capture,
   QObject * parent ) :
QAbstractItemModel { parent },
capture_device_ { std::move(capture) },
quit_capture_ { false }
{
   capture_thread_ =
      std::thread {
         [ this ] ( )
         {
            do
            {
               auto packets =
                  CapturePackets(
                     capture_device_);

               if (!packets.empty())
               {
                  emit
                     NewCapturedPackets(
                        std::make_shared< Packets >(
                           std::move(packets)));
               }
            }
            while (!quit_capture_);
         }
      };

   QObject::connect(
      this,
      &PCAPItemModel::NewCapturedPackets,
      this,
      &PCAPItemModel::OnNewCapturedPackets);
}

PCAPItemModel::~PCAPItemModel( )
{
   if (capture_thread_.joinable())
   {
      quit_capture_ = true;

      pcap_breakloop(
         capture_device_.get());

      capture_thread_.join();
   }
}

int32_t PCAPItemModel::columnCount(
   const QModelIndex & parent ) const
{
   int32_t count { };
   
   if (!parent.isValid())
   {
      count = 14;
   }

   return
      count;
}

int32_t PCAPItemModel::rowCount(
   const QModelIndex & parent ) const
{
   int32_t count { };

   if (!parent.isValid())
   {
      count =
         static_cast< int32_t >(
            packets_.size());
   }

   return
      count;
}

QVariant PCAPItemModel::headerData(
   int32_t section,
   Qt::Orientation orientation,
   int32_t role) const
{
   QVariant header;

   if (Qt::DisplayRole == role &&
       Qt::Horizontal == orientation)
   {
      switch (section)
      {
      case 0:
         header = QString { "Time" };
         break;
      case 1:
         header = QString { "Length" };
         break;
      case 2:
         header = QString { "Ethernet Type" };
         break;
      case 3:
         header = QString { "Src MAC" };
         break;
      case 4:
         header = QString { "Dst MAC" };
         break;
      case 5:
         header = QString { "IP Version" };
         break;
      case 6:
         header = QString { "IP Header Size" };
         break;
      case 7:
         header = QString { "IP Total Length" };
         break;
      case 8:
         header = QString { "IP Frag ID" };
         break;
      case 9:
         header = QString { "IP Frag Flags" };
         break;
      case 10:
         header = QString { "IP Frag Offset" };
         break;
      case 11:
         header = QString { "IP Protocol" };
         break;
      case 12:
         header = QString { "IP Src" };
         break;
      case 13:
         header = QString { "IP Dst" };
         break;
      }
   }

   return
      header;
}

void PCAPItemModel::OnNewCapturedPackets(
   const std::shared_ptr< Packets > & packets )
{
   if (packets &&
       !packets->empty())
   {
      const auto current_packets_size =
         static_cast< int32_t >(packets_.size());
      const auto new_packets_size =
         static_cast< int32_t >(packets->size());

      beginInsertRows(
         QModelIndex { },
         current_packets_size,
         current_packets_size + new_packets_size - 1);

      for (auto & packet : *packets)
      {
         packets_.emplace_back(
            std::move(packet));
      }

      endInsertRows();
   }
}

QModelIndex PCAPItemModel::parent(
   const QModelIndex & index ) const
{
   std::ignore = index;

   return
      QModelIndex { };
}

QVariant PCAPItemModel::data(
   const QModelIndex & index,
   int32_t role ) const
{
   QVariant value;

   if (Qt::DisplayRole == role &&
       index.isValid() &&
       packets_.size() > index.row())
   {
      switch (index.column())
      {
      case 0:
         value =
            QString::number(
               std::get< 0 >(packets_[index.row()]),
               'f',
               8);
         break;

      case 1:
         value =
            QString::number(
               std::get< 1 >(packets_[index.row()]));
         break;

      case 2:
         {
            const auto ethernet_header =
               std::get< 3 >(packets_[index.row()]);

            if (ethernet_header)
            {
               value =
                  QString::fromStdString(
                     IdentifyPacketType(
                        ethernet_header->type));
            }
         }

         break;

      case 3:
         {
            const auto ethernet_header =
               std::get< 3 >(packets_[index.row()]);

            if (ethernet_header)
            {
               value =
                  QString::fromStdString(
                     FormatMediaAccessControl(
                        ethernet_header->src_mac));
            }
         }

         break;

      case 4:
         {
            const auto ethernet_header =
               std::get< 3 >(packets_[index.row()]);

            if (ethernet_header)
            {
               value =
                  QString::fromStdString(
                     FormatMediaAccessControl(
                        ethernet_header->dest_mac));
            }
         }

         break;

      case 5:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::number(
                     ipv4_header->version);
            }
         }

         break;

      case 6:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::number(
                     CalculateIPHeaderSize(
                        ipv4_header->header_length));
            }
         }

         break;

      case 7:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::number(
                     ntohs(ipv4_header->total_length));
            }
         }

         break;

      case 8:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::number(
                     ntohs(ipv4_header->fragment_id));
            }
         }

         break;

      case 9:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::fromStdString(
                     InterpretFragmentFlags(
                        ipv4_header->fragment_flags_offset));
            }
         }

         break;

      case 10:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::number(
                     CalculateFragmentOffset(
                        ipv4_header->fragment_flags_offset));
            }
         }

         break;

      case 11:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::fromStdString(
                     IdentifyProtocol(
                        ipv4_header->protocol));
            }
         }

         break;

      case 12:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::fromStdString(
                     FormatIPAddress(
                        ipv4_header->source_ip));
            }
         }

         break;

      case 13:
         {
            const auto ipv4_header =
               std::get< 4 >(packets_[index.row()]);

            if (ipv4_header)
            {
               value =
                  QString::fromStdString(
                     FormatIPAddress(
                        ipv4_header->destination_ip));
            }
         }

         break;
      }
   }

   return
      value;
}

QModelIndex PCAPItemModel::index(
   int32_t row,
   int32_t column,
   const QModelIndex & parent ) const
{
   QModelIndex index;

   if (!parent.isValid())
   {
      index =
         createIndex(
            row,
            column,
            const_cast< PacketData * >(
               &packets_[row]));
   }

   return
      index;
}

void PCAPItemModel::OnClearCapturedData( )
{
   if (!packets_.empty())
   {
      beginRemoveRows(
         QModelIndex { },
         0,
         static_cast< int32_t >(
            packets_.size() - 1));

      packets_.clear();

      endRemoveRows();
   }
}

size_t CalculateTCPHeaderSize(
   const uint8_t tcp_header_size )
{
   return
      tcp_header_size * sizeof(uint32_t);
}

void FormatDataBlocks(
   const uint8_t * begin,
   const uint8_t * const end,
   QTextStream & stream )
{
   const std::ptrdiff_t BYTES_PER_LINE { 16 };
   const std::ptrdiff_t EXTRA_SPACE_AT_BYTES { 8 };

   const auto orig_number_flags =
      stream.numberFlags();
   const auto orig_field_width =
      stream.fieldWidth();
   const auto orig_pad_char =
      stream.padChar();

   stream.setNumberFlags(
      QTextStream::UppercaseDigits);
   stream.setPadChar('0');

   while (begin < end)
   {
      const auto distance =
         end - begin;
      const auto stride =
         distance > BYTES_PER_LINE ?
         BYTES_PER_LINE :
         distance;

      stream.setIntegerBase(16);

      for (std::ptrdiff_t i { }; i < stride; ++i)
      {
         if (i && i % EXTRA_SPACE_AT_BYTES == 0)
         {
            stream
               << qSetFieldWidth(0)
               << " ";
         }

         stream
            << qSetFieldWidth(2)
            << *(begin + i)
            << qSetFieldWidth(0)
            << " ";
      }

      if (BYTES_PER_LINE > stride)
      {
         const auto gap =
            BYTES_PER_LINE - stride;

         for (std::ptrdiff_t i { }; gap > i; ++i)
         {
            stream << "   ";
         }

         const auto extra_spaces =
            gap / EXTRA_SPACE_AT_BYTES;

         for (std::ptrdiff_t i { }; extra_spaces > i; ++i)
         {
            stream << " ";
         }
      }

      stream << "     ";

      stream.setIntegerBase(10);

      for (std::ptrdiff_t i { }; i < stride; ++i)
      {
         if (i && i % EXTRA_SPACE_AT_BYTES == 0)
         {
            stream << " ";
         }

         const auto value =
            *(begin + i);

         if (0 <= value && value <= 31 || value >= 127)
         {
            stream << ".";
         }
         else
         {
            stream
               << static_cast< char >(value);
         }

         stream << " ";
      }

      stream << "\n";

      begin += stride;
   }

   stream.setNumberFlags(
      orig_number_flags);
   stream.setFieldWidth(
      orig_field_width);
   stream.setPadChar(
      orig_pad_char);
}

QString FormatTCPPacket(
   const PacketData & packet )
{
   QString spacket;

   const auto tcp_header =
      reinterpret_cast< const osi::transport::tcp * >(
         std::get< 5 >(packet));

   if (tcp_header)
   {
      QTextStream stream {
         &spacket };

      const auto tcp_header_size =
         CalculateTCPHeaderSize(
            tcp_header->header_length);

      stream
         << "-- TCP Header --\n"
         << "        Source Port: " << ntohs(tcp_header->src_port) << "\n"
         << "   Destination Port: " << ntohs(tcp_header->dst_port) << "\n"
         << "         Sequence #: " << ntohl(tcp_header->sequence) << "\n"
         << "  Acknowledgement #: " << ntohl(tcp_header->acknowledgement) << "\n"
         << "        Header Size: " << tcp_header_size << "\n";

      stream.setIntegerBase(16);
      stream.setNumberFlags(
         QTextStream::ShowBase |
         QTextStream::UppercaseDigits |
         stream.numberFlags());

      stream
         << "           Reserved: " << (tcp_header->reserved1 | tcp_header->reserved2 << 4) << "\n";

      stream.setIntegerBase(10);

      stream
         << "         Urgent Bit: " << tcp_header->urgent_bit << "\n"
         << "Acknowledgement Bit: " << tcp_header->acknowledgement_bit << "\n"
         << "           Push Bit: " << tcp_header->push_bit << "\n"
         << "          Reset Bit: " << tcp_header->reset_bit << "\n"
         << "    Synchronize Bit: " << tcp_header->synchronize_bit << "\n"
         << "      Terminate Bit: " << tcp_header->terminate_bit << "\n"
         << "        Window Size: " << ntohs(tcp_header->window_size) << "\n";

      stream.setIntegerBase(16);

      stream
         << "           Checksum: " << ntohs(tcp_header->checksum) << "\n";

      stream.setIntegerBase(10);

      stream
         << "     Urgent Pointer: " << ntohs(tcp_header->urgent_pointer) << "\n";

      if (tcp_header_size > 20)
      {
         stream
            << "\n-- TCP Options --\n";

         const auto tcp_options =
            reinterpret_cast< const uint8_t * >(
               tcp_header + 1);

         FormatDataBlocks(
            tcp_options,
            tcp_options + tcp_header_size - 20,
            stream);
      }

      const auto ipv4_header =
         std::get< 4 >(packet);

      if (ipv4_header)
      {
         const auto tcp_data_begin =
            reinterpret_cast< const uint8_t * >(
               tcp_header) + tcp_header_size;
         const auto tcp_data_end =
            reinterpret_cast< const uint8_t * >(
               ipv4_header) + ntohs(ipv4_header->total_length);

         if (tcp_data_end > tcp_data_begin)
         {
            stream
               << "\n-- TCP Data --\n";

            FormatDataBlocks(
               tcp_data_begin,
               tcp_data_end,
               stream);
         }
      }
   }

   return
      spacket;
}

QString FormatICMPPacket(
   const PacketData & packet )
{
   QString spacket;

   const auto icmp_header =
      reinterpret_cast< const osi::transport::icmp * >(
         std::get< 5 >(packet));

   if (icmp_header)
   {
      QTextStream stream {
         &spacket };

      stream
         << "-- ICMP Header --\n"
         << "    Type: " << icmp_header->type << "\n"
         << "    Code: " << icmp_header->code << "\n";

      stream.setIntegerBase(16);
      stream.setNumberFlags(
         QTextStream::ShowBase |
         QTextStream::UppercaseDigits |
         stream.numberFlags());

      stream
         << "Checksum: " << ntohs(icmp_header->checksum) << "\n";

      stream.setIntegerBase(10);

      if (icmp_header->type == 0 || icmp_header->type == 8)
      {
         stream
            << "\n-- ICMP Echo "
            << (icmp_header->type == 0 ? "Reply --\n" : "Request --\n");

         const auto icmp_echo_header =
            reinterpret_cast< const osi::transport::icmp_echo * >(
               icmp_header);

         stream
            << "      ID: " << ntohs(icmp_echo_header->id) << "\n"
            << "Sequence: " << ntohs(icmp_echo_header->sequence) << "\n";
      }

      const auto ipv4_header =
         std::get< 4 >(packet);

      if (ipv4_header)
      {
         const auto header_size =
            icmp_header->type == 0 || icmp_header->type == 8 ?
               sizeof(osi::transport::icmp_echo) :
               sizeof(osi::transport::icmp);

         const auto icmp_data_begin =
            reinterpret_cast< const uint8_t * >(
               icmp_header) + header_size;
         const auto icmp_data_end =
            reinterpret_cast< const uint8_t * >(
               ipv4_header) + ntohs(ipv4_header->total_length);

         if (icmp_data_end > icmp_data_begin)
         {
            stream
               << "\n-- ICMP Data --\n";

            FormatDataBlocks(
               icmp_data_begin,
               icmp_data_end,
               stream);
         }
      }
   }

   return
      spacket;
}

QString FormatUDPPacket(
   const PacketData & packet )
{
   QString spacket;

   const auto udp_header =
      reinterpret_cast< const osi::transport::udp * >(
         std::get< 5 >(packet));

   if (udp_header)
   {
      QTextStream stream {
         &spacket };

      const auto total_udp_size =
         ntohs(udp_header->total_length);

      stream
         << "-- UDP Header --\n"
         << "     Source Port: " << ntohs(udp_header->src_port) << "\n"
         << "Destination Port: " << ntohs(udp_header->dst_port) << "\n"
         << "      Total Size: " << total_udp_size << "\n";

      stream.setIntegerBase(16);
      stream.setNumberFlags(
         QTextStream::ShowBase |
         QTextStream::UppercaseDigits |
         stream.numberFlags());

      stream
         << "        Checksum: " << ntohs(udp_header->checksum) << "\n";

      stream.setIntegerBase(10);

         const auto udp_data_begin =
            reinterpret_cast< const uint8_t * >(
               udp_header + 1);
         const auto udp_data_end =
            reinterpret_cast< const uint8_t * >(
               udp_header) + total_udp_size;

         if (udp_data_end > udp_data_begin)
         {
            stream
               << "\n-- UDP Data --\n";

            FormatDataBlocks(
               udp_data_begin,
               udp_data_end,
               stream);
         }
   }

   return
      spacket;
}

QString FormatProtocol(
   const PacketData & packet )
{
   QString protocol { "Protocol Undefined" };

   const auto ipv4_header =
      std::get< 4 >(packet);

   if (ipv4_header)
   {
      switch (ipv4_header->protocol)
      {
      case osi::network::PROTOCOL_TCP:
         protocol =
           FormatTCPPacket(
              packet);
         break;
      case osi::network::PROTOCOL_UDP:
         protocol =
            FormatUDPPacket(
               packet);
         break;
      case osi::network::PROTOCOL_ICMP:
         protocol =
            FormatICMPPacket(
               packet);
         break;
      }
   }

   return
      protocol;
}

QString FormatSelection(
   const QModelIndex & index )
{
   QString formatted;

   const auto packet =
      reinterpret_cast< const PacketData * >(
         index.internalPointer());

   if (packet)
   {
      formatted =
         FormatProtocol(
            *packet);
   }

   return
      formatted;
}

int32_t main(
   int32_t argc,
   char * argv[] )
{
   const auto all_devices =
      FindAllDevices();

   if (!all_devices)
   {
      return -1;
   }

   const auto device_names =
      GetInterfaceNames(
         all_devices);

   const auto device_flags =
      GetInterfaceFlags(
         all_devices);

   const auto device_addresses =
      GetInterfaceAddresses(
         all_devices);

   for (const auto & device_name : device_names)
   {
      const auto index =
         std::distance(
            device_names.data(),
            &device_name);

      std::cout
         << index
         << ". "
         << device_name.first
         << " - "
         << device_name.second
         << "\n";

      const auto & device_flag =
         device_flags[index];

      std::cout
         << device_flag
         << "\n";

      const auto & device_address =
         device_addresses[index];

      std::cout
         << device_address
         << "\n\n";
   }

   std::cout
      << "Which device to capture from: ";
   
   size_t device_index { ~0u };

   std::cin >> device_index;

   if (device_index > device_names.size())
   {
      return -2;
   }
   else
   {
      auto capture_device =
         OpenSource(
            device_names[device_index].first);

      if (!capture_device)
      {
         return -3;
      }

      // make sure to capture for ethernet
      const auto datalink =
         pcap_datalink(
            capture_device.get());

      if (datalink != DLT_EN10MB)
      {
         std::cerr
            << "Data link layer for this adapter must be "
               "10 / 100 / 1000 Mb and up ethernet!\n";

         return -4;
      }

      const auto filter_code =
         CreateAndSetFilter(
            capture_device);

      if (!filter_code)
      {
         return -5;
      }

      QApplication application {
        argc,
        argv
      };

      QSplitter splitter;

      QTreeView tree_view;

      tree_view.setModel(
         std::make_unique< PCAPItemModel >(
            std::move(capture_device),
            &tree_view).release());

      splitter.addWidget(
         &tree_view);

      QPlainTextEdit text_edit;

      text_edit.setReadOnly(
         true);
      text_edit.setLineWrapMode(
         QPlainTextEdit::NoWrap);

#if _WIN32
      QFont font_text_edit {
         "Consolas",
         10
      };
#elif __linux__
      QFont font_text_edit {
         "FreeMono",
         10
      };
#else
#error "Define for this platform!"
#endif // _WIN32

      font_text_edit.setBold(
         true);

      text_edit.setFont(
         font_text_edit);

      QObject::connect(
         tree_view.selectionModel(),
         &QItemSelectionModel::selectionChanged,
         [ & ] (
            const QItemSelection & selected,
            const QItemSelection & deselected )
         {
            std::ignore = deselected;

            const auto indexes =
               selected.indexes();

            if (!indexes.empty())
            {
               text_edit.setPlainText(
                  FormatSelection(
                     indexes[0]));
            }          
         }
      );

      QObject::connect(
         &tree_view,
         &QTreeView::pressed,
         [ & ] (
            const QModelIndex & index )
         {
            if (index.isValid() &&
                QGuiApplication::mouseButtons() & Qt::RightButton)
            {
               QMenu menu;

               const auto action =
                  menu.addAction(
                     "Clear Packets");

               if (action)
               {
                  const auto model =
                     dynamic_cast< PCAPItemModel * >(
                        tree_view.model());

                  if (model)
                  {
                     QObject::connect(
                        action,
                        &QAction::triggered,
                        model,
                        &PCAPItemModel::OnClearCapturedData);

                     menu.exec(
                        QCursor::pos());
                  }
               }
            }
         });

      splitter.addWidget(
         &text_edit);

      splitter.show();

      const auto exec_results =
         application.exec();

      return
        exec_results;
   }
}

#include "main.moc"
