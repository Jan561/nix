//! Socket interface functions
//!
//! [Further reading](https://man7.org/linux/man-pages/man7/socket.7.html)
#[cfg(any(target_os = "android", target_os = "linux"))]
#[cfg(feature = "uio")]
use crate::sys::time::TimeSpec;
#[cfg(not(target_os = "redox"))]
#[cfg(feature = "uio")]
use crate::sys::time::TimeVal;
use crate::{errno::Errno, Result};
use cfg_if::cfg_if;
use libc::{self, c_int, size_t, socklen_t};
#[cfg(all(feature = "uio", not(target_os = "redox")))]
use libc::{
    CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_NXTHDR, CMSG_SPACE,
};
#[cfg(not(target_os = "redox"))]
use std::io::{IoSlice, IoSliceMut};

#[cfg(not(target_os = "redox"))]
#[cfg(feature = "uio")]
use std::mem::MaybeUninit;
#[cfg(feature = "net")]
use std::net;
use std::os::unix::io::{AsFd, AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(not(target_os = "redox"))]
use std::ptr::addr_of_mut;
use std::{mem, ptr};

#[deny(missing_docs)]
mod addr;
#[deny(missing_docs)]
pub mod sockopt;

/*
 *
 * ===== Re-exports =====
 *
 */

use self::addr::AddrToOwned;
pub use self::addr::{AddressFamily, InvalidAddressFamilyError, SockaddrFromRaw, SockaddrLike, SockaddressStorage, NoAddress, UnixAddr, UnixAddress, RawAddress, RawAddressSized};

#[cfg(not(any(
    target_os = "solaris",
    target_os = "redox",
)))]
#[cfg(feature = "net")]
pub use self::addr::{LinkAddr, SockaddrIn, SockaddrIn6};
#[cfg(any(
    target_os = "solaris",
    target_os = "redox",
))]
#[cfg(feature = "net")]
pub use self::addr::{SockaddrIn, SockaddrIn6};

#[cfg(any(target_os = "android", target_os = "linux"))]
pub use crate::sys::socket::addr::alg::AlgAddr;
#[cfg(any(target_os = "android", target_os = "linux"))]
pub use crate::sys::socket::addr::netlink::NetlinkAddr;
#[cfg(any(target_os = "ios", target_os = "macos"))]
#[cfg(feature = "ioctl")]
pub use crate::sys::socket::addr::sys_control::SysControlAddr;
#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_os = "macos"
))]
pub use crate::sys::socket::addr::vsock::VsockAddr;

#[cfg(all(feature = "uio", not(target_os = "redox")))]
pub use libc::{cmsghdr, msghdr};
pub use libc::{sa_family_t, sockaddr, sockaddr_storage, sockaddr_un};
#[cfg(feature = "net")]
pub use libc::{sockaddr_in, sockaddr_in6};

#[cfg(feature = "net")]
use crate::sys::socket::addr::{ipv4addr_to_libc, ipv6addr_to_libc};

#[allow(unused_imports)]
pub(crate) use crate::sys::socket::addr::private::SockaddrLikePriv;

/// These constants are used to specify the communication semantics
/// when creating a socket with [`socket()`](fn.socket.html)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
#[non_exhaustive]
pub enum SockType {
    /// Provides sequenced, reliable, two-way, connection-
    /// based byte streams.  An out-of-band data transmission
    /// mechanism may be supported.
    Stream = libc::SOCK_STREAM,
    /// Supports datagrams (connectionless, unreliable
    /// messages of a fixed maximum length).
    Datagram = libc::SOCK_DGRAM,
    /// Provides a sequenced, reliable, two-way connection-
    /// based data transmission path for datagrams of fixed
    /// maximum length; a consumer is required to read an
    /// entire packet with each input system call.
    SeqPacket = libc::SOCK_SEQPACKET,
    /// Provides raw network protocol access.
    #[cfg(not(target_os = "redox"))]
    Raw = libc::SOCK_RAW,
    /// Provides a reliable datagram layer that does not
    /// guarantee ordering.
    #[cfg(not(any(target_os = "haiku", target_os = "redox")))]
    Rdm = libc::SOCK_RDM,
}
// The TryFrom impl could've been derived using libc_enum!.  But for
// backwards-compatibility with Nix-0.25.0 we manually implement it, so as to
// keep the old variant names.
impl TryFrom<i32> for SockType {
    type Error = crate::Error;

    fn try_from(x: i32) -> Result<Self> {
        match x {
            libc::SOCK_STREAM => Ok(Self::Stream),
            libc::SOCK_DGRAM => Ok(Self::Datagram),
            libc::SOCK_SEQPACKET => Ok(Self::SeqPacket),
            #[cfg(not(target_os = "redox"))]
            libc::SOCK_RAW => Ok(Self::Raw),
            #[cfg(not(any(target_os = "haiku", target_os = "redox")))]
            libc::SOCK_RDM => Ok(Self::Rdm),
            _ => Err(Errno::EINVAL),
        }
    }
}

/// Constants used in [`socket`](fn.socket.html) and [`socketpair`](fn.socketpair.html)
/// to specify the protocol to use.
#[repr(i32)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SockProtocol {
    /// TCP protocol ([ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html))
    Tcp = libc::IPPROTO_TCP,
    /// UDP protocol ([ip(7)](https://man7.org/linux/man-pages/man7/ip.7.html))
    Udp = libc::IPPROTO_UDP,
    /// Raw sockets ([raw(7)](https://man7.org/linux/man-pages/man7/raw.7.html))
    Raw = libc::IPPROTO_RAW,
    /// Allows applications to configure and control a KEXT
    /// ([ref](https://developer.apple.com/library/content/documentation/Darwin/Conceptual/NKEConceptual/control/control.html))
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    KextControl = libc::SYSPROTO_CONTROL,
    /// Receives routing and link updates and may be used to modify the routing tables (both IPv4 and IPv6), IP addresses, link
    // parameters, neighbor setups, queueing disciplines, traffic classes and packet classifiers
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkRoute = libc::NETLINK_ROUTE,
    /// Reserved for user-mode socket protocols
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkUserSock = libc::NETLINK_USERSOCK,
    /// Query information about sockets of various protocol families from the kernel
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkSockDiag = libc::NETLINK_SOCK_DIAG,
    /// Netfilter/iptables ULOG.
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkNFLOG = libc::NETLINK_NFLOG,
    /// SELinux event notifications.
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkSELinux = libc::NETLINK_SELINUX,
    /// Open-iSCSI
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkISCSI = libc::NETLINK_ISCSI,
    /// Auditing
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkAudit = libc::NETLINK_AUDIT,
    /// Access to FIB lookup from user space
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkFIBLookup = libc::NETLINK_FIB_LOOKUP,
    /// Netfilter subsystem
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkNetFilter = libc::NETLINK_NETFILTER,
    /// SCSI Transports
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkSCSITransport = libc::NETLINK_SCSITRANSPORT,
    /// Infiniband RDMA
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkRDMA = libc::NETLINK_RDMA,
    /// Transport IPv6 packets from netfilter to user space.  Used by ip6_queue kernel module.
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkIPv6Firewall = libc::NETLINK_IP6_FW,
    /// DECnet routing messages
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkDECNetRoutingMessage = libc::NETLINK_DNRTMSG,
    /// Kernel messages to user space
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkKObjectUEvent = libc::NETLINK_KOBJECT_UEVENT,
    /// Generic netlink family for simplified netlink usage.
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkGeneric = libc::NETLINK_GENERIC,
    /// Netlink interface to request information about ciphers registered with the kernel crypto API as well as allow
    /// configuration of the kernel crypto API.
    /// ([ref](https://www.man7.org/linux/man-pages/man7/netlink.7.html))
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    NetlinkCrypto = libc::NETLINK_CRYPTO,
    /// Non-DIX type protocol number defined for the Ethernet IEEE 802.3 interface that allows packets of all protocols
    /// defined in the interface to be received.
    /// ([ref](https://man7.org/linux/man-pages/man7/packet.7.html))
    // The protocol number is fed into the socket syscall in network byte order.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    EthAll = (libc::ETH_P_ALL as u16).to_be() as i32,
    /// ICMP protocol ([icmp(7)](https://man7.org/linux/man-pages/man7/icmp.7.html))
    Icmp = libc::IPPROTO_ICMP,
    /// ICMPv6 protocol (ICMP over IPv6)
    IcmpV6 = libc::IPPROTO_ICMPV6,
}

impl SockProtocol {
    /// The Controller Area Network raw socket protocol
    /// ([ref](https://docs.kernel.org/networking/can.html#how-to-use-socketcan))
    #[cfg(target_os = "linux")]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    #[allow(non_upper_case_globals)]
    pub const CanRaw: SockProtocol = SockProtocol::Icmp; // Matches libc::CAN_RAW

    /// The Controller Area Network broadcast manager protocol
    /// ([ref](https://docs.kernel.org/networking/can.html#how-to-use-socketcan))
    #[cfg(target_os = "linux")]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    #[allow(non_upper_case_globals)]
    pub const CanBcm: SockProtocol = SockProtocol::NetlinkUserSock; // Matches libc::CAN_BCM

    /// Allows applications and other KEXTs to be notified when certain kernel events occur
    /// ([ref](https://developer.apple.com/library/content/documentation/Darwin/Conceptual/NKEConceptual/control/control.html))
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    #[allow(non_upper_case_globals)]
    pub const KextEvent: SockProtocol = SockProtocol::Icmp;  // Matches libc::SYSPROTO_EVENT
}
#[cfg(any(target_os = "android", target_os = "linux"))]
libc_bitflags! {
    /// Configuration flags for `SO_TIMESTAMPING` interface
    ///
    /// For use with [`Timestamping`][sockopt::Timestamping].
    /// [Further reading](https://www.kernel.org/doc/html/latest/networking/timestamping.html)
    pub struct TimestampingFlag: libc::c_uint {
        /// Report any software timestamps when available.
        SOF_TIMESTAMPING_SOFTWARE;
        /// Report hardware timestamps as generated by SOF_TIMESTAMPING_TX_HARDWARE when available.
        SOF_TIMESTAMPING_RAW_HARDWARE;
        /// Collect transmitting timestamps as reported by hardware
        SOF_TIMESTAMPING_TX_HARDWARE;
        /// Collect transmitting timestamps as reported by software
        SOF_TIMESTAMPING_TX_SOFTWARE;
        /// Collect receiving timestamps as reported by hardware
        SOF_TIMESTAMPING_RX_HARDWARE;
        /// Collect receiving timestamps as reported by software
        SOF_TIMESTAMPING_RX_SOFTWARE;
        /// Generate a unique identifier along with each transmitted packet
        SOF_TIMESTAMPING_OPT_ID;
        /// Return transmit timestamps alongside an empty packet instead of the original packet
        SOF_TIMESTAMPING_OPT_TSONLY;
    }
}

libc_bitflags! {
    /// Additional socket options
    pub struct SockFlag: c_int {
        /// Set non-blocking mode on the new socket
        #[cfg(any(target_os = "android",
                  target_os = "dragonfly",
                  target_os = "freebsd",
                  target_os = "illumos",
                  target_os = "linux",
                  target_os = "netbsd",
                  target_os = "openbsd"))]
        #[cfg_attr(docsrs, doc(cfg(all())))]
        SOCK_NONBLOCK;
        /// Set close-on-exec on the new descriptor
        #[cfg(any(target_os = "android",
                  target_os = "dragonfly",
                  target_os = "freebsd",
                  target_os = "illumos",
                  target_os = "linux",
                  target_os = "netbsd",
                  target_os = "openbsd"))]
        #[cfg_attr(docsrs, doc(cfg(all())))]
        SOCK_CLOEXEC;
        /// Return `EPIPE` instead of raising `SIGPIPE`
        #[cfg(target_os = "netbsd")]
        #[cfg_attr(docsrs, doc(cfg(all())))]
        SOCK_NOSIGPIPE;
        /// For domains `AF_INET(6)`, only allow `connect(2)`, `sendto(2)`, or `sendmsg(2)`
        /// to the DNS port (typically 53)
        #[cfg(target_os = "openbsd")]
        #[cfg_attr(docsrs, doc(cfg(all())))]
        SOCK_DNS;
    }
}

libc_bitflags! {
    /// Flags for send/recv and their relatives
    pub struct MsgFlags: c_int {
        /// Sends or requests out-of-band data on sockets that support this notion
        /// (e.g., of type [`Stream`](enum.SockType.html)); the underlying protocol must also
        /// support out-of-band data.
        MSG_OOB;
        /// Peeks at an incoming message. The data is treated as unread and the next
        /// [`recv()`](fn.recv.html)
        /// or similar function shall still return this data.
        MSG_PEEK;
        /// Receive operation blocks until the full amount of data can be
        /// returned. The function may return smaller amount of data if a signal
        /// is caught, an error or disconnect occurs.
        MSG_WAITALL;
        /// Enables nonblocking operation; if the operation would block,
        /// `EAGAIN` or `EWOULDBLOCK` is returned.  This provides similar
        /// behavior to setting the `O_NONBLOCK` flag
        /// (via the [`fcntl`](../../fcntl/fn.fcntl.html)
        /// `F_SETFL` operation), but differs in that `MSG_DONTWAIT` is a per-
        /// call option, whereas `O_NONBLOCK` is a setting on the open file
        /// description (see [open(2)](https://man7.org/linux/man-pages/man2/open.2.html)),
        /// which will affect all threads in
        /// the calling process and as well as other processes that hold
        /// file descriptors referring to the same open file description.
        #[cfg(not(target_os = "aix"))]
        #[cfg_attr(docsrs, doc(cfg(all())))]
        MSG_DONTWAIT;
        /// Receive flags: Control Data was discarded (buffer too small)
        MSG_CTRUNC;
        /// For raw (`AF_PACKET`), Internet datagram
        /// (since Linux 2.4.27/2.6.8),
        /// netlink (since Linux 2.6.22) and UNIX datagram (since Linux 3.4)
        /// sockets: return the real length of the packet or datagram, even
        /// when it was longer than the passed buffer. Not implemented for UNIX
        /// domain ([unix(7)](https://linux.die.net/man/7/unix)) sockets.
        ///
        /// For use with Internet stream sockets, see [tcp(7)](https://linux.die.net/man/7/tcp).
        MSG_TRUNC;
        /// Terminates a record (when this notion is supported, as for
        /// sockets of type [`SeqPacket`](enum.SockType.html)).
        MSG_EOR;
        /// This flag specifies that queued errors should be received from
        /// the socket error queue. (For more details, see
        /// [recvfrom(2)](https://linux.die.net/man/2/recvfrom))
        #[cfg(any(target_os = "android", target_os = "linux"))]
        #[cfg_attr(docsrs, doc(cfg(all())))]
        MSG_ERRQUEUE;
        /// Set the `close-on-exec` flag for the file descriptor received via a UNIX domain
        /// file descriptor using the `SCM_RIGHTS` operation (described in
        /// [unix(7)](https://linux.die.net/man/7/unix)).
        /// This flag is useful for the same reasons as the `O_CLOEXEC` flag of
        /// [open(2)](https://pubs.opengroup.org/onlinepubs/9699919799/functions/open.html).
        ///
        /// Only used in [`recvmsg`](fn.recvmsg.html) function.
        #[cfg(any(target_os = "android",
                  target_os = "dragonfly",
                  target_os = "freebsd",
                  target_os = "linux",
                  target_os = "netbsd",
                  target_os = "openbsd"))]
        #[cfg_attr(docsrs, doc(cfg(all())))]
        MSG_CMSG_CLOEXEC;
        /// Requests not to send `SIGPIPE` errors when the other end breaks the connection.
        /// (For more details, see [send(2)](https://linux.die.net/man/2/send)).
        #[cfg(any(target_os = "android",
                  target_os = "dragonfly",
                  target_os = "freebsd",
                  target_os = "fuchsia",
                  target_os = "haiku",
                  target_os = "illumos",
                  target_os = "linux",
                  target_os = "netbsd",
                  target_os = "openbsd",
                  target_os = "solaris"))]
        #[cfg_attr(docsrs, doc(cfg(all())))]
        MSG_NOSIGNAL;
        /// Turns on [`MSG_DONTWAIT`] after the first message has been received (only for
        /// `recvmmsg()`).
        #[cfg(any(target_os = "android",
                  target_os = "fuchsia",
                  target_os = "linux",
                  target_os = "netbsd",
                  target_os = "freebsd",
                  target_os = "openbsd",
                  target_os = "solaris"))]
        #[cfg_attr(docsrs, doc(cfg(all())))]
        MSG_WAITFORONE;
    }
}

cfg_if! {
    if #[cfg(any(target_os = "android", target_os = "linux"))] {
        /// Unix credentials of the sending process.
        ///
        /// This struct is used with the `SO_PEERCRED` ancillary message
        /// and the `SCM_CREDENTIALS` control message for UNIX sockets.
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct UnixCredentials(libc::ucred);

        impl UnixCredentials {
            /// Creates a new instance with the credentials of the current process
            pub fn new() -> Self {
                // Safe because these FFI functions are inherently safe
                unsafe {
                    UnixCredentials(libc::ucred {
                        pid: libc::getpid(),
                        uid: libc::getuid(),
                        gid: libc::getgid()
                    })
                }
            }

            /// Returns the process identifier
            pub fn pid(&self) -> libc::pid_t {
                self.0.pid
            }

            /// Returns the user identifier
            pub fn uid(&self) -> libc::uid_t {
                self.0.uid
            }

            /// Returns the group identifier
            pub fn gid(&self) -> libc::gid_t {
                self.0.gid
            }
        }

        impl Default for UnixCredentials {
            fn default() -> Self {
                Self::new()
            }
        }

        impl From<libc::ucred> for UnixCredentials {
            fn from(cred: libc::ucred) -> Self {
                UnixCredentials(cred)
            }
        }

        impl From<UnixCredentials> for libc::ucred {
            fn from(uc: UnixCredentials) -> Self {
                uc.0
            }
        }
    } else if #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))] {
        /// Unix credentials of the sending process.
        ///
        /// This struct is used with the `SCM_CREDS` ancillary message for UNIX sockets.
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct UnixCredentials(libc::cmsgcred);

        impl UnixCredentials {
            /// Returns the process identifier
            pub fn pid(&self) -> libc::pid_t {
                self.0.cmcred_pid
            }

            /// Returns the real user identifier
            pub fn uid(&self) -> libc::uid_t {
                self.0.cmcred_uid
            }

            /// Returns the effective user identifier
            pub fn euid(&self) -> libc::uid_t {
                self.0.cmcred_euid
            }

            /// Returns the real group identifier
            pub fn gid(&self) -> libc::gid_t {
                self.0.cmcred_gid
            }

            /// Returns a list group identifiers (the first one being the effective GID)
            pub fn groups(&self) -> &[libc::gid_t] {
                unsafe {
                    std::slice::from_raw_parts(
                        self.0.cmcred_groups.as_ptr(),
                        self.0.cmcred_ngroups as _
                    )
                }
            }
        }

        impl From<libc::cmsgcred> for UnixCredentials {
            fn from(cred: libc::cmsgcred) -> Self {
                UnixCredentials(cred)
            }
        }
    }
}

cfg_if! {
    if #[cfg(any(
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "macos",
                target_os = "ios"
        ))] {
        /// Return type of [`LocalPeerCred`](crate::sys::socket::sockopt::LocalPeerCred)
        #[repr(transparent)]
        #[derive(Clone, Copy, Debug, Eq, PartialEq)]
        pub struct XuCred(libc::xucred);

        impl XuCred {
            /// Structure layout version
            pub fn version(&self) -> u32 {
                self.0.cr_version
            }

            /// Effective user ID
            pub fn uid(&self) -> libc::uid_t {
                self.0.cr_uid
            }

            /// Returns a list of group identifiers (the first one being the
            /// effective GID)
            pub fn groups(&self) -> &[libc::gid_t] {
                &self.0.cr_groups
            }
        }
    }
}

feature! {
#![feature = "net"]
/// Request for multicast socket operations
///
/// This is a wrapper type around `ip_mreq`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IpMembershipRequest(libc::ip_mreq);

impl IpMembershipRequest {
    /// Instantiate a new `IpMembershipRequest`
    ///
    /// If `interface` is `None`, then `Ipv4Addr::any()` will be used for the interface.
    pub fn new(group: net::Ipv4Addr, interface: Option<net::Ipv4Addr>)
        -> Self
    {
        let imr_addr = match interface {
            None => net::Ipv4Addr::UNSPECIFIED,
            Some(addr) => addr
        };
        IpMembershipRequest(libc::ip_mreq {
            imr_multiaddr: ipv4addr_to_libc(group),
            imr_interface: ipv4addr_to_libc(imr_addr)
        })
    }
}

/// Request for ipv6 multicast socket operations
///
/// This is a wrapper type around `ipv6_mreq`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Ipv6MembershipRequest(libc::ipv6_mreq);

impl Ipv6MembershipRequest {
    /// Instantiate a new `Ipv6MembershipRequest`
    pub const fn new(group: net::Ipv6Addr) -> Self {
        Ipv6MembershipRequest(libc::ipv6_mreq {
            ipv6mr_multiaddr: ipv6addr_to_libc(&group),
            ipv6mr_interface: 0,
        })
    }
}
}

#[cfg(not(target_os = "redox"))]
feature! {
#![feature = "uio"]

/// Calculates the space needed for the provided arguments.
///
/// The arguments are the names of the variants of [`ControlMessageOwnedSpace`]. This macro
/// is const-evaluable.
#[macro_export]
macro_rules! cmsg_space {
    ($($x:ident $(($arg:expr))? ),* $(,)?) => {{
        0usize $(
            + <$crate::sys::socket::ControlMessageOwnedSpace>::$x $(($arg))?.space()
        )*
    }};
}

/// Creates a [`CmsgVecRead`] with the capacity needed for the provided arguments.
///
/// The arguments are the names of the variants of [`ControlMessageOwnedSpace`].
///
/// # Example
///
/// ```
/// # use nix::{cmsg_space, cmsg_vec, sys::socket::CmsgVecRead};
/// let cmsg = cmsg_vec![ScmRights(2), ScmTimestamp];
///
/// assert_eq!(cmsg.capacity(), cmsg_space![ScmRights(2), ScmTimestamp]);
/// ```
#[macro_export]
macro_rules! cmsg_vec {
    ($($x:ident $(($arg:expr))? ),* $(,)?) => {{
        const SPACE: usize = $crate::cmsg_space![$($x $(($arg))? ),*];

        $crate::sys::socket::CmsgVecRead::with_capacity(SPACE)
    }};
}

#[derive(Clone, Copy, Debug)]
pub struct CmsgIterator<'a> {
    /// Control message buffer to decode from. Must adhere to cmsg alignment.
    cmsghdr: Option<&'a cmsghdr>,
    // SAFETY: `msg_control` and `msg_controllen` must be initialized.
    mhdr: MaybeUninit<msghdr>,
}

impl<'a> Iterator for CmsgIterator<'a> {
    type Item = ControlMessageOwned;

    fn next(&mut self) -> Option<ControlMessageOwned> {
        match self.cmsghdr {
            None => None,   // No more messages
            Some(hdr) => {
                // Get the data.
                // Safe if cmsghdr points to valid data returned by recvmsg(2)
                let cm = unsafe { Some(ControlMessageOwned::decode_from(hdr))};
                // Advance the internal pointer.  Safe if mhdr and cmsghdr point
                // to valid data returned by recvmsg(2)
                self.cmsghdr = unsafe {
                    let p = CMSG_NXTHDR(self.mhdr.as_ptr(), hdr as *const _);
                    p.as_ref()
                };
                cm
            }
        }
    }
}

/// A type-safe wrapper around a single control message, as used with
/// [`recvmsg`](#fn.recvmsg).
///
/// Note: this is *not* the owned version of [`ControlMessage`] as they don't
/// necessarily have the same variants.
///
/// [Further reading](https://man7.org/linux/man-pages/man3/cmsg.3.html)

//  Nix version 0.13.0 and earlier used ControlMessage for both recvmsg and
//  sendmsg.  However, on some platforms the messages returned by recvmsg may be
//  unaligned.  ControlMessageOwned takes those messages by copy, obviating any
//  alignment issues.
//
//  See https://github.com/nix-rust/nix/issues/999
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ControlMessageOwned {
    /// Received version of [`ControlMessage::ScmRights`]
    ScmRights(Vec<RawFd>),
    /// Received version of [`ControlMessage::ScmCredentials`]
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    ScmCredentials(UnixCredentials),
    /// Received version of [`ControlMessage::ScmCreds`]
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    ScmCreds(UnixCredentials),
    /// A message of type `SCM_TIMESTAMP`, containing the time the
    /// packet was received by the kernel.
    ///
    /// See the kernel's explanation in "SO_TIMESTAMP" of
    /// [networking/timestamping](https://www.kernel.org/doc/Documentation/networking/timestamping.txt).
    ///
    /// # Examples
    ///
    /// ```
    /// # #[macro_use] extern crate nix;
    /// # use nix::sys::socket::*;
    /// # use nix::sys::time::*;
    /// # use std::io::{IoSlice, IoSliceMut};
    /// # use std::time::*;
    /// # use std::str::FromStr;
    /// # use std::os::unix::io::AsRawFd;
    /// # fn main() {
    /// // Set up
    /// let message = "Ohayō!".as_bytes();
    /// let in_socket = socket(
    ///     AddressFamily::INET,
    ///     SockType::Datagram,
    ///     SockFlag::empty(),
    ///     None).unwrap();
    /// setsockopt(&in_socket, sockopt::ReceiveTimestamp, &true).unwrap();
    /// let localhost = SockaddrIn::from_str("127.0.0.1:0").unwrap();
    /// bind(in_socket.as_raw_fd(), &localhost).unwrap();
    /// let address: Option<SockaddrIn> = getsockname(in_socket.as_raw_fd()).unwrap();
    /// let address = address.unwrap();
    /// // Get initial time
    /// let time0 = SystemTime::now();
    /// // Send the message
    /// let iov = [IoSlice::new(message)];
    /// let flags = MsgFlags::empty();
    /// let l = sendmsg(
    ///     in_socket.as_raw_fd(),
    ///     Some(&address),
    ///     &iov,
    ///     CmsgEmpty::write(),
    ///     flags,
    /// ).unwrap().bytes();
    /// assert_eq!(message.len(), l);
    /// // Receive the message
    /// let mut buffer = vec![0u8; message.len()];
    /// const CMSG_SPACE: usize = cmsg_space!(ScmTimestamp);
    /// let mut cmsg = CmsgVecRead::with_capacity(CMSG_SPACE);
    /// let mut iov = [IoSliceMut::new(&mut buffer)];
    /// let mut header = RecvMsgHeader::new();
    /// let r = recvmsg::<Option<SockaddrIn>, _>(
    ///     in_socket.as_raw_fd(),
    ///     &mut header,
    ///     &mut iov,
    ///     &mut cmsg,
    ///     flags,
    /// ).unwrap();
    /// let rtime = match r.control_messages().next() {
    ///     Some(ControlMessageOwned::ScmTimestamp(rtime)) => rtime,
    ///     Some(_) => panic!("Unexpected control message"),
    ///     None => panic!("No control message")
    /// };
    /// // Check the final time
    /// let time1 = SystemTime::now();
    /// // the packet's received timestamp should lie in-between the two system
    /// // times, unless the system clock was adjusted in the meantime.
    /// let rduration = Duration::new(rtime.tv_sec() as u64,
    ///                               rtime.tv_usec() as u32 * 1000);
    /// assert!(time0.duration_since(UNIX_EPOCH).unwrap() <= rduration);
    /// assert!(rduration <= time1.duration_since(UNIX_EPOCH).unwrap());
    /// // Close socket
    /// # }
    /// ```
    ScmTimestamp(TimeVal),
    /// A set of nanosecond resolution timestamps
    ///
    /// [Further reading](https://www.kernel.org/doc/html/latest/networking/timestamping.html)
    #[cfg(any(target_os = "android", target_os = "linux"))]
    ScmTimestampsns(Timestamps),
    /// Nanoseconds resolution timestamp
    ///
    /// [Further reading](https://www.kernel.org/doc/html/latest/networking/timestamping.html)
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    ScmTimestampns(TimeSpec),
    #[cfg(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
    ))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4PacketInfo(libc::in_pktinfo),
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "openbsd",
        target_os = "netbsd",
    ))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv6PacketInfo(libc::in6_pktinfo),
    #[cfg(any(
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4RecvIf(libc::sockaddr_dl),
    #[cfg(any(
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4RecvDstAddr(libc::in_addr),
    #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4OrigDstAddr(libc::sockaddr_in),
    #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv6OrigDstAddr(libc::sockaddr_in6),

    /// UDP Generic Receive Offload (GRO) allows receiving multiple UDP
    /// packets from a single sender.
    /// Fixed-size payloads are following one by one in a receive buffer.
    /// This Control Message indicates the size of all smaller packets,
    /// except, maybe, the last one.
    ///
    /// `UdpGroSegment` socket option should be enabled on a socket
    /// to allow receiving GRO packets.
    #[cfg(target_os = "linux")]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    UdpGroSegments(u16),

    /// SO_RXQ_OVFL indicates that an unsigned 32 bit value
    /// ancilliary msg (cmsg) should be attached to recieved
    /// skbs indicating the number of packets dropped by the
    /// socket between the last recieved packet and this
    /// received packet.
    ///
    /// `RxqOvfl` socket option should be enabled on a socket
    /// to allow receiving the drop counter.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    RxqOvfl(u32),

    /// Socket error queue control messages read with the `MSG_ERRQUEUE` flag.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4RecvErr(libc::sock_extended_err, Option<sockaddr_in>),
    /// Socket error queue control messages read with the `MSG_ERRQUEUE` flag.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv6RecvErr(libc::sock_extended_err, Option<sockaddr_in6>),

    /// Catch-all variant for unimplemented cmsg types.
    #[doc(hidden)]
    Unknown(UnknownCmsg),
}

/// For representing packet timestamps via `SO_TIMESTAMPING` interface
#[cfg(any(target_os = "android", target_os = "linux"))]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Timestamps {
    /// software based timestamp, usually one containing data
    pub system: TimeSpec,
    /// legacy timestamp, usually empty
    pub hw_trans: TimeSpec,
    /// hardware based timestamp
    pub hw_raw: TimeSpec,
}

impl ControlMessageOwned {
    /// Decodes a `ControlMessageOwned` from raw bytes.
    ///
    /// This is only safe to call if the data is correct for the message type
    /// specified in the header. Normally, the kernel ensures that this is the
    /// case. "Correct" in this case includes correct length, alignment and
    /// actual content.
    // Clippy complains about the pointer alignment of `p`, not understanding
    // that it's being fed to a function that can handle that.
    #[allow(clippy::cast_ptr_alignment)]
    unsafe fn decode_from(header: &cmsghdr) -> ControlMessageOwned
    {
        let p = CMSG_DATA(header);
        // The cast is not unnecessary on all platforms.
        #[allow(clippy::unnecessary_cast)]
        let len = header as *const _ as usize + header.cmsg_len as usize
            - p as usize;
        match (header.cmsg_level, header.cmsg_type) {
            (libc::SOL_SOCKET, libc::SCM_RIGHTS) => {
                let n = len / mem::size_of::<RawFd>();
                let mut fds = Vec::with_capacity(n);
                for i in 0..n {
                    let fdp = (p as *const RawFd).add(i);
                    fds.push(ptr::read_unaligned(fdp));
                }
                ControlMessageOwned::ScmRights(fds)
            },
            #[cfg(any(target_os = "android", target_os = "linux"))]
            (libc::SOL_SOCKET, libc::SCM_CREDENTIALS) => {
                let cred: libc::ucred = ptr::read_unaligned(p as *const _);
                ControlMessageOwned::ScmCredentials(cred.into())
            }
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            (libc::SOL_SOCKET, libc::SCM_CREDS) => {
                let cred: libc::cmsgcred = ptr::read_unaligned(p as *const _);
                ControlMessageOwned::ScmCreds(cred.into())
            }
            #[cfg(not(any(target_os = "aix", target_os = "haiku")))]
            (libc::SOL_SOCKET, libc::SCM_TIMESTAMP) => {
                let tv: libc::timeval = ptr::read_unaligned(p as *const _);
                ControlMessageOwned::ScmTimestamp(TimeVal::from(tv))
            },
            #[cfg(any(target_os = "android", target_os = "linux"))]
            (libc::SOL_SOCKET, libc::SCM_TIMESTAMPNS) => {
                let ts: libc::timespec = ptr::read_unaligned(p as *const _);
                ControlMessageOwned::ScmTimestampns(TimeSpec::from(ts))
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            (libc::SOL_SOCKET, libc::SCM_TIMESTAMPING) => {
                let tp = p as *const libc::timespec;
                let ts: libc::timespec = ptr::read_unaligned(tp);
                let system = TimeSpec::from(ts);
                let ts: libc::timespec = ptr::read_unaligned(tp.add(1));
                let hw_trans = TimeSpec::from(ts);
                let ts: libc::timespec = ptr::read_unaligned(tp.add(2));
                let hw_raw = TimeSpec::from(ts);
                let timestamping = Timestamps { system, hw_trans, hw_raw };
                ControlMessageOwned::ScmTimestampsns(timestamping)
            }
            #[cfg(any(
                target_os = "android",
                target_os = "freebsd",
                target_os = "ios",
                target_os = "linux",
                target_os = "macos"
            ))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IPV6, libc::IPV6_PKTINFO) => {
                let info = ptr::read_unaligned(p as *const libc::in6_pktinfo);
                ControlMessageOwned::Ipv6PacketInfo(info)
            }
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "linux",
                target_os = "macos",
                target_os = "netbsd",
            ))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IP, libc::IP_PKTINFO) => {
                let info = ptr::read_unaligned(p as *const libc::in_pktinfo);
                ControlMessageOwned::Ipv4PacketInfo(info)
            }
            #[cfg(any(
                target_os = "freebsd",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd",
            ))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IP, libc::IP_RECVIF) => {
                let dl = ptr::read_unaligned(p as *const libc::sockaddr_dl);
                ControlMessageOwned::Ipv4RecvIf(dl)
            },
            #[cfg(any(
                target_os = "freebsd",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd",
            ))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IP, libc::IP_RECVDSTADDR) => {
                let dl = ptr::read_unaligned(p as *const libc::in_addr);
                ControlMessageOwned::Ipv4RecvDstAddr(dl)
            },
            #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "linux"))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IP, libc::IP_ORIGDSTADDR) => {
                let dl = ptr::read_unaligned(p as *const libc::sockaddr_in);
                ControlMessageOwned::Ipv4OrigDstAddr(dl)
            },
            #[cfg(target_os = "linux")]
            #[cfg(feature = "net")]
            (libc::SOL_UDP, libc::UDP_GRO) => {
                let gso_size: u16 = ptr::read_unaligned(p as *const _);
                ControlMessageOwned::UdpGroSegments(gso_size)
            },
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            (libc::SOL_SOCKET, libc::SO_RXQ_OVFL) => {
                let drop_counter = ptr::read_unaligned(p as *const u32);
                ControlMessageOwned::RxqOvfl(drop_counter)
            },
            #[cfg(any(target_os = "android", target_os = "linux"))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IP, libc::IP_RECVERR) => {
                let (err, addr) = Self::recv_err_helper::<sockaddr_in>(p, len);
                ControlMessageOwned::Ipv4RecvErr(err, addr)
            },
            #[cfg(any(target_os = "android", target_os = "linux"))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IPV6, libc::IPV6_RECVERR) => {
                let (err, addr) = Self::recv_err_helper::<sockaddr_in6>(p, len);
                ControlMessageOwned::Ipv6RecvErr(err, addr)
            },
            #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "linux"))]
            #[cfg(feature = "net")]
            (libc::IPPROTO_IPV6, libc::IPV6_ORIGDSTADDR) => {
                let dl = ptr::read_unaligned(p as *const libc::sockaddr_in6);
                ControlMessageOwned::Ipv6OrigDstAddr(dl)
            },
            (_, _) => {
                let sl = std::slice::from_raw_parts(p, len);
                let ucmsg = UnknownCmsg(*header, Vec::<u8>::from(sl));
                ControlMessageOwned::Unknown(ucmsg)
            }
        }
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[allow(clippy::cast_ptr_alignment)]    // False positive
    unsafe fn recv_err_helper<T>(p: *mut libc::c_uchar, len: usize) -> (libc::sock_extended_err, Option<T>) {
        let ee = p as *const libc::sock_extended_err;
        let err = ptr::read_unaligned(ee);

        // For errors originating on the network, SO_EE_OFFENDER(ee) points inside the p[..len]
        // CMSG_DATA buffer.  For local errors, there is no address included in the control
        // message, and SO_EE_OFFENDER(ee) points beyond the end of the buffer.  So, we need to
        // validate that the address object is in-bounds before we attempt to copy it.
        let addrp = libc::SO_EE_OFFENDER(ee) as *const T;

        if addrp.offset(1) as usize - (p as usize) > len {
            (err, None)
        } else {
            (err, Some(ptr::read_unaligned(addrp)))
        }
    }
}

/// A type-safe zero-copy wrapper around a single control message, as used wih
/// [`sendmsg`](#fn.sendmsg).  More types may be added to this enum; do not
/// exhaustively pattern-match it.
///
/// [Further reading](https://man7.org/linux/man-pages/man3/cmsg.3.html)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ControlMessage<'a> {
    /// A message of type `SCM_RIGHTS`, containing an array of file
    /// descriptors passed between processes.
    ///
    /// See the description in the "Ancillary messages" section of the
    /// [unix(7) man page](https://man7.org/linux/man-pages/man7/unix.7.html).
    ///
    /// Using multiple `ScmRights` messages for a single `sendmsg` call isn't
    /// recommended since it causes platform-dependent behaviour: It might
    /// swallow all but the first `ScmRights` message or fail with `EINVAL`.
    /// Instead, you can put all fds to be passed into a single `ScmRights`
    /// message.
    ScmRights(&'a [RawFd]),
    /// A message of type `SCM_CREDENTIALS`, containing the pid, uid and gid of
    /// a process connected to the socket.
    ///
    /// This is similar to the socket option `SO_PEERCRED`, but requires a
    /// process to explicitly send its credentials. A process running as root is
    /// allowed to specify any credentials, while credentials sent by other
    /// processes are verified by the kernel.
    ///
    /// For further information, please refer to the
    /// [`unix(7)`](https://man7.org/linux/man-pages/man7/unix.7.html) man page.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    ScmCredentials(&'a UnixCredentials),
    /// A message of type `SCM_CREDS`, containing the pid, uid, euid, gid and groups of
    /// a process connected to the socket.
    ///
    /// This is similar to the socket options `LOCAL_CREDS` and `LOCAL_PEERCRED`, but
    /// requires a process to explicitly send its credentials.
    ///
    /// Credentials are always overwritten by the kernel, so this variant does have
    /// any data, unlike the receive-side
    /// [`ControlMessageOwned::ScmCreds`].
    ///
    /// For further information, please refer to the
    /// [`unix(4)`](https://www.freebsd.org/cgi/man.cgi?query=unix) man page.
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    ScmCreds,

    /// Set IV for `AF_ALG` crypto API.
    ///
    /// For further information, please refer to the
    /// [`documentation`](https://docs.kernel.org/crypto/userspace-if.html)
    #[cfg(any(
        target_os = "android",
        target_os = "linux",
    ))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    AlgSetIv(&'a [u8]),
    /// Set crypto operation for `AF_ALG` crypto API. It may be one of
    /// `ALG_OP_ENCRYPT` or `ALG_OP_DECRYPT`
    ///
    /// For further information, please refer to the
    /// [`documentation`](https://docs.kernel.org/crypto/userspace-if.html)
    #[cfg(any(
        target_os = "android",
        target_os = "linux",
    ))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    AlgSetOp(&'a libc::c_int),
    /// Set the length of associated authentication data (AAD) (applicable only to AEAD algorithms)
    /// for `AF_ALG` crypto API.
    ///
    /// For further information, please refer to the
    /// [`documentation`](https://docs.kernel.org/crypto/userspace-if.html)
    #[cfg(any(
        target_os = "android",
        target_os = "linux",
    ))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    AlgSetAeadAssoclen(&'a u32),

    /// UDP GSO makes it possible for applications to generate network packets
    /// for a virtual MTU much greater than the real one.
    /// The length of the send data no longer matches the expected length on
    /// the wire.
    /// The size of the datagram payload as it should appear on the wire may be
    /// passed through this control message.
    /// Send buffer should consist of multiple fixed-size wire payloads
    /// following one by one, and the last, possibly smaller one.
    #[cfg(target_os = "linux")]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    UdpGsoSegments(&'a u16),

    /// Configure the sending addressing and interface for v4.
    ///
    /// For further information, please refer to the
    /// [`ip(7)`](https://man7.org/linux/man-pages/man7/ip.7.html) man page.
    #[cfg(any(target_os = "linux",
              target_os = "macos",
              target_os = "netbsd",
              target_os = "android",
              target_os = "ios",))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4PacketInfo(&'a libc::in_pktinfo),

    /// Configure the sending addressing and interface for v6.
    ///
    /// For further information, please refer to the
    /// [`ipv6(7)`](https://man7.org/linux/man-pages/man7/ipv6.7.html) man page.
    #[cfg(any(target_os = "linux",
              target_os = "macos",
              target_os = "netbsd",
              target_os = "freebsd",
              target_os = "android",
              target_os = "ios",))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv6PacketInfo(&'a libc::in6_pktinfo),

    /// Configure the IPv4 source address with `IP_SENDSRCADDR`.
    #[cfg(any(
        target_os = "netbsd",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly",
    ))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4SendSrcAddr(&'a libc::in_addr),

    /// Configure the hop limit for v6 multicast traffic.
    ///
    /// Set the IPv6 hop limit for this message. The argument is an integer
    /// between 0 and 255. A value of -1 will set the hop limit to the route
    /// default if possible on the interface. Without this cmsg,  packets sent
    /// with sendmsg have a hop limit of 1 and will not leave the local network.
    /// For further information, please refer to the
    /// [`ipv6(7)`](https://man7.org/linux/man-pages/man7/ipv6.7.html) man page.
    #[cfg(any(target_os = "linux", target_os = "macos",
              target_os = "freebsd", target_os = "dragonfly",
              target_os = "android", target_os = "ios",
              target_os = "haiku"))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv6HopLimit(&'a libc::c_int),

    /// SO_RXQ_OVFL indicates that an unsigned 32 bit value
    /// ancilliary msg (cmsg) should be attached to recieved
    /// skbs indicating the number of packets dropped by the
    /// socket between the last recieved packet and this
    /// received packet.
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    RxqOvfl(&'a u32),

    /// Configure the transmission time of packets.
    ///
    /// For further information, please refer to the
    /// [`tc-etf(8)`](https://man7.org/linux/man-pages/man8/tc-etf.8.html) man
    /// page.
    #[cfg(target_os = "linux")]
    TxTime(&'a u64),
}

// An opaque structure used to prevent cmsghdr from being a public type
#[doc(hidden)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnknownCmsg(cmsghdr, Vec<u8>);

impl<'a> ControlMessage<'a> {
    /// The value of CMSG_SPACE on this message.
    /// Safe because CMSG_SPACE is always safe
    fn space(&self) -> usize {
        unsafe{CMSG_SPACE(self.len() as libc::c_uint) as usize}
    }

    /// The value of CMSG_LEN on this message.
    /// Safe because CMSG_LEN is always safe
    #[cfg(any(target_os = "android",
              all(target_os = "linux", not(target_env = "musl"))))]
    fn cmsg_len(&self) -> usize {
        unsafe{CMSG_LEN(self.len() as libc::c_uint) as usize}
    }

    #[cfg(not(any(target_os = "android",
                  all(target_os = "linux", not(target_env = "musl")))))]
    fn cmsg_len(&self) -> libc::c_uint {
        unsafe{CMSG_LEN(self.len() as libc::c_uint)}
    }

    /// Return a reference to the payload data as a byte pointer
    fn copy_to_cmsg_data(&self, cmsg_data: *mut u8) {
        let data_ptr = match *self {
            ControlMessage::ScmRights(fds) => {
                fds as *const _ as *const u8
            },
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::ScmCredentials(creds) => {
                &creds.0 as *const libc::ucred as *const u8
            }
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            ControlMessage::ScmCreds => {
                // The kernel overwrites the data, we just zero it
                // to make sure it's not uninitialized memory
                unsafe { ptr::write_bytes(cmsg_data, 0, self.len()) };
                return
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::AlgSetIv(iv) => {
                #[allow(deprecated)] // https://github.com/rust-lang/libc/issues/1501
                let af_alg_iv = libc::af_alg_iv {
                    ivlen: iv.len() as u32,
                    iv: [0u8; 0],
                };

                let size = mem::size_of_val(&af_alg_iv);

                unsafe {
                    ptr::copy_nonoverlapping(
                        &af_alg_iv as *const _ as *const u8,
                        cmsg_data,
                        size,
                    );
                    ptr::copy_nonoverlapping(
                        iv.as_ptr(),
                        cmsg_data.add(size),
                        iv.len()
                    );
                };

                return
            },
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::AlgSetOp(op) => {
                op as *const _ as *const u8
            },
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::AlgSetAeadAssoclen(len) => {
                len as *const _ as *const u8
            },
            #[cfg(target_os = "linux")]
            #[cfg(feature = "net")]
            ControlMessage::UdpGsoSegments(gso_size) => {
                gso_size as *const _ as *const u8
            },
            #[cfg(any(target_os = "linux", target_os = "macos",
                      target_os = "netbsd", target_os = "android",
                      target_os = "ios",))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv4PacketInfo(info) => info as *const _ as *const u8,
            #[cfg(any(target_os = "linux", target_os = "macos",
                      target_os = "netbsd", target_os = "freebsd",
                      target_os = "android", target_os = "ios",))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv6PacketInfo(info) => info as *const _ as *const u8,
            #[cfg(any(target_os = "netbsd", target_os = "freebsd",
                      target_os = "openbsd", target_os = "dragonfly"))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv4SendSrcAddr(addr) => addr as *const _ as *const u8,
            #[cfg(any(target_os = "linux", target_os = "macos",
                      target_os = "freebsd", target_os = "dragonfly",
                      target_os = "android", target_os = "ios",
                      target_os = "haiku"))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv6HopLimit(limit) => limit as *const _ as *const u8,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            ControlMessage::RxqOvfl(drop_count) => {
                drop_count as *const _ as *const u8
            },
            #[cfg(target_os = "linux")]
            ControlMessage::TxTime(tx_time) => {
                tx_time as *const _ as *const u8
            },
        };
        unsafe {
            ptr::copy_nonoverlapping(
                data_ptr,
                cmsg_data,
                self.len()
            )
        };
    }

    /// The size of the payload, excluding its cmsghdr
    fn len(&self) -> usize {
        match *self {
            ControlMessage::ScmRights(fds) => {
                mem::size_of_val(fds)
            },
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::ScmCredentials(creds) => {
                mem::size_of_val(creds)
            }
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            ControlMessage::ScmCreds => {
                mem::size_of::<libc::cmsgcred>()
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::AlgSetIv(iv) => {
                mem::size_of::<&[u8]>() + iv.len()
            },
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::AlgSetOp(op) => {
                mem::size_of_val(op)
            },
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::AlgSetAeadAssoclen(len) => {
                mem::size_of_val(len)
            },
            #[cfg(target_os = "linux")]
            #[cfg(feature = "net")]
            ControlMessage::UdpGsoSegments(gso_size) => {
                mem::size_of_val(gso_size)
            },
            #[cfg(any(target_os = "linux", target_os = "macos",
              target_os = "netbsd", target_os = "android",
              target_os = "ios",))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv4PacketInfo(info) => mem::size_of_val(info),
            #[cfg(any(target_os = "linux", target_os = "macos",
              target_os = "netbsd", target_os = "freebsd",
              target_os = "android", target_os = "ios",))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv6PacketInfo(info) => mem::size_of_val(info),
            #[cfg(any(target_os = "netbsd", target_os = "freebsd",
                      target_os = "openbsd", target_os = "dragonfly"))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv4SendSrcAddr(addr) => mem::size_of_val(addr),
            #[cfg(any(target_os = "linux", target_os = "macos",
                      target_os = "freebsd", target_os = "dragonfly",
                      target_os = "android", target_os = "ios",
                      target_os = "haiku"))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv6HopLimit(limit) => {
                mem::size_of_val(limit)
            },
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            ControlMessage::RxqOvfl(drop_count) => {
                mem::size_of_val(drop_count)
            },
            #[cfg(target_os = "linux")]
            ControlMessage::TxTime(tx_time) => {
                mem::size_of_val(tx_time)
            },
        }
    }

    /// Returns the value to put into the `cmsg_level` field of the header.
    fn cmsg_level(&self) -> libc::c_int {
        match *self {
            ControlMessage::ScmRights(_) => libc::SOL_SOCKET,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::ScmCredentials(_) => libc::SOL_SOCKET,
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            ControlMessage::ScmCreds => libc::SOL_SOCKET,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::AlgSetIv(_) | ControlMessage::AlgSetOp(_) |
                ControlMessage::AlgSetAeadAssoclen(_) => libc::SOL_ALG,
            #[cfg(target_os = "linux")]
            #[cfg(feature = "net")]
            ControlMessage::UdpGsoSegments(_) => libc::SOL_UDP,
            #[cfg(any(target_os = "linux", target_os = "macos",
                      target_os = "netbsd", target_os = "android",
                      target_os = "ios",))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv4PacketInfo(_) => libc::IPPROTO_IP,
            #[cfg(any(target_os = "linux", target_os = "macos",
              target_os = "netbsd", target_os = "freebsd",
              target_os = "android", target_os = "ios",))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv6PacketInfo(_) => libc::IPPROTO_IPV6,
            #[cfg(any(target_os = "netbsd", target_os = "freebsd",
                      target_os = "openbsd", target_os = "dragonfly"))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv4SendSrcAddr(_) => libc::IPPROTO_IP,
            #[cfg(any(target_os = "linux", target_os = "macos",
                      target_os = "freebsd", target_os = "dragonfly",
                      target_os = "android", target_os = "ios",
                      target_os = "haiku"))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv6HopLimit(_) => libc::IPPROTO_IPV6,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            ControlMessage::RxqOvfl(_) => libc::SOL_SOCKET,
            #[cfg(target_os = "linux")]
            ControlMessage::TxTime(_) => libc::SOL_SOCKET,
        }
    }

    /// Returns the value to put into the `cmsg_type` field of the header.
    fn cmsg_type(&self) -> libc::c_int {
        match *self {
            ControlMessage::ScmRights(_) => libc::SCM_RIGHTS,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::ScmCredentials(_) => libc::SCM_CREDENTIALS,
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            ControlMessage::ScmCreds => libc::SCM_CREDS,
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::AlgSetIv(_) => {
                libc::ALG_SET_IV
            },
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::AlgSetOp(_) => {
                libc::ALG_SET_OP
            },
            #[cfg(any(target_os = "android", target_os = "linux"))]
            ControlMessage::AlgSetAeadAssoclen(_) => {
                libc::ALG_SET_AEAD_ASSOCLEN
            },
            #[cfg(target_os = "linux")]
            #[cfg(feature = "net")]
            ControlMessage::UdpGsoSegments(_) => {
                libc::UDP_SEGMENT
            },
            #[cfg(any(target_os = "linux", target_os = "macos",
                      target_os = "netbsd", target_os = "android",
                      target_os = "ios",))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv4PacketInfo(_) => libc::IP_PKTINFO,
            #[cfg(any(target_os = "linux", target_os = "macos",
                      target_os = "netbsd", target_os = "freebsd",
                      target_os = "android", target_os = "ios",))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv6PacketInfo(_) => libc::IPV6_PKTINFO,
            #[cfg(any(target_os = "netbsd", target_os = "freebsd",
                      target_os = "openbsd", target_os = "dragonfly"))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv4SendSrcAddr(_) => libc::IP_SENDSRCADDR,
            #[cfg(any(target_os = "linux", target_os = "macos",
                      target_os = "freebsd", target_os = "dragonfly",
                      target_os = "android", target_os = "ios",
                      target_os = "haiku"))]
            #[cfg(feature = "net")]
            ControlMessage::Ipv6HopLimit(_) => libc::IPV6_HOPLIMIT,
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            ControlMessage::RxqOvfl(_) => {
                libc::SO_RXQ_OVFL
            },
            #[cfg(target_os = "linux")]
            ControlMessage::TxTime(_) => {
                libc::SCM_TXTIME
            },
        }
    }

    // Unsafe: cmsg must point to a valid cmsghdr with enough space to
    // encode self.
    unsafe fn encode_into(&self, cmsg: *mut cmsghdr) {
        (*cmsg).cmsg_level = self.cmsg_level();
        (*cmsg).cmsg_type = self.cmsg_type();
        (*cmsg).cmsg_len = self.cmsg_len();
        self.copy_to_cmsg_data(CMSG_DATA(cmsg));
    }
}

/// Variants to be used with [`cmsg_space!`].
///
/// You shouldn't need to use this type directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ControlMessageOwnedSpace {
    /// See [`ControlMessageOwned::ScmRights`].
    ///
    /// Argument is the number of file descriptors.
    ScmRights(usize),
    /// See [`ControlMessageOwned::ScmCredentials`].
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    ScmCredentials,
    /// See [`ControlMessageOwned::ScmCreds`].
    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    ScmCreds,
    /// See [`ControlMessageOwned::ScmTimestamp`].
    ScmTimestamp,
    /// See [`ControlMessageOwned::ScmTimestampns`].
    #[cfg(any(target_os = "android", target_os = "linux"))]
    ScmTimestampsns,
    /// See [`ControlMessageOwned::ScmTimestampns`].
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    ScmTimestampns,
    /// See [`ControlMessageOwned::Ipv4PacketInfo`].
    #[cfg(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
    ))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4PacketInfo,
    /// See [`ControlMessageOwned::Ipv6PacketInfo`].
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "openbsd",
        target_os = "netbsd",
    ))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv6PacketInfo,
    /// See [`ControlMessageOwned::Ipv4RecvIf`].
    #[cfg(any(
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4RecvIf,
    /// See [`ControlMessageOwned::Ipv4RecvDstAddr`].
    #[cfg(any(
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4RecvDstAddr,
    /// See [`ControlMessageOwned::Ipv4OrigDstAddr`].
    #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4OrigDstAddr,
    /// See [`ControlMessageOwned::Ipv6OrigDstAddr`].
    #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv6OrigDstAddr,
    /// See [`ControlMessageOwned::UdpGroSegments`].
    #[cfg(target_os = "linux")]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    UdpGroSegments,
    /// See [`ControlMessageOwned::RxqOvfl`].
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    RxqOvfl,
    /// See [`ControlMessageOwned::Ipv4RecvErr`].
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv4RecvErr,
    /// See [`ControlMessageOwned::Ipv6RecvErr`].
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg(feature = "net")]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    Ipv6RecvErr,
}

impl ControlMessageOwnedSpace {
    const fn len(self) -> usize {
        match self {
            Self::ScmRights(n) => n * mem::size_of::<RawFd>(),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Self::ScmCredentials => mem::size_of::<UnixCredentials>(),
            #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
            Self::ScmCreds => mem::size_of::<UnixCredentials>(),
            Self::ScmTimestamp => mem::size_of::<TimeVal>(),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Self::ScmTimestampsns => mem::size_of::<Timestamps>(),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Self::ScmTimestampns => mem::size_of::<TimeSpec>(),
            #[cfg(any(
                target_os = "android",
                target_os = "ios",
                target_os = "linux",
                target_os = "macos",
                target_os = "netbsd",
            ))]
            #[cfg(feature = "net")]
            Self::Ipv4PacketInfo => mem::size_of::<libc::in_pktinfo>(),
            #[cfg(any(
                target_os = "android",
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "ios",
                target_os = "linux",
                target_os = "macos",
                target_os = "openbsd",
                target_os = "netbsd",
            ))]
            #[cfg(feature = "net")]
            Self::Ipv6PacketInfo => mem::size_of::<libc::in6_pktinfo>(),
            #[cfg(any(
                target_os = "freebsd",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd",
            ))]
            #[cfg(feature = "net")]
            Self::Ipv4RecvIf => mem::size_of::<libc::sockaddr_dl>(),
            #[cfg(any(
                target_os = "freebsd",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd",
            ))]
            #[cfg(feature = "net")]
            Self::Ipv4RecvDstAddr => mem::size_of::<libc::in_addr>(),
            #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "linux"))]
            #[cfg(feature = "net")]
            Self::Ipv4OrigDstAddr => mem::size_of::<libc::sockaddr_in>(),
            #[cfg(any(target_os = "android", target_os = "freebsd", target_os = "linux"))]
            #[cfg(feature = "net")]
            Self::Ipv6OrigDstAddr => mem::size_of::<libc::sockaddr_in6>(),
            #[cfg(target_os = "linux")]
            #[cfg(feature = "net")]
            Self::UdpGroSegments => mem::size_of::<u16>(),
            #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
            Self::RxqOvfl => mem::size_of::<u32>(),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            #[cfg(feature = "net")]
            Self::Ipv4RecvErr => {
                mem::size_of::<libc::sock_extended_err>() + mem::size_of::<libc::sockaddr_in>()
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            #[cfg(feature = "net")]
            Self::Ipv6RecvErr => {
                mem::size_of::<libc::sock_extended_err>() + mem::size_of::<libc::sockaddr_in6>()
            }
        }
    }

    #[doc(hidden)]
    pub const fn space(self) -> usize {
        // SAFETY: CMSG_SPACE has no sideeffects and is always safe.
        unsafe { CMSG_SPACE(self.len() as libc::c_uint) as usize }
    }
}

/// Sends a message through a connection-mode or connectionless-mode socket.
///
/// If the socket is a connectionless-mode socket, the message will *usually* be sent
/// to the address passed in `addr`. Click [here] for more information.
///
/// If the socket is connection-mode, `addr` will be ignored. In that case, using
/// [`NoAddress`] for `S` is recommended.
///
/// Additionally to [`sendto`], it also allows to send control messages.
///
/// [Further reading]
///
/// # Examples
///
/// See [`recvmsg`] for an example using both functions.
///
/// [here]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendmsg.html
/// [Further reading]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendmsg.html
pub fn sendmsg<'a, S, I, C>(
    fd: RawFd,
    addr: Option<&S>,
    iov: &I,
    cmsgs: &C,
    flags: MsgFlags,
) -> Result<SendMsgResult>
where
    S: SockaddrLike,
    I: AsRef<[IoSlice<'a>]>,
    C: CmsgBufWrite + ?Sized,
{
    let header = sendmsg_header(addr, iov.as_ref(), cmsgs);

    let ret = unsafe { libc::sendmsg(fd, &header, flags.bits()) };

    let bytes = Errno::result(ret).map(|x| x as usize)?;

    Ok(SendMsgResult { bytes })
}

/// Receives a message from a connection-mode or connectionless-mode socket.
///
/// It is normally used with connectionless-mode sockets because it permits the application to
/// retrieve the source address of received data.
///
/// Additionally to [`recvfrom`], it also allows to receive control messages.
///
/// [Further reading]
///
/// # Examples
///
/// The following example runs on Linux and Android only.
///
#[cfg_attr(any(target_os = "linux", target_os = "android"), doc = "```")]
#[cfg_attr(not(any(target_os = "linux", target_os = "android")), doc = "```ignore")]
/// # use nix::sys::socket::*;
/// # use nix::cmsg_vec;
/// # use nix::sys::socket::sockopt::Timestamping;
/// # use std::os::fd::AsRawFd;
/// # use std::io::{IoSlice, IoSliceMut};
/// // We use connectionless UDP sockets.
/// let send = socket(
///     AddressFamily::INET,
///     SockType::Datagram,
///     SockFlag::empty(),
///     Some(SockProtocol::Udp),
/// )?;
///
/// let recv = socket(
///     AddressFamily::INET,
///     SockType::Datagram,
///     SockFlag::empty(),
///     Some(SockProtocol::Udp),
/// )?;
///
/// // We enable timestamping on the receiving socket. They will be sent as
/// // control messages by the kernel.
/// setsockopt(&recv, Timestamping, &TimestampingFlag::all())?;
///
/// // This is the address we are going to send the message.
/// let addr = "127.0.0.1:6069".parse::<SockaddrIn>().unwrap();
///
/// bind(recv.as_raw_fd(), &addr)?;
///
/// // The message we are trying to send: [0, 1, 2, ...].
/// let msg: [u8; 1500] = std::array::from_fn(|i| i as u8);
///
/// // Send `msg` on `send` without control messages.
/// //
/// // On connectionless sockets like UDP, the destination address is required.
/// // On connection-oriented sockets like TCP, `addr` would be ignored
/// // and `None` is usually passed instead.
/// let send_res = sendmsg(
///     send.as_raw_fd(),
///     Some(&addr),
///     &[IoSlice::new(&msg)],
///     CmsgEmpty::write(),
///     MsgFlags::empty(),
/// )?;
///
/// // We have actually sent 1500 bytes.
/// assert_eq!(send_res.bytes(), 1500);
///
/// // Initialize a buffer to receive `msg`.
/// let mut buf = [0u8; 1500];
///
/// // The timestamps will land here. The control message type is `ScmTimestampsns`.
/// let mut cmsg = cmsg_vec![ScmTimestampsns];
///
/// // Initialize the container for the `recvmsg`-header.
/// let mut header = RecvMsgHeader::<Option<SockaddrIn>>::new();
///
/// // Receive `msg` on `recv`.
/// let recv_res = recvmsg(
///     recv.as_raw_fd(),
///     &mut header,
///     &mut [IoSliceMut::new(&mut buf)],
///     &mut cmsg,
///     MsgFlags::empty(),
/// )?;
///
/// // We have actually received 1500 bytes.
/// assert_eq!(recv_res.bytes(), 1500);
///
/// // Since this is a connectionless socket, the sender address is returned.
/// // On connection-oriented sockets like TCP, this would be `None`.
/// assert!(recv_res.address().is_some());
///
/// // The received message is identical to the sent one.
/// assert_eq!(buf, msg);
///
/// // We have received a control message containing a timestamp.
/// assert!(matches!(
///     recv_res.control_messages().next(),
///     Some(ControlMessageOwned::ScmTimestampsns(_)),
/// ));
/// # Ok::<(), nix::Error>(())
/// ```
///
/// [Further reading]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvmsg.html
pub fn recvmsg<'a, S, C>(
    fd: RawFd,
    header: &'a mut RecvMsgHeader<S>,
    iov: &mut [IoSliceMut<'_>],
    cmsg_buffer: &'a mut C,
    flags: MsgFlags,
) -> Result<RecvMsgResult<'a, S>>
where
    S: SockaddrFromRaw,
    C: CmsgBufRead + ?Sized,
{
    header.fill_recv(iov, cmsg_buffer);

    let ret = unsafe { libc::recvmsg(fd, header.msg_hdr.as_mut_ptr(), flags.bits()) };

    let bytes = Errno::result(ret).map(|x| x as usize)?;

    let hdr = unsafe { header.msg_hdr.assume_init() };

    Ok(RecvMsgResult { bytes, hdr, _phantom: std::marker::PhantomData })
}

/// Buffer for sending control messages.
///
/// # Safety
///
/// [`Self::raw_parts`] must return a pointer and length `len`, such that
/// if `len > 0`, the pointer must be valid for reads and point to a contiguous buffer with
/// `len` bytes, which contains properly aligned control messages.
///
/// See the libc manual of [`cmsg`] for more information.
///
/// [`cmsg`]: https://www.man7.org/linux/man-pages/man3/cmsg.3.html
pub unsafe trait CmsgBufWrite {
    /// Returns a pointer and length to the buffer containing control messages.
    ///
    /// If the buffer is empty, the pointer can be dangling or null.
    fn raw_parts(&self) -> (*const u8, usize);
}

unsafe impl<'a, T> CmsgBufWrite for &'a T
where
    T: CmsgBufWrite,
{
    fn raw_parts(&self) -> (*const u8, usize) {
        (*self).raw_parts()
    }
}

/// Buffer for receiving control messages.
///
/// # Safety
///
/// [`Self::raw_parts_mut`] must return a pointer and capacity `cap`, such that
/// if `cap > 0`, the pointer must be valid for writes
/// and point to a contiguous buffer with at least `cap` bytes.
///
/// See the libc manual of [`cmsg`] for more information.
///
/// [`cmsg`]: https://www.man7.org/linux/man-pages/man3/cmsg.3.html
pub unsafe trait CmsgBufRead {
    /// Returns a pointer and capacity of the buffer for receiving control messages.
    ///
    /// If the buffer is empty, the pointer can be dangling or null.
    fn raw_parts_mut(&mut self) -> (*mut u8, usize);
}

unsafe impl<'a, T> CmsgBufRead for &'a mut T
where
    T: CmsgBufRead,
{
    fn raw_parts_mut(&mut self) -> (*mut u8, usize) {
        (*self).raw_parts_mut()
    }
}

/// Writes the given control messages into the given buffer.
///
/// Buffers are zero-initialized before writing. If the buffer is already zero-initialized,
/// consider using [`write_cmsg_into_unchecked`] instead.
///
/// Returns the number of bytes written into the buffer. If the buffer was too small,
/// the first control message that didn't fit in is returned additionally.
pub fn write_cmsg_into<'a, I>(
    buf: &mut [u8],
    cmsg: I,
) -> std::result::Result<usize, (usize, ControlMessage<'a>)>
where
    I: IntoIterator<Item = ControlMessage<'a>>,
{
    buf.iter_mut().for_each(|b| *b = 0);

    // SAFETY: `buf` has been zero-initialized.
    unsafe {
        write_cmsg_into_unchecked(buf, cmsg)
    }
}

/// Writes the given control messages into the given buffer.
///
/// Returns the number of bytes written into the buffer. If the buffer was too small,
/// the first control message that didn't fit in is returned additionally.
///
/// # Safety
///
/// `buf` must be zero-initialized before calling this function.
pub unsafe fn write_cmsg_into_unchecked<'a, I>(
    buf: &mut [u8],
    cmsg: I,
) -> std::result::Result<usize, (usize, ControlMessage<'a>)>
where
    I: IntoIterator<Item = ControlMessage<'a>>,
{
    let mut mhdr = cmsg_dummy_mhdr(buf.as_mut_ptr(), buf.len());

    // SAFETY: call to extern function without sideeffects. We need to start from a mutable
    // reference before casting it to a `*const` as we want to use the resulting pointer mutably.
    let mut cmsg_ptr = unsafe { CMSG_FIRSTHDR(mhdr.as_mut_ptr().cast_const()) };

    let mut written = 0;

    let mut cmsg = cmsg.into_iter();

    for c in cmsg.by_ref() {
        if cmsg_ptr.is_null() || c.space() > buf.len() - written {
            return Err((written, c));
        }

        written += c.space();

        // SAFETY: we checked that there is enough space in `buf`.
        // Additionally, relies on `CMSG_FIRSTHDR` and `CMSG_NXTHDR` for safety.
        // `CMSG_FIRSTHDR` and `CMSG_NXTHDR` shouldn't care about the other
        // uninitialized fields of `mhdr`.
        //
        // See https://man7.org/linux/man-pages/man3/cmsg.3.html.
        unsafe {
            c.encode_into(cmsg_ptr.cast());
        }

        // SAFETY: call to extern function without sideeffects. We need to start from a mutable
        // reference before casting it to a `*const` as we want to use the resulting pointer mutably.
        cmsg_ptr = unsafe { CMSG_NXTHDR(mhdr.as_mut_ptr().cast_const(), cmsg_ptr) };
    }

    Ok(written)
}

// FIXME: make `const` once possible in stable rust. Last checked: 1.73.0.
fn cmsg_dummy_mhdr(buf: *mut u8, len: usize) -> MaybeUninit<libc::msghdr> {
    let mut mhdr = MaybeUninit::<libc::msghdr>::zeroed();

    // SAFETY: using `ptr::write` to not drop the old uninitialized value and `addr_of_mut`
    // to not create references of `libc::msghdr` along the way.
    unsafe {
        addr_of_mut!((*mhdr.as_mut_ptr()).msg_control).write(buf.cast());
        addr_of_mut!((*mhdr.as_mut_ptr()).msg_controllen).write(len as _);
    }

    mhdr
}

/// Returns the exact number of bytes required to hold the given control messages.
pub fn cmsg_space_iter<'a, I>(cmsg: I) -> usize
where
    I: IntoIterator<Item = ControlMessage<'a>>,
{
    cmsg.into_iter().map(|c| c.space()).sum()
}

/// Non-extendable heap-allocated container for sending control messages.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CmsgVecWrite {
    inner: Vec<u8>,
}

impl CmsgVecWrite {
    /// Returns an empty [`CmsgVecWrite`].
    ///
    /// No allocations are performed. Use this if no control messages are needed.
    pub const fn empty() -> Self {
        Self { inner: Vec::new() }
    }

    /// Returns an empty [`CmsgVecWrite`] with the given capacity.
    pub fn with_capacity(cap: usize) -> Self {
        Self { inner: Vec::with_capacity(cap) }
    }

    /// Allocates a buffer that contains the given control messages.
    ///
    /// The `size` parameter determines the size of the allocation in bytes.
    /// [`cmsg_space_iter`] can be used to calculate the exact number of bytes required to
    /// hold the control messages.
    ///
    /// If `size` is too small, the first control message that didn't fit in is returned additionally.
    pub fn from_iter<'a, I>(
        cmsg: I,
        size: usize,
    ) -> std::result::Result<Self, (Self, ControlMessage<'a>)>
    where
        I: IntoIterator<Item = ControlMessage<'a>>,
    {
        let mut cmsg_buf = vec![0; size];

        // SAFETY: `cmsg_buf` is zero-initialized.
        match unsafe { write_cmsg_into_unchecked(&mut cmsg_buf, cmsg) } {
            Ok(written) => {
                cmsg_buf.truncate(written);

                Ok(Self {
                    inner: cmsg_buf,
                })
            }
            Err((written, i)) => {
                cmsg_buf.truncate(written);

                Err((
                    Self {
                        inner: cmsg_buf,
                    },
                    i,
                ))
            }
        }
    }

    /// Allocates a buffer that contains the given control messages.
    ///
    /// This is a shorthand for calling [`cmsg_space_iter`] with the cloned iterator,
    /// followed by [`Self::from_iter`].
    pub fn from_iter_clone<'a, I>(cmsg: I) -> Self
    where
        I: IntoIterator<Item = ControlMessage<'a>>,
        I::IntoIter: Clone,
    {
        let cmsg = cmsg.into_iter();

        let len = cmsg_space_iter(cmsg.clone());

        Self::from_iter(cmsg, len).unwrap()
    }

    /// Writes the given control messages into the buffer, replacing the previous contents.
    ///
    /// The `size` parameter determines the minimum size of the allocation in bytes, but the internal
    /// storage might allocate more. [`cmsg_space_iter`] can be used to calculate the exact number of
    /// bytes required to hold the control messages.
    ///
    /// If `size` is too small, the first control message that didn't fit in is returned additionally.
    ///
    /// This function does not allocate if `size` is smaller than the current capacity.
    pub fn write_iter<'a, I>(
        &mut self,
        cmsg: I,
        size: usize,
    ) -> std::result::Result<(), ControlMessage<'a>>
    where
        I: IntoIterator<Item = ControlMessage<'a>>,
    {
        self.inner.clear();
        self.inner.reserve(size);

        (0..size).for_each(|_| self.inner.push(0));

        match unsafe { write_cmsg_into_unchecked(&mut self.inner, cmsg) } {
            Ok(written) => {
                self.inner.truncate(written);

                Ok(())
            }
            Err((written, i)) => {
                self.inner.truncate(written);

                Err(i)
            }
        }
    }

    /// Writes the given control messages into the buffer, replacing the previous contents.
    ///
    /// This is a shorthand for calling [`cmsg_space_iter`] with the cloned iterator,
    /// followed by [`Self::write_iter`].
    ///
    /// This function does not allocate if the calculated size is smaller than the current capacity.
    pub fn write_iter_clone<'a, I>(&mut self, cmsg: I)
    where
        I: IntoIterator<Item = ControlMessage<'a>>,
        I::IntoIter: Clone,
    {
        let cmsg = cmsg.into_iter();

        let len = cmsg_space_iter(cmsg.clone());

        self.write_iter(cmsg, len).unwrap();
    }

    /// Writes the given control messages into the buffer, replacing the previous contents.
    ///
    /// This function does not allocate. If the current allocation can't hold all control messages,
    /// the first control message that didn't fit in is returned additionally.
    pub fn write_iter_in_place<'a, I>(&mut self, cmsg: I) -> std::result::Result<(), ControlMessage<'a>>
    where
        I: IntoIterator<Item = ControlMessage<'a>>,
    {
        self.write_iter(cmsg, self.inner.capacity())
    }

    /// Returns the length of the buffer.
    ///
    /// This is number of bytes that contain valid control messages.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the buffer contains no control messages.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the capacity of the buffer.
    ///
    /// This is the number of bytes that can be written to the buffer.
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Clears the buffer, removing all control messages.
    pub fn clear(&mut self) {
        self.inner.clear();
    }

    /// Reserves extra capacity for the buffer.
    ///
    /// The buffer will be able to hold at least `additional` more bytes
    /// than its current length.
    /// If there is already sufficient space, nothing happens.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX`.
    pub fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional);
    }

    /// Shrinks the capacity of the buffer to at least the maximum of its length
    /// and the given minimum capacity.
    pub fn shrink_to(&mut self, min_capacity: usize) {
        self.inner.shrink_to(min_capacity);
    }

    /// Shrinks the capacity of the buffer as close as possible to its length.
    pub fn shrink_to_fit(&mut self) {
        self.inner.shrink_to_fit();
    }

    /// Returns a pointer and length to the buffer containing control messages.
    fn raw_parts(&self) -> (*const u8, usize) {
        (self.inner.as_ptr(), self.inner.len())
    }
}

// SAFETY: `self.0` contains valid control messages until its length.
unsafe impl CmsgBufWrite for CmsgVecWrite {
    fn raw_parts(&self) -> (*const u8, usize) {
        self.raw_parts()
    }
}

/// Heap-allocated container for receiving control messages.
#[derive(Debug, Default)]
pub struct CmsgVecRead {
    inner: Vec<MaybeUninit<u8>>,
}

impl CmsgVecRead {
    /// Returns an empty [`CmsgVecRead`].
    ///
    /// No allocations are performed. Use this if no control messages are needed.
    pub const fn empty() -> Self {
        Self {
            inner: Vec::new(),
        }
    }

    /// Returns an empty [`CmsgVecRead`] with the given capacity.
    ///
    /// [`cmsg_space!`] can be used to calculate the exact number of bytes required
    /// to hold the received control messages.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            inner: Vec::with_capacity(cap),
        }
    }

    /// Returns the capacity of the buffer.
    ///
    /// This is the number of bytes that can be written to the buffer.
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    /// Reserves extra capacity for the buffer.
    ///
    /// The buffer will be able to hold at least `total` bytes.
    /// If the current capacity is larger than `total`, nothing happens.
    ///
    /// # Panics
    ///
    /// Panics if the new capacity exceeds `isize::MAX`.
    pub fn reserve_total(&mut self, total: usize) {
        self.inner.reserve(total);
    }

    /// Shrinks the capacity of the buffer to at least the given minimum capacity.
    pub fn shrink_to(&mut self, min_capacity: usize) {
        self.inner.shrink_to(min_capacity);
    }

    /// Returns a pointer and capacity of the allocation that can hold control messages.
    fn raw_parts_mut(&mut self) -> (*mut u8, usize) {
        (self.inner.as_mut_ptr().cast(), self.inner.capacity())
    }
}

/// Creates a new [`CmsgVecRead`] with the same capacity as `self`.
impl Clone for CmsgVecRead {
    fn clone(&self) -> Self {
        Self {
            inner: Vec::with_capacity(self.inner.capacity()),
        }
    }
}

// SAFETY: we delegate to a `Vec` with byte-sized elements,
// so the pointer points to an allocation if the returned capacity is non-zero.
unsafe impl CmsgBufRead for CmsgVecRead {
    fn raw_parts_mut(&mut self) -> (*mut u8, usize) {
        self.raw_parts_mut()
    }
}

/// Empy control message buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CmsgEmpty;

impl CmsgEmpty {
    /// Returns a reference to an empty control message buffer that
    /// implements [`CmsgBufWrite`].
    ///
    /// Useful for sending messages without control messages.
    pub fn write() -> &'static Self {
        // SAFETY: `CMSG_EMPTY` is zero-sized and doesn't
        // serve as a singleton protecting any observable state
        // of the program.
        unsafe { ptr::NonNull::dangling().as_ref() }
    }

    /// Returns a mutable reference to an empty control message buffer that
    /// implements [`CmsgBufRead`].
    ///
    /// Useful for receiving messages without control messages.
    pub fn read() -> &'static mut Self {
        // SAFETY: `CMSG_EMPTY` is zero-sized and doesn't
        // serve as a singleton protecting any observable state
        // of the program.
        unsafe { ptr::NonNull::dangling().as_mut() }
    }
}

// SAFETY: returning length 0 is always safe.
unsafe impl CmsgBufWrite for CmsgEmpty {
    fn raw_parts(&self) -> (*const u8, usize) {
        (ptr::null(), 0)
    }
}

// SAFETY: returning capacity 0 is always safe.
unsafe impl CmsgBufRead for CmsgEmpty {
    fn raw_parts_mut(&mut self) -> (*mut u8, usize) {
        (ptr::null_mut(), 0)
    }
}

fn sendmsg_header<S, C>(
    addr: Option<&S>,
    iov: &[IoSlice<'_>],
    cmsg: &C,
) -> libc::msghdr
where
    S: SockaddrLike,
    C: CmsgBufWrite + ?Sized,
{
    let (addr_ptr, addr_len) = addr.map_or((ptr::null(), 0), |a| (a.as_sockaddr(), a.len()));
    let (iov_ptr, iov_len) = (iov.as_ptr(), iov.len());
    let (cmsg_ptr, cmsg_len) = cmsg.raw_parts();

    let mut msg_hdr = MaybeUninit::<libc::msghdr>::zeroed();
    let msg_hdr_ptr = msg_hdr.as_mut_ptr();

    unsafe {
        addr_of_mut!((*msg_hdr_ptr).msg_name).write(addr_ptr.cast_mut().cast());
        addr_of_mut!((*msg_hdr_ptr).msg_namelen).write(addr_len as _);
        addr_of_mut!((*msg_hdr_ptr).msg_iov).write(iov_ptr.cast_mut().cast());
        addr_of_mut!((*msg_hdr_ptr).msg_iovlen).write(iov_len as _);
        addr_of_mut!((*msg_hdr_ptr).msg_control).write(cmsg_ptr.cast_mut().cast());
        addr_of_mut!((*msg_hdr_ptr).msg_controllen).write(cmsg_len as _);
    }

    unsafe { msg_hdr.assume_init() }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
fn sendmmsg_headers_into<'a, I, S, C>(
    buf: &mut [MaybeUninit<libc::mmsghdr>],
    items: I,
) -> usize
where
    I: Iterator<Item = (Option<&'a S>, &'a [IoSlice<'a>], &'a C)>,
    S: SockaddrLike + 'a,
    C: CmsgBufWrite + ?Sized + 'a,
{
    let mut total = 0;

    for (i, (addr, iov, cmsg)) in items.take(buf.len()).enumerate() {
        let mmsg_hdr = libc::mmsghdr {
            msg_hdr: sendmsg_header(addr, iov, cmsg),
            msg_len: 0,
        };

        buf[i].write(mmsg_hdr);

        total = i + 1;
    }

    total
}

fn recvmsg_header<S, C>(
    addr: &mut MaybeUninit<S::Storage>,
    iov: &mut [IoSliceMut<'_>],
    cmsg: &mut C,
) -> libc::msghdr
where
    S: SockaddrFromRaw,
    C: CmsgBufRead + ?Sized,
{
    let (iov_ptr, iov_len) = (iov.as_mut().as_mut_ptr(), iov.as_mut().len());
    let (cmsg_ptr, cmsg_len) = cmsg.raw_parts_mut();

    let mut msg_hdr = MaybeUninit::<libc::msghdr>::zeroed();
    let msg_hdr_ptr = msg_hdr.as_mut_ptr();

    S::init_storage(addr);

    unsafe {
        addr_of_mut!((*msg_hdr_ptr).msg_name).write(addr.as_mut_ptr().cast());
        addr_of_mut!((*msg_hdr_ptr).msg_namelen).write(std::mem::size_of::<S::Storage>() as _);
        addr_of_mut!((*msg_hdr_ptr).msg_iov).write(iov_ptr.cast());
        addr_of_mut!((*msg_hdr_ptr).msg_iovlen).write(iov_len as _);
        addr_of_mut!((*msg_hdr_ptr).msg_control).write(cmsg_ptr.cast());
        addr_of_mut!((*msg_hdr_ptr).msg_controllen).write(cmsg_len as _);
    }

    unsafe { msg_hdr.assume_init() }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
fn recvmmsg_headers_into<'a, 'b, S, I, C>(
    buf: &mut [MaybeUninit<libc::mmsghdr>],
    addrs: &mut [MaybeUninit<S::Storage>],
    items: I,
) -> usize
where
    'b: 'a,
    S: SockaddrFromRaw,
    I: Iterator<Item = (&'a mut [IoSliceMut<'b>], &'a mut C)>,
    C: CmsgBufRead + ?Sized + 'a,
{
    debug_assert_eq!(addrs.len(), buf.len());

    let mut total = 0;

    for (i, (iov, cmsg)) in items.take(buf.len()).enumerate() {
        let mmsg_hdr = libc::mmsghdr {
            msg_hdr: recvmsg_header::<S, _>(&mut addrs[i], iov, cmsg),
            msg_len: 0,
        };

        buf[i].write(mmsg_hdr);

        total = i + 1;
    }

    total
}

/// Growable container holding the headers for [`sendmmsg`].
///
/// This allocation can be reused when calling [`sendmmsg`] multiple times,
/// which can be beneficial for performance.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
#[derive(Debug, Clone, Default)]
pub struct SendMmsgHeaders {
    mmsghdrs: Vec<libc::mmsghdr>,
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
impl SendMmsgHeaders {
    /// Creates a new container for the mmsg-headers.
    ///
    /// No allocations are performed.
    pub const fn new() -> Self {
        Self {
            mmsghdrs: Vec::new(),
        }
    }

    /// Creates a new container for the mmsg-headers and reserves space
    /// for `cap` headers.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            mmsghdrs: Vec::with_capacity(cap),
        }
    }

    fn fill_send<'a, I, S, C>(&mut self, mut items: I)
    where
        I: Iterator<Item = (Option<&'a S>, &'a [IoSlice<'a>], &'a C)> + ExactSizeIterator,
        S: SockaddrLike + 'a,
        C: CmsgBufWrite + ?Sized + 'a,
    {
        let len = items.len();

        self.mmsghdrs.clear();
        self.mmsghdrs.reserve(len);

        let mmsghdrs_uninit_slice = unsafe {
            std::slice::from_raw_parts_mut(self.mmsghdrs.as_mut_ptr().cast(), self.mmsghdrs.capacity())
        };

        let size = sendmmsg_headers_into(mmsghdrs_uninit_slice, items.by_ref());

        if size != len || items.next().is_some() {
            panic!("Len returned by exact size iterator was not accurate");
        }

        unsafe {
            self.mmsghdrs.set_len(size);
        }
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
unsafe impl Send for SendMmsgHeaders {}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
unsafe impl Sync for SendMmsgHeaders {}

/// Growable container holding the headers for [`recvmmsg`].
///
/// This allocation can be reused when calling [`recvmmsg`] multiple times,
/// which can be beneficial for performance.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
#[derive(Debug, Default)]
pub struct RecvMmsgHeaders<S>
where
    S: SockaddrFromRaw,
{
    mmsghdrs: Vec<libc::mmsghdr>,
    addresses: Vec<MaybeUninit<S::Storage>>,
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
impl<S> RecvMmsgHeaders<S>
where
    S: SockaddrFromRaw,
{
    /// Creates a new container for the `mmsg`-headers.
    ///
    /// No allocations are performed.
    pub const fn new() -> Self {
        Self {
            mmsghdrs: Vec::new(),
            addresses: Vec::new(),
        }
    }

    /// Creates a new container for the `mmsg`-headers and reserves space
    /// for `cap` headers.
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            mmsghdrs: Vec::with_capacity(cap),
            addresses: Vec::with_capacity(cap),
        }
    }

    fn fill_recv<'a, 'b, I, C>(&mut self, mut items: I)
    where
        'b: 'a,
        I: Iterator<Item = (&'a mut [IoSliceMut<'b>], &'a mut C)> + ExactSizeIterator,
        C: CmsgBufRead + ?Sized + 'a,
    {
        let len = items.len();

        self.mmsghdrs.clear();
        self.addresses.clear();

        self.mmsghdrs.reserve(len);
        self.addresses.reserve(len);

        // SAFETY: `MaybeUninit` is transparent, and doesn't need to be initialized.
        let mmsghdrs_uninit_slice = unsafe {
            std::slice::from_raw_parts_mut(self.mmsghdrs.as_mut_ptr().cast(), len)
        };

        let addresses_uninit_slice = unsafe {
            std::slice::from_raw_parts_mut(self.addresses.as_mut_ptr(), len)
        };

        let size = recvmmsg_headers_into::<S, _, _>(mmsghdrs_uninit_slice, addresses_uninit_slice, items.by_ref());

        if size != len || items.next().is_some() {
            panic!("Len returned by exact size iterator was not accurate");
        }

        // SAFETY: `size` headers were initialized by `recvmmsg_headers_into`.
        unsafe {
            self.mmsghdrs.set_len(size);
            self.addresses.set_len(size);
        }
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
unsafe impl<S> Send for RecvMmsgHeaders<S>
where
    S: SockaddrFromRaw + Send,
{}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
unsafe impl<S> Sync for RecvMmsgHeaders<S>
where
    S: SockaddrFromRaw + Sync,
{}

/// Stack-allocated container holding a single header for [`recvmsg`].
#[derive(Debug)]
pub struct RecvMsgHeader<S>
where
    S: SockaddrFromRaw,
{
    msg_hdr: MaybeUninit<libc::msghdr>,
    address: MaybeUninit<S::Storage>,
}

impl<S> RecvMsgHeader<S>
where
    S: SockaddrFromRaw,
{
    /// Creates a new container for a single message header.
    pub const fn new() -> Self {
        Self {
            msg_hdr: MaybeUninit::uninit(),
            address: MaybeUninit::uninit(),
        }
    }

    fn fill_recv<C>(&mut self, iov: &mut [IoSliceMut<'_>], cmsg: &mut C)
    where
        C: CmsgBufRead + ?Sized,
    {
        let msg_hdr = recvmsg_header::<S, _>(&mut self.address, iov, cmsg);

        self.msg_hdr.write(msg_hdr);
    }
}

impl<S> Default for RecvMsgHeader<S>
where
    S: SockaddrFromRaw,
{
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl<S> Send for RecvMsgHeader<S>
where
    S: SockaddrFromRaw + Send,
{}

unsafe impl<S> Sync for RecvMsgHeader<S>
where
    S: SockaddrFromRaw + Sync,
{}

/// An extension of [`sendmsg`] that allows the caller to transmit multiple messages on a socket
/// using a single system call.
///
/// This has performance benefits for some applications.
///
/// Returns an iterator producing [`SendMsgResult`], one per sent message.
///
/// # Panics
///
/// This function panics if:
///
/// - The length of the [`ExactSizeIterator`] is not accurate.
/// - The number of messages exceeds `u32::MAX` (not applicable for FreeBSD).
///
/// # Bugs (in underlying implementation, at least in Linux)
///
/// If an error occurs after at least one message has been sent, the
/// call succeeds, and returns the number of messages sent.  The
/// error code is lost.  The caller can retry the transmission,
/// starting at the first failed message, but there is no guarantee
/// that, if an error is returned, it will be the same as the one
/// that was lost on the previous call.
///
/// # Examples
///
/// See [`recvmmsg`] for an example using both functions.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
pub fn sendmmsg<'h, 'a, J, S, I, C>(
    fd: RawFd,
    headers: &'h mut SendMmsgHeaders,
    items: J,
    flags: MsgFlags,
) -> crate::Result<SendMmsgResult<'h>>
where
    J: IntoIterator<Item = (Option<&'a S>, &'a I, &'a C)>,
    J::IntoIter: ExactSizeIterator,
    S: SockaddrLike + 'a,
    I: AsRef<[IoSlice<'a>]> + ?Sized + 'a,
    C: CmsgBufWrite + ?Sized + 'a,
{
    headers.fill_send(items.into_iter().map(|(addr, iov, cmsg)| (addr, iov.as_ref(), cmsg)));

    #[cfg(not(target_os = "freebsd"))]
    let mmsghdrs_len = headers.mmsghdrs.len().try_into().unwrap();

    #[cfg(target_os = "freebsd")]
    let mmsghdrs_len = headers.mmsghdrs.len() as _;

    let sent = Errno::result(unsafe {
        libc::sendmmsg(
            fd,
            headers.mmsghdrs.as_mut_ptr(),
            mmsghdrs_len,
            flags.bits() as _,
        )
    })? as usize;

    Ok(SendMmsgResult {
        headers: headers.mmsghdrs[..sent].iter(),
    })
}

/// An extension of [`recvmsg`] that allows the caller to receive multiple messages from a socket
/// using a single system call.
///
/// This has performance benefits for some applications. A further extension over [`recvmsg`] is
/// support for a timeout on the receive operation.
///
/// Returns an iterator procucing [`RecvMsgResult`], one per received message.
///
/// # Panics
///
/// This function panics if:
///
/// - The length of the [`ExactSizeIterator`] is not accurate.
/// - The number of messages exceeds `u32::MAX` (not applicable for FreeBSD).
///
/// # Bugs (in underlying implementation, at least in Linux)
///
/// The timeout argument does not work as intended.  The timeout is
/// checked only after the receipt of each datagram, so that if not all
/// datagrams are received before the timeout expires, but
/// then no further datagrams are received, the call will block
/// forever.
///
/// If an error occurs after at least one message has been received,
/// the call succeeds, and returns the number of messages received.
/// The error code is expected to be returned on a subsequent call to
/// [`recvmmsg`].  In the current implementation, however, the error
/// code can be overwritten in the meantime by an unrelated network
/// event on a socket, for example an incoming ICMP packet.
///
/// # Examples
///
/// ```
/// # use nix::sys::socket::*;
/// # use std::os::fd::AsRawFd;
/// # use std::io::{IoSlice, IoSliceMut};
/// // We use connectionless UDP sockets.
/// let send = socket(
///     AddressFamily::INET,
///     SockType::Datagram,
///     SockFlag::empty(),
///     Some(SockProtocol::Udp),
/// )?;
///
/// let recv = socket(
///     AddressFamily::INET,
///     SockType::Datagram,
///     SockFlag::empty(),
///     Some(SockProtocol::Udp),
/// )?;
///
/// // This is the address we are going to send the message.
/// let addr = "127.0.0.1:6069".parse::<SockaddrIn>().unwrap();
///
/// bind(recv.as_raw_fd(), &addr)?;
///
/// // The two messages we are trying to send: [0, 1, 2, ...] and [0, 2, 4, ...].
/// let msg_1: [u8; 1500] = std::array::from_fn(|i| i as u8);
/// let send_iov_1 = [IoSlice::new(&msg_1)];
///
/// let msg_2: [u8; 1500] = std::array::from_fn(|i| (i * 2) as u8);
/// let send_iov_2 = [IoSlice::new(&msg_2)];
///
/// // We preallocate headers for 2 messages.
/// let mut send_headers = SendMmsgHeaders::with_capacity(2);
///
/// // Zip everything together.
/// //
/// // On connectionless sockets like UDP, destination addresses are required.
/// // Each message can be sent to a different address.
/// let send_items = [
///     (Some(&addr), &send_iov_1, CmsgEmpty::write()),
///     (Some(&addr), &send_iov_2, CmsgEmpty::write()),
/// ];
///
/// // Send the messages on the send socket.
/// let mut send_res = sendmmsg(
///     send.as_raw_fd(),
///     &mut send_headers,
///     send_items,
///     MsgFlags::empty(),
/// )?;
///
/// // We have actually sent 2 messages.
/// assert_eq!(send_res.len(), 2);
///
/// // We have actually sent 1500 bytes per message.
/// assert!(send_res.all(|res| res.bytes() == 1500));
///
/// // Initialize buffers to receive the messages.
/// let mut buf_1 = [0u8; 1500];
/// let mut recv_iov_1 = [IoSliceMut::new(&mut buf_1)];
///
/// let mut buf_2 = [0u8; 1500];
/// let mut recv_iov_2 = [IoSliceMut::new(&mut buf_2)];
///
/// // We preallocate headers for 2 messages.
/// let mut recv_headers = RecvMmsgHeaders::<Option<SockaddrIn>>::new();
///
/// // Zip everything together.
/// let mut recv_items = [
///     (&mut recv_iov_1, CmsgEmpty::read()),
///     (&mut recv_iov_2, CmsgEmpty::read()),
/// ];
///
/// // Receive `msg` on `recv`.
/// let mut recv_res = recvmmsg(
///     recv.as_raw_fd(),
///     &mut recv_headers,
///     recv_items,
///     MsgFlags::empty(),
///     None,
/// )?;
///
/// // We have actually received two messages.
/// assert_eq!(recv_res.len(), 2);
///
/// // We have actually received 1500 bytes per message.
/// // Since this is a connectionless socket, the sender address is returned as well.
/// assert!(recv_res.all(|res| {
///     res.bytes() == 1500 && res.address().is_some()
/// }));
///
/// // The received messages are identical to the sent ones.
/// assert_eq!(buf_1, msg_1);
/// assert_eq!(buf_2, msg_2);
///
/// # Ok::<(), nix::Error>(())
/// ```
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
pub fn recvmmsg<'h, 'a, 'b, S, J, I, C>(
    fd: RawFd,
    headers: &'h mut RecvMmsgHeaders<S>,
    items: J,
    flags: MsgFlags,
    mut timeout: Option<crate::sys::time::TimeSpec>,
) -> crate::Result<RecvMmsgResult<'h, S>>
where
    S: SockaddrFromRaw,
    J: IntoIterator<Item = (&'a mut I, &'h mut C)>,
    J::IntoIter: ExactSizeIterator,
    I: AsMut<[IoSliceMut<'b>]> + ?Sized + 'a,
    C: CmsgBufRead + ?Sized + 'h,
{
    headers.fill_recv(items.into_iter().map(|(iov, cmsg)| (iov.as_mut(), cmsg)));

    let timeout_ptr = timeout
        .as_mut()
        .map_or_else(std::ptr::null_mut, |t| t as *mut _ as *mut libc::timespec);

    #[cfg(not(target_os = "freebsd"))]
    let mmsghdrs_len = headers.mmsghdrs.len().try_into().unwrap();

    #[cfg(target_os = "freebsd")]
    let mmsghdrs_len = headers.mmsghdrs.len() as _;

    let recv = Errno::result(unsafe {
        libc::recvmmsg(
            fd,
            headers.mmsghdrs.as_mut_ptr(),
            mmsghdrs_len,
            flags.bits() as _,
            timeout_ptr,
        )
    })? as usize;

    Ok(RecvMmsgResult {
        headers: headers.mmsghdrs[..recv].iter(),
        _s: std::marker::PhantomData,
    })
}

/// Iterator over [`SendMsgResult`]s.
///
/// Returned by [`sendmmsg`].
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
#[derive(Debug, Clone)]
pub struct SendMmsgResult<'a> {
    headers: std::slice::Iter<'a, libc::mmsghdr>,
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
impl<'a> Iterator for SendMmsgResult<'a> {
    type Item = SendMsgResult;

    fn next(&mut self) -> Option<Self::Item> {
        self.headers.next().map(|&hdr| SendMsgResult {
            bytes: hdr.msg_len as _,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.headers.size_hint()
    }

    fn count(self) -> usize {
        self.headers.count()
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.headers.nth(n).map(|&hdr| SendMsgResult {
            bytes: hdr.msg_len as _,
        })
    }

    fn last(self) -> Option<Self::Item> {
        self.headers.last().map(|&hdr| SendMsgResult {
            bytes: hdr.msg_len as _,
        })
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
impl<'a> ExactSizeIterator for SendMmsgResult<'a> {
    fn len(&self) -> usize {
        self.headers.len()
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
impl<'a> DoubleEndedIterator for SendMmsgResult<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.headers.next_back().map(|&hdr| SendMsgResult {
            bytes: hdr.msg_len as _,
        })
    }

    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.headers.nth_back(n).map(|&hdr| SendMsgResult {
            bytes: hdr.msg_len as _,
        })
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
impl<'a> std::iter::FusedIterator for SendMmsgResult<'a> {}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
unsafe impl<'a> Send for SendMmsgResult<'a> {}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
unsafe impl<'a> Sync for SendMmsgResult<'a> {}

/// Iterator over [`RecvMsgResult`]s.
///
/// Returned by [`recvmmsg`].
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
#[derive(Debug, Clone)]
pub struct RecvMmsgResult<'a, S> {
    headers: std::slice::Iter<'a, libc::mmsghdr>,
    _s: std::marker::PhantomData<fn() -> S>,
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
impl<'a, S> Iterator for RecvMmsgResult<'a, S> {
    type Item = RecvMsgResult<'a, S>;

    fn next(&mut self) -> Option<Self::Item> {
        self.headers.next().map(|&hdr| RecvMsgResult {
            bytes: hdr.msg_len as _,
            hdr: hdr.msg_hdr,
            _phantom: std::marker::PhantomData,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.headers.size_hint()
    }

    fn count(self) -> usize {
        self.headers.count()
    }

    fn nth(&mut self, n: usize) -> Option<Self::Item> {
        self.headers.nth(n).map(|&hdr| RecvMsgResult {
            bytes: hdr.msg_len as _,
            hdr: hdr.msg_hdr,
            _phantom: std::marker::PhantomData,
        })
    }

    fn last(self) -> Option<Self::Item> {
        self.headers.last().map(|&hdr| RecvMsgResult {
            bytes: hdr.msg_len as _,
            hdr: hdr.msg_hdr,
            _phantom: std::marker::PhantomData,
        })
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
impl<'a, S> ExactSizeIterator for RecvMmsgResult<'a, S> {
    fn len(&self) -> usize {
        self.headers.len()
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
impl<'a, S> DoubleEndedIterator for RecvMmsgResult<'a, S> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.headers.next_back().map(|&hdr| RecvMsgResult {
            bytes: hdr.msg_len as _,
            hdr: hdr.msg_hdr,
            _phantom: std::marker::PhantomData,
        })
    }

    fn nth_back(&mut self, n: usize) -> Option<Self::Item> {
        self.headers.nth_back(n).map(|&hdr| RecvMsgResult {
            bytes: hdr.msg_len as _,
            hdr: hdr.msg_hdr,
            _phantom: std::marker::PhantomData,
        })
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
impl<'a, S> std::iter::FusedIterator for RecvMmsgResult<'a, S> {}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
unsafe impl<'a, S> Send for RecvMmsgResult<'a, S>
where
    S: Send,
{}

#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "netbsd",
))]
unsafe impl<'a, S> Sync for RecvMmsgResult<'a, S>
where
    S: Sync,
{}

/// Result for sending messages.
#[derive(Debug, Clone, Copy)]
pub struct SendMsgResult {
    bytes: usize,
}

impl SendMsgResult {
    /// Returns the number of bytes sent.
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

unsafe impl Send for SendMsgResult {}

unsafe impl Sync for SendMsgResult {}

/// Result for receiving messages.
#[derive(Debug, Clone, Copy)]
pub struct RecvMsgResult<'a, S> {
    bytes: usize,
    hdr: libc::msghdr,
    // For covariance without drop check, should we ever need a `Drop` impl.
    // In that case, we can safely annotate `S` with `#[may_dangle]`.
    #[allow(clippy::type_complexity)]
    _phantom: std::marker::PhantomData<(&'a (), fn() -> S)>,
}

impl<'a, S> RecvMsgResult<'a, S>
where
    S: SockaddrFromRaw,
{
    /// Returns the number of bytes received.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// Returns the address of the sender, if available.
    ///
    /// If the socket is
    ///
    /// - connection-oriented (e.g. TCP), `None` is returned.
    ///
    /// - connectionless (e.g. UDP), `Some` is returned.
    pub fn address(&self) -> S::Out<'_> {
        // SAFETY: `self.0` either contains a valid address, or a provable invalid address
        // as initialized by `S:init_storage`.
        unsafe {
            S::from_raw(self.hdr.msg_name.cast_const().cast(), self.hdr.msg_namelen)
        }
    }

    /// Returns the number of bytes received in the control message buffer.
    pub fn control_bytes(&self) -> usize {
        self.hdr.msg_controllen as _
    }

    /// Returns an iterator over the received control messages.
    pub fn control_messages(&self) -> CmsgIterator<'_> {
        CmsgIterator {
            // SAFETY: `self.0` contains valid control messages, so casting to a
            // reference is safe. Note that if the buffer was empty, `CMSG_FIRSTHDR`
            // would return a null pointer, which gets casted to `None` by `as_ref`.
            cmsghdr: unsafe { CMSG_FIRSTHDR(&self.hdr).as_ref() },
            mhdr: MaybeUninit::new(self.hdr),
        }
    }

    /// Returns the received flags of the message from the kernel.
    pub fn flags(&self) -> MsgFlags {
        MsgFlags::from_bits_truncate(self.hdr.msg_flags as _)
    }
}

unsafe impl<'a, S> Send for RecvMsgResult<'a, S>
where
    S: Send,
{}

unsafe impl<'a, S> Sync for RecvMsgResult<'a, S>
where
    S: Sync,
{}

#[derive(Debug)]
pub struct IoSliceIterator<'a> {
    index: usize,
    remaining: usize,
    slices: &'a [IoSlice<'a>],
}

impl<'a> Iterator for IoSliceIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.slices.len() {
            return None;
        }
        let slice = &self.slices[self.index][..self.remaining.min(self.slices[self.index].len())];
        self.remaining -= slice.len();
        self.index += 1;
        if slice.is_empty() {
            return None;
        }

        Some(slice)
    }
}

// test contains both recvmmsg and timestaping which is linux only
// there are existing tests for recvmmsg only in tests/
#[cfg(target_os = "linux")]
#[cfg(test)]
mod test {
    use crate::sys::socket::ControlMessageOwned;
    use crate::*;
    use std::str::FromStr;
    use std::os::unix::io::AsRawFd;

    #[cfg_attr(qemu, ignore)]
    #[test]
    fn test_recvmm_2() -> crate::Result<()> {
        use crate::sys::socket::{
            AddressFamily,sendmsg, setsockopt, socket, sockopt::Timestamping, MsgFlags, SockFlag, SockType,
            SockaddrIn, TimestampingFlag, CmsgEmpty,
        };
        use std::io::{IoSlice, IoSliceMut};

        let sock_addr = SockaddrIn::from_str("127.0.0.1:6791").unwrap();

        let ssock = socket(
            AddressFamily::INET,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )?;

        let rsock = socket(
            AddressFamily::INET,
            SockType::Datagram,
            SockFlag::SOCK_NONBLOCK,
            None,
        )?;

        crate::sys::socket::bind(rsock.as_raw_fd(), &sock_addr)?;

        setsockopt(&rsock, Timestamping, &TimestampingFlag::all())?;

        let sbuf = (0..400).map(|i| i as u8).collect::<Vec<_>>();

        let mut recv_buf = vec![0; 1024];

        let mut recv_iovs = Vec::new();
        let mut pkt_iovs = Vec::new();

        for (ix, chunk) in recv_buf.chunks_mut(256).enumerate() {
            pkt_iovs.push(IoSliceMut::new(chunk));
            if ix % 2 == 1 {
                recv_iovs.push(pkt_iovs);
                pkt_iovs = Vec::new();
            }
        }
        drop(pkt_iovs);

        let flags = MsgFlags::empty();
        let iov1 = [IoSlice::new(&sbuf)];

        const CMSG_SPACE: usize = cmsg_space!(ScmTimestampsns);
        sendmsg(ssock.as_raw_fd(), Some(&sock_addr), &iov1, CmsgEmpty::write(), flags).unwrap();

        let mut headers = super::RecvMmsgHeaders::<()>::with_capacity(recv_iovs.len());

        let mut cmsgs = Vec::with_capacity(recv_iovs.len());

        for _ in 0..recv_iovs.len() {
            cmsgs.push(super::CmsgVecRead::with_capacity(CMSG_SPACE));
        }

        let t = sys::time::TimeSpec::from_duration(std::time::Duration::from_secs(10));

        let items = recv_iovs.iter_mut().zip(cmsgs.iter_mut());

        let recv = super::recvmmsg(rsock.as_raw_fd(), &mut headers, items, flags, Some(t))?;

        for rmsg in recv {
            #[cfg(not(any(qemu, target_arch = "aarch64")))]
            let mut saw_time = false;

            for cmsg in rmsg.control_messages() {
                if let ControlMessageOwned::ScmTimestampsns(timestamps) = cmsg {
                    let ts = timestamps.system;

                    let sys_time =
                        crate::time::clock_gettime(crate::time::ClockId::CLOCK_REALTIME)?;
                    let diff = if ts > sys_time {
                        ts - sys_time
                    } else {
                        sys_time - ts
                    };
                    assert!(std::time::Duration::from(diff).as_secs() < 60);
                    #[cfg(not(any(qemu, target_arch = "aarch64")))]
                    {
                        saw_time = true;
                    }
                }
            }

            #[cfg(not(any(qemu, target_arch = "aarch64")))]
            assert!(saw_time);

            assert_eq!(rmsg.bytes(), 400);
        }

        Ok(())
    }

    #[test]
    fn cmsg_empty_sanity() {
        use super::*;

        assert_eq!(CmsgEmpty::write().raw_parts().1, 0);
        assert_eq!(CmsgEmpty::read().raw_parts_mut().1, 0);
    }
}
}

/// Create an endpoint for communication
///
/// The `protocol` specifies a particular protocol to be used with the
/// socket.  Normally only a single protocol exists to support a
/// particular socket type within a given protocol family, in which case
/// protocol can be specified as `None`.  However, it is possible that many
/// protocols may exist, in which case a particular protocol must be
/// specified in this manner.
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/socket.html)
pub fn socket<T: Into<Option<SockProtocol>>>(
    domain: AddressFamily,
    ty: SockType,
    flags: SockFlag,
    protocol: T,
) -> Result<OwnedFd> {
    let protocol = match protocol.into() {
        None => 0,
        Some(p) => p as c_int,
    };

    // SockFlags are usually embedded into `ty`, but we don't do that in `nix` because it's a
    // little easier to understand by separating it out. So we have to merge these bitfields
    // here.
    let mut ty = ty as c_int;
    ty |= flags.bits();

    let res = unsafe { libc::socket(domain.family(), ty, protocol) };

    match res {
        -1 => Err(Errno::last()),
        fd => {
            // Safe because libc::socket returned success
            unsafe { Ok(OwnedFd::from_raw_fd(fd)) }
        }
    }
}

/// Create a pair of connected sockets
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/socketpair.html)
pub fn socketpair<T: Into<Option<SockProtocol>>>(
    domain: AddressFamily,
    ty: SockType,
    protocol: T,
    flags: SockFlag,
) -> Result<(OwnedFd, OwnedFd)> {
    let protocol = match protocol.into() {
        None => 0,
        Some(p) => p as c_int,
    };

    // SockFlags are usually embedded into `ty`, but we don't do that in `nix` because it's a
    // little easier to understand by separating it out. So we have to merge these bitfields
    // here.
    let mut ty = ty as c_int;
    ty |= flags.bits();

    let mut fds = [-1, -1];

    let res = unsafe {
        libc::socketpair(domain.family(), ty, protocol, fds.as_mut_ptr())
    };
    Errno::result(res)?;

    // Safe because socketpair returned success.
    unsafe { Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

/// Listen for connections on a socket
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/listen.html)
pub fn listen<F: AsFd>(sock: &F, backlog: usize) -> Result<()> {
    let fd = sock.as_fd().as_raw_fd();
    let res = unsafe { libc::listen(fd, backlog as c_int) };

    Errno::result(res).map(drop)
}

/// Bind a name to a socket
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/bind.html)
pub fn bind<S>(fd: RawFd, addr: &S) -> Result<()>
where
    S: SockaddrLike,
{
    let res = unsafe { libc::bind(fd, addr.as_sockaddr(), addr.len()) };

    Errno::result(res).map(drop)
}

/// Accept a connection on a socket
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/accept.html)
pub fn accept(sockfd: RawFd) -> Result<RawFd> {
    let res = unsafe { libc::accept(sockfd, ptr::null_mut(), ptr::null_mut()) };

    Errno::result(res)
}

/// Accept a connection on a socket
///
/// [Further reading](https://man7.org/linux/man-pages/man2/accept.2.html)
#[cfg(any(
    all(
        target_os = "android",
        any(
            target_arch = "aarch64",
            target_arch = "x86",
            target_arch = "x86_64"
        )
    ),
    target_os = "dragonfly",
    target_os = "emscripten",
    target_os = "freebsd",
    target_os = "fuchsia",
    target_os = "illumos",
    target_os = "linux",
    target_os = "netbsd",
    target_os = "openbsd"
))]
pub fn accept4(sockfd: RawFd, flags: SockFlag) -> Result<RawFd> {
    let res = unsafe {
        libc::accept4(sockfd, ptr::null_mut(), ptr::null_mut(), flags.bits())
    };

    Errno::result(res)
}

/// Initiate a connection on a socket
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/connect.html)
pub fn connect(fd: RawFd, addr: &dyn SockaddrLike) -> Result<()> {
    let res = unsafe { libc::connect(fd, addr.as_sockaddr(), addr.len()) };

    Errno::result(res).map(drop)
}

/// Receive data from a connection-oriented socket. Returns the number of
/// bytes read
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/recv.html)
pub fn recv(sockfd: RawFd, buf: &mut [u8], flags: MsgFlags) -> Result<usize> {
    unsafe {
        let ret = libc::recv(
            sockfd,
            buf.as_mut_ptr().cast(),
            buf.len() as size_t,
            flags.bits(),
        );

        Errno::result(ret).map(|r| r as usize)
    }
}

/// Receive data from a connectionless or connection-oriented socket. Returns
/// the number of bytes read and, for connectionless sockets,  the socket
/// address of the sender.
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/recvfrom.html)
pub fn recvfrom<'a, T: SockaddrFromRaw>(
    sockfd: RawFd,
    buf: &mut [u8],
) -> Result<(usize, T::Out<'static>)> {
    unsafe {
        let mut addr = mem::MaybeUninit::<T::Storage>::uninit();
        let mut len = mem::size_of_val(&addr) as socklen_t;

        let ret = Errno::result(libc::recvfrom(
            sockfd,
            buf.as_mut_ptr().cast(),
            buf.len() as size_t,
            0,
            addr.as_mut_ptr().cast(),
            &mut len as *mut socklen_t,
        ))? as usize;

        Ok((ret, T::from_raw(addr.as_ptr(), len)))
    }
}

/// Send a message to a socket
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/sendto.html)
pub fn sendto(
    fd: RawFd,
    buf: &[u8],
    addr: &dyn SockaddrLike,
    flags: MsgFlags,
) -> Result<usize> {
    let ret = unsafe {
        libc::sendto(
            fd,
            buf.as_ptr().cast(),
            buf.len() as size_t,
            flags.bits(),
            addr.as_sockaddr(),
            addr.len(),
        )
    };

    Errno::result(ret).map(|r| r as usize)
}

/// Send data to a connection-oriented socket. Returns the number of bytes read
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/send.html)
pub fn send(fd: RawFd, buf: &[u8], flags: MsgFlags) -> Result<usize> {
    let ret = unsafe {
        libc::send(
            fd,
            buf.as_ptr().cast(),
            buf.len() as size_t,
            flags.bits(),
        )
    };

    Errno::result(ret).map(|r| r as usize)
}

/*
 *
 * ===== Socket Options =====
 *
 */

/// Represents a socket option that can be retrieved.
pub trait GetSockOpt: Copy {
    type Val;

    /// Look up the value of this socket option on the given socket.
    fn get<F: AsFd>(&self, fd: &F) -> Result<Self::Val>;
}

/// Represents a socket option that can be set.
pub trait SetSockOpt: Clone {
    type Val;

    /// Set the value of this socket option on the given socket.
    fn set<F: AsFd>(&self, fd: &F, val: &Self::Val) -> Result<()>;
}

/// Get the current value for the requested socket option
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getsockopt.html)
pub fn getsockopt<F: AsFd, O: GetSockOpt>(fd: &F, opt: O) -> Result<O::Val> {
    opt.get(fd)
}

/// Sets the value for the requested socket option
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/setsockopt.html)
///
/// # Examples
///
/// ```
/// use nix::sys::socket::setsockopt;
/// use nix::sys::socket::sockopt::KeepAlive;
/// use std::net::TcpListener;
///
/// let listener = TcpListener::bind("0.0.0.0:0").unwrap();
/// let fd = listener;
/// let res = setsockopt(&fd, KeepAlive, &true);
/// assert!(res.is_ok());
/// ```
pub fn setsockopt<F: AsFd, O: SetSockOpt>(
    fd: &F,
    opt: O,
    val: &O::Val,
) -> Result<()> {
    opt.set(fd, val)
}

/// Get the address of the peer connected to the socket `fd`.
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getpeername.html)
pub fn getpeername<T: SockaddrFromRaw>(fd: RawFd) -> Result<T::Owned> {
    unsafe {
        let mut addr = MaybeUninit::<T::Storage>::uninit();
        let mut len = mem::size_of::<T::Storage>() as _;

        T::init_storage(&mut addr);

        let ret =
            libc::getpeername(fd, addr.as_mut_ptr().cast(), &mut len);

        Errno::result(ret)?;

        Ok(T::from_raw(addr.as_ptr(), len).to_owned_addr())
    }
}

/// Get the current address to which the socket `fd` is bound.
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/getsockname.html)
pub fn getsockname<T: SockaddrFromRaw>(fd: RawFd) -> Result<T::Owned> {
    unsafe {
        let mut addr = MaybeUninit::<T::Storage>::uninit();

        T::init_storage(&mut addr);

        let mut len = mem::size_of::<T::Storage>() as _;

        let ret =
            libc::getsockname(fd, addr.as_mut_ptr().cast(), &mut len);

        Errno::result(ret)?;

        Ok(T::from_raw(addr.as_ptr(), len).to_owned_addr())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Shutdown {
    /// Further receptions will be disallowed.
    Read,
    /// Further  transmissions will be disallowed.
    Write,
    /// Further receptions and transmissions will be disallowed.
    Both,
}

/// Shut down part of a full-duplex connection.
///
/// [Further reading](https://pubs.opengroup.org/onlinepubs/9699919799/functions/shutdown.html)
pub fn shutdown(df: RawFd, how: Shutdown) -> Result<()> {
    unsafe {
        use libc::shutdown;

        let how = match how {
            Shutdown::Read => libc::SHUT_RD,
            Shutdown::Write => libc::SHUT_WR,
            Shutdown::Both => libc::SHUT_RDWR,
        };

        Errno::result(shutdown(df, how)).map(drop)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "redox"))]
    #[test]
    fn can_use_cmsg_space() {
        let _ = cmsg_space!(ScmTimestamp);
    }

    #[cfg(not(any(
        target_os = "redox",
        target_os = "linux",
        target_os = "android"
    )))]
    #[test]
    fn can_open_routing_socket() {
        let _ = super::socket(
            super::AddressFamily::ROUTE,
            super::SockType::Raw,
            super::SockFlag::empty(),
            None,
        )
        .expect("Failed to open routing socket");
    }
}
