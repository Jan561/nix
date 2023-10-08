#[cfg(any(
    target_os = "android",
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "haiku",
    target_os = "fuchsia",
    target_os = "aix",
))]
#[cfg(feature = "net")]
pub use self::datalink::LinkAddr;
#[cfg(any(target_os = "android", target_os = "linux", target_os = "macos"))]
pub use self::vsock::VsockAddr;
use super::sa_family_t;
use crate::errno::Errno;
#[cfg(any(target_os = "android", target_os = "linux"))]
use crate::sys::socket::addr::alg::AlgAddr;
#[cfg(any(target_os = "android", target_os = "linux"))]
use crate::sys::socket::addr::netlink::NetlinkAddr;
#[cfg(all(
    feature = "ioctl",
    any(target_os = "ios", target_os = "macos")
))]
use crate::sys::socket::addr::sys_control::SysControlAddr;
use crate::{NixPath, Result};
use cfg_if::cfg_if;
use memoffset::offset_of;
use std::convert::TryInto;
use std::ffi::OsStr;
use std::hash::{Hash, Hasher};
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{addr_of_mut, addr_of};
use std::{fmt, mem, net, ptr, slice};

/// Convert a std::net::Ipv4Addr into the libc form.
#[cfg(feature = "net")]
pub(crate) const fn ipv4addr_to_libc(addr: net::Ipv4Addr) -> libc::in_addr {
    libc::in_addr {
        s_addr: u32::from_ne_bytes(addr.octets())
    }
}

/// Convert a std::net::Ipv6Addr into the libc form.
#[cfg(feature = "net")]
pub(crate) const fn ipv6addr_to_libc(addr: &net::Ipv6Addr) -> libc::in6_addr {
    libc::in6_addr {
        s6_addr: addr.octets()
    }
}

/// A possible error when converting a c_int to [`AddressFamily`].
#[derive(Debug, Clone, Copy)]
pub struct InvalidAddressFamilyError;

/// Address families, corresponding to `AF_*` constants in libc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressFamily(libc::c_int);

impl AddressFamily {
    /// Converts a c_int to an address family.
    ///
    /// The argument must fit into `sa_family_t`.
    pub const fn new(family: libc::c_int) -> std::result::Result<Self, InvalidAddressFamilyError> {
        if family > libc::sa_family_t::MAX as _ {
            return Err(InvalidAddressFamilyError);
        }

        Ok(Self(family))
    }

    /// Returns the c_int representation of the address family.
    pub const fn family(&self) -> libc::c_int {
        self.0
    }
}

impl AddressFamily {
    /// Represents `AF_802`.
    #[cfg(any(
        target_os = "illumos",
        target_os = "solaris",
    ))]
    pub const _802: Self = Self(libc::AF_802);
    /// Represents `AF_ALG`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const ALG: Self = Self(libc::AF_ALG);
    /// Represents `AF_APPLETALK`.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const APPLETALK: Self = Self(libc::AF_APPLETALK);
    /// Represents `AF_ARP`.
    #[cfg(any(
        target_os = "freebsd",
        target_os = "netbsd",
    ))]
    pub const ARP: Self = Self(libc::AF_ARP);
    /// Represents `AF_ASH`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const ASH: Self = Self(libc::AF_ASH);
    /// Represents `AF_ATM`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
    ))]
    pub const ATM: Self = Self(libc::AF_ATM);
    /// Represents `AF_ATMPVC`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const ATMPVC: Self = Self(libc::AF_ATMPVC);
    /// Represents `AF_ATMSVC`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const ATMSVC: Self = Self(libc::AF_ATMSVC);
    /// Represents `AF_AX25`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const AX25: Self = Self(libc::AF_AX25);
    /// Represents `AF_BLUETOOTH`.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "haiku",
        target_os = "linux",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    pub const BLUETOOTH: Self = Self(libc::AF_BLUETOOTH);
    /// Represents `AF_BRIDGE`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const BRIDGE: Self = Self(libc::AF_BRIDGE);
    /// Represents `AF_CAIF`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const CAIF: Self = Self(libc::AF_CAIF);
    /// Represents `AF_CAN`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const CAN: Self = Self(libc::AF_CAN);
    /// Represents `AF_CCITT`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const CCITT: Self = Self(libc::AF_CCITT);
    /// Represents `AF_CHAOS`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const CHAOS: Self = Self(libc::AF_CHAOS);
    /// Represents `AF_CNT`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    pub const CNT: Self = Self(libc::AF_CNT);
    /// Represents `AF_COIP`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    pub const COIP: Self = Self(libc::AF_COIP);
    /// Represents `AF_DATAKIT`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const DATAKIT: Self = Self(libc::AF_DATAKIT);
    /// Represents `AF_DECnet`.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const DEC_NET: Self = Self(libc::AF_DECnet);
    /// Represents `AF_DLI`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const DLI: Self = Self(libc::AF_DLI);
    /// Represents `AF_E164`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    pub const E164: Self = Self(libc::AF_E164);
    /// Represents `AF_ECMA`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const ECMA: Self = Self(libc::AF_ECMA);
    /// Represents `AF_ECONET`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const ECONET: Self = Self(libc::AF_ECONET);
    /// Represents `AF_ENCAP`.
    #[cfg(target_os = "openbsd")]
    pub const ENCAP: Self = Self(libc::AF_ENCAP);
    /// Represents `AF_FILE`.
    #[cfg(any(
        target_os = "illumos",
        target_os = "solaris",
    ))]
    pub const FILE: Self = Self(libc::AF_FILE);
    /// Represents `AF_GOSIP`.
    #[cfg(any(
        target_os = "illumos",
        target_os = "solaris",
    ))]
    pub const GOSIP: Self = Self(libc::AF_GOSIP);
    /// Represents `AF_HYLINK`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const HYLINK: Self = Self(libc::AF_HYLINK);
    /// Represents `AF_IB`.
    #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
    pub const IB: Self = Self(libc::AF_IB);
    /// Represents `AF_IEEE80211`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
    ))]
    pub const IEEE80211: Self = Self(libc::AF_IEEE80211);
    /// Represents `AF_IEEE802154`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const IEEE802154: Self = Self(libc::AF_IEEE802154);
    /// Represents `AF_IMPLINK`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const IMPLINK: Self = Self(libc::AF_IMPLINK);
    /// Represents `AF_INET`.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
    ))]
    pub const INET: Self = Self(libc::AF_INET);
    /// Represents `AF_INET6`.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
    ))]
    pub const INET6: Self = Self(libc::AF_INET6);
    /// Represents `AF_INET6_SDP`.
    #[cfg(target_os = "freebsd")]
    pub const INET6_SDP: Self = Self(libc::AF_INET6_SDP);
    /// Represents `AF_INET_OFFLOAD`.
    #[cfg(any(
        target_os = "illumos",
        target_os = "solaris",
    ))]
    pub const INET_OFFLOAD: Self = Self(libc::AF_INET_OFFLOAD);
    /// Represents `AF_INET_SDP`.
    #[cfg(target_os = "freebsd")]
    pub const INET_SDP: Self = Self(libc::AF_INET_SDP);
    /// Represents `AF_IPX`.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const IPX: Self = Self(libc::AF_IPX);
    /// Represents `AF_IRDA`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const IRDA: Self = Self(libc::AF_IRDA);
    /// Represents `AF_ISDN`.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    pub const ISDN: Self = Self(libc::AF_ISDN);
    /// Represents `AF_ISO`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    pub const ISO: Self = Self(libc::AF_ISO);
    /// Represents `AF_IUCV`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const IUCV: Self = Self(libc::AF_IUCV);
    /// Represents `AF_KEY`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "linux",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const KEY: Self = Self(libc::AF_KEY);
    /// Represents `AF_LAT`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const LAT: Self = Self(libc::AF_LAT);
    /// Represents `AF_LINK`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const LINK: Self = Self(libc::AF_LINK);
    /// Represents `AF_LLC`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const LLC: Self = Self(libc::AF_LLC);
    /// Represents `AF_LOCAL`.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const LOCAL: Self = Self(libc::AF_LOCAL);
    /// Represents `AF_MPLS`.
    #[cfg(all(
        any(
            target_os = "dragonfly",
            target_os = "linux",
            target_os = "netbsd",
            target_os = "openbsd",
        ),
        not(target_env = "uclibc"),
    ))]
    pub const MPLS: Self = Self(libc::AF_MPLS);
    /// Represents `AF_NATM`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
    ))]
    pub const NATM: Self = Self(libc::AF_NATM);
    /// Represents `AF_NBS`.
    #[cfg(any(
        target_os = "illumos",
        target_os = "solaris",
    ))]
    pub const NBS: Self = Self(libc::AF_NBS);
    /// Represents `AF_NCA`.
    #[cfg(any(
        target_os = "illumos",
        target_os = "solaris",
    ))]
    pub const NCA: Self = Self(libc::AF_NCA);
    /// Represents `AF_NDRV`.
    #[cfg(any(
        target_os = "ios",
        target_os = "macos",
    ))]
    pub const NDRV: Self = Self(libc::AF_NDRV);
    /// Represents `AF_NETBEUI`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const NETBEUI: Self = Self(libc::AF_NETBEUI);
    /// Represents `AF_NETBIOS`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
    ))]
    pub const NETBIOS: Self = Self(libc::AF_NETBIOS);
    /// Represents `AF_NETGRAPH`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
    ))]
    pub const NETGRAPH: Self = Self(libc::AF_NETGRAPH);
    /// Represents `AF_NETLINK`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const NETLINK: Self = Self(libc::AF_NETLINK);
    /// Represents `AF_NETROM`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const NETROM: Self = Self(libc::AF_NETROM);
    /// Represents `AF_NFC`.
    #[cfg(any(
        target_os = "android",
        target_os = "linux",
    ))]
    pub const NFC: Self = Self(libc::AF_NFC);
    /// Represents `AF_NIT`.
    #[cfg(any(
        target_os = "illumos",
        target_os = "solaris",
    ))]
    pub const NIT: Self = Self(libc::AF_NIT);
    /// Represents `AF_NOTIFY`.
    #[cfg(target_os = "haiku")]
    pub const NOTIFY: Self = Self(libc::AF_NOTIFY);
    /// Represents `AF_NS`.
    #[cfg(any(
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const NS: Self = Self(libc::AF_NS);
    /// Represents `AF_OROUTE`.
    #[cfg(target_os = "netbsd")]
    pub const OROUTE: Self = Self(libc::AF_OROUTE);
    /// Represents `AF_OSI`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const OSI: Self = Self(libc::AF_OSI);
    /// Represents `AF_OSINET`.
    #[cfg(any(
        target_os = "illumos",
        target_os = "solaris",
    ))]
    pub const OSINET: Self = Self(libc::AF_OSINET);
    /// Represents `AF_PACKET`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "linux",
        target_os = "solaris",
    ))]
    pub const PACKET: Self = Self(libc::AF_PACKET);
    /// Represents `AF_PHONET`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const PHONET: Self = Self(libc::AF_PHONET);
    /// Represents `AF_POLICY`.
    #[cfg(any(
        target_os = "illumos",
        target_os = "solaris",
    ))]
    pub const POLICY: Self = Self(libc::AF_POLICY);
    /// Represents `AF_PPP`.
    #[cfg(any(
        target_os = "ios",
        target_os = "macos",
    ))]
    pub const PPP: Self = Self(libc::AF_PPP);
    /// Represents `AF_PPPOX`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const PPPOX: Self = Self(libc::AF_PPPOX);
    /// Represents `AF_PUP`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "illumos",
        target_os = "ios",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const PUP: Self = Self(libc::AF_PUP);
    /// Represents `AF_RDS`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const RDS: Self = Self(libc::AF_RDS);
    /// Represents `AF_ROSE`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const ROSE: Self = Self(libc::AF_ROSE);
    /// Represents `AF_ROUTE`.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const ROUTE: Self = Self(libc::AF_ROUTE);
    /// Represents `AF_RXRPC`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const RXRPC: Self = Self(libc::AF_RXRPC);
    /// Represents `AF_SCLUSTER`.
    #[cfg(target_os = "freebsd")]
    pub const SCLUSTER: Self = Self(libc::AF_SCLUSTER);
    /// Represents `AF_SECURITY`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const SECURITY: Self = Self(libc::AF_SECURITY);
    /// Represents `AF_SIP`.
    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "openbsd",
    ))]
    pub const SIP: Self = Self(libc::AF_SIP);
    /// Represents `AF_SLOW`.
    #[cfg(target_os = "freebsd")]
    pub const SLOW: Self = Self(libc::AF_SLOW);
    /// Represents `AF_SNA`.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "solaris",
    ))]
    pub const SNA: Self = Self(libc::AF_SNA);
    /// Represents `AF_SYSTEM`.
    #[cfg(any(
        target_os = "ios",
        target_os = "macos",
    ))]
    pub const SYSTEM: Self = Self(libc::AF_SYSTEM);
    /// Represents `AF_SYS_CONTROL`.
    #[cfg(any(
        target_os = "ios",
        target_os = "macos",
    ))]
    pub const SYS_CONTROL: Self = Self(libc::AF_SYS_CONTROL);
    /// Represents `AF_TIPC`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const TIPC: Self = Self(libc::AF_TIPC);
    /// Represents `AF_TRILL`.
    #[cfg(any(
        target_os = "illumos",
        target_os = "solaris",
    ))]
    pub const TRILL: Self = Self(libc::AF_TRILL);
    /// Represents `AF_UNIX`.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
    ))]
    pub const UNIX: Self = Self(libc::AF_UNIX);
    /// Represents `AF_UNSPEC`.
    #[cfg(any(
        target_os = "android",
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "fuchsia",
        target_os = "haiku",
        target_os = "illumos",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "redox",
        target_os = "solaris",
    ))]
    pub const UNSPEC: Self = Self(libc::AF_UNSPEC);
    /// Represents `AF_UTUN`.
    #[cfg(any(
        target_os = "ios",
        target_os = "macos",
    ))]
    pub const UTUN: Self = Self(libc::AF_UTUN);
    /// Represents `AF_VSOCK`.
    #[cfg(any(
        target_os = "android",
        target_os = "ios",
        target_os = "linux",
        target_os = "macos",
    ))]
    pub const VSOCK: Self = Self(libc::AF_VSOCK);
    /// Represents `AF_WANPIPE`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
    ))]
    pub const WANPIPE: Self = Self(libc::AF_WANPIPE);
    /// Represents `AF_X25`.
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "linux",
        target_os = "solaris",
    ))]
    pub const X25: Self = Self(libc::AF_X25);
    /// Represents `AF_XDP`.
    #[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
    pub const XDP: Self = Self(libc::AF_XDP);
}

pub(super) mod private {
    use std::mem::MaybeUninit;

    /// # Safety
    ///
    /// For implementors of this trait, `&self` must be castable to `&libc::sockaddr` (usually this requires
    /// that `Self` is `#[repr(C)]`).
    ///
    /// Furthermore, the following invariants must hold:
    ///
    /// - `Self::init_storage` must initialize its argument in a way, such that after calling this function,
    /// the memory representation of the argument must be either valid or *provably* invalid for `Self`.
    ///
    /// - `Self::from_raw` must return `None` if the provided address pointer is invalid for `Self`. This includes
    /// invalidity checks setuped by `Self::init_storage`.
    pub unsafe trait SockaddrLikePriv {
        /// Unsafe constructor from a variable length source
        ///
        /// Some C APIs from provide `len`, and others do not.  If it's provided it
        /// will be validated.  If not, it will be guessed based on the family.
        ///
        /// # Safety
        ///
        /// One of the following must be true:
        ///
        /// - `addr` must be valid for the specific type of sockaddr.
        /// - `addr` has been initialized with `Self::init_storage`.
        ///
        /// Additionally, if `addr` is valid for `Self`, then `len` must not exceed the
        /// length of valid data in `addr`.
        unsafe fn from_raw(
            addr: *const libc::sockaddr,
            len: Option<libc::socklen_t>,
        ) -> Option<Self>
        where
            Self: Sized;

        /// Initialize the storage for this socket address, such that after calling this function,
        /// the memory representation of the argument is either valid or *provably* invalid for `Self`.
        fn init_storage(buf: &mut MaybeUninit<Self>)
        where
            Self: Sized,
        {
            // The family of a zero-initialized socket address is `AF_UNSPEC`. A zeroed storage
            // is always valid for this address family.
            *buf = MaybeUninit::zeroed();
        }
    }
}

/// # Safety
///
/// For implementors of this trait, `&Self::Storage` must be castable to `&libc::sockaddr` (usually this requires
/// that `Self::Storage` is `#[repr(C)]`).
///
/// Furthermore, the following invariants must hold:
///
/// - `Self::init_storage` must initialize its argument in a way, such that after calling this function,
/// the memory representation of the argument must be either valid or *provably* invalid for `Self`.
///
/// - `Self::from_raw` must run the invalidity checks setuped by `Self::init_storage`.
pub unsafe trait SockaddrFromRaw {
    /// The libc storage type for this socket address.
    type Storage;

    /// Unsafe constructor from a variable length source.
    ///
    /// Some C APIs from provide `len`, and others do not.  If it's provided it
    /// will be validated.  If not, it will be guessed based on the family.
    ///
    /// # Safety
    ///
    /// One of the following must be true:
    ///
    /// - `addr` must be valid `Self::Storage`.
    /// - `addr` has been initialized with `Self::init_storage`.
    ///
    /// Additionally, if `addr` is valid for `Self::Storage`, then `len` must not exceed the
    /// length of valid data in `addr`.
    unsafe fn from_raw(
        addr: *const Self::Storage,
        len: libc::socklen_t,
    ) -> Self
    where
        Self: Sized;

    /// Initialize the storage for this socket address, such that after calling this function,
    /// the memory representation of the argument is either valid or *provably* invalid for `Self`.
    fn init_storage(buf: &mut MaybeUninit<Self::Storage>);
}


/// Anything that, in C, can be cast back and forth to `sockaddr`.
///
/// Most implementors also implement `AsRef<libc::XXX>` to access their
/// inner type read-only.
///
/// This trait is [sealed] and cannot be implemented inside other crates.
///
/// [sealed]: https://rust-lang.github.io/api-guidelines/future-proofing.html#sealed-traits-protect-against-downstream-implementations-c-sealed

// SAFETY: the invariants of `Self::len` must be upheld by all implementors.
#[allow(clippy::len_without_is_empty)]
#[allow(clippy::missing_safety_doc)]
pub unsafe trait SockaddrLike: private::SockaddrLikePriv {
    /// Returns a raw pointer to the inner structure.  Useful for FFI.
    fn as_ptr(&self) -> *const libc::sockaddr {
        self as *const Self as *const libc::sockaddr
    }

    /// Return the address family of this socket.
    ///
    /// # Examples
    /// One common use is to match on the family of a union type, like this:
    /// ```
    /// # use nix::sys::socket::*;
    /// # use std::os::unix::io::AsRawFd;
    /// let fd = socket(AddressFamily::INET, SockType::Stream,
    ///     SockFlag::empty(), None).unwrap();
    /// let ss: SockaddrStorage = getsockname(fd.as_raw_fd()).unwrap();
    /// match ss.family() {
    ///     AddressFamily::INET => println!("{}", ss.as_sockaddr_in().unwrap()),
    ///     AddressFamily::INET6 => println!("{}", ss.as_sockaddr_in6().unwrap()),
    ///     _ => println!("Unexpected address family")
    /// }
    /// ```
    fn family(&self) -> AddressFamily {
        // SAFETY: safe because of guarantees provided by `SockaddrLikePriv`.
        unsafe {
            AddressFamily((*(self as *const Self as *const libc::sockaddr)).sa_family as _)
        }
    }

    cfg_if! {
        if #[cfg(not(any(
            target_os = "android",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "linux",
            target_os = "redox",
        )))] {

            /// Return the length of valid data in the sockaddr structure.
            ///
            /// For fixed-size sockaddrs, this should be the size of the
            /// structure.  But for variable-sized types like [`UnixAddr`] it
            /// may be less.
            fn len(&self) -> libc::socklen_t {
                // SAFETY: all references of implementors need to be castable to
                // `&libc::sockaddr`, as required by safety invariants of this trait.
                unsafe {
                    (*(self as *const Self as *const libc::sockaddr)).sa_len
                }.into()
            }
        } else {
            /// Return the length of valid data in the sockaddr structure.
            ///
            /// For fixed-size sockaddrs, this should be the size of the
            /// structure.  But for variable-sized types like [`UnixAddr`] it
            /// may be less.
            fn len(&self) -> libc::socklen_t;
        }
    }

    /// Return the available space in the structure
    fn size() -> libc::socklen_t
    where
        Self: Sized,
    {
        mem::size_of::<Self>() as libc::socklen_t
    }
}

macro_rules! sockaddr_len_static {
    () => {
        fn len(&self) -> libc::socklen_t {
            mem::size_of::<Self>() as libc::socklen_t
        }
    };
}

/// Empty address storage that can't be instantiated.
///
/// Will be replaced by `!` if that type ever [stabilizes].
///
/// [stabilizes]: https://github.com/rust-lang/rust/issues/35121
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoAddress {}

// SAFETY: `Self` (and thus `&self`) cannot be instantiated, meaning the safety
// invariant regarding `&self` can be ignored.
//
// `Self::from_raw` always returns `None`, which is always safe. Therefore, `Self::init_storage`
// can be a no-op.
unsafe impl private::SockaddrLikePriv for NoAddress {
    unsafe fn from_raw(
        _: *const libc::sockaddr,
        _: Option<libc::socklen_t>,
    ) -> Option<Self> {
        None
    }

    fn init_storage(_: &mut MaybeUninit<Self>) {
        // Nothing to do
    }
}

unsafe impl SockaddrFromRaw for () {
    type Storage = NoAddress;

    unsafe fn from_raw(
        _: *const Self::Storage,
        _: libc::socklen_t,
    ) -> Self {
        // Returns `()`
    }

    fn init_storage(_: &mut MaybeUninit<Self::Storage>) {
        // Nothing to do
    }
}

// SAFETY: `Self` is ZST, so `Self::len` returns 0, which is always safe.
unsafe impl SockaddrLike for NoAddress {
    sockaddr_len_static!();
}

/// A wrapper around `sockaddr_un`.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct UnixAddr {
    // INVARIANT: sun & sun_len are valid as defined by docs for from_raw_parts
    sun: libc::sockaddr_un,
    /// The length of the valid part of `sun`, including the sun_family field
    /// but excluding any trailing nul.
    // On the BSDs, this field is built into sun
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "linux",
        target_os = "redox",
    ))]
    sun_len: u8,
}

// linux man page unix(7) says there are 3 kinds of unix socket:
// pathname: addrlen = offsetof(struct sockaddr_un, sun_path) + strlen(sun_path) + 1
// unnamed: addrlen = sizeof(sa_family_t)
// abstract: addren > sizeof(sa_family_t), name = sun_path[..(addrlen - sizeof(sa_family_t))]
//
// what we call path_len = addrlen - offsetof(struct sockaddr_un, sun_path)
#[derive(PartialEq, Eq, Hash)]
enum UnixAddrKind<'a> {
    Pathname(&'a Path),
    Unnamed,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    Abstract(&'a [u8]),
}
impl<'a> UnixAddrKind<'a> {
    /// Safety: sun & sun_len must be valid
    #[allow(clippy::unnecessary_cast)]   // Not unnecessary on all platforms
    unsafe fn get(sun: &'a libc::sockaddr_un, sun_len: u8) -> Self {
        assert!(sun_len as usize >= offset_of!(libc::sockaddr_un, sun_path));
        let path_len =
            sun_len as usize - offset_of!(libc::sockaddr_un, sun_path);
        if path_len == 0 {
            return Self::Unnamed;
        }
        #[cfg(any(target_os = "android", target_os = "linux"))]
        if sun.sun_path[0] == 0 {
            let name = slice::from_raw_parts(
                sun.sun_path.as_ptr().add(1).cast(),
                path_len - 1,
            );
            return Self::Abstract(name);
        }
        let pathname =
            slice::from_raw_parts(sun.sun_path.as_ptr().cast(), path_len);
        if pathname.last() == Some(&0) {
            // A trailing NUL is not considered part of the path, and it does
            // not need to be included in the addrlen passed to functions like
            // bind().  However, Linux adds a trailing NUL, even if one was not
            // originally present, when returning addrs from functions like
            // getsockname() (the BSDs do not do that).  So we need to filter
            // out any trailing NUL here, so sockaddrs can round-trip through
            // the kernel and still compare equal.
            Self::Pathname(Path::new(OsStr::from_bytes(
                &pathname[0..pathname.len() - 1],
            )))
        } else {
            Self::Pathname(Path::new(OsStr::from_bytes(pathname)))
        }
    }
}

impl UnixAddr {
    /// Create a new sockaddr_un representing a filesystem path.
    #[allow(clippy::unnecessary_cast)]   // Not unnecessary on all platforms
    pub fn new<P: ?Sized + NixPath>(path: &P) -> Result<UnixAddr> {
        path.with_nix_path(|cstr| unsafe {
            let mut ret = libc::sockaddr_un {
                sun_family: libc::AF_UNIX as sa_family_t,
                ..mem::zeroed()
            };

            let bytes = cstr.to_bytes();

            if bytes.len() >= ret.sun_path.len() {
                return Err(Errno::ENAMETOOLONG);
            }

            let sun_len = (bytes.len()
                + offset_of!(libc::sockaddr_un, sun_path))
            .try_into()
            .unwrap();

            #[cfg(any(
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd"
            ))]
            {
                ret.sun_len = sun_len;
            }
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                ret.sun_path.as_mut_ptr().cast(),
                bytes.len(),
            );

            Ok(UnixAddr::from_raw_parts(ret, sun_len))
        })?
    }

    /// Create a new `sockaddr_un` representing an address in the "abstract namespace".
    ///
    /// The leading nul byte for the abstract namespace is automatically added;
    /// thus the input `path` is expected to be the bare name, not NUL-prefixed.
    /// This is a Linux-specific extension, primarily used to allow chrooted
    /// processes to communicate with processes having a different filesystem view.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    #[allow(clippy::unnecessary_cast)]   // Not unnecessary on all platforms
    pub fn new_abstract(path: &[u8]) -> Result<UnixAddr> {
        unsafe {
            let mut ret = libc::sockaddr_un {
                sun_family: libc::AF_UNIX as sa_family_t,
                ..mem::zeroed()
            };

            if path.len() >= ret.sun_path.len() {
                return Err(Errno::ENAMETOOLONG);
            }
            let sun_len =
                (path.len() + 1 + offset_of!(libc::sockaddr_un, sun_path))
                    .try_into()
                    .unwrap();

            // Abstract addresses are represented by sun_path[0] ==
            // b'\0', so copy starting one byte in.
            ptr::copy_nonoverlapping(
                path.as_ptr(),
                ret.sun_path.as_mut_ptr().offset(1).cast(),
                path.len(),
            );

            Ok(UnixAddr::from_raw_parts(ret, sun_len))
        }
    }

    /// Create a new `sockaddr_un` representing an "unnamed" unix socket address.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    pub fn new_unnamed() -> UnixAddr {
        let ret = libc::sockaddr_un {
            sun_family: libc::AF_UNIX as sa_family_t,
            ..unsafe { mem::zeroed() }
        };

        let sun_len: u8 =
            offset_of!(libc::sockaddr_un, sun_path).try_into().unwrap();

        unsafe { UnixAddr::from_raw_parts(ret, sun_len) }
    }

    /// Create a UnixAddr from a raw `sockaddr_un` struct and a size. `sun_len`
    /// is the size of the valid portion of the struct, excluding any trailing
    /// NUL.
    ///
    /// # Safety
    /// This pair of sockaddr_un & sun_len must be a valid unix addr, which
    /// means:
    /// - sun_len >= offset_of(sockaddr_un, sun_path)
    /// - sun_len <= sockaddr_un.sun_path.len() - offset_of(sockaddr_un, sun_path)
    /// - if this is a unix addr with a pathname, sun.sun_path is a
    ///   fs path, not necessarily nul-terminated.
    pub(crate) unsafe fn from_raw_parts(
        sun: libc::sockaddr_un,
        sun_len: u8,
    ) -> UnixAddr {
        cfg_if! {
            if #[cfg(any(target_os = "android",
                     target_os = "fuchsia",
                     target_os = "illumos",
                     target_os = "linux",
                     target_os = "redox",
                ))]
            {
                UnixAddr { sun, sun_len }
            } else {
                assert_eq!(sun_len, sun.sun_len);
                UnixAddr {sun}
            }
        }
    }

    fn kind(&self) -> UnixAddrKind<'_> {
        // SAFETY: our sockaddr is always valid because of the invariant on the struct
        unsafe { UnixAddrKind::get(&self.sun, self.sun_len()) }
    }

    /// If this address represents a filesystem path, return that path.
    pub fn path(&self) -> Option<&Path> {
        match self.kind() {
            UnixAddrKind::Pathname(path) => Some(path),
            _ => None,
        }
    }

    /// If this address represents an abstract socket, return its name.
    ///
    /// For abstract sockets only the bare name is returned, without the
    /// leading NUL byte. `None` is returned for unnamed or path-backed sockets.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    pub fn as_abstract(&self) -> Option<&[u8]> {
        match self.kind() {
            UnixAddrKind::Abstract(name) => Some(name),
            _ => None,
        }
    }

    /// Check if this address is an "unnamed" unix socket address.
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    #[inline]
    pub fn is_unnamed(&self) -> bool {
        matches!(self.kind(), UnixAddrKind::Unnamed)
    }

    /// Returns the addrlen of this socket - `offsetof(struct sockaddr_un, sun_path)`
    #[inline]
    pub fn path_len(&self) -> usize {
        self.sun_len() as usize - offset_of!(libc::sockaddr_un, sun_path)
    }
    /// Returns a pointer to the raw `sockaddr_un` struct
    #[inline]
    pub fn as_ptr(&self) -> *const libc::sockaddr_un {
        &self.sun
    }
    /// Returns a mutable pointer to the raw `sockaddr_un` struct
    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut libc::sockaddr_un {
        &mut self.sun
    }

    fn sun_len(&self) -> u8 {
        cfg_if! {
            if #[cfg(any(target_os = "android",
                     target_os = "fuchsia",
                     target_os = "illumos",
                     target_os = "linux",
                     target_os = "redox",
                ))]
            {
                self.sun_len
            } else {
                self.sun.sun_len
            }
        }
    }
}

unsafe impl private::SockaddrLikePriv for UnixAddr {
    unsafe fn from_raw(
        addr: *const libc::sockaddr,
        len: Option<libc::socklen_t>,
    ) -> Option<Self> {
        if let Some(l) = len {
            if (l as usize) < offset_of!(libc::sockaddr_un, sun_path)
                || l > u8::MAX as libc::socklen_t
            {
                return None;
            }
        }

        // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
        unsafe {
            if addr_of!((*addr).sa_family).read() as libc::c_int != libc::AF_UNIX {
                return None;
            }
        }

        let mut su: libc::sockaddr_un = mem::zeroed();
        let sup = &mut su as *mut libc::sockaddr_un as *mut u8;
        cfg_if! {
            if #[cfg(any(target_os = "android",
                         target_os = "fuchsia",
                         target_os = "illumos",
                         target_os = "linux",
                         target_os = "redox",
                ))] {
                let su_len = len.unwrap_or(
                    mem::size_of::<libc::sockaddr_un>() as libc::socklen_t
                );
            } else {
                let su_len = len.unwrap_or((*addr).sa_len as libc::socklen_t);
            }
        };
        ptr::copy(addr as *const u8, sup, su_len as usize);
        Some(Self::from_raw_parts(su, su_len as u8))
    }

    fn init_storage(buf: &mut MaybeUninit<Self>) {
        // The family of `Self` is `AF_UNIX`, so setting the family to `AF_UNSPEC` is sufficient.
        let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
        unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
    }
}

unsafe impl SockaddrFromRaw for Option<UnixAddr> {
    type Storage = libc::sockaddr_un;

    unsafe fn from_raw(
        addr: *const Self::Storage,
        len: libc::socklen_t,
    ) -> Self {

        if (len as usize) < offset_of!(libc::sockaddr_un, sun_path)
            || len > u8::MAX as libc::socklen_t
        {
            return None;
        }

        // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
        unsafe {
            if addr_of!((*addr).sun_family).read() as libc::c_int != libc::AF_UNIX {
                return None;
            }
        }

        let mut su = MaybeUninit::<libc::sockaddr_un>::zeroed();

        unsafe {
            ptr::copy_nonoverlapping(addr, su.as_mut_ptr(), 1);

            Some(UnixAddr::from_raw_parts(su.assume_init(), len as u8))
        }
    }

    fn init_storage(buf: &mut MaybeUninit<Self::Storage>) {
        // The family of `Self` is `AF_UNIX`, so setting the family to `AF_UNSPEC` is sufficient.
        let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
        unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
    }
}

unsafe impl SockaddrFromRaw for MaybeUninit<UnixAddr> {
    type Storage = libc::sockaddr_un;

    unsafe fn from_raw(
        addr: *const Self::Storage,
        _len: libc::socklen_t,
    ) -> Self {
        let mut unix_addr = MaybeUninit::<UnixAddr>::uninit();
        let unix_addr_ptr = unix_addr.as_mut_ptr();

        unsafe {
            ptr::copy_nonoverlapping(addr.cast(), addr_of_mut!((*unix_addr_ptr).sun), 1);

            #[cfg(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "illumos",
                target_os = "linux",
                target_os = "redox",
            ))]
            addr_of_mut!((*unix_addr_ptr).sun_len).write(_len as u8);
        }

        unix_addr
    }

    fn init_storage(_: &mut MaybeUninit<Self::Storage>) {
        // Nothing to do
    }
}

unsafe impl SockaddrLike for UnixAddr {
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "linux",
        target_os = "redox",
    ))]
    fn len(&self) -> libc::socklen_t {
        self.sun_len.into()
    }


    fn size() -> libc::socklen_t {
        mem::size_of::<libc::sockaddr_un>() as libc::socklen_t
    }

}

impl AsRef<libc::sockaddr_un> for UnixAddr {
    fn as_ref(&self) -> &libc::sockaddr_un {
        &self.sun
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn fmt_abstract(abs: &[u8], f: &mut fmt::Formatter) -> fmt::Result {
    use fmt::Write;
    f.write_str("@\"")?;
    for &b in abs {
        use fmt::Display;
        char::from(b).escape_default().fmt(f)?;
    }
    f.write_char('"')?;
    Ok(())
}

impl fmt::Display for UnixAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.kind() {
            UnixAddrKind::Pathname(path) => path.display().fmt(f),
            UnixAddrKind::Unnamed => f.pad("<unbound UNIX socket>"),
            #[cfg(any(target_os = "android", target_os = "linux"))]
            UnixAddrKind::Abstract(name) => fmt_abstract(name, f),
        }
    }
}

impl PartialEq for UnixAddr {
    fn eq(&self, other: &UnixAddr) -> bool {
        self.kind() == other.kind()
    }
}

impl Eq for UnixAddr {}

impl Hash for UnixAddr {
    fn hash<H: Hasher>(&self, s: &mut H) {
        self.kind().hash(s)
    }
}

/// An IPv4 socket address
#[cfg(feature = "net")]
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SockaddrIn(libc::sockaddr_in);

#[cfg(feature = "net")]
impl SockaddrIn {
    /// Returns the IP address associated with this socket address, in native
    /// endian.
    pub const fn ip(&self) -> libc::in_addr_t {
        u32::from_be(self.0.sin_addr.s_addr)
    }

    /// Creates a new socket address from IPv4 octets and a port number.
    pub fn new(a: u8, b: u8, c: u8, d: u8, port: u16) -> Self {
        Self(libc::sockaddr_in {
            #[cfg(any(
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "aix",
                target_os = "haiku",
                target_os = "openbsd"
            ))]
            sin_len: Self::size() as u8,
            sin_family: libc::AF_INET as sa_family_t,
            sin_port: u16::to_be(port),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes([a, b, c, d]),
            },
            sin_zero: unsafe { mem::zeroed() },
        })
    }

    /// Returns the port number associated with this socket address, in native
    /// endian.
    pub const fn port(&self) -> u16 {
        u16::from_be(self.0.sin_port)
    }
}

#[cfg(feature = "net")]
unsafe impl private::SockaddrLikePriv for SockaddrIn {
    unsafe fn from_raw(
        addr: *const libc::sockaddr,
        len: Option<libc::socklen_t>,
    ) -> Option<Self> {
        if let Some(l) = len {
            if l != mem::size_of::<libc::sockaddr_in>() as libc::socklen_t {
                return None;
            }
        }

        // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
        unsafe {
            if addr_of!((*addr).sa_family).read() as libc::c_int != libc::AF_INET {
                return None;
            }
        }

        Some(Self(ptr::read_unaligned(addr as *const _)))
    }

    fn init_storage(buf: &mut MaybeUninit<Self>) {
        // The family of `Self` is `AF_INET`, so setting the family to `AF_UNSPEC` is sufficient.
        let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
        unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
    }
}

#[cfg(feature = "net")]
unsafe impl SockaddrFromRaw for Option<SockaddrIn> {
    type Storage = libc::sockaddr_in;

    unsafe fn from_raw(
        addr: *const Self::Storage,
        len: libc::socklen_t,
    ) -> Self {
        if len != mem::size_of::<libc::sockaddr_in>() as libc::socklen_t {
            return None;
        }

        // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
        unsafe {
            if addr_of!((*addr).sin_family).read() as libc::c_int != libc::AF_INET {
                return None;
            }
        }

        Some(SockaddrIn(ptr::read(addr)))
    }

    fn init_storage(buf: &mut MaybeUninit<Self::Storage>) {
        // The family of `Self` is `AF_INET`, so setting the family to `AF_UNSPEC` is sufficient.
        let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
        unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
    }
}

#[cfg(feature = "net")]
unsafe impl SockaddrFromRaw for MaybeUninit<SockaddrIn> {
    type Storage = libc::sockaddr_in;

    unsafe fn from_raw(
        addr: *const Self::Storage,
        _: libc::socklen_t,
    ) -> Self {
        let mut res = MaybeUninit::<SockaddrIn>::uninit();

        unsafe {
            ptr::copy_nonoverlapping(addr, res.as_mut_ptr().cast(), 1);
        }

        res
    }

    fn init_storage(_: &mut MaybeUninit<Self::Storage>) {
        // Nothing to do
    }
}

#[cfg(feature = "net")]
unsafe impl SockaddrLike for SockaddrIn {
    sockaddr_len_static!();
}

#[cfg(feature = "net")]
impl AsRef<libc::sockaddr_in> for SockaddrIn {
    fn as_ref(&self) -> &libc::sockaddr_in {
        &self.0
    }
}

#[cfg(feature = "net")]
impl fmt::Display for SockaddrIn {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ne = u32::from_be(self.0.sin_addr.s_addr);
        let port = u16::from_be(self.0.sin_port);
        write!(
            f,
            "{}.{}.{}.{}:{}",
            ne >> 24,
            (ne >> 16) & 0xFF,
            (ne >> 8) & 0xFF,
            ne & 0xFF,
            port
        )
    }
}

#[cfg(feature = "net")]
impl From<net::SocketAddrV4> for SockaddrIn {
    fn from(addr: net::SocketAddrV4) -> Self {
        Self(libc::sockaddr_in {
            #[cfg(any(
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "haiku",
                target_os = "hermit",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd"
            ))]
            sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
            sin_family: libc::AF_INET as sa_family_t,
            sin_port: addr.port().to_be(), // network byte order
            sin_addr: ipv4addr_to_libc(*addr.ip()),
            ..unsafe { mem::zeroed() }
        })
    }
}

#[cfg(feature = "net")]
impl From<SockaddrIn> for net::SocketAddrV4 {
    fn from(addr: SockaddrIn) -> Self {
        net::SocketAddrV4::new(
            net::Ipv4Addr::from(addr.0.sin_addr.s_addr.to_ne_bytes()),
            u16::from_be(addr.0.sin_port),
        )
    }
}

#[cfg(feature = "net")]
impl std::str::FromStr for SockaddrIn {
    type Err = net::AddrParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        net::SocketAddrV4::from_str(s).map(SockaddrIn::from)
    }
}

/// An IPv6 socket address
#[cfg(feature = "net")]
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SockaddrIn6(libc::sockaddr_in6);

#[cfg(feature = "net")]
impl SockaddrIn6 {
    /// Returns the flow information associated with this address.
    pub const fn flowinfo(&self) -> u32 {
        self.0.sin6_flowinfo
    }

    /// Returns the IP address associated with this socket address.
    pub fn ip(&self) -> net::Ipv6Addr {
        net::Ipv6Addr::from(self.0.sin6_addr.s6_addr)
    }

    /// Returns the port number associated with this socket address, in native
    /// endian.
    pub const fn port(&self) -> u16 {
        u16::from_be(self.0.sin6_port)
    }

    /// Returns the scope ID associated with this address.
    pub const fn scope_id(&self) -> u32 {
        self.0.sin6_scope_id
    }
}

#[cfg(feature = "net")]
unsafe impl SockaddrFromRaw for Option<SockaddrIn6> {
    type Storage = libc::sockaddr_in6;

    unsafe fn from_raw(
        addr: *const Self::Storage,
        len: libc::socklen_t,
    ) -> Self {
        if len != mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t {
            return None;
        }

        // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
        unsafe {
            if addr_of!((*addr).sin6_family).read() as libc::c_int != libc::AF_INET {
                return None;
            }
        }

        Some(SockaddrIn6(ptr::read(addr)))
    }

    fn init_storage(buf: &mut MaybeUninit<Self::Storage>) {
        // The family of `Self` is `AF_INET`, so setting the family to `AF_UNSPEC` is sufficient.
        let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
        unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
    }
}

#[cfg(feature = "net")]
unsafe impl SockaddrFromRaw for MaybeUninit<SockaddrIn6> {
    type Storage = libc::sockaddr_in6;

    unsafe fn from_raw(
        addr: *const Self::Storage,
        _: libc::socklen_t,
    ) -> Self {
        let mut res = MaybeUninit::<SockaddrIn6>::uninit();

        unsafe {
            ptr::copy_nonoverlapping(addr, res.as_mut_ptr().cast(), 1);
        }

        res
    }

    fn init_storage(_: &mut MaybeUninit<Self::Storage>) {
        // Nothing to do
    }
}

#[cfg(feature = "net")]
unsafe impl private::SockaddrLikePriv for SockaddrIn6 {
    unsafe fn from_raw(
        addr: *const libc::sockaddr,
        len: Option<libc::socklen_t>,
    ) -> Option<Self> {
        if let Some(l) = len {
            if l != mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t {
                return None;
            }
        }

        // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
        unsafe {
            if addr_of!((*addr).sa_family).read() as libc::c_int != libc::AF_INET6 {
                return None;
            }
        }

        Some(Self(ptr::read_unaligned(addr as *const _)))
    }

    fn init_storage(buf: &mut MaybeUninit<Self>) {
        // The family of `Self` is `AF_INE6T`, so setting the family to `AF_UNSPEC` is sufficient.
        let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
        unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
    }
}
#[cfg(feature = "net")]
unsafe impl SockaddrLike for SockaddrIn6 {
    sockaddr_len_static!();
}

#[cfg(feature = "net")]
impl AsRef<libc::sockaddr_in6> for SockaddrIn6 {
    fn as_ref(&self) -> &libc::sockaddr_in6 {
        &self.0
    }
}

#[cfg(feature = "net")]
impl fmt::Display for SockaddrIn6 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // These things are really hard to display properly.  Easier to let std
        // do it.
        let std = net::SocketAddrV6::new(
            self.ip(),
            self.port(),
            self.flowinfo(),
            self.scope_id(),
        );
        std.fmt(f)
    }
}

#[cfg(feature = "net")]
impl From<net::SocketAddrV6> for SockaddrIn6 {
    fn from(addr: net::SocketAddrV6) -> Self {
        #[allow(clippy::needless_update)] // It isn't needless on Illumos
        Self(libc::sockaddr_in6 {
            #[cfg(any(
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "haiku",
                target_os = "hermit",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "openbsd"
            ))]
            sin6_len: mem::size_of::<libc::sockaddr_in6>() as u8,
            sin6_family: libc::AF_INET6 as sa_family_t,
            sin6_port: addr.port().to_be(), // network byte order
            sin6_addr: ipv6addr_to_libc(addr.ip()),
            sin6_flowinfo: addr.flowinfo(), // host byte order
            sin6_scope_id: addr.scope_id(), // host byte order
            ..unsafe { mem::zeroed() }
        })
    }
}

#[cfg(feature = "net")]
impl From<SockaddrIn6> for net::SocketAddrV6 {
    fn from(addr: SockaddrIn6) -> Self {
        net::SocketAddrV6::new(
            net::Ipv6Addr::from(addr.0.sin6_addr.s6_addr),
            u16::from_be(addr.0.sin6_port),
            addr.0.sin6_flowinfo,
            addr.0.sin6_scope_id,
        )
    }
}

#[cfg(feature = "net")]
impl std::str::FromStr for SockaddrIn6 {
    type Err = net::AddrParseError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        net::SocketAddrV6::from_str(s).map(SockaddrIn6::from)
    }
}

/// Socket address storage
#[derive(Debug, Clone, Copy)]
pub struct SockaddrStorageWrapper {
    storage: SockaddrStorage,
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "linux",
        target_os = "redox",
    ))]
    len: libc::socklen_t,
}

#[allow(clippy::len_without_is_empty)]
impl SockaddrStorageWrapper {
    /// Returns the length of the socket address.
    pub fn len(&self) -> usize {
        cfg_if! {
            if #[cfg(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "illumos",
                target_os = "linux",
                target_os = "redox",
            ))] {
                self.len as usize
            } else {
                unsafe {
                    self.storage.ss.ss_len as usize
                }
            }
        }
    }

    /// Returns the inner storage.
    pub fn into_inner(self) -> SockaddrStorage {
        self.storage
    }
}

impl std::ops::Deref for SockaddrStorageWrapper {
    type Target = SockaddrStorage;

    fn deref(&self) -> &Self::Target {
        &self.storage
    }
}

/// A container for any sockaddr type
///
/// Just like C's `sockaddr_storage`, this type is large enough to hold any type
/// of sockaddr.  It can be used as an argument with functions like
/// [`bind`](super::bind) and [`getsockname`](super::getsockname).  Though it is
/// a union, it can be safely accessed through the `as_*` methods.
///
/// # Example
/// ```
/// # use nix::sys::socket::*;
/// # use std::str::FromStr;
/// # use std::os::unix::io::AsRawFd;
/// let localhost = SockaddrIn::from_str("127.0.0.1:8081").unwrap();
/// let fd = socket(AddressFamily::INET, SockType::Stream, SockFlag::empty(),
///     None).unwrap();
/// bind(fd.as_raw_fd(), &localhost).expect("bind");
/// let ss: SockaddrStorage = getsockname(fd.as_raw_fd()).expect("getsockname");
/// assert_eq!(&localhost, ss.as_sockaddr_in().unwrap());
/// ```
#[derive(Clone, Copy, Eq)]
#[repr(C)]
pub union SockaddrStorage {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    alg: AlgAddr,
    #[cfg(all(feature = "net", not(target_os = "redox")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "net")))]
    dl: LinkAddr,
    #[cfg(any(target_os = "android", target_os = "linux"))]
    nl: NetlinkAddr,
    #[cfg(all(
        feature = "ioctl",
        any(target_os = "ios", target_os = "macos")
    ))]
    #[cfg_attr(docsrs, doc(cfg(feature = "ioctl")))]
    sctl: SysControlAddr,
    #[cfg(feature = "net")]
    sin: SockaddrIn,
    #[cfg(feature = "net")]
    sin6: SockaddrIn6,
    ss: libc::sockaddr_storage,
    su: UnixAddr,
    #[cfg(any(target_os = "android", target_os = "linux", target_os = "macos" ))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    vsock: VsockAddr,
}

unsafe impl SockaddrFromRaw for SockaddrStorageWrapper {
    type Storage = libc::sockaddr_storage;

    unsafe fn from_raw(
        addr: *const Self::Storage,
        _len: libc::socklen_t,
    ) -> Self {
        let ss = unsafe { SockaddrStorage { ss: ptr::read(addr) } };

        SockaddrStorageWrapper {
            storage: ss,
            #[cfg(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "illumos",
                target_os = "linux",
                target_os = "redox",
            ))]
            len: _len,
        }
    }

    fn init_storage(buf: &mut MaybeUninit<Self::Storage>) {
        unsafe {
            buf.as_mut_ptr().write_bytes(0u8, 1);
        }
    }
}

unsafe impl SockaddrFromRaw for MaybeUninit<SockaddrStorageWrapper> {
    type Storage = libc::sockaddr_storage;

    unsafe fn from_raw(
        addr: *const Self::Storage,
        _len: libc::socklen_t,
    ) -> Self {
        let mut res = MaybeUninit::<SockaddrStorageWrapper>::uninit();
        let res_ptr = res.as_mut_ptr();

        unsafe {
            ptr::copy_nonoverlapping(addr.cast(), addr_of_mut!((*res_ptr).storage), 1);

            #[cfg(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "illumos",
                target_os = "linux",
                target_os = "redox",
            ))]
            addr_of_mut!((*res_ptr).len).write(_len);
        }

        res
    }

    fn init_storage(_: &mut MaybeUninit<Self::Storage>) {
        // Nothing to do
    }
}

unsafe impl private::SockaddrLikePriv for SockaddrStorage {
    unsafe fn from_raw(
        addr: *const libc::sockaddr,
        l: Option<libc::socklen_t>,
    ) -> Option<Self> {
        if addr.is_null() {
            return None;
        }
        if let Some(len) = l {
            let ulen = len as usize;
            if ulen < offset_of!(libc::sockaddr, sa_data)
                || ulen > mem::size_of::<libc::sockaddr_storage>()
            {
                None
            } else {
                let mut ss: libc::sockaddr_storage = mem::zeroed();
                let ssp = &mut ss as *mut libc::sockaddr_storage as *mut u8;
                ptr::copy(addr as *const u8, ssp, len as usize);
                #[cfg(any(
                    target_os = "android",
                    target_os = "fuchsia",
                    target_os = "illumos",
                    target_os = "linux"
                ))]
                if i32::from(ss.ss_family) == libc::AF_UNIX {
                    // Safe because we UnixAddr is strictly smaller than
                    // SockaddrStorage, and we just initialized the structure.
                    (*(&mut ss as *mut libc::sockaddr_storage
                        as *mut UnixAddr))
                        .sun_len = len as u8;
                }
                Some(Self { ss })
            }
        } else {
            // If length is not available and addr is of a fixed-length type,
            // copy it.  If addr is of a variable length type and len is not
            // available, then there's nothing we can do.
            match (*addr).sa_family as i32 {
                #[cfg(any(target_os = "android", target_os = "linux"))]
                libc::AF_ALG => {
                    AlgAddr::from_raw(addr, l).map(|alg| Self { alg })
                }
                #[cfg(feature = "net")]
                libc::AF_INET => {
                    SockaddrIn::from_raw(addr, l).map(|sin| Self { sin })
                }
                #[cfg(feature = "net")]
                libc::AF_INET6 => {
                    SockaddrIn6::from_raw(addr, l).map(|sin6| Self { sin6 })
                }
                #[cfg(any(
                    target_os = "dragonfly",
                    target_os = "freebsd",
                    target_os = "ios",
                    target_os = "macos",
                    target_os = "illumos",
                    target_os = "netbsd",
                    target_os = "haiku",
                    target_os = "openbsd"
                ))]
                #[cfg(feature = "net")]
                libc::AF_LINK => {
                    LinkAddr::from_raw(addr, l).map(|dl| Self { dl })
                }
                #[cfg(any(target_os = "android", target_os = "linux"))]
                libc::AF_NETLINK => {
                    NetlinkAddr::from_raw(addr, l).map(|nl| Self { nl })
                }
                #[cfg(any(
                    target_os = "android",
                    target_os = "fuchsia",
                    target_os = "linux"
                ))]
                #[cfg(feature = "net")]
                libc::AF_PACKET => {
                    LinkAddr::from_raw(addr, l).map(|dl| Self { dl })
                }
                #[cfg(all(
                    feature = "ioctl",
                    any(target_os = "ios", target_os = "macos")
                ))]
                libc::AF_SYSTEM => {
                    SysControlAddr::from_raw(addr, l).map(|sctl| Self { sctl })
                }
                #[cfg(any(target_os = "android", target_os = "linux", target_os = "macos" ))]
                libc::AF_VSOCK => {
                    VsockAddr::from_raw(addr, l).map(|vsock| Self { vsock })
                }
                _ => None,
            }
        }
    }
}

unsafe impl SockaddrLike for SockaddrStorage {
    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "illumos",
        target_os = "linux",
        target_os = "redox",
    ))]
    fn len(&self) -> libc::socklen_t {
        match self.as_unix_addr() {
            // The UnixAddr type knows its own length
            Some(ua) => ua.len(),
            // For all else, we're just a boring SockaddrStorage
            None => mem::size_of_val(self) as libc::socklen_t,
        }
    }
}

macro_rules! accessors {
    (
        $fname:ident,
        $fname_mut:ident,
        $sockty:ty,
        $family:expr,
        $libc_ty:ty,
        $field:ident) => {
        /// Safely and falliably downcast to an immutable reference
        pub fn $fname(&self) -> Option<&$sockty> {
            if self.family() == $family
                && self.len() >= mem::size_of::<$libc_ty>() as libc::socklen_t
            {
                // Safe because family and len are validated
                Some(unsafe { &self.$field })
            } else {
                None
            }
        }

        /// Safely and falliably downcast to a mutable reference
        pub fn $fname_mut(&mut self) -> Option<&mut $sockty> {
            if self.family() == $family
                && self.len() >= mem::size_of::<$libc_ty>() as libc::socklen_t
            {
                // Safe because family and len are validated
                Some(unsafe { &mut self.$field })
            } else {
                None
            }
        }
    };
}

impl SockaddrStorage {
    /// Downcast to an immutable `[UnixAddr]` reference.
    pub fn as_unix_addr(&self) -> Option<&UnixAddr> {
        cfg_if! {
            if #[cfg(any(target_os = "android",
                     target_os = "fuchsia",
                     target_os = "illumos",
                     target_os = "linux"
                ))]
            {
                let p = unsafe{ &self.ss as *const libc::sockaddr_storage };
                // Safe because UnixAddr is strictly smaller than
                // sockaddr_storage, and we're fully initialized
                let len = unsafe {
                    (*(p as *const UnixAddr )).sun_len as usize
                };
            } else {
                let len = self.len() as usize;
            }
        }
        // Sanity checks
        if self.family() != AddressFamily::UNIX
            || len < offset_of!(libc::sockaddr_un, sun_path)
            || len > mem::size_of::<libc::sockaddr_un>()
        {
            None
        } else {
            Some(unsafe { &self.su })
        }
    }

    /// Downcast to a mutable `[UnixAddr]` reference.
    pub fn as_unix_addr_mut(&mut self) -> Option<&mut UnixAddr> {
        cfg_if! {
            if #[cfg(any(target_os = "android",
                     target_os = "fuchsia",
                     target_os = "illumos",
                     target_os = "linux"
                ))]
            {
                let p = unsafe{ &self.ss as *const libc::sockaddr_storage };
                // Safe because UnixAddr is strictly smaller than
                // sockaddr_storage, and we're fully initialized
                let len = unsafe {
                    (*(p as *const UnixAddr )).sun_len as usize
                };
            } else {
                let len = self.len() as usize;
            }
        }
        // Sanity checks
        if self.family() != AddressFamily::UNIX
            || len < offset_of!(libc::sockaddr_un, sun_path)
            || len > mem::size_of::<libc::sockaddr_un>()
        {
            None
        } else {
            Some(unsafe { &mut self.su })
        }
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    accessors! {as_alg_addr, as_alg_addr_mut, AlgAddr,
    AddressFamily::ALG, libc::sockaddr_alg, alg}

    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux"
    ))]
    #[cfg(feature = "net")]
    accessors! {
    as_link_addr, as_link_addr_mut, LinkAddr,
    AddressFamily::PACKET, libc::sockaddr_ll, dl}

    #[cfg(any(
        target_os = "dragonfly",
        target_os = "freebsd",
        target_os = "ios",
        target_os = "macos",
        target_os = "illumos",
        target_os = "netbsd",
        target_os = "openbsd"
    ))]
    #[cfg(feature = "net")]
    accessors! {
    as_link_addr, as_link_addr_mut, LinkAddr,
    AddressFamily::LINK, libc::sockaddr_dl, dl}

    #[cfg(feature = "net")]
    accessors! {
    as_sockaddr_in, as_sockaddr_in_mut, SockaddrIn,
    AddressFamily::INET, libc::sockaddr_in, sin}

    #[cfg(feature = "net")]
    accessors! {
    as_sockaddr_in6, as_sockaddr_in6_mut, SockaddrIn6,
    AddressFamily::INET6, libc::sockaddr_in6, sin6}

    #[cfg(any(target_os = "android", target_os = "linux"))]
    accessors! {as_netlink_addr, as_netlink_addr_mut, NetlinkAddr,
    AddressFamily::NETLINK, libc::sockaddr_nl, nl}

    #[cfg(all(feature = "ioctl", any(target_os = "ios", target_os = "macos")))]
    #[cfg_attr(docsrs, doc(cfg(feature = "ioctl")))]
    accessors! {as_sys_control_addr, as_sys_control_addr_mut, SysControlAddr,
    AddressFamily::SYSTEM, libc::sockaddr_ctl, sctl}

    #[cfg(any(target_os = "android", target_os = "linux", target_os = "macos"))]
    #[cfg_attr(docsrs, doc(cfg(all())))]
    accessors! {as_vsock_addr, as_vsock_addr_mut, VsockAddr,
    AddressFamily::VSOCK, libc::sockaddr_vm, vsock}
}

impl fmt::Debug for SockaddrStorage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("SockaddrStorage")
            // Safe because sockaddr_storage has the least specific
            // field types
            .field("ss", unsafe { &self.ss })
            .finish()
    }
}

impl fmt::Display for SockaddrStorage {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            match self.ss.ss_family as i32 {
                #[cfg(any(target_os = "android", target_os = "linux"))]
                libc::AF_ALG => self.alg.fmt(f),
                #[cfg(feature = "net")]
                libc::AF_INET => self.sin.fmt(f),
                #[cfg(feature = "net")]
                libc::AF_INET6 => self.sin6.fmt(f),
                #[cfg(any(
                    target_os = "dragonfly",
                    target_os = "freebsd",
                    target_os = "ios",
                    target_os = "macos",
                    target_os = "illumos",
                    target_os = "netbsd",
                    target_os = "openbsd"
                ))]
                #[cfg(feature = "net")]
                libc::AF_LINK => self.dl.fmt(f),
                #[cfg(any(target_os = "android", target_os = "linux"))]
                libc::AF_NETLINK => self.nl.fmt(f),
                #[cfg(any(
                    target_os = "android",
                    target_os = "linux",
                    target_os = "fuchsia"
                ))]
                #[cfg(feature = "net")]
                libc::AF_PACKET => self.dl.fmt(f),
                #[cfg(any(target_os = "ios", target_os = "macos"))]
                #[cfg(feature = "ioctl")]
                libc::AF_SYSTEM => self.sctl.fmt(f),
                libc::AF_UNIX => self.su.fmt(f),
                #[cfg(any(target_os = "android", target_os = "linux", target_os = "macos"))]
                libc::AF_VSOCK => self.vsock.fmt(f),
                _ => "<Address family unspecified>".fmt(f),
            }
        }
    }
}

#[cfg(feature = "net")]
impl From<net::SocketAddrV4> for SockaddrStorage {
    fn from(s: net::SocketAddrV4) -> Self {
        unsafe {
            let mut ss: Self = mem::zeroed();
            ss.sin = SockaddrIn::from(s);
            ss
        }
    }
}

#[cfg(feature = "net")]
impl From<net::SocketAddrV6> for SockaddrStorage {
    fn from(s: net::SocketAddrV6) -> Self {
        unsafe {
            let mut ss: Self = mem::zeroed();
            ss.sin6 = SockaddrIn6::from(s);
            ss
        }
    }
}

#[cfg(feature = "net")]
impl From<net::SocketAddr> for SockaddrStorage {
    fn from(s: net::SocketAddr) -> Self {
        match s {
            net::SocketAddr::V4(sa4) => Self::from(sa4),
            net::SocketAddr::V6(sa6) => Self::from(sa6),
        }
    }
}

impl Hash for SockaddrStorage {
    fn hash<H: Hasher>(&self, s: &mut H) {
        unsafe {
            match self.ss.ss_family as i32 {
                #[cfg(any(target_os = "android", target_os = "linux"))]
                libc::AF_ALG => self.alg.hash(s),
                #[cfg(feature = "net")]
                libc::AF_INET => self.sin.hash(s),
                #[cfg(feature = "net")]
                libc::AF_INET6 => self.sin6.hash(s),
                #[cfg(any(
                    target_os = "dragonfly",
                    target_os = "freebsd",
                    target_os = "ios",
                    target_os = "macos",
                    target_os = "illumos",
                    target_os = "netbsd",
                    target_os = "openbsd"
                ))]
                #[cfg(feature = "net")]
                libc::AF_LINK => self.dl.hash(s),
                #[cfg(any(target_os = "android", target_os = "linux"))]
                libc::AF_NETLINK => self.nl.hash(s),
                #[cfg(any(
                    target_os = "android",
                    target_os = "linux",
                    target_os = "fuchsia"
                ))]
                #[cfg(feature = "net")]
                libc::AF_PACKET => self.dl.hash(s),
                #[cfg(any(target_os = "ios", target_os = "macos"))]
                #[cfg(feature = "ioctl")]
                libc::AF_SYSTEM => self.sctl.hash(s),
                libc::AF_UNIX => self.su.hash(s),
                #[cfg(any(target_os = "android", target_os = "linux", target_os = "macos"))]
                libc::AF_VSOCK => self.vsock.hash(s),
                _ => self.ss.hash(s),
            }
        }
    }
}

impl PartialEq for SockaddrStorage {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            match (self.ss.ss_family as i32, other.ss.ss_family as i32) {
                #[cfg(any(target_os = "android", target_os = "linux"))]
                (libc::AF_ALG, libc::AF_ALG) => self.alg == other.alg,
                #[cfg(feature = "net")]
                (libc::AF_INET, libc::AF_INET) => self.sin == other.sin,
                #[cfg(feature = "net")]
                (libc::AF_INET6, libc::AF_INET6) => self.sin6 == other.sin6,
                #[cfg(any(
                    target_os = "dragonfly",
                    target_os = "freebsd",
                    target_os = "ios",
                    target_os = "macos",
                    target_os = "illumos",
                    target_os = "netbsd",
                    target_os = "openbsd"
                ))]
                #[cfg(feature = "net")]
                (libc::AF_LINK, libc::AF_LINK) => self.dl == other.dl,
                #[cfg(any(target_os = "android", target_os = "linux"))]
                (libc::AF_NETLINK, libc::AF_NETLINK) => self.nl == other.nl,
                #[cfg(any(
                    target_os = "android",
                    target_os = "fuchsia",
                    target_os = "linux"
                ))]
                #[cfg(feature = "net")]
                (libc::AF_PACKET, libc::AF_PACKET) => self.dl == other.dl,
                #[cfg(any(target_os = "ios", target_os = "macos"))]
                #[cfg(feature = "ioctl")]
                (libc::AF_SYSTEM, libc::AF_SYSTEM) => self.sctl == other.sctl,
                (libc::AF_UNIX, libc::AF_UNIX) => self.su == other.su,
                #[cfg(any(target_os = "android", target_os = "linux", target_os = "macos"))]
                (libc::AF_VSOCK, libc::AF_VSOCK) => self.vsock == other.vsock,
                _ => false,
            }
        }
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[cfg_attr(docsrs, doc(cfg(all())))]
pub mod netlink {
    use super::*;
    use libc::{sa_family_t, sockaddr_nl};
    use std::{fmt, mem};

    /// Address for the Linux kernel user interface device.
    ///
    /// # References
    ///
    /// [netlink(7)](https://man7.org/linux/man-pages/man7/netlink.7.html)
    #[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
    #[repr(transparent)]
    pub struct NetlinkAddr(pub(in super::super) sockaddr_nl);

    impl NetlinkAddr {
        /// Construct a new socket address from its port ID and multicast groups
        /// mask.
        pub fn new(pid: u32, groups: u32) -> NetlinkAddr {
            let mut addr: sockaddr_nl = unsafe { mem::zeroed() };
            addr.nl_family = libc::AF_NETLINK as sa_family_t;
            addr.nl_pid = pid;
            addr.nl_groups = groups;

            NetlinkAddr(addr)
        }

        /// Return the socket's port ID.
        pub const fn pid(&self) -> u32 {
            self.0.nl_pid
        }

        /// Return the socket's multicast groups mask
        pub const fn groups(&self) -> u32 {
            self.0.nl_groups
        }
    }

    unsafe impl SockaddrFromRaw for Option<NetlinkAddr> {
        type Storage = libc::sockaddr_nl;

        unsafe fn from_raw(
            addr: *const Self::Storage,
            len: libc::socklen_t,
        ) -> Self {
            if len != mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t {
                return None;
            }

            // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
            unsafe {
                if addr_of!((*addr).nl_family).read() as libc::c_int != libc::AF_NETLINK {
                    return None;
                }
            }

            Some(NetlinkAddr(ptr::read(addr)))
        }

        fn init_storage(buf: &mut MaybeUninit<Self::Storage>) {
            // The family of `Self` is `AF_NETLINK`, so setting the family to `AF_UNSPEC` is sufficient.
            let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
            unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
        }
    }

    unsafe impl SockaddrFromRaw for MaybeUninit<NetlinkAddr> {
        type Storage = libc::sockaddr_nl;

        unsafe fn from_raw(
            addr: *const Self::Storage,
            _: libc::socklen_t,
        ) -> Self {
            let mut res = MaybeUninit::<NetlinkAddr>::uninit();

            unsafe {
                ptr::copy_nonoverlapping(addr, res.as_mut_ptr().cast(), 1);
            }

            res
        }

        fn init_storage(_: &mut MaybeUninit<Self::Storage>) {
            // Nothing to do
        }
    }

    unsafe impl private::SockaddrLikePriv for NetlinkAddr {
        unsafe fn from_raw(
            addr: *const libc::sockaddr,
            len: Option<libc::socklen_t>,
        ) -> Option<Self> {
            if let Some(l) = len {
                if l != mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t {
                    return None;
                }
            }

            // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
            unsafe {
                if addr_of!((*addr).sa_family).read() as libc::c_int != libc::AF_NETLINK {
                    return None;
                }
            }

            Some(Self(ptr::read_unaligned(addr as *const _)))
        }

        fn init_storage(buf: &mut MaybeUninit<Self>) {
            // The family of `Self` is `AF_NETLINK`, so setting the family to `AF_UNSPEC` is sufficient.
            let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
            unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
        }
    }

    unsafe impl SockaddrLike for NetlinkAddr {
        sockaddr_len_static!();
    }

    impl AsRef<libc::sockaddr_nl> for NetlinkAddr {
        fn as_ref(&self) -> &libc::sockaddr_nl {
            &self.0
        }
    }

    impl fmt::Display for NetlinkAddr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "pid: {} groups: {}", self.pid(), self.groups())
        }
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
#[cfg_attr(docsrs, doc(cfg(all())))]
pub mod alg {
    use super::*;
    use libc::{sockaddr_alg, AF_ALG};
    use std::ffi::CStr;
    use std::hash::{Hash, Hasher};
    use std::{fmt, mem, str};

    /// Socket address for the Linux kernel crypto API
    #[derive(Copy, Clone)]
    #[repr(transparent)]
    pub struct AlgAddr(pub(in super::super) sockaddr_alg);

    unsafe impl SockaddrFromRaw for Option<AlgAddr> {
        type Storage = libc::sockaddr_alg;

        unsafe fn from_raw(
            addr: *const Self::Storage,
            len: libc::socklen_t,
        ) -> Self {
            if len != mem::size_of::<libc::sockaddr_alg>() as libc::socklen_t {
                return None;
            }

            // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
            unsafe {
                if addr_of!((*addr).salg_family).read() as libc::c_int != libc::AF_ALG {
                    return None;
                }
            }

            Some(AlgAddr(ptr::read(addr)))
        }

        fn init_storage(buf: &mut MaybeUninit<Self::Storage>) {
            // The family of `Self` is `AF_ALG`, so setting the family to `AF_UNSPEC` is sufficient.
            let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
            unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
        }
    }

    unsafe impl SockaddrFromRaw for MaybeUninit<AlgAddr> {
        type Storage = libc::sockaddr_alg;

        unsafe fn from_raw(
            addr: *const Self::Storage,
            _: libc::socklen_t,
        ) -> Self {
            let mut res = MaybeUninit::<AlgAddr>::uninit();

            unsafe {
                ptr::copy_nonoverlapping(addr, res.as_mut_ptr().cast(), 1);
            }

            res
        }

        fn init_storage(_: &mut MaybeUninit<Self::Storage>) {
            // Nothing to do
        }
    }

    unsafe impl private::SockaddrLikePriv for AlgAddr {
        unsafe fn from_raw(
            addr: *const libc::sockaddr,
            l: Option<libc::socklen_t>,
        ) -> Option<Self> {
            if let Some(l) = l {
                if l != mem::size_of::<libc::sockaddr_alg>() as libc::socklen_t
                {
                    return None;
                }
            }

            // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
            unsafe {
                if addr_of!((*addr).sa_family).read() as libc::c_int != libc::AF_ALG {
                    return None;
                }
            }

            Some(Self(ptr::read_unaligned(addr as *const _)))
        }

        fn init_storage(buf: &mut MaybeUninit<Self>) {
            // The family of `Self` is `AF_ALG`, so setting the family to `AF_UNSPEC` is sufficient.
            let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
            unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
        }
    }

    unsafe impl SockaddrLike for AlgAddr {
        sockaddr_len_static!();
    }

    impl AsRef<libc::sockaddr_alg> for AlgAddr {
        fn as_ref(&self) -> &libc::sockaddr_alg {
            &self.0
        }
    }

    // , PartialEq, Eq, Debug, Hash
    impl PartialEq for AlgAddr {
        fn eq(&self, other: &Self) -> bool {
            let (inner, other) = (self.0, other.0);
            (
                inner.salg_family,
                &inner.salg_type[..],
                inner.salg_feat,
                inner.salg_mask,
                &inner.salg_name[..],
            ) == (
                other.salg_family,
                &other.salg_type[..],
                other.salg_feat,
                other.salg_mask,
                &other.salg_name[..],
            )
        }
    }

    impl Eq for AlgAddr {}

    impl Hash for AlgAddr {
        fn hash<H: Hasher>(&self, s: &mut H) {
            let inner = self.0;
            (
                inner.salg_family,
                &inner.salg_type[..],
                inner.salg_feat,
                inner.salg_mask,
                &inner.salg_name[..],
            )
                .hash(s);
        }
    }

    impl AlgAddr {
        /// Construct an `AF_ALG` socket from its cipher name and type.
        pub fn new(alg_type: &str, alg_name: &str) -> AlgAddr {
            let mut addr: sockaddr_alg = unsafe { mem::zeroed() };
            addr.salg_family = AF_ALG as u16;
            addr.salg_type[..alg_type.len()]
                .copy_from_slice(alg_type.to_string().as_bytes());
            addr.salg_name[..alg_name.len()]
                .copy_from_slice(alg_name.to_string().as_bytes());

            AlgAddr(addr)
        }

        /// Return the socket's cipher type, for example `hash` or `aead`.
        pub fn alg_type(&self) -> &CStr {
            unsafe {
                CStr::from_ptr(self.0.salg_type.as_ptr().cast())
            }
        }

        /// Return the socket's cipher name, for example `sha1`.
        pub fn alg_name(&self) -> &CStr {
            unsafe {
                CStr::from_ptr(self.0.salg_name.as_ptr().cast())
            }
        }
    }

    impl fmt::Display for AlgAddr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "type: {} alg: {}",
                self.alg_name().to_string_lossy(),
                self.alg_type().to_string_lossy()
            )
        }
    }

    impl fmt::Debug for AlgAddr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            fmt::Display::fmt(self, f)
        }
    }
}

feature! {
#![feature = "ioctl"]
#[cfg(any(target_os = "ios", target_os = "macos"))]
pub mod sys_control {
    use libc::{self, c_uchar};
    use std::{fmt, mem, ptr};
    use std::os::unix::io::RawFd;
    use crate::{Errno, Result};
    use super::*;

    // FIXME: Move type into `libc`
    #[repr(C)]
    #[derive(Clone, Copy)]
    #[allow(missing_debug_implementations)]
    pub struct ctl_ioc_info {
        pub ctl_id: u32,
        pub ctl_name: [c_uchar; MAX_KCTL_NAME],
    }

    const CTL_IOC_MAGIC: u8 = b'N';
    const CTL_IOC_INFO: u8 = 3;
    const MAX_KCTL_NAME: usize = 96;

    ioctl_readwrite!(ctl_info, CTL_IOC_MAGIC, CTL_IOC_INFO, ctl_ioc_info);

    /// Apple system control socket
    ///
    /// # References
    ///
    /// <https://developer.apple.com/documentation/kernel/sockaddr_ctl>
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    #[repr(transparent)]
    pub struct SysControlAddr(pub(in super::super) libc::sockaddr_ctl);

    unsafe impl SockaddrFromRaw for Option<SysControlAddr> {
        type Storage = libc::sockaddr_ctl;

        unsafe fn from_raw(
            addr: *const Self::Storage,
            len: libc::socklen_t,
        ) -> Self {
            if len != mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t {
                return None;
            }

            // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
            unsafe {
                if addr_of!((*addr).sc_family).read() as libc::c_int != libc::AF_SYSTEM {
                    return None;
                }
            }

            Some(SysControlAddr(ptr::read(addr)))
        }

        fn init_storage(buf: &mut MaybeUninit<Self::Storage>) {
            // The family of `Self` is `AF_SYSTEM`, so setting the family to `AF_UNSPEC` is sufficient.
            let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
            unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
        }
    }

    unsafe impl SockaddrFromRaw for MaybeUninit<SysControlAddr> {
        type Storage = libc::sockaddr_ctl;

        unsafe fn from_raw(
            addr: *const Self::Storage,
            _: libc::socklen_t,
        ) -> Self {
            let mut res = MaybeUninit::<SysControlAddr>::uninit();

            unsafe {
                ptr::copy_nonoverlapping(addr, res.as_mut_ptr().cast(), 1);
            }

            res
        }

        fn init_storage(_: &mut MaybeUninit<Self::Storage>) {
            // Nothing to do
        }
    }

    unsafe impl private::SockaddrLikePriv for SysControlAddr {
        unsafe fn from_raw(
            addr: *const libc::sockaddr,
            len: Option<libc::socklen_t>,
        ) -> Option<Self> {
            if let Some(l) = len {
                if l != mem::size_of::<libc::sockaddr_ctl>() as libc::socklen_t {
                    return None;
                }
            }

            // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
            unsafe {
                if addr_of!((*addr).sa_family).read() as libc::c_int != libc::AF_SYSTEM {
                    return None;
                }
            }

            Some(Self(ptr::read_unaligned(addr as *const _)))
        }

        fn init_storage(buf: &mut MaybeUninit<Self>) {
            // The family of `Self` is `AF_SYSTEM`, so setting the family to `AF_UNSPEC` is sufficient.
            let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
            unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
        }
    }

    unsafe impl SockaddrLike for SysControlAddr {
        sockaddr_len_static!();
    }

    impl AsRef<libc::sockaddr_ctl> for SysControlAddr {
        fn as_ref(&self) -> &libc::sockaddr_ctl {
            &self.0
        }
    }

    impl SysControlAddr {
        /// Construct a new `SysControlAddr` from its kernel unique identifier
        /// and unit number.
        pub const fn new(id: u32, unit: u32) -> SysControlAddr {
            let addr = libc::sockaddr_ctl {
                sc_len: mem::size_of::<libc::sockaddr_ctl>() as c_uchar,
                sc_family: libc::AF_SYSTEM as c_uchar,
                ss_sysaddr: libc::AF_SYS_CONTROL as u16,
                sc_id: id,
                sc_unit: unit,
                sc_reserved: [0; 5]
            };

            SysControlAddr(addr)
        }

        /// Construct a new `SysControlAddr` from its human readable name and
        /// unit number.
        pub fn from_name(sockfd: RawFd, name: &str, unit: u32) -> Result<SysControlAddr> {
            if name.len() > MAX_KCTL_NAME {
                return Err(Errno::ENAMETOOLONG);
            }

            let mut ctl_name = [0; MAX_KCTL_NAME];
            ctl_name[..name.len()].clone_from_slice(name.as_bytes());
            let mut info = ctl_ioc_info { ctl_id: 0, ctl_name };

            unsafe { ctl_info(sockfd, &mut info)?; }

            Ok(SysControlAddr::new(info.ctl_id, unit))
        }

        /// Return the kernel unique identifier
        pub const fn id(&self) -> u32 {
            self.0.sc_id
        }

        /// Return the kernel controller private unit number.
        pub const fn unit(&self) -> u32 {
            self.0.sc_unit
        }
    }

    impl fmt::Display for SysControlAddr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            fmt::Debug::fmt(self, f)
        }
    }
}
}

#[cfg(any(target_os = "android", target_os = "linux", target_os = "fuchsia"))]
#[cfg_attr(docsrs, doc(cfg(all())))]
mod datalink {
    feature! {
    #![feature = "net"]
    use super::*;

    /// Hardware Address
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    #[repr(transparent)]
    pub struct LinkAddr(pub(in super::super) libc::sockaddr_ll);

    impl LinkAddr {
        /// Physical-layer protocol
        pub fn protocol(&self) -> u16 {
            self.0.sll_protocol
        }

        /// Interface number
        pub fn ifindex(&self) -> usize {
            self.0.sll_ifindex as usize
        }

        /// ARP hardware type
        pub fn hatype(&self) -> u16 {
            self.0.sll_hatype
        }

        /// Packet type
        pub fn pkttype(&self) -> u8 {
            self.0.sll_pkttype
        }

        /// Length of MAC address
        pub fn halen(&self) -> usize {
            self.0.sll_halen as usize
        }

        /// Physical-layer address (MAC)
        // Returns an Option just for cross-platform compatibility
        pub fn addr(&self) -> Option<[u8; 6]> {
            Some([
                self.0.sll_addr[0],
                self.0.sll_addr[1],
                self.0.sll_addr[2],
                self.0.sll_addr[3],
                self.0.sll_addr[4],
                self.0.sll_addr[5],
            ])
        }
    }

    impl fmt::Display for LinkAddr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            if let Some(addr) = self.addr() {
                write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    addr[0],
                    addr[1],
                    addr[2],
                    addr[3],
                    addr[4],
                    addr[5])
            } else {
                Ok(())
            }
        }
    }

    unsafe impl SockaddrFromRaw for Option<LinkAddr> {
        type Storage = libc::sockaddr_ll;

        unsafe fn from_raw(
            addr: *const Self::Storage,
            len: libc::socklen_t,
        ) -> Self {
            if len != mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t {
                return None;
            }

            // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
            unsafe {
                if addr_of!((*addr).sll_family).read() as libc::c_int != libc::AF_PACKET {
                    return None;
                }
            }

            Some(LinkAddr(ptr::read(addr)))
        }

        fn init_storage(buf: &mut MaybeUninit<Self::Storage>) {
            // The family of `Self` is `AF_PACKET`, so setting the family to `AF_UNSPEC` is sufficient.
            let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
            unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
        }
    }

    unsafe impl SockaddrFromRaw for MaybeUninit<LinkAddr> {
        type Storage = libc::sockaddr_ll;

        unsafe fn from_raw(
            addr: *const Self::Storage,
            _: libc::socklen_t,
        ) -> Self {
            let mut res = MaybeUninit::<LinkAddr>::uninit();

            unsafe {
                ptr::copy_nonoverlapping(addr, res.as_mut_ptr().cast(), 1);
            }

            res
        }

        fn init_storage(_: &mut MaybeUninit<Self::Storage>) {
            // Nothing to do
        }
    }

    unsafe impl private::SockaddrLikePriv for LinkAddr {
        unsafe fn from_raw(addr: *const libc::sockaddr,
            len: Option<libc::socklen_t>)
        -> Option<Self>
        {
            if let Some(l) = len {
                if l != mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t {
                    return None;
                }
            }

            // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
            unsafe {
                if addr_of!((*addr).sa_family).read() as libc::c_int != libc::AF_PACKET {
                    return None;
                }
            }

            Some(Self(ptr::read_unaligned(addr as *const _)))
        }

        fn init_storage(buf: &mut MaybeUninit<Self>) {
            // The family of `Self` is `AF_NETLINK`, so setting the family to `AF_UNSPEC` is sufficient.
            let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
            unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_PACKET as _) }
        }
    }

    unsafe impl SockaddrLike for LinkAddr {
        sockaddr_len_static!();
    }

    impl AsRef<libc::sockaddr_ll> for LinkAddr {
        fn as_ref(&self) -> &libc::sockaddr_ll {
            &self.0
        }
    }

    }
}

#[cfg(any(
    target_os = "dragonfly",
    target_os = "freebsd",
    target_os = "ios",
    target_os = "macos",
    target_os = "illumos",
    target_os = "netbsd",
    target_os = "haiku",
    target_os = "aix",
    target_os = "openbsd"
))]
#[cfg_attr(docsrs, doc(cfg(all())))]
mod datalink {
    feature! {
    #![feature = "net"]
    use super::*;

    /// Hardware Address
    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    #[repr(transparent)]
    pub struct LinkAddr(pub(in super::super) libc::sockaddr_dl);

    impl LinkAddr {
        /// interface index, if != 0, system given index for interface
        #[cfg(not(target_os = "haiku"))]
        pub fn ifindex(&self) -> usize {
            self.0.sdl_index as usize
        }

        /// Datalink type
        #[cfg(not(target_os = "haiku"))]
        pub fn datalink_type(&self) -> u8 {
            self.0.sdl_type
        }

        /// MAC address start position
        pub fn nlen(&self) -> usize {
            self.0.sdl_nlen as usize
        }

        /// link level address length
        pub fn alen(&self) -> usize {
            self.0.sdl_alen as usize
        }

        /// link layer selector length
        #[cfg(not(target_os = "haiku"))]
        pub fn slen(&self) -> usize {
            self.0.sdl_slen as usize
        }

        /// if link level address length == 0,
        /// or `sdl_data` not be larger.
        pub fn is_empty(&self) -> bool {
            let nlen = self.nlen();
            let alen = self.alen();
            let data_len = self.0.sdl_data.len();

            alen == 0 || nlen + alen >= data_len
        }

        /// Physical-layer address (MAC)
        // The cast is not unnecessary on all platforms.
        #[allow(clippy::unnecessary_cast)]
        pub fn addr(&self) -> Option<[u8; 6]> {
            let nlen = self.nlen();
            let data = self.0.sdl_data;

            if self.is_empty() {
                None
            } else {
                Some([
                    data[nlen] as u8,
                    data[nlen + 1] as u8,
                    data[nlen + 2] as u8,
                    data[nlen + 3] as u8,
                    data[nlen + 4] as u8,
                    data[nlen + 5] as u8,
                ])
            }
        }
    }

    impl fmt::Display for LinkAddr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            if let Some(addr) = self.addr() {
                write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                    addr[0],
                    addr[1],
                    addr[2],
                    addr[3],
                    addr[4],
                    addr[5])
            } else {
                Ok(())
            }
        }
    }

    unsafe impl SockaddrFromRaw for Option<LinkAddr> {
        type Storage = libc::sockaddr_dl;

        unsafe fn from_raw(
            addr: *const Self::Storage,
            len: libc::socklen_t,
        ) -> Self {
            if len != mem::size_of::<libc::sockaddr_dl>() as libc::socklen_t {
                return None;
            }

            // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
            unsafe {
                if addr_of!((*addr).sdl_family).read() as libc::c_int != libc::AF_LINK {
                    return None;
                }
            }

            Some(LinkAddr(ptr::read(addr)))
        }

        fn init_storage(buf: &mut MaybeUninit<Self::Storage>) {
            // The family of `Self` is `AF_LINK`, so setting the family to `AF_UNSPEC` is sufficient.
            let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;

            unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
        }
    }

    unsafe impl SockaddrFromRaw for MaybeUninit<LinkAddr> {
        type Storage = libc::sockaddr_dl;

        unsafe fn from_raw(
            addr: *const Self::Storage,
            _: libc::socklen_t,
        ) -> Self {
            let mut res = MaybeUninit::<LinkAddr>::uninit();

            unsafe {
                ptr::copy_nonoverlapping(addr, res.as_mut_ptr().cast(), 1);
            }

            res
        }

        fn init_storage(_: &mut MaybeUninit<Self::Storage>) {
            // Nothing to do
        }
    }

    unsafe impl private::SockaddrLikePriv for LinkAddr {
        unsafe fn from_raw(
            addr: *const libc::sockaddr,
            len: Option<libc::socklen_t>,
        ) -> Option<Self> {
            if let Some(l) = len {
                if l != mem::size_of::<libc::sockaddr_dl>() as libc::socklen_t {
                    return None;
                }
            }

            // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
            unsafe {
                if addr_of!((*addr).sa_family).read() as libc::c_int != libc::AF_LINK {
                    return None;
                }
            }

            Some(Self(ptr::read_unaligned(addr as *const _)))
        }

        fn init_storage(buf: &mut MaybeUninit<Self>) {
            // The family of `Self` is `AF_LINK`, so setting the family to `AF_UNSPEC` is sufficient.
            let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
            unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
        }

    }

    unsafe impl SockaddrLike for LinkAddr {
        sockaddr_len_static!();
    }

    impl AsRef<libc::sockaddr_dl> for LinkAddr {
        fn as_ref(&self) -> &libc::sockaddr_dl {
            &self.0
        }
    }
    }
}

#[cfg(any(target_os = "android", target_os = "linux", target_os = "macos"))]
#[cfg_attr(docsrs, doc(cfg(all())))]
pub mod vsock {
    use super::*;
    use libc::{sa_family_t, sockaddr_vm};
    use std::hash::{Hash, Hasher};
    use std::{fmt, mem};

    /// Socket address for VMWare VSockets protocol
    ///
    /// # References
    ///
    /// [vsock(7)](https://man7.org/linux/man-pages/man7/vsock.7.html)
    #[derive(Copy, Clone)]
    #[repr(transparent)]
    pub struct VsockAddr(pub(in super::super) sockaddr_vm);

    unsafe impl SockaddrFromRaw for Option<VsockAddr> {
        type Storage = libc::sockaddr_vm;

        unsafe fn from_raw(
            addr: *const Self::Storage,
            len: libc::socklen_t,
        ) -> Self {
            if len != mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t {
                return None;
            }

            // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
            unsafe {
                if addr_of!((*addr).svm_family).read() as libc::c_int != libc::AF_VSOCK {
                    return None;
                }
            }

            Some(VsockAddr(ptr::read(addr)))
        }

        fn init_storage(buf: &mut MaybeUninit<Self::Storage>) {
            // The family of `Self` is `AF_VSOCK`, so setting the family to `AF_UNSPEC` is sufficient.
            let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
            unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
        }
    }

    unsafe impl SockaddrFromRaw for MaybeUninit<VsockAddr> {
        type Storage = libc::sockaddr_vm;

        unsafe fn from_raw(
            addr: *const Self::Storage,
            _: libc::socklen_t,
        ) -> Self {
            let mut res = MaybeUninit::<VsockAddr>::uninit();

            unsafe {
                ptr::copy_nonoverlapping(addr, res.as_mut_ptr().cast(), 1);
            }

            res
        }

        fn init_storage(_: &mut MaybeUninit<Self::Storage>) {
            // Nothing to do
        }
    }

    unsafe impl private::SockaddrLikePriv for VsockAddr {
        unsafe fn from_raw(
            addr: *const libc::sockaddr,
            len: Option<libc::socklen_t>,
        ) -> Option<Self> {
            if let Some(l) = len {
                if l != mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t {
                    return None;
                }
            }

            // SAFETY: `sa_family` has been initialized by `Self::init_storage` or by the syscall.
            unsafe {
                if addr_of!((*addr).sa_family).read() as libc::c_int != libc::AF_VSOCK {
                    return None;
                }
            }

            Some(Self(ptr::read_unaligned(addr as *const _)))
        }

        fn init_storage(buf: &mut MaybeUninit<Self>) {
            // The family of `Self` is `AF_VSOCK`, so setting the family to `AF_UNSPEC` is sufficient.
            let ptr = buf.as_mut_ptr() as *mut libc::sockaddr;
            unsafe { addr_of_mut!((*ptr).sa_family).write(libc::AF_UNSPEC as _) }
        }
    }

    unsafe impl SockaddrLike for VsockAddr {
        sockaddr_len_static!();
    }

    impl AsRef<libc::sockaddr_vm> for VsockAddr {
        fn as_ref(&self) -> &libc::sockaddr_vm {
            &self.0
        }
    }

    impl PartialEq for VsockAddr {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        fn eq(&self, other: &Self) -> bool {
            let (inner, other) = (self.0, other.0);
            (inner.svm_family, inner.svm_cid, inner.svm_port)
                == (other.svm_family, other.svm_cid, other.svm_port)
        }
        #[cfg(target_os = "macos")]
        fn eq(&self, other: &Self) -> bool {
            let (inner, other) = (self.0, other.0);
            (inner.svm_family, inner.svm_cid, inner.svm_port, inner.svm_len)
                == (other.svm_family, other.svm_cid, other.svm_port, inner.svm_len)
        }
    }

    impl Eq for VsockAddr {}

    impl Hash for VsockAddr {
        #[cfg(any(target_os = "android", target_os = "linux"))]
        fn hash<H: Hasher>(&self, s: &mut H) {
            let inner = self.0;
            (inner.svm_family, inner.svm_cid, inner.svm_port).hash(s);
        }
        #[cfg(target_os = "macos")]
        fn hash<H: Hasher>(&self, s: &mut H) {
            let inner = self.0;
            (inner.svm_family, inner.svm_cid, inner.svm_port, inner.svm_len).hash(s);
        }
    }

    /// VSOCK Address
    ///
    /// The address for AF_VSOCK socket is defined as a combination of a
    /// 32-bit Context Identifier (CID) and a 32-bit port number.
    impl VsockAddr {
        /// Construct a `VsockAddr` from its raw fields.
        pub fn new(cid: u32, port: u32) -> VsockAddr {
            let mut addr: sockaddr_vm = unsafe { mem::zeroed() };
            addr.svm_family = libc::AF_VSOCK as sa_family_t;
            addr.svm_cid = cid;
            addr.svm_port = port;

            #[cfg(target_os = "macos")]
            {
             addr.svm_len =  std::mem::size_of::<sockaddr_vm>() as u8;
            }
            VsockAddr(addr)
        }

        /// Context Identifier (CID)
        pub fn cid(&self) -> u32 {
            self.0.svm_cid
        }

        /// Port number
        pub fn port(&self) -> u32 {
            self.0.svm_port
        }
    }

    impl fmt::Display for VsockAddr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "cid: {} port: {}", self.cid(), self.port())
        }
    }

    impl fmt::Debug for VsockAddr {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            fmt::Display::fmt(self, f)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod types {
        use super::*;

        #[test]
        fn test_ipv4addr_to_libc() {
            let s = std::net::Ipv4Addr::new(1, 2, 3, 4);
            let l = ipv4addr_to_libc(s);
            assert_eq!(l.s_addr, u32::to_be(0x01020304));
        }

        #[test]
        fn test_ipv6addr_to_libc() {
            let s = std::net::Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8);
            let l = ipv6addr_to_libc(&s);
            assert_eq!(
                l.s6_addr,
                [0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8]
            );
        }
    }

    #[cfg(not(target_os = "redox"))]
    mod link {
        #![allow(clippy::cast_ptr_alignment)]

        #[cfg(any(
            target_os = "ios",
            target_os = "macos",
            target_os = "illumos"
        ))]
        use super::super::super::socklen_t;
        use super::*;

        /// Don't panic when trying to display an empty datalink address
        #[cfg(any(
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "ios",
            target_os = "macos",
            target_os = "netbsd",
            target_os = "openbsd"
        ))]
        #[test]
        fn test_datalink_display() {
            use super::super::LinkAddr;
            use std::mem;

            let la = LinkAddr(libc::sockaddr_dl {
                sdl_len: 56,
                sdl_family: 18,
                sdl_index: 5,
                sdl_type: 24,
                sdl_nlen: 3,
                sdl_alen: 0,
                sdl_slen: 0,
                ..unsafe { mem::zeroed() }
            });
            format!("{la}");
        }

        #[cfg(all(
            any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "linux"
            ),
            target_endian = "little"
        ))]
        #[test]
        fn linux_loopback() {
            use super::private::SockaddrLikePriv;

            #[repr(align(2))]
            struct Raw([u8; 20]);

            let bytes = Raw([
                17u8, 0, 0, 0, 1, 0, 0, 0, 4, 3, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0,
            ]);
            let sa = bytes.0.as_ptr().cast();
            let len = None;
            let sock_addr =
                unsafe { SockaddrStorage::from_raw(sa, len) }.unwrap();
            assert_eq!(sock_addr.family(), AddressFamily::PACKET);
            match sock_addr.as_link_addr() {
                Some(dl) => assert_eq!(dl.addr(), Some([1, 2, 3, 4, 5, 6])),
                None => panic!("Can't unwrap sockaddr storage"),
            }
        }

        #[cfg(any(target_os = "ios", target_os = "macos"))]
        #[test]
        fn macos_loopback() {
            use super::private::SockaddrLikePriv;

            let bytes =
                [20i8, 18, 1, 0, 24, 3, 0, 0, 108, 111, 48, 0, 0, 0, 0, 0];
            let sa = bytes.as_ptr().cast();
            let len = Some(bytes.len() as socklen_t);
            let sock_addr =
                unsafe { SockaddrStorage::from_raw(sa, len) }.unwrap();
            assert_eq!(sock_addr.family(), AddressFamily::LINK);
            match sock_addr.as_link_addr() {
                Some(dl) => {
                    assert!(dl.addr().is_none());
                }
                None => panic!("Can't unwrap sockaddr storage"),
            }
        }

        #[cfg(any(target_os = "ios", target_os = "macos"))]
        #[test]
        fn macos_tap() {
            use super::private::SockaddrLikePriv;

            let bytes = [
                20i8, 18, 7, 0, 6, 3, 6, 0, 101, 110, 48, 24, 101, -112, -35,
                76, -80,
            ];
            let ptr = bytes.as_ptr();
            let sa = ptr as *const libc::sockaddr;
            let len = Some(bytes.len() as socklen_t);

            let sock_addr =
                unsafe { SockaddrStorage::from_raw(sa, len).unwrap() };
            assert_eq!(sock_addr.family(), AddressFamily::LINK);
            match sock_addr.as_link_addr() {
                Some(dl) => {
                    assert_eq!(dl.addr(), Some([24u8, 101, 144, 221, 76, 176]))
                }
                None => panic!("Can't unwrap sockaddr storage"),
            }
        }

        #[cfg(target_os = "illumos")]
        #[test]
        fn illumos_tap() {
            use super::private::SockaddrLikePriv;

            let bytes = [25u8, 0, 0, 0, 6, 0, 6, 0, 24, 101, 144, 221, 76, 176];
            let ptr = bytes.as_ptr();
            let sa = ptr as *const libc::sockaddr;
            let len = Some(bytes.len() as socklen_t);
            let _sock_addr = unsafe { SockaddrStorage::from_raw(sa, len) };

            assert!(_sock_addr.is_some());

            let sock_addr = _sock_addr.unwrap();

            assert_eq!(sock_addr.family(), AddressFamily::LINK);

            assert_eq!(
                sock_addr.as_link_addr().unwrap().addr(),
                Some([24u8, 101, 144, 221, 76, 176])
            );
        }

        #[test]
        fn size() {
            #[cfg(any(
                target_os = "aix",
                target_os = "dragonfly",
                target_os = "freebsd",
                target_os = "ios",
                target_os = "macos",
                target_os = "netbsd",
                target_os = "illumos",
                target_os = "openbsd",
                target_os = "haiku"
            ))]
            let l = mem::size_of::<libc::sockaddr_dl>();
            #[cfg(any(
                target_os = "android",
                target_os = "fuchsia",
                target_os = "linux"
            ))]
            let l = mem::size_of::<libc::sockaddr_ll>();
            assert_eq!(LinkAddr::size() as usize, l);
        }
    }

    mod sockaddr_in {
        use super::*;
        use std::str::FromStr;

        #[test]
        fn display() {
            let s = "127.0.0.1:8080";
            let addr = SockaddrIn::from_str(s).unwrap();
            assert_eq!(s, format!("{addr}"));
        }

        #[test]
        fn size() {
            assert_eq!(
                mem::size_of::<libc::sockaddr_in>(),
                SockaddrIn::size() as usize
            );
        }
    }

    mod sockaddr_in6 {
        use super::*;
        use std::str::FromStr;

        #[test]
        fn display() {
            let s = "[1234:5678:90ab:cdef::1111:2222]:8080";
            let addr = SockaddrIn6::from_str(s).unwrap();
            assert_eq!(s, format!("{addr}"));
        }

        #[test]
        fn size() {
            assert_eq!(
                mem::size_of::<libc::sockaddr_in6>(),
                SockaddrIn6::size() as usize
            );
        }

        #[test]
        // Ensure that we can convert to-and-from std::net variants without change.
        fn to_and_from() {
            let s = "[1234:5678:90ab:cdef::1111:2222]:8080";
            let mut nix_sin6 = SockaddrIn6::from_str(s).unwrap();
            nix_sin6.0.sin6_flowinfo = 0x12345678;
            nix_sin6.0.sin6_scope_id = 0x9abcdef0;

            let std_sin6: std::net::SocketAddrV6 = nix_sin6.into();
            assert_eq!(nix_sin6, std_sin6.into());
        }
    }

    mod sockaddr_storage {
        use super::*;
        use super::private::SockaddrLikePriv;

        #[test]
        fn from_sockaddr_un_named() {
            let ua = UnixAddr::new("/var/run/mysock").unwrap();
            let ptr = ua.as_ptr().cast();
            let ss = unsafe { SockaddrStorage::from_raw(ptr, Some(ua.len())) }
                .unwrap();
            assert_eq!(ss.len(), ua.len());
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        #[test]
        fn from_sockaddr_un_abstract_named() {
            let name = String::from("nix\0abstract\0test");
            let ua = UnixAddr::new_abstract(name.as_bytes()).unwrap();
            let ptr = ua.as_ptr().cast();
            let ss = unsafe { SockaddrStorage::from_raw(ptr, Some(ua.len())) }
                .unwrap();
            assert_eq!(ss.len(), ua.len());
        }

        #[cfg(any(target_os = "android", target_os = "linux"))]
        #[test]
        fn from_sockaddr_un_abstract_unnamed() {
            let ua = UnixAddr::new_unnamed();
            let ptr = ua.as_ptr().cast();
            let ss = unsafe { SockaddrStorage::from_raw(ptr, Some(ua.len())) }
                .unwrap();
            assert_eq!(ss.len(), ua.len());
        }
    }

    mod unixaddr {
        use super::*;

        #[cfg(any(target_os = "android", target_os = "linux"))]
        #[test]
        fn abstract_sun_path() {
            let name = String::from("nix\0abstract\0test");
            let addr = UnixAddr::new_abstract(name.as_bytes()).unwrap();

            let sun_path1 =
                unsafe { &(*addr.as_ptr()).sun_path[..addr.path_len()] };
            let sun_path2 = [
                0, 110, 105, 120, 0, 97, 98, 115, 116, 114, 97, 99, 116, 0,
                116, 101, 115, 116,
            ];
            assert_eq!(sun_path1, sun_path2);
        }

        #[test]
        fn size() {
            assert_eq!(
                mem::size_of::<libc::sockaddr_un>(),
                UnixAddr::size() as usize
            );
        }
    }
}
