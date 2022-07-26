/*
 * Copyright (c) 2022 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::{
    array::TryFromSliceError,
    fmt,
    net::{IpAddr, Ipv6Addr},
    str::FromStr,
};

use bitflags::bitflags;
use log::{error, info};

use super::environment::get_k8s_local_node_ip;

pub mod h2pack;

mod error;
pub use error::{Error, Result};

#[cfg(target_os = "linux")]
mod ethtool;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use ethtool::*;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[derive(Debug)]
pub struct NeighborEntry {
    pub src_addr: IpAddr,
    pub src_link: Link,
    pub dest_addr: IpAddr,
    pub dest_mac_addr: MacAddr,
}

bitflags! {
    #[derive(Default)]
    pub struct LinkFlags: u32 {
        const UP = 1 << 0;
        const BROADCAST = 1 << 1;
        const LOOPBACK = 1 << 3;
        const POINT_TO_POINT = 1 << 4;
        const MULTICAST = 1 << 12;
    }
}

#[cfg(target_os = "linux")]
use neli::consts::rtnl::{Iff, IffFlags};
#[cfg(target_os = "linux")]
impl From<&IffFlags> for LinkFlags {
    fn from(flags: &IffFlags) -> Self {
        let mut fs = Self::default();
        if flags.contains(&Iff::Up) {
            fs |= Self::UP;
        }
        if flags.contains(&Iff::Broadcast) {
            fs |= Self::BROADCAST;
        }
        if flags.contains(&Iff::Loopback) {
            fs |= Self::LOOPBACK;
        }
        if flags.contains(&Iff::Pointopoint) {
            fs |= Self::POINT_TO_POINT;
        }
        if flags.contains(&Iff::Multicast) {
            fs |= Self::MULTICAST;
        }
        fs
    }
}
#[cfg(target_os = "linux")]
impl From<u32> for LinkFlags {
    fn from(flags: u32) -> Self {
        Self::from_bits_truncate(flags)
    }
}

#[derive(Debug, Default, Clone)]
pub struct Link {
    pub if_index: u32,
    pub mac_addr: MacAddr,
    pub name: String,
    pub flags: LinkFlags,
    pub if_type: Option<String>,
    pub parent_index: Option<u32>,
}

impl PartialEq for Link {
    fn eq(&self, other: &Self) -> bool {
        self.if_index.eq(&other.if_index)
    }
}

impl Eq for Link {}

impl PartialOrd for Link {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.if_index.partial_cmp(&other.if_index)
    }
}

impl Ord for Link {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.if_index.cmp(&other.if_index)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Addr {
    pub if_index: u32,
    pub ip_addr: IpAddr,
    pub scope: u8,
    pub prefix_len: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct Route {
    pub src_ip: IpAddr,
    pub oif_index: u32,
    pub gateway: Option<IpAddr>,
}

pub const MAC_ADDR_LEN: usize = 6;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Default, Copy, Hash)]
// slice is in bigendian
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const ZERO: MacAddr = MacAddr([0, 0, 0, 0, 0, 0]);

    const BROADCAST: u64 = 0xffffffffffff;
    const MULTICAST: u64 = 0x010000000000;
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }

    pub fn is_multicast(octets: &[u8]) -> bool {
        assert!(octets.len() > MAC_ADDR_LEN);
        octets[0] & 0x1 == 1
    }

    pub fn is_unicast(mac: MacAddr) -> bool {
        let mac_num = u64::from(mac);
        mac_num != Self::BROADCAST && mac_num & Self::MULTICAST != Self::MULTICAST
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl From<MacAddr> for u64 {
    fn from(mac: MacAddr) -> Self {
        ((u16::from_be_bytes(mac.0[0..2].try_into().unwrap()) as u64) << 32)
            | u32::from_be_bytes(mac.0[2..6].try_into().unwrap()) as u64
    }
}

impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        MacAddr(octets)
    }
}

impl TryFrom<&[u8]> for MacAddr {
    type Error = TryFromSliceError;
    fn try_from(octets: &[u8]) -> Result<Self, Self::Error> {
        <[u8; 6]>::try_from(octets).map(Self::from)
    }
}

impl TryFrom<u64> for MacAddr {
    type Error = u64;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value & 0xFFFF_0000_0000_0000 != 0 {
            return Err(value);
        }
        Ok(MacAddr(value.to_be_bytes()[2..].try_into().unwrap()))
    }
}

impl FromStr for MacAddr {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut addr = [0u8; 6];
        for (idx, n_s) in s.split(":").enumerate() {
            if idx >= MAC_ADDR_LEN {
                return Err(Error::ParseMacFailed(s.to_string()));
            }
            match u8::from_str_radix(n_s, 16) {
                Ok(n) => addr[idx] = n,
                Err(_) => return Err(Error::ParseMacFailed(s.to_string())),
            }
        }
        Ok(MacAddr(addr))
    }
}

pub fn is_unicast_link_local(ip: &Ipv6Addr) -> bool {
    // Ipv6Addr::is_unicast_link_local()是实验API无法使用
    ip.segments()[0] & 0xffc0 == 0xfe80
}

pub fn get_mac_by_ip(ip: IpAddr) -> Result<MacAddr> {
    let links = link_list()?;
    let addrs = addr_list()?;
    let if_idx = addrs
        .iter()
        .find_map(|a| {
            if a.ip_addr == ip {
                Some(a.if_index)
            } else {
                None
            }
        })
        .ok_or(Error::LinkIdxNotFoundByIP(format!(
            "can't find interface index by ip {}",
            ip
        )))?;

    let mac = links
        .iter()
        .find_map(|l| {
            if l.if_index == if_idx {
                Some(l.mac_addr)
            } else {
                None
            }
        })
        .ok_or(Error::LinkIdxNotFoundByIP(format!(
            "can't find mac address by ip {}",
            ip
        )))?;

    Ok(mac)
}

pub fn get_ctrl_ip_and_mac(dest: IpAddr) -> (IpAddr, MacAddr) {
    // Directlly use env.K8S_NODE_IP_FOR_DEEPFLOW as the ctrl_ip reported by deepflow-agent if available
    match get_k8s_local_node_ip() {
        Some(ip) => {
            info!(
                "use K8S_NODE_IP_FOR_DEEPFLOW env ip as destination_ip({})",
                ip
            );
            let ctrl_mac = get_mac_by_ip(ip);
            if ctrl_mac.is_err() {
                error!("failed getting ctrl_mac from {}: {:?}", ip, ctrl_mac);
            }
            (ip, ctrl_mac.unwrap())
        }
        None => {
            let tuple = get_route_src_ip_and_mac(&dest);
            if tuple.is_err() {
                error!("failed getting control ip and mac");
            }
            tuple.unwrap()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_constructions() {
        let expected = MacAddr([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]);
        assert_eq!("12:34:56:78:9a:bc", format!("{}", expected));

        assert_eq!("12:34:56:78:9a:bc".parse::<MacAddr>().unwrap(), expected);
        assert_eq!(MacAddr::try_from(0x123456789abc).unwrap(), expected);
        assert_eq!(
            MacAddr::try_from([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc]).unwrap(),
            expected
        );
        assert_eq!(
            MacAddr::try_from(&[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc][..]).unwrap(),
            expected
        );
    }

    #[test]
    fn mac_to_u64() {
        assert_eq!(
            u64::from(MacAddr([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc])),
            0x123456789abc
        );
    }
}
