use std::{collections::HashMap, net::Ipv4Addr, ops::{Shl, Deref, DerefMut}};

use pnet_datalink::MacAddr;

#[derive(Debug)]
pub struct AddressesHolder
{
    free: Vec<Ipv4Addr>,
    processing: HashMap<MacAddr, Ipv4Addr>,
    occupied: HashMap<Ipv4Addr, MacAddr>,
    mask: u8,
    network: Ipv4Addr,
    broadcast: Ipv4Addr,
}

pub struct HolderNode
{
    own_ip: Ipv4Addr,
    own_mac: MacAddr,
    holder: AddressesHolder,
}

impl Deref for HolderNode
{
    type Target = AddressesHolder;

    fn deref(&self) -> &Self::Target
    { &self.holder }
}

impl DerefMut for HolderNode
{
    fn deref_mut(&mut self) -> &mut Self::Target
    { &mut self.holder }
}

#[derive(Debug)]
pub enum AddressError
{
    NoFreeAddr,
    MacIsNotProcessed,
    AddressIsOccupied{ mac: MacAddr },
}

type Result<T> = std::prelude::rust_2021::Result<T, AddressError>;

impl AddressesHolder
{
    pub fn new(network: Ipv4Addr, mask: u8) -> Self
    {
        let as_num: u32 = network.into();
        let mask_bits = u32::max_value() << (u32::BITS - mask as u32);
        assert_eq!(as_num, as_num & mask_bits);

        let max_addr = as_num | (!mask_bits);
        let broadcast = Ipv4Addr::from(max_addr);
        let free = ((as_num + 1)..max_addr)
            .map(Into::into)
            .collect();

        Self {
            free,
            processing: HashMap::default(),
            occupied: HashMap::default(),
            mask,
            network,
            broadcast,
        }
    }

    pub fn offer_ip(&mut self, mac: MacAddr) -> Result<Ipv4Addr>
    {
        if let Some(ip) = self.processing.get(&mac) {
            return Ok(*ip)
        }

        let new_ip = self.free.pop().ok_or(AddressError::NoFreeAddr)?;
        self.processing.insert(mac, new_ip);

        Ok(new_ip)
    }

    pub fn accept_ip(&mut self, mac: MacAddr) -> Result<(MacAddr, Ipv4Addr)>
    {
        let found = self.occupied.iter()
            .find_map(|(ip, curr_mac)| if *curr_mac == mac { Some(*ip) } else { None });
        if let Some(occupied_ip) = found {
            return Ok((mac, occupied_ip))
        }

        match self.processing.remove(&mac) {
            Some(ip) => {
                self.occupied.insert(ip, mac);
                Ok((mac, ip))
            },
            None => Err(AddressError::MacIsNotProcessed),
        }
    }

    pub fn broadcast(&self) -> Ipv4Addr
    { self.broadcast }

    pub fn network(&self) -> Ipv4Addr
    { self.network }

    pub fn mask(&self) -> u8
    { self.mask }

    pub fn mask_ip(&self) -> Ipv4Addr
    {
        let mask_bits = u32::max_value() << (u32::BITS - self.mask as u32);
        Ipv4Addr::from(mask_bits)
    }

    pub fn set_own_address(mut self, ip: Ipv4Addr, mac: MacAddr) -> Result<HolderNode>
    {
        let min_addr: u32 = self.network.into();
        let max_addr: u32 = self.broadcast.into();

        let as_num: u32 = ip.into();

        assert!(min_addr < as_num && as_num < max_addr,
            "{ip} is out of bounds for {}/{} network",
            self.network,
            self.mask
        );

        if let Some(prev_mac) = self.occupied.get(&ip) {
            Err(AddressError::AddressIsOccupied { mac: *prev_mac })
        } else {
            let ip_idx = self.free.iter().position(|addr| *addr == ip)
                .expect("Non-free and non-occupied address");
            self.free.remove(ip_idx);
            self.occupied.insert(ip, mac);
            Ok(HolderNode{ own_ip: ip, own_mac: mac, holder: self })
        }
    }

}

impl HolderNode
{
    pub fn own_ip(&self) -> Ipv4Addr
    { self.own_ip }

    pub fn own_mac(&self) -> MacAddr
    { self.own_mac }
}
