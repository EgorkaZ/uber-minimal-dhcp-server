use std::{net::Ipv4Addr, ops::Deref};

use dhcproto::v4::{self, DhcpOptions};
use pnet_datalink::MacAddr;

use crate::addresses::HolderNode;

pub struct DhcpMessage<'p>
{
    pub eth_head: etherparse::Ethernet2HeaderSlice<'p>,
    pub ip_head: etherparse::Ipv4HeaderSlice<'p>,
    pub ip_ext: etherparse::Ipv4ExtensionsSlice<'p>,
    pub udp_head: etherparse::UdpHeaderSlice<'p>,
    pub dhcp: v4::Message,
    pub dhcp_type: v4::MessageType,
    pub raw: &'p [u8],
}

impl DhcpMessage<'_>
{
    pub fn src_ip(&self) -> Ipv4Addr
    { self.ip_head.source_addr() }

    pub fn dst_ip(&self) -> Ipv4Addr
    { self.ip_head.destination_addr() }

    pub fn src_mac(&self) -> MacAddr
    { MacAddr::from(self.eth_head.source()) }

    pub fn dst_mac(&self) -> MacAddr
    { MacAddr::from(self.eth_head.destination()) }

    pub fn chaddr(&self) -> MacAddr
    {
        let chaddr = self.dhcp.chaddr();
        let as_arr: [u8; 6] = chaddr.try_into().unwrap();
        MacAddr::from(as_arr)
    }

    pub fn msg_type(&self) -> v4::MessageType
    { self.dhcp_type }
}

pub fn log_dhcp(msg: &DhcpMessage<'_>)
{
    println!("DHCP<{:?}> [{}] {} ({}) -> {} -> ({})",
        msg.msg_type(),
        msg.raw.len(),
        msg.src_ip(), msg.src_mac(),
        msg.dst_ip(), msg.dst_mac()
    );

    {
        let chaddr = msg.chaddr();
        let msg = &msg.dhcp;

        println!("  opcode: {:?}", msg.opcode());
        println!("  xid: {}", msg.xid());
        println!("  htype: {:?}", msg.htype());
        println!("  chaddr: {chaddr}");
        println!("  ciaddr: {}", msg.ciaddr());
        println!("  yiaddr: {}", msg.yiaddr());
        println!("  siaddr: {}", msg.siaddr());
        println!("  giaddr: {}", msg.giaddr());
        println!("  sname: {:?}", msg.sname());
    }
}

pub struct DhcpResponder
{
    holder: HolderNode,
}

impl DhcpResponder
{
    pub fn new(holder: HolderNode) -> Self
    { Self { holder } }

    pub fn response(&mut self, msg: &DhcpMessage<'_>) -> v4::Message
    {
        match msg.msg_type() {
            v4::MessageType::Discover => self.response_discover(msg),
            v4::MessageType::Offer => todo!(),
            v4::MessageType::Request => self.response_request(msg),
            v4::MessageType::Decline => todo!(),
            v4::MessageType::Ack => todo!(),
            v4::MessageType::Nak => todo!(),
            v4::MessageType::Release => todo!(),
            v4::MessageType::Inform => todo!(),
            v4::MessageType::Unknown(_) => todo!(),
        }
    }

    fn response_discover(&mut self, msg: &DhcpMessage<'_>) -> v4::Message
    {
        let proposed_ip = match self.holder.offer_ip(msg.chaddr()) {
            Ok(ip) => ip,
            Err(err) => panic!("Cannot offer IP: {err:?}")
        };

        let opts = self.dhcp_resp_options(v4::MessageType::Offer);

        let xid = msg.dhcp.xid();
        let mut rsp = v4::Message::default();
        rsp.set_opts(opts)
            .set_siaddr(self.holder.own_ip())
            .set_yiaddr(proposed_ip)
            .set_chaddr(&msg.chaddr().octets())
            .set_opcode(v4::Opcode::BootReply)
            .set_xid(xid);

        rsp
    }

    fn response_request(&mut self, msg: &DhcpMessage<'_>) -> v4::Message
    {
        let (mac, ip) = match self.holder.accept_ip(msg.chaddr()) {
            Ok(res) => res,
            Err(err) => panic!("Cannot accept id: {err:?}"),
        };

        assert_eq!(mac, msg.chaddr());

        let opts = self.dhcp_resp_options(v4::MessageType::Ack);

        let xid = msg.dhcp.xid();
        let mut rsp = v4::Message::default();
        rsp.set_opts(opts)
            .set_siaddr(self.holder.own_ip())
            .set_yiaddr(ip)
            .set_chaddr(&msg.chaddr().octets())
            .set_opcode(v4::Opcode::BootReply)
            .set_xid(xid);

        rsp
    }

    fn dhcp_resp_options(&self, msg_type: v4::MessageType) -> DhcpOptions
    {
        let mut opts = DhcpOptions::default();
        opts.insert(v4::DhcpOption::MessageType(msg_type));
        opts.insert(v4::DhcpOption::SubnetMask(self.holder.mask_ip()));
        opts.insert(v4::DhcpOption::BroadcastAddr(self.holder.broadcast()));
        opts.insert(v4::DhcpOption::AddressLeaseTime(30));
        opts.insert(v4::DhcpOption::ServerIdentifier(self.holder.own_ip()));
        opts
    }
}

impl Deref for DhcpResponder
{
    type Target = HolderNode;

    fn deref(&self) -> &Self::Target
    { &self.holder }
}
