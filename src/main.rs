mod addresses;
mod dhcp_responder;

use std::{net::{Ipv4Addr}, str::FromStr};

use dhcp_responder::*;
use dhcproto::{Decodable, Decoder, v4::{self}, Encodable};
use etherparse::{InternetSlice, TransportSlice, PacketBuilder, LinkSlice};
use pnet_datalink::{linux::{interfaces, channel, Config}, Channel};
use addresses::*;

use crate::dhcp_responder::log_dhcp;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;

const ZERO_IPV4_ADDR: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);


fn main() -> std::io::Result<()>
{
    let (mut server, tap, mut sender, mut receiver) = {
        let tap = interfaces().into_iter().find(|int| int.name == "tap0").unwrap();
        let chan = channel(&tap, Config::default())
            .unwrap_or_else(|err| panic!("Couldn't create channel! {err}"));

        let self_mac = tap.mac.unwrap();
        println!("Interface with MAC: {self_mac} {} up", if tap.is_up() { "is" } else { "isn't" });

        let (sender, receiver) = match chan {
            Channel::Ethernet(sender, receiver) => (sender, receiver),
            _ => panic!("Weird chan"),
        };

        let self_addr = Ipv4Addr::from_str("10.206.158.1").unwrap();
        let holder = AddressesHolder::new(Ipv4Addr::new(10, 206, 158, 0), 24);
        let holder = holder.set_own_address(self_addr, self_mac)
            .unwrap_or_else(|err| panic!("Couldn't create HolderNode: {err:?}"));

        let server = DhcpResponder::new(holder);
        (server, tap, sender, receiver)
    };

    while let Ok(packet_raw) = receiver.next() {
        // println!("Got packet");
        let msg = match filter_dhcp_req(packet_raw) {
            Some(msg) => msg,
            _ => continue,
        };

        log_dhcp(&msg);

        let resp = server.response(&msg);
        let dhcp_buf = resp.to_vec()
            .unwrap_or_else(|err| panic!("Couldn't encode DHCP response: {err}"));

        let resp_head = PacketBuilder::ethernet2(server.own_mac().octets(), msg.chaddr().octets())
            .ipv4(server.own_ip().octets(), resp.yiaddr().octets(), 64)
            .udp(DHCP_SERVER_PORT, DHCP_CLIENT_PORT);

        let mut resp_buf = Vec::with_capacity(resp_head.size(dhcp_buf.len()));
        resp_head.write(&mut resp_buf, &dhcp_buf).unwrap();

        println!("Sending response of {} bytes", resp_buf.len());
        sender.send_to(&resp_buf, Some(tap.clone())).unwrap()?;
    }
    Ok(())
}

fn filter_dhcp_req(packet_raw: &[u8]) -> Option<DhcpMessage<'_>>
{
    let parsed = match etherparse::SlicedPacket::from_ethernet(packet_raw) {
        Ok(packet) => packet,
        Err(err) => { eprintln!("Invalid packet or sth: {err}"); return None },
    };

    let eth_head = match parsed.link {
        Some(LinkSlice::Ethernet2(head)) => head,
        None => return None,
    };

    let (ip_head, ip_ext) = match parsed.ip {
        Some(InternetSlice::Ipv4(header, ext)) => (header, ext),
        _ => return None,
    };
    if ip_head.source_addr() != ZERO_IPV4_ADDR {
        return None
    }

    let udp_head = match parsed.transport {
        Some(TransportSlice::Udp(head)) => head,
        _ => return None
    };

    if udp_head.destination_port() != DHCP_SERVER_PORT || udp_head.source_port() != DHCP_CLIENT_PORT {
        return None
    }

    let dhcp = v4::Message::decode(&mut Decoder::new(parsed.payload))
        .unwrap_or_else(|err| panic!("Couldn't parse DHCP request {err}"));

    let msg_type = *match dhcp.opts().get(v4::OptionCode::MessageType) {
        Some(v4::DhcpOption::MessageType(msg_type)) => msg_type,
        Some(_) => panic!("Wrong option type lies there"),
        None => panic!("I want MessageType very much"),
    };

    Some(DhcpMessage {
        eth_head,
        ip_head,
        ip_ext,
        udp_head,
        dhcp,
        dhcp_type: msg_type,
        raw: packet_raw
    })
}
