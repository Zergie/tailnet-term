use std::net::Ipv4Addr;

use serde_json::Value;

pub fn permits(map: &Value, peer: Ipv4Addr, local: Ipv4Addr, port: u16) -> bool {
    let partial = map["PacketFilters"].as_object();
    let base_cleared = partial.is_some_and(|rules| {
        rules.get("*").is_some_and(Value::is_null) || rules.contains_key("base")
    });
    (!base_cleared && permitted_rules(&map["PacketFilter"], peer, local, port))
        || partial.is_some_and(|rules| {
            rules
                .values()
                .any(|rules| permitted_rules(rules, peer, local, port))
        })
}

fn permitted_rules(rules: &Value, peer: Ipv4Addr, local: Ipv4Addr, port: u16) -> bool {
    rules.as_array().is_some_and(|rules| {
        rules.iter().any(|rule| {
            let tcp_allowed = rule["IPProto"].is_null()
                || rule["IPProto"].as_array().is_some_and(|protocols| {
                    protocols.is_empty()
                        || protocols
                            .iter()
                            .any(|protocol| protocol.as_u64() == Some(6))
                });
            tcp_allowed
                && rule["SrcIPs"].as_array().is_some_and(|sources| {
                    sources.iter().enumerate().any(|(index, source)| {
                        let bits = rule["SrcBits"].get(index).and_then(Value::as_u64);
                        matches_address(source, bits, peer)
                    })
                })
                && rule["DstPorts"].as_array().is_some_and(|targets| {
                    targets.iter().any(|target| {
                        let first = target["Ports"]["First"].as_u64().unwrap_or(0);
                        let last = target["Ports"]["Last"].as_u64().unwrap_or(0);
                        (first..=last).contains(&u64::from(port))
                            && matches_address(&target["IP"], target["Bits"].as_u64(), local)
                    })
                })
        })
    })
}

fn matches_address(value: &Value, old_bits: Option<u64>, ip: Ipv4Addr) -> bool {
    let Some(text) = value.as_str() else {
        return false;
    };
    if text == "*" {
        return true;
    }
    if let Some((first, last)) = text.split_once('-') {
        return match (first.parse::<Ipv4Addr>(), last.parse::<Ipv4Addr>()) {
            (Ok(first), Ok(last)) => old_bits.is_none() && (first..=last).contains(&ip),
            _ => false,
        };
    }
    let (network, bits) = match text.split_once('/') {
        Some((network, bits)) if old_bits.is_none() => (network, bits.parse().ok()),
        Some(_) => return false,
        None => (text, Some(old_bits.unwrap_or(32))),
    };
    match (network.parse::<Ipv4Addr>(), bits) {
        (Ok(network), Some(bits @ 0..=32)) => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - bits)
            };
            u32::from(ip) & mask == u32::from(network) & mask
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn checks_peer_protocol_port_and_filter_updates() {
        let peer = Ipv4Addr::new(100, 90, 0, 10);
        let local = Ipv4Addr::new(100, 90, 0, 20);
        let rule = json!({"SrcIPs":["100.90.0.0/24"],"IPProto":[6], "DstPorts":[{"IP":"100.90.0.20","Ports":{"First":7681,"Last":7681}}]});
        let mut map = json!({"PacketFilter":[rule.clone()]});
        assert!(permits(&map, peer, local, 7681));
        assert!(!permits(&map, peer, local, 7682));
        assert!(!permits(&map, Ipv4Addr::new(100, 91, 0, 10), local, 7681));
        assert!(!permits(&map, peer, Ipv4Addr::new(100, 91, 0, 20), 7681));
        assert!(!permits(&Value::Null, peer, local, 7681));
        map["PacketFilter"][0]["IPProto"] = json!([17]);
        assert!(!permits(&map, peer, local, 7681));
        map = json!({"PacketFilter":[rule], "PacketFilters":{"*":null}});
        assert!(!permits(&map, peer, local, 7681));
    }
}
