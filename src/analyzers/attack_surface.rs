use std::collections::HashMap;

use crate::models::Finding;

#[derive(Debug, Clone)]
pub struct AttackSurfaceNode {
    pub host: String,
    pub ips: Vec<String>,
    pub ports: Vec<u16>,
    pub services: Vec<String>,
    pub technologies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AttackSurface {
    pub domain: String,
    pub nodes: Vec<AttackSurfaceNode>,
    pub total_ips: usize,
    pub total_ports: usize,
    pub total_services: usize,
}

pub struct AttackSurfaceMapper;

impl AttackSurfaceMapper {
    pub fn map(domain: &str, findings: &[Finding]) -> AttackSurface {
        let mut node_map: HashMap<String, AttackSurfaceNode> = HashMap::new();

        for finding in findings {
            match finding {
                Finding::Subdomain(sub) => {
                    let node = node_map
                        .entry(sub.subdomain.clone())
                        .or_insert_with(|| AttackSurfaceNode {
                            host: sub.subdomain.clone(),
                            ips: Vec::new(),
                            ports: Vec::new(),
                            services: Vec::new(),
                            technologies: Vec::new(),
                        });

                    for ip in &sub.ip_addresses {
                        if !node.ips.contains(ip) {
                            node.ips.push(ip.clone());
                        }
                    }
                }
                Finding::Asset(asset) => {
                    let node = node_map
                        .entry(asset.host.clone())
                        .or_insert_with(|| AttackSurfaceNode {
                            host: asset.host.clone(),
                            ips: Vec::new(),
                            ports: Vec::new(),
                            services: Vec::new(),
                            technologies: Vec::new(),
                        });

                    if !node.ips.contains(&asset.ip) {
                        node.ips.push(asset.ip.clone());
                    }

                    for port in &asset.ports {
                        if !node.ports.contains(port) {
                            node.ports.push(*port);
                        }
                    }

                    for service in &asset.services {
                        if let Some(ref name) = service.service_name {
                            if !node.services.contains(name) {
                                node.services.push(name.clone());
                            }
                        }
                    }

                    for tech in &asset.technologies {
                        if !node.technologies.contains(tech) {
                            node.technologies.push(tech.clone());
                        }
                    }
                }
                _ => {}
            }
        }

        let nodes: Vec<AttackSurfaceNode> = node_map.into_values().collect();
        let total_ips = nodes.iter().map(|n| n.ips.len()).sum();
        let total_ports = nodes.iter().map(|n| n.ports.len()).sum();
        let total_services = nodes.iter().map(|n| n.services.len()).sum();

        AttackSurface {
            domain: domain.to_string(),
            nodes,
            total_ips,
            total_ports,
            total_services,
        }
    }
}
