use std::collections::HashSet;

use crate::models::Finding;

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TechProfile {
    pub host: String,
    pub technologies: Vec<String>,
}

pub struct TechFingerprinter;

impl TechFingerprinter {
    pub fn fingerprint(findings: &[Finding]) -> Vec<TechProfile> {
        let mut profiles = Vec::new();

        for finding in findings {
            if let Finding::Asset(asset) = finding {
                let mut techs: HashSet<String> = HashSet::new();

                for service in &asset.services {
                    if let Some(ref product) = service.service_name {
                        techs.insert(product.clone());
                    }
                    if let Some(ref version) = service.version {
                        if let Some(ref product) = service.service_name {
                            techs.insert(format!("{} {}", product, version));
                        }
                    }
                }

                for tech in &asset.technologies {
                    techs.insert(tech.clone());
                }

                if !techs.is_empty() {
                    profiles.push(TechProfile {
                        host: asset.host.clone(),
                        technologies: techs.into_iter().collect(),
                    });
                }
            }
        }

        profiles
    }
}
