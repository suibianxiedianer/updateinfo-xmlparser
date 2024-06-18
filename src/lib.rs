use std::fs::File;
use std::io;

use cvrf_xmlparser::{Severity, XmlReader};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, instrument, trace};
use xml::reader::XmlEvent;

#[cfg(test)]
mod test;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfoDb {
    db: Vec<UpdateInfo>,
}

impl UpdateInfoDb {
    pub fn new() -> Self {
        UpdateInfoDb { db: Vec::new() }
    }

    #[instrument(skip(self))]
    pub fn load_xml(&mut self, xmlfile: &str) -> io::Result<()> {
        let file = File::open(xmlfile)?;
        let mut source = XmlReader::new(file);
        let xmlreader = &mut source;

        loop {
            let event = xmlreader.next();
            if xmlreader.depth() != 2 {
                if event == Ok(XmlEvent::EndDocument) {
                    trace!("End of the xml, break...");
                    break;
                }
                continue;
            }

            let mut updateinfo = UpdateInfo::new();
            updateinfo.load_from_xml(xmlreader);
            self.db.push(updateinfo);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    // sa id
    id: String,

    // sa title
    title: String,

    // sa severity
    severity: Severity,

    // the product? openEuler/CULinux
    release: String,

    // 用处不大，先不用
    //date: String,

    // cve ids，可能有多个
    cves: Vec<String>,

    // 安全公告的描述
    description: String,

    // 此次更新包含的软件包列表
    pkglist: Vec<RpmInfo>,
}

impl UpdateInfo {
    pub fn new() -> Self {
        UpdateInfo {
            id: String::new(),
            title: String::new(),
            severity: Severity::new(),
            release: String::new(),
            //date: String::new(),
            cves: Vec::new(),
            description: String::new(),
            pkglist: Vec::new(),
        }
    }

    #[instrument(skip(self, xmlreader))]
    fn load_from_xml(&mut self, xmlreader: &mut XmlReader) {
        loop {
            let key = if let Some(key) = xmlreader.next_start_name_under_depth(1) {
                key
            } else {
                break;
            };

            debug!("Parser {key} content");
            match key.as_str() {
                "id" => self.id = xmlreader.next_characters(),
                "title" => self.title = xmlreader.next_characters(),
                "severity" => {
                    self.severity = xmlreader.next_characters().parse::<Severity>().unwrap()
                }
                "release" => self.release = xmlreader.next_characters(),
                "description" => self.description = xmlreader.next_characters(),
                "references" => self.handle_references(xmlreader),
                "pkglist" => self.handle_pkglist(xmlreader),
                _ => {}
            }
        }
    }

    #[instrument(skip(self, xmlreader))]
    fn handle_references(&mut self, xmlreader: &mut XmlReader) {
        loop {
            if xmlreader.depth() < 3 {
                break;
            }
            match xmlreader.next() {
                Ok(XmlEvent::StartElement { attributes, .. }) => {
                    for attr in attributes {
                        match attr.name.local_name.as_str() {
                            "id" => self.cves.push(attr.value.clone()),
                            _ => {}
                        }
                    }
                }
                Err(e) => {
                    error!("XmlReader Error: {e}");
                    break;
                }
                _ => {}
            }
        }
    }

    #[instrument(skip(self, xmlreader))]
    fn handle_pkglist(&mut self, xmlreader: &mut XmlReader) {
        loop {
            if xmlreader.depth() < 3 {
                break;
            }
            match xmlreader.next() {
                Ok(XmlEvent::StartElement {
                    name, attributes, ..
                }) => {
                    if name.local_name.as_str() != "package" {
                        continue;
                    }
                    let mut rpminfo = RpmInfo::new();

                    for attr in attributes {
                        rpminfo.set(attr.name.local_name.as_str(), attr.value.clone());
                        /*
                        match attr.name.local_name.as_str() {
                            "name" => rpminfo.name = attr.value.clone(),
                            "epoch" => rpminfo.epoch = attr.value.clone(),
                            "version" => rpminfo.version = attr.value.clone(),
                            "release" => rpminfo.release = attr.value.clone(),
                            "arch" => rpminfo.arch = attr.value.clone(),
                            _ => {}
                        }
                        */
                    }

                    rpminfo.set("file", xmlreader.next_characters());
                    rpminfo.set("sa", self.id.clone());
                    self.pkglist.push(rpminfo);
                }
                Err(e) => {
                    error!("XmlReader Error: {e}");
                    break;
                }
                _ => {}
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpmInfo {
    // 包名
    name: String,
    // 可能为空
    epoch: String,

    version: String,

    release: String,

    arch: String,

    file: String,

    sa: String,
}

impl RpmInfo {
    pub fn new() -> Self {
        RpmInfo {
            name: String::new(),
            epoch: String::new(),
            version: String::new(),
            release: String::new(),
            arch: String::new(),
            file: String::new(),
            sa: String::new(),
        }
    }

    #[instrument(skip(self))]
    pub fn set(&mut self, key: &str, value: String) {
        match key {
            "name" => self.name = value,
            "epoch" => self.epoch = value,
            "version" => self.version = value,
            "release" => self.release = value,
            "arch" => self.arch = value,
            "file" => self.file = value,
            "sa" => self.sa = value,
            _ => error!("Unknow field: {key}"),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn epoch(&self) -> Option<&str> {
        if self.epoch != "" {
            Some(&self.epoch)
        } else {
            None
        }
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn release(&self) -> &str {
        &self.release
    }

    pub fn arch(&self) -> &str {
        &self.arch
    }

    pub fn file(&self) -> &str {
        &self.file
    }

    pub fn sa(&self) -> &str {
        &self.sa
    }

    pub fn evr(&self) -> String {
        if self.epoch().is_some() {
            format!("{}:{}-{}", self.epoch, self.version, self.release)
        } else {
            format!("{}-{}", self.version, self.release)
        }
    }

    pub fn nevra(&self) -> String {
        format!("{}-{}-{}", self.name, self.evr(), self.arch)
    }
}
