use cvrf_xmlparser::{Severity, XmlReader};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfoDb {
    db: Vec<UpdateInfo>,
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
