use crate::*;

#[test]
fn it_works() {
    let updatexml = "test/updateinfo.xml";

    let mut db = UpdateInfoDb::new();
    db.load_xml(&updatexml).unwrap();

    let id = "openEuler-SA-2022-1587";
    let title = "An update for mariadb is now available for openEuler-22.03-LTS";
    let severity = cvrf_xmlparser::Severity::Important;
    let release = "openEuler";
    let cves = 10;

    let updateinfo = &db.db[0];
    assert_eq!(updateinfo.id, id);
    assert_eq!(updateinfo.title, title);
    assert_eq!(updateinfo.severity, severity);
    assert_eq!(updateinfo.release, release);
    assert_eq!(updateinfo.cves.len(), cves);

    assert!(true);
}
