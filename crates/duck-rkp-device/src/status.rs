use std::collections::BTreeMap;

use duck_core::Context;
use duck_platform::{exec, props};
use serde::Serialize;

use crate::{
    soc::{self, Detection, State},
    v1,
};

pub(crate) const LIBRARY_PATH: &str = "/vendor/lib64/libkeymasterdeviceutils.so";
pub(crate) const DEVICE_PATH: &str = "/dev/smcinvoke";

/// The limitations every run reports. The CLI requires an explicit acknowledgement of
/// both, and the WebUI shows them in a dialog before a request is sent.
pub(crate) const LIMITATIONS: [&str; 2] = ["partial_device_support", "rkp_only"];

/// What the device offers, without sending anything to KeyMint or to a server.
///
/// Passing these checks only means the prerequisites are present: firmware support and
/// server acceptance stay unconfirmed until a run succeeds.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct DeviceStatus {
    pub prerequisites_met: bool,
    pub android_arm64: bool,
    pub root: bool,
    pub library_present: bool,
    pub device_present: bool,
    pub v1_available: bool,
    pub v1_native_available: bool,
    pub v2_available: bool,
    pub aidl_apk: Option<String>,
    pub qualcomm_soc: bool,
    pub mediatek_soc: bool,
    pub library_path: &'static str,
    pub device_path: &'static str,
    pub fingerprint: String,
    pub device_manufacturer: String,
    pub soc_manufacturer: String,
    pub soc_detection: Detection,
    pub limitations: [&'static str; 2],
    pub blockers: Vec<&'static str>,
}

pub(crate) fn detect(ctx: &Context) -> DeviceStatus {
    detect_with_properties(ctx, &props::all())
}

fn detect_with_properties(ctx: &Context, properties: &BTreeMap<String, String>) -> DeviceStatus {
    let fingerprint = properties
        .get("ro.build.fingerprint")
        .cloned()
        .unwrap_or_default();
    let soc_manufacturer = properties
        .get("ro.soc.manufacturer")
        .cloned()
        .unwrap_or_default();

    let android_arm64 = cfg!(all(target_os = "android", target_arch = "aarch64"));
    let root = exec::stdout_or_empty("id", &["-u"]).trim() == "0";
    let library_present = ctx.sysroot.path(LIBRARY_PATH).is_file();
    let device_present = ctx.sysroot.path(DEVICE_PATH).exists();
    let aidl_apk = v1::find_aidl_apk(&ctx.sysroot).map(|path| path.display().to_string());
    let v1_available = aidl_apk.is_some() && ctx.sysroot.path(v1::APP_PROCESS).is_file();
    let soc_detection = soc::detect(properties, &ctx.sysroot);
    let qualcomm_soc = soc_detection.state == State::Qualcomm;
    let mediatek_soc = soc_detection.state == State::MediaTek;
    // Only the AIDL bridge is vendor independent. Native adapters use Qualcomm's ABI.
    let v2_available = qualcomm_soc && library_present && device_present;

    let mut blockers = Vec::new();
    for (passed, name) in [
        (android_arm64, "android_arm64_required"),
        (root, "root_required"),
        (!fingerprint.trim().is_empty(), "fingerprint_missing"),
    ] {
        if !passed {
            blockers.push(name);
        }
    }
    if !v1_available && !v2_available {
        if !mediatek_soc && !library_present {
            blockers.push("keymint_library_missing");
        }
        if !mediatek_soc && !device_present {
            blockers.push("smcinvoke_missing");
        }
        blockers.push("v1_unavailable");
    }
    if let Some(blocker) = soc::blocker(&soc_detection) {
        blockers.push(blocker);
    }

    DeviceStatus {
        prerequisites_met: blockers.is_empty(),
        android_arm64,
        root,
        library_present,
        device_present,
        v1_available,
        v1_native_available: v2_available,
        v2_available,
        aidl_apk,
        qualcomm_soc,
        mediatek_soc,
        library_path: LIBRARY_PATH,
        device_path: DEVICE_PATH,
        fingerprint,
        device_manufacturer: device_manufacturer(properties),
        soc_manufacturer,
        soc_detection,
        limitations: LIMITATIONS,
        blockers,
    }
}

fn device_manufacturer(properties: &BTreeMap<String, String>) -> String {
    ["ro.product.manufacturer", "ro.product.vendor.manufacturer"]
        .iter()
        .filter_map(|name| properties.get(*name))
        .map(|value| value.trim())
        .find(|value| !value.is_empty())
        .unwrap_or_default()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_manufacturer_uses_product_properties_with_vendor_fallback() {
        for (product, vendor, expected) in [
            (Some(" Xiaomi "), Some("vendor"), "Xiaomi"),
            (Some(" \t "), Some(" Google "), "Google"),
            (None, Some("Google"), "Google"),
            (Some(""), Some("  "), ""),
            (None, None, ""),
        ] {
            let mut properties = BTreeMap::from([("ro.soc.manufacturer".into(), "QTI".into())]);
            for (name, value) in [
                ("ro.product.manufacturer", product),
                ("ro.product.vendor.manufacturer", vendor),
            ] {
                if let Some(value) = value {
                    properties.insert(name.into(), value.into());
                }
            }
            assert_eq!(device_manufacturer(&properties), expected);
        }
    }

    #[test]
    fn every_limitation_has_a_stable_id() {
        assert_eq!(LIMITATIONS, ["partial_device_support", "rkp_only"]);
    }

    #[test]
    fn v1_resources_do_not_require_v2_vendor_library_or_device_node() {
        let root = tempfile::tempdir().unwrap();
        for file in [
            "system/bin/app_process",
            "apex/com.android.rkpd/priv-app/rkpd/rkpdapp.apk",
        ] {
            let path = root.path().join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, []).unwrap();
        }
        let ctx = Context {
            paths: duck_core::AppPaths::for_root(root.path(), root.path()),
            sysroot: duck_core::Sysroot::new(root.path()),
        };
        let status = detect(&ctx);
        assert!(status.v1_available);
        assert!(!status.v2_available);
        assert!(!status.library_present);
        assert!(!status.device_present);
        assert!(!status.blockers.contains(&"keymint_library_missing"));
        assert!(!status.blockers.contains(&"smcinvoke_missing"));
        assert!(
            crate::issuance::blockers_for(&status, crate::issuance::Protocol::V2)
                .contains(&"v2_unavailable")
        );
    }

    #[test]
    fn mediatek_uses_only_aidl_even_when_qualcomm_resource_paths_exist() {
        let root = tempfile::tempdir().unwrap();
        for file in [
            LIBRARY_PATH,
            DEVICE_PATH,
            v1::APP_PROCESS,
            "/apex/com.android.rkpd/priv-app/rkpd/rkpdapp.apk",
        ] {
            let path = root.path().join(file.trim_start_matches('/'));
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, []).unwrap();
        }
        let ctx = Context {
            paths: duck_core::AppPaths::for_root(root.path(), root.path()),
            sysroot: duck_core::Sysroot::new(root.path()),
        };
        let properties = [("ro.soc.manufacturer".into(), "MediaTek".into())].into();
        let status = detect_with_properties(&ctx, &properties);
        assert!(status.mediatek_soc && status.v1_available);
        assert!(status.library_present && status.device_present);
        assert!(!status.v2_available && !status.v1_native_available);
        assert_eq!(
            crate::issuance::candidates(crate::issuance::Protocol::Auto, &status),
            [crate::issuance::Method::V1]
        );
        for (protocol, blocker) in [
            (crate::issuance::Protocol::V2, "v2_unavailable"),
            (crate::issuance::Protocol::V1Native, "v1_native_unavailable"),
        ] {
            assert!(crate::issuance::blockers_for(&status, protocol).contains(&blocker));
        }
        std::fs::remove_file(ctx.sysroot.path(v1::APP_PROCESS)).unwrap();
        let unavailable = detect_with_properties(&ctx, &properties);
        assert!(!unavailable.v1_available);
        assert!(unavailable.blockers.contains(&"v1_unavailable"));
        assert!(
            crate::issuance::candidates(crate::issuance::Protocol::Auto, &unavailable).is_empty()
        );
    }
}
