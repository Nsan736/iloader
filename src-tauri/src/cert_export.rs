// Export the existing signing identity (private key + matching Apple development
// certificate) as a PKCS#12 file.
//
// This intentionally does NOT use `CertificateIdentity::retrieve`, because that
// creates a new private key / requests a new certificate (and may revoke others)
// when no match is found. Here we only look up what already exists and fail
// otherwise. Nothing secret (key, certificate, password, email) is logged.

use isideload::dev::certificates::CertificatesApi;
use rsa::{
    RsaPrivateKey,
    pkcs1::EncodeRsaPublicKey,
    pkcs8::{DecodePrivateKey, EncodePrivateKey},
};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;
use x509_cert::{
    Certificate,
    der::{Decode, Encode},
};

use crate::{
    error::AppError,
    secure_storage::create_sideloading_storage,
    sideload::{SideloaderGuard, SideloaderMutex},
};

const MACHINE_NAME: &str = "iloader";

#[tauri::command]
pub async fn export_p12(
    app: AppHandle,
    password: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let p12 = {
        let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

        // Same storage key isideload uses: "<sha256(email)>/key". Read only, never create.
        let email_hash = hex::encode(Sha256::digest(sideloader.get_mut().get_email().as_bytes()));
        let storage = create_sideloading_storage(&app)?;
        let key_der = storage
            .retrieve_data(&format!("{}/key", email_hash))
            .map_err(|_| AppError::Misc("Failed to read the private key from storage".into()))?
            .filter(|k| !k.is_empty())
            .ok_or_else(|| {
                AppError::Misc(
                    "No stored private key was found for this account. Nothing was created or revoked."
                        .into(),
                )
            })?;
        let private_key = RsaPrivateKey::from_pkcs8_der(&key_der)
            .map_err(|_| AppError::Misc("The stored private key could not be read".into()))?;
        let public_key_der = private_key
            .to_public_key()
            .to_pkcs1_der()
            .map_err(|_| AppError::Misc("Failed to encode the public key".into()))?;

        let team = sideloader.get_mut().get_team().await?;
        let certs = sideloader
            .get_mut()
            .get_dev_session()
            .list_ios_certs(&team)
            .await?;

        let certificate = certs
            .iter()
            .filter(|c| c.machine_name.as_deref() == Some(MACHINE_NAME))
            .find_map(|c| {
                let x509 = Certificate::from_der(c.cert_content.as_ref()?.as_ref()).ok()?;
                let cert_public_key = x509
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .as_bytes()?;
                (cert_public_key == public_key_der.as_bytes()).then_some(x509)
            })
            .ok_or_else(|| {
                AppError::Misc(
                    "No Apple development certificate named \"iloader\" matches the stored private key. Nothing was created or revoked."
                        .into(),
                )
            })?;

        build_p12(&private_key, &certificate, &password)?
    };

    let save_path = app
        .dialog()
        .file()
        .add_filter("PKCS#12", &["p12"])
        .set_file_name("iloader.p12")
        .set_title("Export P12")
        .blocking_save_file();

    if let Some(save_path) = save_path
        && let Some(save_path) = save_path.as_path()
    {
        tokio::fs::write(save_path, &p12)
            .await
            .map_err(|e| AppError::Filesystem("Failed to write p12 file".into(), e.to_string()))?;
        Ok(())
    } else {
        Err(AppError::Canceled("Export".into()))
    }
}

// Mirrors isideload's `CertificateIdentity::as_p12`, without its error logging
// (which would write the certificate subject to the log).
fn build_p12(
    private_key: &RsaPrivateKey,
    certificate: &Certificate,
    password: &str,
) -> Result<Vec<u8>, AppError> {
    let fail = |what: &str| AppError::Misc(format!("Failed to build p12: {}", what));

    let cert_der = certificate.to_der().map_err(|_| fail("certificate"))?;
    let key_der = private_key
        .to_pkcs8_der()
        .map_err(|_| fail("private key"))?
        .as_bytes()
        .to_vec();

    let cert = p12_keystore::Certificate::from_der(&cert_der).map_err(|_| fail("certificate"))?;
    let local_key_id = Sha1::digest(&key_der)[..8].to_vec();
    let key_chain = p12_keystore::PrivateKeyChain::new(
        local_key_id,
        p12_keystore::PrivateKey::from_der(&key_der).map_err(|_| fail("private key"))?,
        vec![cert],
    );

    let mut keystore = p12_keystore::KeyStore::new();
    keystore.add_entry(
        "isideload",
        p12_keystore::KeyStoreEntry::PrivateKeyChain(key_chain),
    );
    keystore
        .writer(password)
        .write()
        .map_err(|_| fail("archive"))
}
