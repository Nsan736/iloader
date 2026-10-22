import "./Certificates.css";
import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { useError } from "../ErrorContext";
import { useTranslation } from "react-i18next";
import { Modal } from "../components/Modal";

export type Certificate = {
  name: string;
  certificateId: string;
  serialNumber: string;
  machineName: string;
  machineId: string;
};

export const Certificates = () => {
  const { t } = useTranslation();
  const [certificates, setCertificates] = useState<Certificate[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const loadingRef = useRef<boolean>(false);
  const { err } = useError();
  const [exportOpen, setExportOpen] = useState<boolean>(false);
  const [exportPassword, setExportPassword] = useState<string>("");
  const [exporting, setExporting] = useState<boolean>(false);

  const loadCertificates = useCallback(async () => {
    if (loadingRef.current) return;
    const promise = async () => {
      loadingRef.current = true;
      setLoading(true);
      let certs = await invoke<Certificate[]>("get_certificates");
      setCertificates(certs);
      setLoading(false);
      loadingRef.current = false;
    };
    toast.promise(promise, {
      loading: t("certificates.loading"),
      success: t("certificates.loaded_success"),
      error: (e) => err(t("certificates.failed_load"), e),
    });
  }, [setCertificates, t]);

  const revokeCertificate = useCallback(
    async (serialNumber: string) => {
      const promise = invoke<void>("revoke_certificate", {
        serialNumber,
      });
      promise.then(loadCertificates);
      toast.promise(promise, {
        loading: t("certificates.revoking"),
        success: t("certificates.revoked_success"),
        error: (e) => err(t("certificates.failed_revoke"), e),
      });
    },
    [setCertificates, loadCertificates, t],
  );

  const closeExport = useCallback(() => {
    setExportOpen(false);
    setExportPassword("");
  }, []);

  const exportP12 = useCallback(async () => {
    const password = exportPassword;
    closeExport();
    setExporting(true);
    const promise = invoke<void>("export_p12", { password });
    promise.finally(() => setExporting(false));
    toast.promise(promise, {
      loading: t("certificates.exporting_p12"),
      success: t("certificates.exported_p12_success"),
      error: (e) => err(t("certificates.failed_export_p12"), e),
    });
  }, [exportPassword, closeExport, t]);

  useEffect(() => {
    loadCertificates();
  }, []);

  return (
    <>
      <h2>{t("certificates.manage")}</h2>
      {certificates.length === 0 ? (
        <div>{loading ? t("certificates.loading") : t("certificates.none_found")}</div>
      ) : (
        <div className="card">
          <div className="certificate-table-container">
            <table className="certificate-table">
              <thead>
                <tr className="certificate-item">
                  <th className="cert-item-part">{t("certificates.name")}</th>
                  <th className="cert-item-part">{t("certificates.serial_number")}</th>
                  <th className="cert-item-part">{t("certificates.machine_name")}</th>
                  <th className="cert-item-part">{t("certificates.machine_id")}</th>
                  <th>{t("certificates.revoke")}</th>
                </tr>
              </thead>
              <tbody>
                {certificates.map((cert, i) => (
                  <tr
                    key={cert.certificateId}
                    className={
                      "certificate-item" +
                      (i === certificates.length - 1 ? " cert-item-last" : "")
                    }
                  >
                    <td className="cert-item-part">{cert.name}</td>
                    <td className="cert-item-part">{cert.serialNumber}</td>
                    <td className="cert-item-part">{cert.machineName}</td>
                    <td className="cert-item-part">{cert.machineId}</td>
                    <td
                      className="cert-item-revoke"
                      role="button"
                      tabIndex={0}
                      onClick={() => revokeCertificate(cert.serialNumber)}
                    >
                      {t("certificates.revoke")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
      <button
        style={{ marginTop: "1em", width: "100%" }}
        onClick={loadCertificates}
        disabled={loading}
      >
        {t("common.refresh")}
      </button>
      <button
        style={{ marginTop: "1em", width: "100%" }}
        onClick={() => setExportOpen(true)}
        disabled={exporting}
      >
        {t("certificates.export_p12")}
      </button>
      <Modal isOpen={exportOpen} close={closeExport} sizeFit>
        <h2>{t("certificates.export_p12")}</h2>
        <p>{t("certificates.export_p12_desc")}</p>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            exportP12();
          }}
        >
          <input
            type="password"
            autoComplete="new-password"
            placeholder={t("certificates.export_p12_password")}
            value={exportPassword}
            onChange={(e) => setExportPassword(e.target.value)}
            style={{ width: "100%", boxSizing: "border-box" }}
            autoFocus
          />
          <div style={{ display: "flex", gap: "0.5em", marginTop: "1em" }}>
            <button type="button" style={{ flex: 1 }} onClick={closeExport}>
              {t("common.cancel")}
            </button>
            <button type="submit" style={{ flex: 1 }}>
              {t("certificates.export_p12")}
            </button>
          </div>
        </form>
      </Modal>
    </>
  );
};
