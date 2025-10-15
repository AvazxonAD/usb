const { PKCS11 } = require("pkcs11js");
const pkcs11 = new PKCS11();
const dllPath = "./etpkcs11/opensc_pkcs11.dll";

pkcs11.load(dllPath);

try {
  pkcs11.C_Initialize({ flags: PKCS11.CKF_OS_LOCKING_OK });
  console.log("PKCS#11 initialized successfully");

  const slots = pkcs11.C_GetSlotList(true);
  console.log("Available slots:", slots);

  if (slots.length > 0) {
    const tokenInfo = pkcs11.C_GetTokenInfo(slots[0]);
    console.log("Token serial number:", tokenInfo.serialNumber.trim());
  }

  pkcs11.C_Finalize();
} catch (e) {
  console.error("PKCS#11 error:", e);
}
