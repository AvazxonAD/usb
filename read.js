const { PKCS11 } = require("pkcs11js");
const pkcs11 = new PKCS11();

try {
  pkcs11.load("./eTPKCS11.dll");
  pkcs11.C_Initialize();

  const slots = pkcs11.C_GetSlotList(true);
  console.log("Ulangan slotlar:", slots);
} catch (e) {
  console.error(e);
} finally {
  console.log(pkcs11)
}
