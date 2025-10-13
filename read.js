const fs = require("fs");
const path = require("path");
const pkcs11js = require("pkcs11js");
const pkcs11 = new pkcs11js.PKCS11();

const file_name = `eTPKCS11.dll`;
const folder = "C://Windows/System32";

const files = fs.readdirSync(folder);

for (let item of files) {
  if (item === file_name) {
    console.log("connect");
    console.log(item);
  }
}

const file_path = `${folder}/${file_name}`;

const _path = path.join(file_path);
console.log(_path);

pkcs11.load(_path);
pkcs11.C_Initialize();

async function run() {
  try {
    pkcs11.load(dllPath);
    pkcs11.C_Initialize();

    const slots = pkcs11.C_GetSlotList(true);
    if (!slots || slots.length === 0) {
      console.log("Token topilmadi");
      return;
    }

    const slot = slots[0];

    const info = pkcs11.C_GetSlotInfo(slot);
    console.log("Slot info:", info);

    const session = pkcs11.C_OpenSession(slot, pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION);
    const pin = "12345678";
    pkcs11.C_Login(session, 1, pin);

    pkcs11.C_FindObjectsInit(session, [{ type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY }]);

    const handles = pkcs11.C_FindObjects(session, 10);
    pkcs11.C_FindObjectsFinal(session);

    if (!handles || handles.length === 0) {
      console.log("Private key topilmadi");
      pkcs11.C_Logout(session);
      pkcs11.C_CloseSession(session);
      pkcs11.C_Finalize();
      return;
    }

    const privateKey = handles[0];

    const dataToSign = Buffer.from("Hello, token!");
    const mechanism = { mechanism: pkcs11.CKM_SHA1_RSA_PKCS };

    pkcs11.C_SignInit(session, mechanism, privateKey);
    const signature = pkcs11.C_Sign(session, dataToSign);

    console.log("Signature (base64):", signature.toString("base64"));

    pkcs11.C_Logout(session);
    pkcs11.C_CloseSession(session);
    pkcs11.C_Finalize();
  } catch (err) {
    console.error("Xatolik:", err);
    try {
      pkcs11.C_Finalize();
    } catch (e) {}
  }
}

run();
