const pcsclite = require('@pokusew/pcsclite');

console.log('=== ePass2003 - To\'g\'ri ketma-ketlik ===\n');

const PIN = '12345678'; // O'z PIN kodingizni kiriting!

const pcsc = pcsclite();

// APDU javobni parse qilish
function parseResponse(response, name) {
  if (response.length < 2) {
    console.log(`   ❌ ${name}: Javob juda qisqa`);
    return { success: false, sw1: 0, sw2: 0, data: Buffer.alloc(0) };
  }
  
  const sw1 = response[response.length - 2];
  const sw2 = response[response.length - 1];
  const data = response.slice(0, -2);
  
  const statusStr = `${sw1.toString(16).padStart(2, '0').toUpperCase()} ${sw2.toString(16).padStart(2, '0').toUpperCase()}`;
  
  let success = false;
  let message = '';
  
  if (sw1 === 0x90 && sw2 === 0x00) {
    success = true;
    message = '✅ Muvaffaqiyatli';
  } else if (sw1 === 0x61) {
    success = true;
    message = `✅ Muvaffaqiyatli (${sw2} bytes qoldi)`;
  } else if (sw1 === 0x6C) {
    message = `⚠️  Noto'g'ri uzunlik (to'g'risi: ${sw2})`;
  } else if (sw1 === 0x69 && sw2 === 0x82) {
    message = '❌ Security status not satisfied';
  } else if (sw1 === 0x69 && sw2 === 0x85) {
    message = '❌ Conditions of use not satisfied';
  } else if (sw1 === 0x6A && sw2 === 0x82) {
    message = '❌ File not found';
  } else if (sw1 === 0x6A && sw2 === 0x86) {
    message = '❌ Incorrect P1 P2';
  } else if (sw1 === 0x63 && (sw2 & 0xF0) === 0xC0) {
    message = `⚠️  Verification failed (${sw2 & 0x0F} tries left)`;
  } else {
    message = '⚠️  Noma\'lum status';
  }
  
  console.log(`   ${name}: ${statusStr} - ${message}`);
  if (data.length > 0) {
    console.log(`   Data (${data.length} bytes):`, data.slice(0, Math.min(32, data.length)).toString('hex').toUpperCase());
  }
  
  return { success, sw1, sw2, data };
}

// APDU yuborish
function sendAPDU(reader, protocol, apdu, name) {
  return new Promise((resolve, reject) => {
    console.log(`\n📤 ${name}`);
    console.log(`   CMD: ${apdu.toString('hex').toUpperCase()}`);
    
    reader.transmit(apdu, 4096, protocol, (err, response) => {
      if (err) {
        console.log(`   ❌ Xatolik: ${err.message}`);
        reject(err);
      } else {
        const result = parseResponse(response, 'Response');
        resolve(result);
      }
    });
  });
}

pcsc.on('reader', (reader) => {
  console.log('✓ Reader:', reader.name);

  reader.on('status', (status) => {
    const changes = status.state ^ reader.state;
    
    if ((changes & reader.SCARD_STATE_PRESENT) && (status.state & reader.SCARD_STATE_PRESENT)) {
      console.log('\n✅ Token ulandi!');
      console.log('ATR:', status.atr.toString('hex').toUpperCase());
      
      reader.connect({ share_mode: reader.SCARD_SHARE_SHARED }, async (err, protocol) => {
        if (err) {
          console.error('❌ Connect xatolik:', err.message);
          return;
        }

        console.log('✓ Protocol:', protocol === 1 ? 'T=0' : 'T=1');
        console.log('\n=== BOSHLASH ===');

        try {
          // 1. GET DATA - Token ma'lumotlarini olish
          await sendAPDU(
            reader, protocol,
            Buffer.from([0x00, 0xCA, 0x01, 0x00, 0x00]),
            '1. GET DATA (Token info)'
          );

          // 2. SELECT Master File
          await sendAPDU(
            reader, protocol,
            Buffer.from([0x00, 0xA4, 0x00, 0x0C, 0x02, 0x3F, 0x00]),
            '2. SELECT MF (3F00)'
          );

          // 3. SELECT Application by AID - PKCS#15
          const pkcs15Aid = Buffer.from([0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35]);
          await sendAPDU(
            reader, protocol,
            Buffer.concat([Buffer.from([0x00, 0xA4, 0x04, 0x00, pkcs15Aid.length]), pkcs15Aid]),
            '3. SELECT PKCS#15 Application'
          );

          // 4. SELECT by Path - PKCS#15 Directory
          await sendAPDU(
            reader, protocol,
            Buffer.from([0x00, 0xA4, 0x08, 0x00, 0x02, 0x50, 0x15]),
            '4. SELECT PKCS#15 Dir (5015)'
          );

          // 5. LIST FILES
          await sendAPDU(
            reader, protocol,
            Buffer.from([0x80, 0xAA, 0x00, 0x00, 0x00]),
            '5. LIST FILES'
          );

          // 6. GET RESPONSE agar 61 xx bo'lsa
          await sendAPDU(
            reader, protocol,
            Buffer.from([0x00, 0xC0, 0x00, 0x00, 0x00]),
            '6. GET RESPONSE'
          );

          // 7. VERIFY PIN (turli variantlar)
          console.log('\n=== PIN VERIFY ===');
          
          const pinVariants = [
            { p2: 0x00, name: 'User PIN (P2=00)' },
            { p2: 0x01, name: 'Key reference 01' },
            { p2: 0x80, name: 'Local PIN (P2=80)' },
            { p2: 0x81, name: 'Global PIN (P2=81)' },
          ];

          let authenticated = false;
          for (const variant of pinVariants) {
            const pinBuf = Buffer.from(PIN, 'ascii');
            const result = await sendAPDU(
              reader, protocol,
              Buffer.concat([Buffer.from([0x00, 0x20, 0x00, variant.p2, pinBuf.length]), pinBuf]),
              `VERIFY ${variant.name}`
            );
            
            if (result.success) {
              authenticated = true;
              break;
            }
          }

          if (!authenticated) {
            console.log('\n⚠️  PIN authenticate ishlamadi, davom etamiz...');
          }

          // 8. READ BINARY - turli offsetlar
          console.log('\n=== MA\'LUMOTLARNI O\'QISH ===');
          
          const offsets = [0x0000, 0x0001, 0x0002];
          for (const offset of offsets) {
            await sendAPDU(
              reader, protocol,
              Buffer.from([0x00, 0xB0, (offset >> 8) & 0xFF, offset & 0xFF, 0x00]),
              `READ BINARY (offset ${offset.toString(16).padStart(4, '0')})`
            );
          }

          // 9. SELECT va READ - turli file IDlar
          console.log('\n=== FAYLLARNI O\'QISH ===');
          
          const fileIds = [
            { id: [0x50, 0x15], name: 'PKCS#15' },
            { id: [0x50, 0x32], name: 'TokenInfo' },
            { id: [0x44, 0x01], name: 'Certificates' },
            { id: [0x40, 0x01], name: 'Private Keys' },
            { id: [0x42, 0x01], name: 'Public Keys' },
          ];

          for (const file of fileIds) {
            const selectResult = await sendAPDU(
              reader, protocol,
              Buffer.concat([Buffer.from([0x00, 0xA4, 0x02, 0x00, 0x02]), Buffer.from(file.id)]),
              `SELECT ${file.name} (${file.id.map(b => b.toString(16).padStart(2, '0')).join('')})`
            );

            if (selectResult.success) {
              await sendAPDU(
                reader, protocol,
                Buffer.from([0x00, 0xB0, 0x00, 0x00, 0x00]),
                `READ ${file.name}`
              );
            }
          }

          console.log('\n✅ Barcha testlar tugadi!\n');
          
        } catch (error) {
          console.error('\n❌ Xatolik:', error.message);
        } finally {
          reader.close();
          pcsc.close();
        }
      });
    }
  });
});

pcsc.on('error', (err) => {
  if (!err.message.includes('cancelled')) {
    console.error('❌ Xatolik:', err.message);
  }
});

console.log('⏳ Token kutilmoqda...\n');