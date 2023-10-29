const nodemailer = require("nodemailer");
const pool = require("../db/connection.js");


// function for sending mail
function sendMail(name, email) {
    let mailTransporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: 'cmlroot147@gmail.com',
            pass: ''
        }
    });

    let mailDetails = {
        from: 'cmlroot147@gmail.com',
        to: email,
        subject: 'Welcome Email',
        text: "Welcome " + name + " to our Password Manager App Your keys to a secure and organized online life are now in your hands. Safely store and access your passwords with ease. Happy secure browsing!"
    };

    mailTransporter.sendMail(mailDetails, function (err, data) {
        if (err) {
            // console.log('Error Occurs');
            throw err
        } else {
            console.log("mail send successfully");
        }
    });
}

//random String generation
function generateString(objPass) {
    if (objPass) {

        const upperCase1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const lowerCase1 = "abcdefghijklmnopqrstuvwxyz";
        const intger1 = "0123456789";
        const special1 = "!@#$%^&*(){}?/><|\~";
        let characters = '';
        if (objPass.upperCase) {
            characters = characters + upperCase1;
        }
        if (objPass.lowerCase) {
            characters = characters + lowerCase1;
        }
        if (objPass.integer) {
            characters = characters + intger1;
        }
        if (objPass.special) {
            characters = characters + special1;
        }
        let result = '';
        const charactersLength = characters.length;
        for (let i = 0; i < objPass.length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;

    } else {
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        let result = '';
        const charactersLength = characters.length;
        for (let i = 0; i < 10; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    }
    return false;
}


//function  to check login credentials

async function check(req, res) {

    const email = req.body.email;
    const password = req.body.password;
    //console.log(email+" of type "+typeof(email)+"and "+password+" of type "+typeof(password))
    var q = "Select password from user_table where email=?";
    let values = [
        email

    ]
    return new Promise((resolve, reject) => {
        pool.query(q, values, (error, result) => {
            if (error) {
                return reject(error);
            }

            return resolve(result);
        });

    })
}



//Cryptographic Hashing Algo sha1
function sha1(message) {
    function rotateLeft(n, s) {
        return (n << s) | (n >>> (32 - s));
    }

    function preProcessMessage(message) {
        const originalMessageLength = message.length * 8;
        message += String.fromCharCode(0x80);

        let zeroPadding = '';
        while ((message.length * 8) % 512 !== 448) {
            zeroPadding += String.fromCharCode(0x00);
            message += String.fromCharCode(0x00);
        }

        const zeroPadLength = 64 - (message.length + 8) % 64;
        zeroPadding += String.fromCharCode((originalMessageLength >>> 56) & 0xFF,
            (originalMessageLength >>> 48) & 0xFF,
            (originalMessageLength >>> 40) & 0xFF,
            (originalMessageLength >>> 32) & 0xFF,
            (originalMessageLength >>> 24) & 0xFF,
            (originalMessageLength >>> 16) & 0xFF,
            (originalMessageLength >>> 8) & 0xFF,
            originalMessageLength & 0xFF);

        return message + zeroPadding;
    }

    function calculateSHA1(message) {
        const K = [
            0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
        ];

        const w = [];
        for (let i = 0; i < 80; i++) {
            w[i] = 0;
        }

        let h0 = 0x67452301;
        let h1 = 0xEFCDAB89;
        let h2 = 0x98BADCFE;
        let h3 = 0x10325476;
        let h4 = 0xC3D2E1F0;

        message = preProcessMessage(message);

        const chunks = message.length / 64;
        for (let i = 0; i < chunks; i++) {
            const chunk = message.slice(i * 64, (i + 1) * 64);
            for (let j = 0; j < 16; j++) {
                w[j] = chunk.charCodeAt(j * 4) << 24 |
                    chunk.charCodeAt(j * 4 + 1) << 16 |
                    chunk.charCodeAt(j * 4 + 2) << 8 |
                    chunk.charCodeAt(j * 4 + 3);
            }

            for (let j = 16; j < 80; j++) {
                w[j] = rotateLeft(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
            }

            let a = h0;
            let b = h1;
            let c = h2;
            let d = h3;
            let e = h4;

            for (let j = 0; j < 80; j++) {
                let f, k;
                if (j < 20) {
                    f = (b & c) | ((~b) & d);
                    k = K[0];
                } else if (j < 40) {
                    f = b ^ c ^ d;
                    k = K[1];
                } else if (j < 60) {
                    f = (b & c) | (b & d) | (c & d);
                    k = K[2];
                } else {
                    f = b ^ c ^ d;
                    k = K[3];
                }

                const temp = (rotateLeft(a, 5) + f + e + k + w[j]) >>> 0;
                e = d;
                d = c;
                c = rotateLeft(b, 30) >>> 0;
                b = a;
                a = temp;
            }

            h0 = (h0 + a) >>> 0;
            h1 = (h1 + b) >>> 0;
            h2 = (h2 + c) >>> 0;
            h3 = (h3 + d) >>> 0;
            h4 = (h4 + e) >>> 0;
        }

        const hashArray = [h0, h1, h2, h3, h4];
        return hashArray.map(num => ('0000000' + num.toString(16)).slice(-8)).join('');
    }

    return calculateSHA1(message);
}




//Encryption decryption  

'use strict';
var Aes = {};

Aes.cipher = function (input, w) {
    var Nb = 4;               // block size (in words): no of columns in state (fixed at 4 for AES)
    var Nr = w.length / Nb - 1; // no of rounds: 10/12/14 for 128/192/256-bit keys

    var state = [[], [], [], []];  // initialise 4xNb byte-array 'state' with input [§3.4]
    for (var i = 0; i < 4 * Nb; i++) state[i % 4][Math.floor(i / 4)] = input[i];

    state = Aes.addRoundKey(state, w, 0, Nb);

    for (var round = 1; round < Nr; round++) {
        state = Aes.subBytes(state, Nb);
        state = Aes.shiftRows(state, Nb);
        state = Aes.mixColumns(state, Nb);
        state = Aes.addRoundKey(state, w, round, Nb);
    }

    state = Aes.subBytes(state, Nb);
    state = Aes.shiftRows(state, Nb);
    state = Aes.addRoundKey(state, w, Nr, Nb);

    var output = new Array(4 * Nb);  // convert state to 1-d array before returning [§3.4]
    for (var i = 0; i < 4 * Nb; i++) output[i] = state[i % 4][Math.floor(i / 4)];

    return output;
};

Aes.keyExpansion = function (key) {
    var Nb = 4;            // block size (in words): no of columns in state (fixed at 4 for AES)
    var Nk = key.length / 4; // key length (in words): 4/6/8 for 128/192/256-bit keys
    var Nr = Nk + 6;       // no of rounds: 10/12/14 for 128/192/256-bit keys

    var w = new Array(Nb * (Nr + 1));
    var temp = new Array(4);

    // initialise first Nk words of expanded key with cipher key
    for (var i = 0; i < Nk; i++) {
        var r = [key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]];
        w[i] = r;
    }

    // expand the key into the remainder of the schedule
    for (var i = Nk; i < (Nb * (Nr + 1)); i++) {
        w[i] = new Array(4);
        for (var t = 0; t < 4; t++) temp[t] = w[i - 1][t];
        // each Nk'th word has extra transformation
        if (i % Nk == 0) {
            temp = Aes.subWord(Aes.rotWord(temp));
            for (var t = 0; t < 4; t++) temp[t] ^= Aes.rCon[i / Nk][t];
        }
        // 256-bit key has subWord applied every 4th word
        else if (Nk > 6 && i % Nk == 4) {
            temp = Aes.subWord(temp);
        }
        // xor w[i] with w[i-1] and w[i-Nk]
        for (var t = 0; t < 4; t++) w[i][t] = w[i - Nk][t] ^ temp[t];
    }

    return w;
};

Aes.subBytes = function (s, Nb) {
    for (var r = 0; r < 4; r++) {
        for (var c = 0; c < Nb; c++) s[r][c] = Aes.sBox[s[r][c]];
    }
    return s;
};

Aes.shiftRows = function (s, Nb) {
    var t = new Array(4);
    for (var r = 1; r < 4; r++) {
        for (var c = 0; c < 4; c++) t[c] = s[r][(c + r) % Nb];  // shift into temp copy
        for (var c = 0; c < 4; c++) s[r][c] = t[c];         // and copy back
    }          // note that this will work for Nb=4,5,6, but not 7,8 (always 4 for AES):
    return s;  // see asmaes.sourceforge.net/rijndael/rijndaelImplementation.pdf
};

Aes.mixColumns = function (s, Nb) {
    for (var c = 0; c < 4; c++) {
        var a = new Array(4);  // 'a' is a copy of the current column from 's'
        var b = new Array(4);  // 'b' is a•{02} in GF(2^8)
        for (var i = 0; i < 4; i++) {
            a[i] = s[i][c];
            b[i] = s[i][c] & 0x80 ? s[i][c] << 1 ^ 0x011b : s[i][c] << 1;
        }
        // a[n] ^ b[n] is a•{03} in GF(2^8)
        s[0][c] = b[0] ^ a[1] ^ b[1] ^ a[2] ^ a[3]; // {02}•a0 + {03}•a1 + a2 + a3
        s[1][c] = a[0] ^ b[1] ^ a[2] ^ b[2] ^ a[3]; // a0 • {02}•a1 + {03}•a2 + a3
        s[2][c] = a[0] ^ a[1] ^ b[2] ^ a[3] ^ b[3]; // a0 + a1 + {02}•a2 + {03}•a3
        s[3][c] = a[0] ^ b[0] ^ a[1] ^ a[2] ^ b[3]; // {03}•a0 + a1 + a2 + {02}•a3
    }
    return s;
};
Aes.addRoundKey = function (state, w, rnd, Nb) {
    for (var r = 0; r < 4; r++) {
        for (var c = 0; c < Nb; c++) state[r][c] ^= w[rnd * 4 + c][r];
    }
    return state;
};
Aes.subWord = function (w) {
    for (var i = 0; i < 4; i++) w[i] = Aes.sBox[w[i]];
    return w;
};
Aes.rotWord = function (w) {
    var tmp = w[0];
    for (var i = 0; i < 3; i++) w[i] = w[i + 1];
    w[3] = tmp;
    return w;
};


// sBox is pre-computed multiplicative inverse in GF(2^8) used in subBytes and keyExpansion [§5.1.1]
Aes.sBox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];


// rCon is Round Constant used for the Key Expansion [1st col is 2^(r-1) in GF(2^8)] [§5.2]
Aes.rCon = [[0x00, 0x00, 0x00, 0x00],
[0x01, 0x00, 0x00, 0x00],
[0x02, 0x00, 0x00, 0x00],
[0x04, 0x00, 0x00, 0x00],
[0x08, 0x00, 0x00, 0x00],
[0x10, 0x00, 0x00, 0x00],
[0x20, 0x00, 0x00, 0x00],
[0x40, 0x00, 0x00, 0x00],
[0x80, 0x00, 0x00, 0x00],
[0x1b, 0x00, 0x00, 0x00],
[0x36, 0x00, 0x00, 0x00]];


/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
if (typeof module != 'undefined' && module.exports) module.exports = Aes; // ≡ export default Aes

Aes.Ctr = {};
Aes.Ctr.encrypt = function (plaintext, password, nBits) {
    var blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
    if (!(nBits == 128 || nBits == 192 || nBits == 256)) throw new Error('Key size is not 128 / 192 / 256');
    plaintext = String(plaintext).utf8Encode();
    password = String(password).utf8Encode();
    var nBytes = nBits / 8;  // no bytes in key (16/24/32)
    var pwBytes = new Array(nBytes);
    for (var i = 0; i < nBytes; i++) {  // use 1st 16/24/32 chars of password for key
        pwBytes[i] = i < password.length ? password.charCodeAt(i) : 0;
    }
    var key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes)); // gives us 16-byte key
    key = key.concat(key.slice(0, nBytes - 16));  // expand key to 16/24/32 bytes long
    var counterBlock = new Array(blockSize);

    var nonce = (new Date()).getTime();  // timestamp: milliseconds since 1-Jan-1970
    var nonceMs = nonce % 1000;
    var nonceSec = Math.floor(nonce / 1000);
    var nonceRnd = Math.floor(Math.random() * 0xffff);
    // for debugging: nonce = nonceMs = nonceSec = nonceRnd = 0;

    for (var i = 0; i < 2; i++) counterBlock[i] = (nonceMs >>> i * 8) & 0xff;
    for (var i = 0; i < 2; i++) counterBlock[i + 2] = (nonceRnd >>> i * 8) & 0xff;
    for (var i = 0; i < 4; i++) counterBlock[i + 4] = (nonceSec >>> i * 8) & 0xff;

    // and convert it to a string to go on the front of the ciphertext
    var ctrTxt = '';
    for (var i = 0; i < 8; i++) ctrTxt += String.fromCharCode(counterBlock[i]);

    // generate key schedule - an expansion of the key into distinct Key Rounds for each round
    var keySchedule = Aes.keyExpansion(key);

    var blockCount = Math.ceil(plaintext.length / blockSize);
    var ciphertext = '';

    for (var b = 0; b < blockCount; b++) {
        // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
        // done in two stages for 32-bit ops: using two words allows us to go past 2^32 blocks (68GB)
        for (var c = 0; c < 4; c++) counterBlock[15 - c] = (b >>> c * 8) & 0xff;
        for (var c = 0; c < 4; c++) counterBlock[15 - c - 4] = (b / 0x100000000 >>> c * 8);

        var cipherCntr = Aes.cipher(counterBlock, keySchedule);  // -- encrypt counter block --

        // block size is reduced on final block
        var blockLength = b < blockCount - 1 ? blockSize : (plaintext.length - 1) % blockSize + 1;
        var cipherChar = new Array(blockLength);

        for (var i = 0; i < blockLength; i++) {
            // -- xor plaintext with ciphered counter char-by-char --
            cipherChar[i] = cipherCntr[i] ^ plaintext.charCodeAt(b * blockSize + i);
            cipherChar[i] = String.fromCharCode(cipherChar[i]);
        }
        ciphertext += cipherChar.join('');

        // if within web worker, announce progress every 1000 blocks (roughly every 50ms)
        if (typeof WorkerGlobalScope != 'undefined' && self instanceof WorkerGlobalScope) {
            if (b % 1000 == 0) self.postMessage({ progress: b / blockCount });
        }
    }

    ciphertext = (ctrTxt + ciphertext).base64Encode();

    return ciphertext;
};
Aes.Ctr.decrypt = function (ciphertext, password, nBits) {
    var blockSize = 16;  // block size fixed at 16 bytes / 128 bits (Nb=4) for AES
    if (!(nBits == 128 || nBits == 192 || nBits == 256)) throw new Error('Key size is not 128 / 192 / 256');
    ciphertext = String(ciphertext).base64Decode();
    password = String(password).utf8Encode();

    // use AES to encrypt password (mirroring encrypt routine)
    var nBytes = nBits / 8;  // no bytes in key
    var pwBytes = new Array(nBytes);
    for (var i = 0; i < nBytes; i++) {
        pwBytes[i] = i < password.length ? password.charCodeAt(i) : 0;
    }
    var key = Aes.cipher(pwBytes, Aes.keyExpansion(pwBytes));
    key = key.concat(key.slice(0, nBytes - 16));  // expand key to 16/24/32 bytes long

    // recover nonce from 1st 8 bytes of ciphertext
    var counterBlock = new Array(8);
    var ctrTxt = ciphertext.slice(0, 8);
    for (var i = 0; i < 8; i++) counterBlock[i] = ctrTxt.charCodeAt(i);

    // generate key schedule
    var keySchedule = Aes.keyExpansion(key);

    // separate ciphertext into blocks (skipping past initial 8 bytes)
    var nBlocks = Math.ceil((ciphertext.length - 8) / blockSize);
    var ct = new Array(nBlocks);
    for (var b = 0; b < nBlocks; b++) ct[b] = ciphertext.slice(8 + b * blockSize, 8 + b * blockSize + blockSize);
    ciphertext = ct;  // ciphertext is now array of block-length strings

    // plaintext will get generated block-by-block into array of block-length strings
    var plaintext = '';

    for (var b = 0; b < nBlocks; b++) {
        // set counter (block #) in last 8 bytes of counter block (leaving nonce in 1st 8 bytes)
        for (var c = 0; c < 4; c++) counterBlock[15 - c] = ((b) >>> c * 8) & 0xff;
        for (var c = 0; c < 4; c++) counterBlock[15 - c - 4] = (((b + 1) / 0x100000000 - 1) >>> c * 8) & 0xff;

        var cipherCntr = Aes.cipher(counterBlock, keySchedule);  // encrypt counter block

        var plaintxtByte = new Array(ciphertext[b].length);
        for (var i = 0; i < ciphertext[b].length; i++) {
            // -- xor plaintext with ciphered counter byte-by-byte --
            plaintxtByte[i] = cipherCntr[i] ^ ciphertext[b].charCodeAt(i);
            plaintxtByte[i] = String.fromCharCode(plaintxtByte[i]);
        }
        plaintext += plaintxtByte.join('');

        // if within web worker, announce progress every 1000 blocks (roughly every 50ms)
        if (typeof WorkerGlobalScope != 'undefined' && self instanceof WorkerGlobalScope) {
            if (b % 1000 == 0) self.postMessage({ progress: b / nBlocks });
        }
    }

    plaintext = plaintext.utf8Decode();  // decode from UTF8 back to Unicode multi-byte chars

    return plaintext;
};

if (typeof String.prototype.utf8Encode == 'undefined') {
    String.prototype.utf8Encode = function () {
        return unescape(encodeURIComponent(this));
    };
}
if (typeof String.prototype.utf8Decode == 'undefined') {
    String.prototype.utf8Decode = function () {
        try {
            return decodeURIComponent(escape(this));
        } catch (e) {
            return this; // invalid UTF-8? return as-is
        }
    };
}

if (typeof String.prototype.base64Encode == 'undefined') {
    String.prototype.base64Encode = function () {
        if (typeof btoa != 'undefined') return btoa(this); // browser
        if (typeof Buffer != 'undefined') return new Buffer(this, 'binary').toString('base64'); // Node.js
        throw new Error('No Base64 Encode');
    };
}

if (typeof String.prototype.base64Decode == 'undefined') {
    String.prototype.base64Decode = function () {
        if (typeof atob != 'undefined') return atob(this); // browser
        if (typeof Buffer != 'undefined') return new Buffer(this, 'base64').toString('binary'); // Node.js
        throw new Error('No Base64 Decode');
    };
}
if (typeof module != 'undefined' && module.exports) module.exports = Aes.Ctr; // ≡ export default Aes.Ctr
// const ct=Aes.Ctr.encrypt("Hello","Bilal",128);
// console.log(ct);
// const dt=Aes.Ctr.decrypt("JwNfz3DBEmVnlOZnHA==","Bilal",128);
// console.log("After Decryption    "+dt);



//creating Cipher and hash
function objCipherHash(objPass) {

    const key = "CiberSecurity";
    console.log("first Encryption " + Aes.Ctr.encrypt('bilal', key, 128));
    console.log("second Encryption " + Aes.Ctr.encrypt('bilal', key, 128));
    console.log("first Decryption " + Aes.Ctr.decrypt(Aes.Ctr.encrypt('bilal', key, 128),key,128));
    console.log("second Decryption " + Aes.Ctr.decrypt(Aes.Ctr.encrypt('bilal', key, 128),key,128));

    if (objPass) {
        const randomString = generateString(objPass);
        const key = "CiberSecurity";
        const cipher = Aes.Ctr.encrypt(randomString, key, 128);
        const object2 = {
            hash: randomString,
            cipher: cipher
        }
        return object2;
    } else {
        const randomString = generateString(null);
        const hash = sha1(randomString);
        const key = "CiberSecurity";
        const cipher = Aes.Ctr.encrypt(hash, key, 128);
        const object2 = {
            hash: hash,
            cipher: cipher
        }
        return object2;
    }
}
//encrypt the cipher-----------
function encryptCipher(text) {
    const key = "CiberSecurity";
    const cipher = Aes.Ctr.encrypt(text, key, 128);
    return cipher;
}

// fetching the cipher and decrypting the cipher
function decryptCipher(cipher) {
    const key = "CiberSecurity";
    const fetchedHash = Aes.Ctr.decrypt(cipher, key, 128);
    return fetchedHash;
}


module.exports = {
    sendMail: sendMail,
    check: check,
    sha1: sha1,
    objCipherHash: objCipherHash,
    randomString: generateString,
    decryptCipher: decryptCipher,
    encryptCipher: encryptCipher

}

