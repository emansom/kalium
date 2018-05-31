package org.abstractj.kalium.crypto;

import static org.abstractj.kalium.NaCl.Sodium.CRYPTO_PWHASH_STRBYTES;
import static org.abstractj.kalium.NaCl.sodium;
import org.abstractj.kalium.encoders.Encoder;

public class Argon2Password {

    public String hash(byte[] passwd, Encoder encoder,  long opslimit, long memlimit) {
        byte[] buffer = new byte[CRYPTO_PWHASH_STRBYTES];
        sodium().crypto_pwhash_str(buffer, passwd, passwd.length, opslimit, memlimit);
        return encoder.encode(buffer);
    }

    public boolean verify(byte[] hashed_passwd, byte[] passwd) {
        int result = sodium().crypto_pwhash_str_verify(hashed_passwd, passwd, passwd.length);
        return result == 0;
    }

}
