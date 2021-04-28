package com.danubetech.keyformats.crypto.impl;

import com.danubetech.keyformats.crypto.PublicKeyVerifier;
import com.danubetech.keyformats.jose.JWSAlgorithm;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Sha256Hash;
import org.bitcoinj.core.SignatureDecodeException;

import java.security.GeneralSecurityException;

public class secp256k1_ES256K_PublicKeyVerifier extends PublicKeyVerifier<ECKey> {

    public secp256k1_ES256K_PublicKeyVerifier(ECKey publicKey) {

        super(publicKey, JWSAlgorithm.ES256K);
    }

    @Override
    public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

        try {

            return this.getPublicKey().verify(Sha256Hash.hash(content), signature);
        } catch (SignatureDecodeException ex) {

            throw new GeneralSecurityException(ex.getMessage(), ex);
        }
    }
}
