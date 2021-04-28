package com.danubetech.keyformats.crypto.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.danubetech.keyformats.crypto.PublicKeyVerifier;

import java.security.GeneralSecurityException;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public class RSA_PS256_PublicKeyVerifier extends PublicKeyVerifier<RSAPublicKey> {

	public RSA_PS256_PublicKeyVerifier(RSAPublicKey publicKey) {

		super(publicKey, JWSAlgorithm.PS256.getName());
	}

	@Override
	public boolean verify(byte[] content, byte[] signature) throws GeneralSecurityException {

		PSSParameterSpec pssParameterSpec = new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

		Signature jcaSignature = Signature.getInstance("SHA256withRSAandMGF1");
		jcaSignature.setParameter(pssParameterSpec);

		jcaSignature.initVerify(this.getPublicKey());
		jcaSignature.update(content);

		return jcaSignature.verify(signature);
	}
}
