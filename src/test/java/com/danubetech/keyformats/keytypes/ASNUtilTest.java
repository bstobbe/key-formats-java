package com.danubetech.keyformats.keytypes;

import com.danubetech.keyformats.util.ASNUtil;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ASNUtilTest {

	static final byte[] asn1ESSignature;
	static final byte[] jwsSignature;

	static {
		try {
			asn1ESSignature = Hex.decodeHex("3045022015b2ba8fa18e69882ef4bce07b7b52d1b81c9794e48e2397772125283bbb502d022100f8db6a7ed904fd1dac609685e2c58f3c3beb3c9d27388a0a90fc632c871477d4");
			jwsSignature = Hex.decodeHex("15b2ba8fa18e69882ef4bce07b7b52d1b81c9794e48e2397772125283bbb502df8db6a7ed904fd1dac609685e2c58f3c3beb3c9d27388a0a90fc632c871477d4");
		} catch (DecoderException ex) {
			throw new ExceptionInInitializerError(ex);
		}
	}

	@Test
	public void testAsn1ESSignatureToJwsSignature() throws Exception {
		byte[] jwsSignature = ASNUtil.asn1ESSignatureToJwsSignature(asn1ESSignature, 64);
		assertEquals(Hex.encodeHexString(jwsSignature), Hex.encodeHexString(ASNUtilTest.jwsSignature));
	}

	@Test
	public void testJwsSignatureToAsn1ESSignature() throws Exception {
		byte[] asn1ESSignature = ASNUtil.jwsSignatureToAsn1ESSignature(jwsSignature);
		assertEquals(Hex.encodeHexString(asn1ESSignature), Hex.encodeHexString(ASNUtilTest.asn1ESSignature));
	}
}
