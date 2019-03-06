package com.fedex.security.common;

import javax.crypto.Cipher;
import java.util.Properties;

public interface CipherProvider {
	void configure(String paramString, Properties paramProperties);

	boolean isConfigured(String paramString);

	Cipher getEncryptionCipher(String paramString);

	Cipher getEncryptionCipher(String paramString, boolean paramBoolean);

	Cipher[] getDecryptionCiphers(String paramString);

	void resetDecryptionCipher(String paramString, Cipher paramCipher);

	Cipher[] getDecryptionCiphers(String paramString, boolean paramBoolean);

	void setRotationCallback(RotationCallback paramRotationCallback);

	interface RotationCallback {
		void cleanup(String paramString);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\common\CipherProvider.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */