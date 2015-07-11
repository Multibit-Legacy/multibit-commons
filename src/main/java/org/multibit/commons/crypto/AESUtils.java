package org.multibit.commons.crypto;

import com.google.common.base.Preconditions;
import com.google.protobuf.ByteString;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.Utils;
import org.bitcoinj.crypto.KeyCrypterException;
import org.bitcoinj.crypto.KeyCrypterScrypt;
import org.bitcoinj.wallet.Protos;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.crypto.BufferedBlockCipher;
import org.spongycastle.crypto.InvalidCipherTextException;
import org.spongycastle.crypto.engines.AESFastEngine;
import org.spongycastle.crypto.modes.CBCBlockCipher;
import org.spongycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.crypto.params.ParametersWithIV;
import org.spongycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

/**
 * <p>Utility class to provide the following to BRIT API:</p>
 * <ul>
 * <li>Encryption and decryption using AES</li>
 * </ul>
 *
 * @since 0.0.1
 */
public class AESUtils {

  /**
   * Key length in bytes.
   */
  public static final int KEY_LENGTH = 32; // = 256 bits.

  /**
   * The size of an AES block in bytes.
   * This is also the length of the initialisation vector.
   */
  public static final int BLOCK_LENGTH = 16;  // = 128 bits.

  /**
   * Utilities have private constructors
   */
  private AESUtils() {
  }

  /**
   * Password based encryption using AES - CBC 256 bits.
   *
   * @param plainBytes           The unencrypted bytes for encryption
   * @param aesKey               The AES key to use for encryption
   * @param initialisationVector The initialisationVector to use whilst encrypting
   *
   * @return The encrypted bytes
   */
  public static byte[] encrypt(byte[] plainBytes, KeyParameter aesKey, byte[] initialisationVector) throws KeyCrypterException {

    checkNotNull(plainBytes);
    checkNotNull(aesKey);
    checkNotNull(initialisationVector);
    checkState(initialisationVector.length == BLOCK_LENGTH, "The initialisationVector must be " + BLOCK_LENGTH + " bytes long.");

    ParametersWithIV keyWithIv = new ParametersWithIV(aesKey, initialisationVector);

    try {
      // Encrypt using AES
      BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
      cipher.init(true, keyWithIv);
      byte[] encryptedBytes = new byte[cipher.getOutputSize(plainBytes.length)];
      final int processLength = cipher.processBytes(plainBytes, 0, plainBytes.length, encryptedBytes, 0);
      final int doFinalLength;

      doFinalLength = cipher.doFinal(encryptedBytes, processLength);
      return Arrays.copyOf(encryptedBytes, processLength + doFinalLength);
    } catch (RuntimeException | InvalidCipherTextException e) {
      throw new KeyCrypterException("Could not encrypt bytes.", e);
    }

  }

  /**
   * Decrypt bytes previously encrypted with this class.
   *
   * @param encryptedBytes       The encrypted bytes required to decrypt
   * @param aesKey               The AES key to use for decryption
   * @param initialisationVector The initialisationVector to use whilst decrypting
   *
   * @return The decrypted bytes
   *
   * @throws KeyCrypterException if bytes could not be decoded to a valid key
   */

  public static byte[] decrypt(byte[] encryptedBytes, KeyParameter aesKey, byte[] initialisationVector) throws KeyCrypterException {

    checkNotNull(encryptedBytes);
    checkNotNull(aesKey);
    checkNotNull(initialisationVector);

    try {
      ParametersWithIV keyWithIv = new ParametersWithIV(new KeyParameter(aesKey.getKey()), initialisationVector);

      // Decrypt the message.
      BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESFastEngine()));
      cipher.init(false, keyWithIv);

      int minimumSize = cipher.getOutputSize(encryptedBytes.length);
      byte[] outputBuffer = new byte[minimumSize];
      int length1 = cipher.processBytes(encryptedBytes, 0, encryptedBytes.length, outputBuffer, 0);
      int length2 = cipher.doFinal(outputBuffer, length1);
      int actualLength = length1 + length2;

      byte[] decryptedBytes = new byte[actualLength];
      System.arraycopy(outputBuffer, 0, decryptedBytes, 0, actualLength);

      return decryptedBytes;
    } catch (RuntimeException | InvalidCipherTextException e) {
      // Most likely a bad password
      throw new KeyCrypterException("Could not decrypt: " + e.getMessage() , e);
    }
  }

  /**
   * Generate 160 bits of entropy from the seed bytes.
   * This uses a number of trapdoor functions and is tweakable by specifying a custom salt value
   *
   * @param seed seed bytes to use as 'credentials'/ initial value
   * @param salt salt value used to customise trapdoor functions
   * @return entropy 20 bytes of entropy
   */
  public static byte[] generate160BitsOfEntropy(byte[] seed, byte[] salt) {
    Preconditions.checkNotNull(seed);
    Preconditions.checkNotNull(salt);

    BigInteger seedBigInteger = new BigInteger(1, seed);

    // Convert the seed to entropy using various trapdoor functions.

    // Scrypt - scrypt is run using the seedBigInteger.toString() as the 'credentials'.
    // This returns a byte array (normally used as an AES256 key but here passed on to more trapdoor functions).
    // The scrypt parameters used are the default, except for the salt which is passed in.
    Protos.ScryptParameters.Builder scryptParametersBuilder = Protos.ScryptParameters.newBuilder().setSalt(ByteString.copyFrom(salt));
    Protos.ScryptParameters scryptParameters = scryptParametersBuilder.build();
    KeyCrypterScrypt keyCrypterScrypt = new KeyCrypterScrypt(scryptParameters);
    KeyParameter keyParameter = keyCrypterScrypt.deriveKey(seedBigInteger.toString());
    byte[] derivedKey = keyParameter.getKey();

    // Ensure that the seed is within the Bitcoin EC group.
    X9ECParameters params = SECNamedCurves.getByName("secp256k1");
    BigInteger sizeOfGroup = params.getN();

    BigInteger derivedKeyBigInteger = new BigInteger(1, derivedKey);

    derivedKeyBigInteger = derivedKeyBigInteger.mod(sizeOfGroup);

    // EC curve generator function used to convert the key just derived (a 'private key') to a 'public key'
    ECPoint point = ECKey.CURVE.getG().multiply(derivedKeyBigInteger);
    // Note the public key is not compressed
    byte[] publicKey = point.getEncoded();

    // SHA256RIPE160 to generate final walletId bytes from the 'public key'

    return Utils.sha256hash160(publicKey);
  }

  /**
   * Create an AES 256 key given 20 bytes of entropy (e.g. a walletId) and a salt byte array
   * @param seed entropy, typically a wallet id or a credentials as bytes
   * @param salt bytes, used as salt
   * @return a KeyParameter suitable for AES encryption and decryption
   * @throws NoSuchAlgorithmException
   */
  public static KeyParameter createAESKey(byte[] seed, byte[] salt) throws NoSuchAlgorithmException {
    Preconditions.checkNotNull(seed);
    Preconditions.checkNotNull(salt);

    byte[] entropy = generate160BitsOfEntropy(seed, salt);

    // Stretch the 20 byte entropy to 32 bytes (256 bits) using SHA256
    byte[] stretchedEntropy = MessageDigest.getInstance("SHA-256").digest(entropy);

    return new KeyParameter(stretchedEntropy);
  }

}
