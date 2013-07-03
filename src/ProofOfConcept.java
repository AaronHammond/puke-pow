import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;
import java.util.*;

public class ProofOfConcept {

    public static void main(String[] args) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {

	    CredentialResponse credentialResponse = CredentialService.getCredentials("11APPLES11");
        String hashedAPIKey = credentialResponse.hashedAPIKey;
        Long lccID = credentialResponse.lccID;

        System.out.println("Our hashed api key is " + hashedAPIKey + " and our ID is " + lccID.toString());

        PublicKeyRequest publicKeyRequest = new PublicKeyRequest(lccID, hashedAPIKey);
        PublicKeyResponse publicKeyResponse = KeyService.processRequest(publicKeyRequest);

        // we now have the public key and our base hash. let's get to work!
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKeyResponse.publicKey);
        Scanner scanner = new Scanner(System.in);
        // this holds the ccn data
        byte[] ccn = new byte[0];
        for(int i = 0; i < 16; i++) {
            String digit = scanner.next("[0-9]");
            ccn = addElement(ccn, (Byte.valueOf(digit)));
            hashedAPIKey = HashService.hash(hashedAPIKey + digit);
            if(ccn.length != 1){
                // talk to me about this. there was a bit of a wrinkle in my understanding of the params for public key encryption (surrounding practical length for RSA application)
                byte[] subccn = Arrays.copyOfRange(ccn, 11*i + i, ccn.length);
                byte[] reappend = Arrays.copyOfRange(ccn, 0, 11 * i + i);
                byte[] encryptedSubCCN = cipher.doFinal(subccn);
                ccn = concat(reappend, encryptedSubCCN);
            }
            else {
                ccn = cipher.doFinal(ccn);
            }
        }
        byte[] decryptedCCN = KeyService.decrypt(ccn, publicKeyResponse.txn);
        String decryptedString = "";
        for(byte b : decryptedCCN){
            decryptedString += b;
        }
        System.out.println("Our decryption of the card: " + decryptedString);
        System.out.println("Our final hash: " + hashedAPIKey);
        String pofHash = HashService.pof(decryptedCCN, lccID);
        System.out.println("Proof of work hash: " + pofHash);
        System.out.println("Do they match? " + pofHash.equals(hashedAPIKey));
    }

    static byte[] addElement(byte[] org, byte added) {
        byte[] result = Arrays.copyOf(org, org.length + 1);
        result[org.length] = added;
        return result;
    }

    static byte[] concat(byte[] A, byte[] B) {
        int aLen = A.length;
        int bLen = B.length;
        byte[] C= new byte[aLen+bLen];
        System.arraycopy(A, 0, C, 0, aLen);
        System.arraycopy(B, 0, C, aLen, bLen);
        return C;

    }

        private static class CredentialResponse {
        Long lccID;
        String hashedAPIKey;

        public CredentialResponse(Long id, String hashedAPIKey) {
            lccID = id;
            this.hashedAPIKey = hashedAPIKey;
        }
    }
    private static class PublicKeyRequest {
        String lccID;
        String hashedAPIKey;

        public PublicKeyRequest(Long lccID, String hashedAPIKey) {
            lccID = lccID;
            hashedAPIKey = hashedAPIKey;
        }
    }
    private static class PublicKeyResponse {
        PublicKey publicKey;
        Long txn;

        public PublicKeyResponse(PublicKey aPublic, Long txn) {
            publicKey = aPublic;
            this.txn = txn;
        }
    }

    private static HashMap<Long, String> idToHashedAPIKeyMap = new HashMap<Long, String>();
    private static HashMap<Long, PrivateKey> txnToPrivateKeyMap = new HashMap<Long, PrivateKey>();

    // for a true PoC, these should be interfaces...

    private static class KeyService {
        static SecureRandom random = new SecureRandom();
        static PublicKeyResponse processRequest(PublicKeyRequest request) {
            KeyPairGenerator kpg = null;
            try {
                kpg = KeyPairGenerator.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            Long txn = random.nextLong();
            txnToPrivateKeyMap.put(txn, kp.getPrivate());
            return new PublicKeyResponse(kp.getPublic(), txn);
        }
        static byte[] decrypt(byte[] ccn, Long txn) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
            PrivateKey privateKey = txnToPrivateKeyMap.get(txn);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            // we're down to the final decryption
            if(ccn.length == 256) {
                return new byte[] {cipher.doFinal(ccn)[0] };
            }
            byte[] priorToAppend = Arrays.copyOfRange(ccn, 0, ccn.length - 256);
            byte[] decrypt = Arrays.copyOfRange(ccn, ccn.length - 256, ccn.length);
            byte[] decrypted = cipher.doFinal(decrypt);

            byte[] next = concat(priorToAppend, decrypted);
            next = Arrays.copyOfRange(next, 0, next.length-1);
            return addElement(decrypt(next, txn), decrypted[244]);
        }
    }

    private static class CredentialService {


        static SecureRandom random = new SecureRandom();

        public static CredentialResponse getCredentials(String apiKey){
            String hashedAPIKey = "";
            try {
                hashedAPIKey = HashService.hash(apiKey);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
            }
            Long id = random.nextLong();
            idToHashedAPIKeyMap.put(id, hashedAPIKey);
            return new CredentialResponse(id, hashedAPIKey);
        }
    }

    private static class HashService {

        public static String pof(byte[] salts, Long lccID) throws UnsupportedEncodingException, NoSuchAlgorithmException {
            String pofHash = idToHashedAPIKeyMap.get(lccID);
            for(byte salt : salts) {
                pofHash = hash(pofHash + salt);
            }
            return pofHash;
        }

        public static String hash(String string) throws UnsupportedEncodingException, NoSuchAlgorithmException {
               return SHA1(string);
        }

        private static String convToHex(byte[] data) {
            StringBuilder buf = new StringBuilder();
            for (int i = 0; i < data.length; i++) {
                int halfbyte = (data[i] >>> 4) & 0x0F;
                int two_halfs = 0;
                do {
                    if ((0 <= halfbyte) && (halfbyte <= 9))
                        buf.append((char) ('0' + halfbyte));
                    else
                        buf.append((char) ('a' + (halfbyte - 10)));
                    halfbyte = data[i] & 0x0F;
                } while(two_halfs++ < 1);
            }
            return buf.toString();
        }

        private static String SHA1(String text) throws NoSuchAlgorithmException,
                UnsupportedEncodingException {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] sha1hash = new byte[40];
            md.update(text.getBytes("iso-8859-1"), 0, text.length());
            sha1hash = md.digest();
            return convToHex(sha1hash);
        }
    }


}
