
import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;


public class Cbcenc {
	//putting into AES to encrypt
	private static byte[] encrypt_data(byte[] data) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
	IllegalBlockSizeException, BadPaddingException{
		String key = "bad8deadcafef00d";

		/*SecretKeySpec(byte[] key, String algorithm)
		Constructs a secret key from the given byte array.*/
		SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes(), "AES");

		//provide details for mode and padding scheme
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

		//init(int opmode, Key key) Initializes this cipher mode with a key.
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

		// public final byte[] doFinal(byte[] input)
		byte[] ct = cipher.doFinal(data);
        	return ct;
   	}
	
	//generate IV with random()
	public static void IVgen(LinkedList<Integer> IVrand){
		Random rand = new Random();
		
		for(int i = 0; i < 128; i++){
			//each bit
			int r = rand.nextInt(15)+1;//15 is max number in a bit,1 is min
			IVrand.add(r);
		}
	
	}
	
	public static void main(String[] args)throws Exception{
		String test = "1234567890abcdef";
		
		//Make IV
		LinkedList<Integer> IVrand = new LinkedList<Integer>();
		Cbcenc.IVgen(IVrand);
		
		//test IV
		for(int i : IVrand){
			System.out.print(i);
		}
		System.out.println();
	
		
		//encrypt
		//getBytes returns an array of bytes
		byte[] ct = Cbcenc.encrypt_data(test.getBytes());
		System.out.println(new String(ct));
			
	}
}
