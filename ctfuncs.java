import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.io.*;

public class ctfuncs
{
	
	static int BIT_BLOCK_SIZE = 128;
	//need to divide by 8 because it will be in BYTES
	// so 128 bits / 8 = 16 bytes
	static int BLOCK_SIZE = BIT_BLOCK_SIZE/8;
	
	//Put block and key into AES to encrypt
	static byte[] encrypt_data(byte[] data, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
	IllegalBlockSizeException, BadPaddingException
	{
		/*SecretKeySpec(byte[] key, String algorithm)
		Constructs a secret key from the given byte array.*/
		SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");


		//provide details for mode and padding scheme
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

		//init(int opmode, Key key) Initializes this cipher mode with a key.
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

		// public final byte[] doFinal(byte[] input)
		byte[] ct = cipher.doFinal(data);
        
		return ct;
   	}
	
	//Put block and key into AES to decrypt
	public static byte[] decrypt_data(byte[] encData, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
	IllegalBlockSizeException, BadPaddingException
    {
		/*SecretKeySpec(byte[] key, String algorithm)
		Constructs a secret key from the given byte array.*/
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        
        //provide details for mode and padding scheme
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        //init(int opmode, Key key) Initializes this cipher mode with a key.
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);

        byte[] original = cipher.doFinal(encData);
        return original;
    }
	
	/*
	 * Generates random IV 
	 */
	public static byte[] IVgen()
	{
		byte[] IV = new byte[BLOCK_SIZE];	
		SecureRandom random = new SecureRandom();
		random.nextBytes(IV);

		return IV;
	}

	/*
	 * Gets key file from command line with -k command
	 */
	public static byte[] key_file ( String[] args ) throws Exception
	{
		byte[] data = null;
				
		for ( int i = 0; i < args.length; i++ )
		{
			//-k <key file>:  required, specifies a file storing a valid AES key as a hex encoded string
			if ( args[i].equals("-k") )
			{
				i++;
				

				data =  read_hex_file(args[i]);

				
				break;
			}

		}

		if (data == null)
		{
			System.err.println("No file was found. Need to exit");
			System.exit(0);
		}
		
		return data;
					
	}
	
	/* 
	 * looks for input file, error if not found
	 */
	public static byte[] input_file ( String[] args ) throws Exception
	{
		byte[] data = null;
				
		for ( int i = 0; i < args.length; i++ )
		{
			//Tries to find input file
			if ( args[i].equals("-i") )
			{
				i++;
				
				data = read_file(args[i]);
				
				break;
			}
			
		}
		
		if (data == null)
		{
			System.err.println("No file was found. Need to exit");
			System.exit(0);
		}
		
		return data;
					
	}
	
	/*
	 * Gets output file name from command line with -o
	 */
	public static void output_file ( String[] args, byte[] output ) throws Exception
	{
		for ( int i = 0; i < args.length; i++ )
		{
			//-o <output file>: required, specifies the path of the file where the resulting output is stored
			if ( args[i].equals("-o") )
			{
				i++;
				write_file( args[i], output );
				break;
			}
		}
	}
		
	/*
	 * (Optional) Gets IV from file using -v
	 */
	public static byte[] iv_file ( String[] args )throws Exception
	{
		byte[] data = null;
		
		boolean iv_found = false;
		
		for ( int i = 0; i < args.length; i++ )
		{
			//looks for the iv file
			if ( args[i].equals("-v") )
			{
				i++;
				
				data = read_file(args[i]);
				
				break;
			}
		}
		
		
		if( iv_found )
		{
			return data;
		}
		else
		{
			data = IVgen();
			return data;
		}
		
	}
	
	/*
	 * Gets data from file 1 byte at a time
	 */
	public static byte[] read_file(String filename) throws Exception
	{
		InputStream is = null;
				
		byte[] data;
		
		try
		{
			is = new FileInputStream(filename);
		    
			File file = new File(filename);
			
			data = new byte[(int) file.length()];
			
			is.read(data);

			return data;
			
		}
		catch (Exception e)
		{
			System.err.format("Exception occurred trying to read '%s'.", filename);
			e.printStackTrace();
			return null;
		}
		finally
		{
			 if(is!=null)
			 {
				 is.close();
			 }
		}
	}
	

	public static byte[] read_hex_file(String filename) throws Exception
	{
		InputStream is = null;
				
		byte[] data;
		
		try
		{ 
			File file = new File(filename);
						
			FileReader fr = new FileReader(filename);

			// Always wrap FileReader in BufferedReader.
			BufferedReader br = new BufferedReader(fr);
			
			long file_size = file.length();
			
			//have to divide by 2 since it is in hex (2 characters = 1 byte)
			data = new byte[(int)file_size/2];
			
			String key_text = br.readLine();

			
			String hex_byte_string = new String();
			
			for (int i = 0; i < file_size; i += 2)
			{
				hex_byte_string = key_text.substring(i, i+2);
				
				data[i/2] = (byte)Integer.parseInt(hex_byte_string, 16);
				
			}
									
			br.close();
			
			return data;
			
		}
		catch (Exception e)
		{
			System.err.format("Exception occurred trying to read '%s'.", filename);
			e.printStackTrace();
			return null;
		}
		finally
		{
			 if(is!=null)
			 {
				 is.close();
			 }
		}
	}
	
	

	/*
	 * Writes data to chosen file
	 */
	public static void write_file(String filename, byte[] data ) throws Exception
	{
		
			FileOutputStream stream = new FileOutputStream(filename);
			try 
			{	
					stream.write(data);
			}
			catch (Exception e)
			{
				System.err.format("Exception occurred trying to write '%s'.", filename);
				e.printStackTrace();
			}
			finally
			{
				stream.close();
			}
			
	}
	
	/*
	 * Separates message into blocks with no extra +1 for padding
	 */
	public static byte[][] make_b( byte[] data, int data_size )
	{		
		byte[][] data_blocks = new byte[(data_size/BLOCK_SIZE)][BLOCK_SIZE];
		
		for( int i = 0; i < data_size; i++ ) 
		{
			data_blocks[i/BLOCK_SIZE][i%BLOCK_SIZE]= data[i];
		} 
		
		return data_blocks;
	}
		
	/*
	 * Separates message into blocks and pads to correct length
	 */
	public static byte[][] make_blocks( byte[] data, int data_size )
	{		
		//the +1 is for the padding. 
		byte[][] data_blocks = new byte[(data_size/BLOCK_SIZE)+1][BLOCK_SIZE];
		
		for( int i = 0; i < data_size; i++ ) 
		{
			data_blocks[i/BLOCK_SIZE][i%BLOCK_SIZE] = data[i];
		} 
		
		return data_blocks;
	}
	
	/*
	 * merge_blocks for decryption
	 */
	public static byte[] merge_blocks( byte[][] data )
	{
		int data_size = data.length * BLOCK_SIZE;
		
		byte[] data_string = new byte[data_size];
		
		for( int i = 0; i < data_size; i++ ) 
		{
			data_string[i] = data[i/BLOCK_SIZE][i%BLOCK_SIZE];
		} 
		
		return data_string;
	}
	
	/*
	 * Pads message blocks to correct length of 128 bits
	 */
	public static byte[][] padding( byte[][] data, int msg_length )
	{		
		
		int data_size = data.length * BLOCK_SIZE;
		
		byte padding = (byte)(data_size - msg_length);
		

		for( int i = msg_length; i < data_size; i++ ) 
		{
			data[i/BLOCK_SIZE][i%BLOCK_SIZE] = padding;

		} 		
		return data;
	}
	
	/*
	 * Unpads ciphertext for decryption
	 */
	public static byte[] unpadding( byte[] data )
	{		

		int last_byte = data.length - 1;

		int unpadded_length = BLOCK_SIZE - data[last_byte];

		
		byte[] unpadded_data = new byte[unpadded_length];
		
		for ( int i = 0; i < unpadded_length; i++ )
		{
			unpadded_data[i] = data[i];
		}

				
		return unpadded_data;
		
			
	}
	
	
	public static int padding_length( byte[] data )
	{		
		int last_byte = data.length - 1;

		int padding_length = (int)data[last_byte];
				
		return padding_length;
		
			
	}
	
	

	/*
	 * Appends IV to cipher text message
	 */
	public static byte[] append_bytes( byte[] to_data, byte[] from_data, int to_data_starting_byte )
	{
		for ( int i = 0; i < from_data.length; i++ )
		{
			to_data[(to_data_starting_byte*BLOCK_SIZE)+i] = from_data[i];
		}
		
		return to_data;
	}
	
	/*
	 * Implements XOR on bytes
	 */
	public static byte[] xor_bytes( byte[] data1, byte[] data2 )
	{
		byte[] xor_data = new byte[BLOCK_SIZE];
		
		for( int i = 0; i < BLOCK_SIZE; i++ )
		{
			xor_data[i] = (byte) (data1[i] ^ data2[i]);
		}
		
		return xor_data;
	}
	
	/*
	 * converts bytes to string message, don't need
	 */
	public static String make_string( byte[] data )
	{
		String message = "";
		
		//convert to text and add to message
		for(byte b:data) {
		     
		    // convert byte to character
		    char c = (char)b;
		    
		    message += c;
		    // prints character
		   
		 }
		
		return message;
	}
	
	/*
	 * FOR TESTING of byte[]
	 */
	public static synchronized void test_printing( byte[] data )
	{

		int i = 0;
		for(byte b:data) {
	         i++;

	        // convert byte to character
	        char c = (char)b;
			 
	        // prints character
			   System.out.println(b + ":" + c);
	     }

		System.out.print("Size: ");
		System.out.print(i);
		System.out.println();

		System.out.println("------------------------");;
	}
	
	/*This is for incrementing a byte array by a certain number*/
	public static byte[] increment_by (byte[] B, int N){

		int i, j;
		//boolean carry = true;

		for (i = 0; i < N; i++){

			boolean carry = true;
			for (j = B.length-1; j >= 0; j--){

				if (carry){
					
					if (B[j] < 0xffff){
						
						B[j] += 1;
						carry = false;

					}else{
						B[j] = 0;
						carry = true;
					}

				}
			}
		}
		return B;
	}
}
