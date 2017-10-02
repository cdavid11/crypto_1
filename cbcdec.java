public class cbcdec{
	
	static int BIT_BLOCK_SIZE = 128;
	//need to divide by 8 because it will be in BYTES
	// so 128 bits / 8 = 16 bytes
	static int BLOCK_SIZE = BIT_BLOCK_SIZE/8;//16
	
	public static void main(String[] args) throws Exception{

		byte[] key_data;
		byte[] cipher_text;
		byte[] msg;
		byte[] after_xor;
		byte[] prev_block = null;
		
		byte[][] cipher_blocks;
		
		byte[] temp_data = null;
		
		int cipher_size;
		
		//open files from cmd line args
		key_data = ctfuncs.key_file(args);
		cipher_text = ctfuncs.input_file(args);
		cipher_size = cipher_text.length;
		
		//iv_data = ctfuncs.iv_file(args);
		
		//break message apart into blocks of 128 bits
		cipher_blocks = ctfuncs.make_b(cipher_text, cipher_size);  //THIS IS WITHOUT +1 for padding, bc don't need
		msg = new byte[cipher_size];
		
		//Send IV and cipherblocks through AES, XOR with prev block
		for ( int i = 1; i < (cipher_size/BLOCK_SIZE); i++ ){
			after_xor = null;
			
			//if last block, take off padding
			if(i == (cipher_size/BLOCK_SIZE)-1) { 
				temp_data = ctfuncs.decrypt_data(cipher_blocks[i], key_data);
				prev_block = cipher_blocks[i-1];
				
				after_xor = ctfuncs.xor_bytes(prev_block, temp_data);
				
				byte[] unpadded = ctfuncs.unpadding(after_xor);
				ctfuncs.append_bytes(msg, unpadded, i-1);	
			}
			else {
				temp_data = ctfuncs.decrypt_data(cipher_blocks[i], key_data);
				prev_block = cipher_blocks[i-1];//first one is IV
				
				after_xor = ctfuncs.xor_bytes(prev_block, temp_data);
				
				ctfuncs.append_bytes(msg, after_xor, i-1);
			}
		}	
		
		//create decrypted file
		ctfuncs.output_file(args, msg);
	}
}
