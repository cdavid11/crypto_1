import java.util.Arrays;

public class ctrdec implements Runnable
{
	static int BIT_BLOCK_SIZE = 128;
	//need to divide by 8 because it will be in BYTES
	// so 128 bits / 8 = 16 bytes
	static int BLOCK_SIZE = BIT_BLOCK_SIZE/8;

	byte[] key_data;
	byte[] input_data;
	byte[] iv_data;
	byte[][] input_blocks;
	byte[][] plain_blocks;
	int input_size;
	int thread_start;
	int num_blocks;	

	/*Syncronized method to get the start values of each thread {0..3} in this case as we're assuming
	 * a 4 core processor*/
	public synchronized int get_start(){

		int rv = thread_start;
		thread_start++;
		return rv;

	}


	public void run () 
	{


		int my_block;
		int last_offset;
		byte[] my_IV;
		byte[] AES_Out;
		byte[] plain_block;


		/*Find out which block we need to start with and get the IV + my_block*/
		my_block = get_start();
		my_IV = iv_data.clone();
		my_IV = ctfuncs.increment_by(my_IV, my_block);

		if (input_size%BLOCK_SIZE != 0){
			num_blocks = input_size/BLOCK_SIZE + 1;
		}else{
			num_blocks = input_size/BLOCK_SIZE;
		}

		while(my_block < num_blocks){


			/*Take IV + my_block and send it through the pseudorandom function. Take output and XOR
			 * with plaintext block. Truncate the last block to be the same as message size.*/
			try{
				AES_Out = ctfuncs.encrypt_data(my_IV, key_data);
				plain_block = ctfuncs.xor_bytes(AES_Out, input_blocks[my_block]);

				plain_blocks[my_block - 1] = plain_block;



			}
			catch (Exception e){
				e.printStackTrace(System.out);
				System.exit(0);
			}

			/*Increment this threads block by 4, check to see if this is too large
			 *va:63: and then increment the IV by 4 if not, break otherwise*/
			my_block += 4;
			if (my_block > num_blocks) break;
			my_IV = ctfuncs.increment_by(my_IV,4);

		}

		return;
	}

	/*Class constructor*/
	public ctrdec(String[] args) throws Exception{

		thread_start = 1;

		//open files from cmd line args
		this.key_data = ctfuncs.key_file(args);
		this.input_data = ctfuncs.input_file(args);
		this.input_size = input_data.length;
		this.input_blocks = ctfuncs.make_blocks(input_data, input_size);
		this.iv_data = input_blocks[0];

		if(this.input_size%BLOCK_SIZE != 0) this.plain_blocks = new byte [input_size/BLOCK_SIZE + 1][];
		else this.plain_blocks = new byte [input_size/BLOCK_SIZE][];
	}

	public static void main(String[] args) throws Exception
	{

		Thread[] t = new Thread[4];
		ctrdec C = new ctrdec(args);
		boolean at_end = false;

		/*Fire off four threads for the class that'll call the run function!*/
		for (int i = 0; i < 4; i++){
			t[i] = new Thread(C);
			t[i].start();
		}

		/*Wait for the threads to return before continuing*/
		for (int i = 0; i < 4; i++) t[i].join();

		/*Lay the blocks out sequentially*/
		byte[] plain_text = new byte [C.input_size - BLOCK_SIZE];
		for (int i = 0; i < C.num_blocks - 1; i++){

			for (int j = 0; j < C.plain_blocks[i].length; j++){
				plain_text[(BLOCK_SIZE * i) + j] = C.plain_blocks[i][j];
				
			//	System.out.println("Bit #: " + ((BLOCK_SIZE * i) + j));
				if ((BLOCK_SIZE * i) + j == (C.input_size - BLOCK_SIZE - 1)){

					at_end = true;
					break;
				}

				if (at_end == true) break;
			}

		}
		//create encrypted file
		ctfuncs.output_file(args, plain_text);
	}
}
