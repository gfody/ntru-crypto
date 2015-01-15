using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace NTRU
{
	public class NTRUEncrypt : IDisposable
	{
		public struct ParamDetail
		{
			public double Speed;
			public int Strength;
			public int MaxInput;
			public int OutputSize;
			public int PublicKeySize;
			public int PrivateKeySize;
		}

		public enum ParamSet
		{
			/// <summary>Max input size: 60,  Output size: 552,  Performance rank: 2.7</summary>
			EES401EP1 = 0,
			/// <summary>Max input size: 67,  Output size: 618,  Performance rank: 3.4</summary>
			EES449EP1 = 1,
			/// <summary>Max input size: 101, Output size: 931,  Performance rank: 5.5</summary>
			EES677EP1 = 2,
			/// <summary>Max input size: 170, Output size: 1495, Performance rank: 6.8</summary>
			EES1087EP2 = 3,
			/// <summary>Max input size: 86,  Output size: 744,  Performance rank: 1.9</summary>
			EES541EP1 = 4,
			/// <summary>Max input size: 97,  Output size: 843,  Performance rank: 2.3</summary>
			EES613EP1 = 5,
			/// <summary>Max input size: 141, Output size: 1220, Performance rank: 4.1</summary>
			EES887EP1 = 6,
			/// <summary>Max input size: 186, Output size: 1611, Performance rank: 6.6</summary>
			EES1171EP1 = 7,
			/// <summary>Max input size: 108, Output size: 907,  Performance rank: 1.8</summary>
			EES659EP1 = 8,
			/// <summary>Max input size: 125, Output size: 1047, Performance rank: 2.2</summary>
			EES761EP1 = 9,
			/// <summary>Max input size: 178, Output size: 1495, Performance rank: 4.0</summary>
			EES1087EP1 = 10,
			/// <summary>Max input size: 247, Output size: 2062, Performance rank: 6.4</summary>
			EES1499EP1 = 11,
			/// <summary>Max input size: 60,  Output size: 552,  Performance rank: 1.0</summary>
			EES401EP2 = 12,
			/// <summary>Max input size: 65,  Output size: 604,  Performance rank: 1.1</summary>
			EES439EP1 = 13,
			/// <summary>Max input size: 86,  Output size: 816,  Performance rank: 1.6</summary>
			EES593EP1 = 14,
			/// <summary>Max input size: 106, Output size: 1022, Performance rank: 2.3</summary>
			EES743EP1 = 15,
		}

		public static Dictionary<ParamSet, ParamDetail> ParamDetails = new Dictionary<ParamSet, ParamDetail>() {
			{ParamSet.EES401EP2,  new ParamDetail { Speed = 1.0, Strength = 112, MaxInput = 60,  OutputSize = 552,  PublicKeySize = 557,  PrivateKeySize = 607  }},
			{ParamSet.EES439EP1,  new ParamDetail { Speed = 1.1, Strength = 128, MaxInput = 65,  OutputSize = 604,  PublicKeySize = 609,  PrivateKeySize = 659  }},
			{ParamSet.EES593EP1,  new ParamDetail { Speed = 1.6, Strength = 192, MaxInput = 86,  OutputSize = 816,  PublicKeySize = 821,  PrivateKeySize = 891  }},
			{ParamSet.EES659EP1,  new ParamDetail { Speed = 1.8, Strength = 112, MaxInput = 108, OutputSize = 907,  PublicKeySize = 912,  PrivateKeySize = 1007 }},
			{ParamSet.EES541EP1,  new ParamDetail { Speed = 1.9, Strength = 112, MaxInput = 86,  OutputSize = 744,  PublicKeySize = 749,  PrivateKeySize = 858  }},
			{ParamSet.EES761EP1,  new ParamDetail { Speed = 2.2, Strength = 128, MaxInput = 125, OutputSize = 1047, PublicKeySize = 1052, PrivateKeySize = 1157 }},
			{ParamSet.EES613EP1,  new ParamDetail { Speed = 2.3, Strength = 128, MaxInput = 97,  OutputSize = 843,  PublicKeySize = 848,  PrivateKeySize = 971  }},
			{ParamSet.EES743EP1,  new ParamDetail { Speed = 2.3, Strength = 256, MaxInput = 106, OutputSize = 1022, PublicKeySize = 1027, PrivateKeySize = 1120 }},
			{ParamSet.EES401EP1,  new ParamDetail { Speed = 2.7, Strength = 112, MaxInput = 60,  OutputSize = 552,  PublicKeySize = 557,  PrivateKeySize = 638  }},
			{ParamSet.EES449EP1,  new ParamDetail { Speed = 3.4, Strength = 128, MaxInput = 67,  OutputSize = 618,  PublicKeySize = 623,  PrivateKeySize = 713  }},
			{ParamSet.EES1087EP1, new ParamDetail { Speed = 4.0, Strength = 192, MaxInput = 178, OutputSize = 1495, PublicKeySize = 1500, PrivateKeySize = 1674 }},
			{ParamSet.EES887EP1,  new ParamDetail { Speed = 4.1, Strength = 192, MaxInput = 141, OutputSize = 1220, PublicKeySize = 1225, PrivateKeySize = 1403 }},
			{ParamSet.EES677EP1,  new ParamDetail { Speed = 5.5, Strength = 192, MaxInput = 101, OutputSize = 931,  PublicKeySize = 936,  PrivateKeySize = 1072 }},
			{ParamSet.EES1499EP1, new ParamDetail { Speed = 6.4, Strength = 256, MaxInput = 247, OutputSize = 2062, PublicKeySize = 2067, PrivateKeySize = 2285 }},
			{ParamSet.EES1171EP1, new ParamDetail { Speed = 6.6, Strength = 256, MaxInput = 186, OutputSize = 1611, PublicKeySize = 1616, PrivateKeySize = 1851 }},
			{ParamSet.EES1087EP2, new ParamDetail { Speed = 6.8, Strength = 256, MaxInput = 170, OutputSize = 1495, PublicKeySize = 1500, PrivateKeySize = 1718 }}};

		/// <summary>Interop wrapper for NtruEncrypt_DLL</summary>
		/// <param name="parameters">Keygen parameters</param>
		/// <param name="seed">Specify null to use cryptographic RNG, or a seed value for deterministic RNG. Deterministic RNG should only be used for debugging purposes!</param>
		public NTRUEncrypt(ParamSet parameters, int? seed = null)
		{
			this.parameters = parameters;
			this.seed = seed;

			NTRUResult result;
			result = ntru_crypto_drbg_instantiate(ParamDetails[parameters].Strength, null, 0, new EntropyFunction(GetEntropy), out handle);

			if (result != NTRUResult.OK)
				throw new Exception(result.ToString());
		}

		public void GenerateKeys(out byte[] public_key, out byte[] private_key)
		{
			int public_key_size = ParamDetails[parameters].PublicKeySize;
			int private_key_size = ParamDetails[parameters].PrivateKeySize;
			public_key = new byte[public_key_size];
			private_key = new byte[private_key_size];

			NTRUResult result;
			result = ntru_crypto_ntru_encrypt_keygen(handle, parameters, ref public_key_size, public_key, ref private_key_size, private_key);

			if (result != NTRUResult.OK)
				throw new Exception(result.ToString());
		}

		public void Reseed(int? seed)
		{
			this.seed = seed;
			rng = seed.HasValue ? (RandomNumberGenerator)new DeterministicRNG(seed.Value) : new RNGCryptoServiceProvider();

			NTRUResult result;
			result = ntru_crypto_drbg_reseed(handle);

			if (result != NTRUResult.OK)
				throw new Exception(result.ToString());
		}

		public byte[] Encrypt(byte[] public_key, byte[] input)
		{
			int OutputSize = ParamDetails[parameters].OutputSize;
			byte[] Output = new byte[OutputSize];

			NTRUResult result;
			result = ntru_crypto_ntru_encrypt(handle, public_key.Length, public_key, input.Length, input, ref OutputSize, Output);

			if (result != NTRUResult.OK)
				throw new Exception(result.ToString());

			return Output;
		}

		public static byte[] Encrypt(ParamSet parameters, byte[] public_key, byte[] input, int? seed = null)
		{
			using (var x = new NTRUEncrypt(parameters, seed))
				return x.Encrypt(public_key, input);
		}

		public static byte[] EncodePublicKey(byte[] public_key)
		{
			int info_len = 0;

			NTRUResult result;
			result = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(public_key.Length, public_key, ref info_len, IntPtr.Zero);

			if (result != NTRUResult.OK)
				throw new Exception(result.ToString());

			byte[] info = new byte[info_len];

			result = ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(public_key.Length, public_key, ref info_len, info);

			if (result != NTRUResult.OK)
				throw new Exception(result.ToString());

			return info;
		}

		public static byte[] DecodePublicKey(byte[] encoded_public_key)
		{
			int pubkey_len = 0;
			int encoded_size = encoded_public_key.Length;
			IntPtr addr_next = IntPtr.Zero;

			NTRUResult result;
			result = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(encoded_public_key, ref pubkey_len, IntPtr.Zero, ref addr_next, ref encoded_size);

			if (result != NTRUResult.OK)
				throw new Exception(result.ToString());

			byte[] pubkey = new byte[pubkey_len];

			result = ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(encoded_public_key, ref pubkey_len, pubkey, ref addr_next, ref encoded_size);

			if (result != NTRUResult.OK)
				throw new Exception(result.ToString());

			return pubkey;
		}

		public static byte[] Decrypt(byte[] private_key, byte[] input)
		{
			int output_len;

			NTRUResult result;
			result = ntru_crypto_ntru_decrypt(private_key.Length, private_key, input.Length, input, out output_len, IntPtr.Zero);
	
			if (result != NTRUResult.OK)
				throw new Exception(result.ToString());

			byte[] output = new byte[output_len];

			result = ntru_crypto_ntru_decrypt(private_key.Length, private_key, input.Length, input, ref output_len, output);
	
			if (result != NTRUResult.OK)
				throw new Exception(result.ToString());

			return output;
		}

		public void Dispose()
		{
			ntru_crypto_drbg_uninstantiate(handle);
		}

		#region private

		private enum NTRUResult
		{
			OK = 0,
			DRBG_OUT_OF_MEMORY = 0xA01,
			DRBG_BAD_PARAMETER = 0xA02,
			DRBG_BAD_LENGTH = 0xA03,
			DRBG_NOT_AVAILABLE = 0xA04,
			DRBG_ENTROPY_FAIL = 0xA05,
			NTRU_FAIL = 0x3001,
			NTRU_BAD_PARAMETER = 0x3002,
			NTRU_BAD_LENGTH = 0x3003,
			NTRU_BUFFER_TOO_SMALL = 0x3004,
			NTRU_INVALID_PARAMETER_SET = 0x3005,
			NTRU_BAD_PUBLIC_KEY = 0x3006,
			NTRU_BAD_PRIVATE_KEY = 0x3007,
			NTRU_OUT_OF_MEMORY = 0x3008,
			NTRU_BAD_ENCODING = 0x3009,
			NTRU_OID_NOT_RECOGNIZED = 0x300A,
			NTRU_UNSUPPORTED_PARAM_SET = 0x300B,
		}

		private enum EntropyCommand
		{
			GET_NUM_BYTES_PER_BYTE_OF_ENTROPY = 0,
			INIT = 1,
			GET_BYTE_OF_ENTROPY = 2,
		}

		int? seed;
		int handle;
		ParamSet parameters;
		RandomNumberGenerator rng;

		private int GetEntropy(EntropyCommand cmd, ref byte data)
		{
			switch (cmd)
			{
				case EntropyCommand.INIT:
					rng = seed.HasValue ? (RandomNumberGenerator)new DeterministicRNG(seed.Value) : new RNGCryptoServiceProvider();
					return 1;

				case EntropyCommand.GET_NUM_BYTES_PER_BYTE_OF_ENTROPY:
					data = 1;
					return 1;

				case EntropyCommand.GET_BYTE_OF_ENTROPY:
					byte[] r = new byte[1];
					rng.GetBytes(r);
					data = r[0];
					return 1;
			}

			return 0;
		}

		class DeterministicRNG : RandomNumberGenerator
		{
			Random r;

			public DeterministicRNG(int seed)
			{
				r = new Random(seed);
			}

			public override void GetBytes(byte[] data)
			{
				r.NextBytes(data);
			}
		}

		#endregion

		#region interop
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		private delegate int EntropyFunction(EntropyCommand cmd, ref byte data);

		[DllImport("NtruEncrypt_DLL.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
		private static extern NTRUResult ntru_crypto_drbg_instantiate(int sec_strength_bits, string pers_str, int pers_str_bytes, EntropyFunction entropy_fn, out int handle);

		[DllImport("NtruEncrypt_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern NTRUResult ntru_crypto_drbg_uninstantiate(int handle);

		[DllImport("NtruEncrypt_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern NTRUResult ntru_crypto_drbg_reseed(int handle);

		[DllImport("NtruEncrypt_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern NTRUResult ntru_crypto_ntru_encrypt(int handle, int pubkey_len, byte[] pubkey, int input_len, byte[] input, ref int output_len, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 5)]byte[] output);

		[DllImport("NtruEncrypt_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern NTRUResult ntru_crypto_ntru_decrypt(int privkey_len, byte[] privkey, int input_len, byte[] input, out int output_len, IntPtr output);

		[DllImport("NtruEncrypt_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern NTRUResult ntru_crypto_ntru_decrypt(int privkey_len, byte[] privkey, int input_len, byte[] input, ref int output_len, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)]byte[] output);

		[DllImport("NtruEncrypt_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern NTRUResult ntru_crypto_ntru_encrypt_keygen(int handle, ParamSet paramset, ref int pubkey_len, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)]byte[] pubkey, ref int privkey_len, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 4)]byte[] privkey);

		[DllImport("NtruEncrypt_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern NTRUResult ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(int pubkey_len, byte[] pub_key, ref int info_len, IntPtr info);

		[DllImport("NtruEncrypt_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern NTRUResult ntru_crypto_ntru_encrypt_publicKey2SubjectPublicKeyInfo(int pubkey_len, byte[] pub_key, ref int info_len, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 2)]byte[] info);

		[DllImport("NtruEncrypt_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern NTRUResult ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(byte[] info, ref int pubkey_len, IntPtr pubkey, ref IntPtr addr_next, ref int next_len);

		[DllImport("NtruEncrypt_DLL.dll", CallingConvention = CallingConvention.Cdecl)]
		private static extern NTRUResult ntru_crypto_ntru_encrypt_subjectPublicKeyInfo2PublicKey(byte[] info, ref int pubkey_len, [MarshalAs(UnmanagedType.LPArray, SizeParamIndex = 1)]byte[] pubkey, ref IntPtr addr_next, ref int next_len);

		#endregion
	}
}
