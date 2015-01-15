using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace NTRU
{
	class Program
	{
		static void Main(string[] args)
		{
			foreach (var seed in new int?[] { null, 0 })
			{
				Console.WriteLine(seed.HasValue ? "Deterministic RNG" : "Cryptographic RNG");
				Console.WriteLine("Parameter set\tEncrypt time\t\tDecrypt time");

				foreach (var param_set in NTRUEncrypt.ParamDetails)
				{
					Sanity(param_set.Key, seed);

					TimeSpan e_time, d_time;
					Benchmark(param_set.Key, seed, out e_time, out d_time);
					Console.WriteLine(param_set.Key + "\t" + e_time + "\t" + d_time);
				}
			}
			Console.WriteLine("Testing complete");
			Console.ReadLine();
		}

		public static void Sanity(NTRUEncrypt.ParamSet paramset, int? seed)
		{
			byte[] pubkey, privkey, encrypted;

			byte[] input = new byte[NTRUEncrypt.ParamDetails[paramset].MaxInput];
			new Random().NextBytes(input);

			using (var ntrulib = new NTRUEncrypt(paramset, seed))
			{
				ntrulib.GenerateKeys(out pubkey, out privkey);
				encrypted = ntrulib.Encrypt(pubkey, input);
			}

			if (!NTRUEncrypt.Decrypt(privkey, encrypted).SequenceEqual(input))
				throw new Exception("Decrypted value does not match input!");
		}

		public static void Benchmark(NTRUEncrypt.ParamSet paramset, int? seed, out TimeSpan e_time, out TimeSpan d_time)
		{
			byte[] pubkey, privkey;
			using (var ntrulib = new NTRUEncrypt(paramset, seed))
				ntrulib.GenerateKeys(out pubkey, out privkey);

			byte[] input = new byte[60];
			new Random().NextBytes(input);

			DateTime t = DateTime.Now;

			byte[] encrypted = null;
			using (var ntrulib = new NTRUEncrypt(paramset, seed))
				for (int i = 0; i < 10000; i++)
					encrypted = ntrulib.Encrypt(pubkey, input);

			e_time = DateTime.Now - t;
			t = DateTime.Now;

			byte[] decrypted;
			for (int i = 0; i < 10000; i++)
				decrypted = NTRUEncrypt.Decrypt(privkey, encrypted);

			d_time = DateTime.Now - t;
		}
	}

}
