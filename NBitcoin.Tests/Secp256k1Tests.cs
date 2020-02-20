using System;
using System.Collections.Generic;
using System.Text;
using Xunit;
using NBitcoin.Secp256k1;

namespace NBitcoin.Tests
{
	public class Secp256k1Tests
	{
		Scalar One = new Scalar(1, 0, 0, 0, 0, 0, 0, 0);
		Scalar Two = new Scalar(2, 0, 0, 0, 0, 0, 0, 0);
		Scalar Three = new Scalar(3, 0, 0, 0, 0, 0, 0, 0);
		Scalar OneToEight = new Scalar(1, 2, 3, 4, 5, 6, 7, 8);
		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanAddScalar()
		{
			var actual = One + Two;
			Assert.Equal(Three, actual);

			var expected = new Scalar(2, 4, 6, 8, 10, 12, 14, 16);
			Assert.Equal(expected, OneToEight + OneToEight);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void CanSerializeScalar()
		{
			Span<byte> output = stackalloc byte[32];
			OneToEight.WriteToSpan(output);
			var actual = new Scalar(output);
			Assert.Equal(OneToEight, actual);
		}

		[Fact]
		[Trait("UnitTest", "UnitTest")]
		public void scalar_test()
		{
			Span<byte> c = stackalloc byte[32];
			var s = random_scalar_order_test();
			var s1 = random_scalar_order_test();
			var s2 = random_scalar_order_test();

			s2.WriteToSpan(c);

			{
				int i;
				/* Test that fetching groups of 4 bits from a scalar and recursing n(i)=16*n(i-1)+p(i) reconstructs it. */
				Scalar n = Scalar.Zero;
				for (i = 0; i < 256; i += 4)
				{
					Scalar t = new Scalar(s.GetBits(256 - 4 - i, 4));
					int j;
					for (j = 0; j < 4; j++)
					{
						n = n + n;
					}
					n = n + t;
				}
				Assert.Equal(n, s);
			}

			{
				/* Test that fetching groups of randomly-sized bits from a scalar and recursing n(i)=b*n(i-1)+p(i) reconstructs it. */
				Scalar n = Scalar.Zero;
				int i = 0;
				while (i < 256)
				{
					int j;
					int now = (int)(secp256k1_rand_int(15) + 1);
					if (now + i > 256)
					{
						now = 256 - i;
					}
					Scalar t = new Scalar(s.GetBitsVar(256 - now - i, now));
					for (j = 0; j < now; j++)
					{
						n = n + n;
					}
					n = n + t;
					i += now;
				}
				Assert.Equal(n, s);
			}


			{
				/* Test that scalar inverses are equal to the inverse of their number modulo the order. */
				if (!s.IsZero)
				{
					var inv = s.Inverse();
				}
			}

		Scalar random_scalar_order_test()
		{
			Scalar scalar = Scalar.Zero;
			do
			{
				Span<byte> output = stackalloc byte[32];
				RandomUtils.GetBytes(output);
				scalar = new Scalar(output, out int overflow);
				if (overflow != 0 || scalar.IsZero)
				{
					continue;
				}
				break;
			} while (true);
			return scalar;
		}
		static int[] addbits = new int[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 2, 1, 0 };
		static int secp256k1_test_rng_integer_bits_left = 0;
		static ulong secp256k1_test_rng_integer;
		static uint secp256k1_rand_int(uint range)
		{
			/* We want a uniform integer between 0 and range-1, inclusive.
			 * B is the smallest number such that range <= 2**B.
			 * two mechanisms implemented here:
			 * - generate B bits numbers until one below range is found, and return it
			 * - find the largest multiple M of range that is <= 2**(B+A), generate B+A
			 *   bits numbers until one below M is found, and return it modulo range
			 * The second mechanism consumes A more bits of entropy in every iteration,
			 * but may need fewer iterations due to M being closer to 2**(B+A) then
			 * range is to 2**B. The array below (indexed by B) contains a 0 when the
			 * first mechanism is to be used, and the number A otherwise.
			 */
			uint trange, mult;
			int bits = 0;
			if (range <= 1)
			{
				return 0;
			}
			trange = range - 1;
			while (trange > 0)
			{
				trange >>= 1;
				bits++;
			}
			if (addbits[bits] != 0)
			{
				bits = bits + addbits[bits];
				mult = ((~((uint)0)) >> (32 - bits)) / range;
				trange = range * mult;
			}
			else
			{
				trange = range;
				mult = 1;
			}
			while (true)
			{
				uint x = secp256k1_rand_bits(bits);
				if (x < trange)
				{
					return (mult == 1) ? x : (x % range);
				}
			}
		}
		static uint secp256k1_rand_bits(int bits)
		{
			uint ret;
			if (secp256k1_test_rng_integer_bits_left < bits)
			{
				secp256k1_test_rng_integer |= (((ulong)RandomUtils.GetUInt32()) << secp256k1_test_rng_integer_bits_left);
				secp256k1_test_rng_integer_bits_left += 32;
			}
			ret = (uint)secp256k1_test_rng_integer;
			secp256k1_test_rng_integer >>= bits;
			secp256k1_test_rng_integer_bits_left -= bits;
			ret &= ((~((uint)0)) >> (32 - bits));
			return ret;
		}
	}
}
