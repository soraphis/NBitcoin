using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	internal enum ScalarOperation
	{
		Add,
		Multiply
	}
	readonly struct Scalar
	{
		static Scalar _Zero = new Scalar(0, 0, 0, 0, 0, 0, 0, 0);
		public static ref Scalar Zero => ref _Zero;

		const uint SECP256K1_N_0 = 0xD0364141U;
		const uint SECP256K1_N_1 = 0xBFD25E8CU;
		const uint SECP256K1_N_2 = 0xAF48A03BU;
		const uint SECP256K1_N_3 = 0xBAAEDCE6U;
		const uint SECP256K1_N_4 = 0xFFFFFFFEU;
		const uint SECP256K1_N_5 = 0xFFFFFFFFU;
		const uint SECP256K1_N_6 = 0xFFFFFFFFU;
		const uint SECP256K1_N_7 = 0xFFFFFFFFU;
		const uint SECP256K1_N_C_0 = ~SECP256K1_N_0 + 1;
		const uint SECP256K1_N_C_1 = ~SECP256K1_N_1;
		const uint SECP256K1_N_C_2 = ~SECP256K1_N_2;
		const uint SECP256K1_N_C_3 = ~SECP256K1_N_3;
		const uint SECP256K1_N_C_4 = 1;
		readonly uint d0, d1, d2, d3, d4, d5, d6, d7;
		public Scalar(uint d0, uint d1, uint d2, uint d3, uint d4, uint d5, uint d6, uint d7)
		{
			this.d0 = d0;
			this.d1 = d1;
			this.d2 = d2;
			this.d3 = d3;
			this.d4 = d4;
			this.d5 = d5;
			this.d6 = d6;
			this.d7 = d7;
		}

		internal Scalar(uint value)
		{
			d0 = d1 = d2 = d3 = d4 = d5 = d6 = d7 = 0;
			d0 = value;
		}
		internal Scalar(ReadOnlySpan<byte> b32): this(b32, out _)
		{
		}
		internal Scalar(ReadOnlySpan<byte> b32, out int overflow)
		{
			d0 = (uint)b32[31] | (uint)b32[30] << 8 | (uint)b32[29] << 16 | (uint)b32[28] << 24;
			d1 = (uint)b32[27] | (uint)b32[26] << 8 | (uint)b32[25] << 16 | (uint)b32[24] << 24;
			d2 = (uint)b32[23] | (uint)b32[22] << 8 | (uint)b32[21] << 16 | (uint)b32[20] << 24;
			d3 = (uint)b32[19] | (uint)b32[18] << 8 | (uint)b32[17] << 16 | (uint)b32[16] << 24;
			d4 = (uint)b32[15] | (uint)b32[14] << 8 | (uint)b32[13] << 16 | (uint)b32[12] << 24;
			d5 = (uint)b32[11] | (uint)b32[10] << 8 | (uint)b32[9] << 16 | (uint)b32[8] << 24;
			d6 = (uint)b32[7] | (uint)b32[6] << 8 | (uint)b32[5] << 16 | (uint)b32[4] << 24;
			d7 = (uint)b32[3] | (uint)b32[2] << 8 | (uint)b32[1] << 16 | (uint)b32[0] << 24;
			overflow = CheckOverflow();
			{
				// Reduce
				ulong t;
				VERIFY_CHECK(overflow == 0 || overflow == 1);
				t = d0 + (uint)overflow * SECP256K1_N_C_0;
				d0 = (uint)t; t >>= 32;
				t += d1 + (uint)overflow * SECP256K1_N_C_1;
				d1 = (uint)t; t >>= 32;
				t += d2 + (uint)overflow * SECP256K1_N_C_2;
				d2 = (uint)t; t >>= 32;
				t += d3 + (uint)overflow * SECP256K1_N_C_3;
				d3 = (uint)t; t >>= 32;
				t += d4 + (uint)overflow * SECP256K1_N_C_4;
				d4 = (uint)t; t >>= 32;
				t += d5;
				d5 = (uint)t; t >>= 32;
				t += d6;
				d6 = (uint)t; t >>= 32;
				t += d7;
				d7 = (uint)t;
			}
		}
		internal Scalar(ScalarOperation op, in Scalar a, in Scalar b, out int overflow)
		{
			d0 = d1 = d2 = d3 = d4 = d5 = d6 = d7 = 0;
			overflow = 0;
			switch (op)
			{
				case ScalarOperation.Add:
					{
						ulong t = (ulong)a.d0 + b.d0;
						d0 = (uint)t; t >>= 32;
						t += (ulong)a.d1 + b.d1;
						d1 = (uint)t; t >>= 32;
						t += (ulong)a.d2 + b.d2;
						d2 = (uint)t; t >>= 32;
						t += (ulong)a.d3 + b.d3;
						d3 = (uint)t; t >>= 32;
						t += (ulong)a.d4 + b.d4;
						d4 = (uint)t; t >>= 32;
						t += (ulong)a.d5 + b.d5;
						d5 = (uint)t; t >>= 32;
						t += (ulong)a.d6 + b.d6;
						d6 = (uint)t; t >>= 32;
						t += (ulong)a.d7 + b.d7;
						d7 = (uint)t; t >>= 32;
						overflow = (int)(t + (uint)CheckOverflow());
						VERIFY_CHECK(overflow == 0 || overflow == 1);
					}
					break;
				case ScalarOperation.Multiply:
					{

					}
					break;
			}

			{
				// Reduce
				ulong t;
				VERIFY_CHECK(overflow == 0 || overflow == 1);
				t = d0 + (uint)overflow * SECP256K1_N_C_0;
				d0 = (uint)t; t >>= 32;
				t += d1 + (uint)overflow * SECP256K1_N_C_1;
				d1 = (uint)t; t >>= 32;
				t += d2 + (uint)overflow * SECP256K1_N_C_2;
				d2 = (uint)t; t >>= 32;
				t += d3 + (uint)overflow * SECP256K1_N_C_3;
				d3 = (uint)t; t >>= 32;
				t += d4 + (uint)overflow * SECP256K1_N_C_4;
				d4 = (uint)t; t >>= 32;
				t += d5;
				d5 = (uint)t; t >>= 32;
				t += d6;
				d6 = (uint)t; t >>= 32;
				t += d7;
				d7 = (uint)t;
			}
		}

		private static void VERIFY_CHECK(bool value)
		{
			if (!value)
				throw new InvalidOperationException("VERIFY_CHECK failed (bug in C# secp256k1)");
		}

		internal readonly int CheckOverflow()
		{
			int yes = 0;
			int no = 0;
			no |= (d7 < SECP256K1_N_7 ? 1 : 0);
			no |= (d6 < SECP256K1_N_6 ? 1 : 0);
			no |= (d5 < SECP256K1_N_5 ? 1 : 0);
			no |= (d4 < SECP256K1_N_4 ? 1 : 0);
			yes |= (d4 > SECP256K1_N_4 ? 1 : 0) & ~no;
			no |= (d3 < SECP256K1_N_3 ? 1 : 0) & ~yes;
			yes |= (d3 > SECP256K1_N_3 ? 1 : 0) & ~no;
			no |= (d2 < SECP256K1_N_2 ? 1 : 0) & ~yes;
			yes |= (d2 > SECP256K1_N_2 ? 1 : 0) & ~no;
			no |= (d1 < SECP256K1_N_1 ? 1 : 0) & ~yes;
			yes |= (d1 > SECP256K1_N_1 ? 1 : 0) & ~no;
			yes |= (d0 >= SECP256K1_N_0 ? 1 : 0) & ~no;
			return yes;
		}

		public readonly void WriteToSpan(Span<byte> bin)
		{
			bin[0] = (byte)(d7 >> 24); bin[1] = (byte)(d7 >> 16); bin[2] = (byte)(d7 >> 8); bin[3] = (byte)d7;
			bin[4] = (byte)(d6 >> 24); bin[5] = (byte)(d6 >> 16); bin[6] = (byte)(d6 >> 8); bin[7] = (byte)d6;
			bin[8] = (byte)(d5 >> 24); bin[9] = (byte)(d5 >> 16); bin[10] = (byte)(d5 >> 8); bin[11] = (byte)d5;
			bin[12] = (byte)(d4 >> 24); bin[13] = (byte)(d4 >> 16); bin[14] = (byte)(d4 >> 8); bin[15] = (byte)d4;
			bin[16] = (byte)(d3 >> 24); bin[17] = (byte)(d3 >> 16); bin[18] = (byte)(d3 >> 8); bin[19] = (byte)d3;
			bin[20] = (byte)(d2 >> 24); bin[21] = (byte)(d2 >> 16); bin[22] = (byte)(d2 >> 8); bin[23] = (byte)d2;
			bin[24] = (byte)(d1 >> 24); bin[25] = (byte)(d1 >> 16); bin[26] = (byte)(d1 >> 8); bin[27] = (byte)d1;
			bin[28] = (byte)(d0 >> 24); bin[29] = (byte)(d0 >> 16); bin[30] = (byte)(d0 >> 8); bin[31] = (byte)d0;
		}

		internal readonly uint GetBits(int offset, int count)
		{
			if (offset < 0)
				throw new ArgumentOutOfRangeException(nameof(offset), "Offset should be more than 0");
			if (count < 0)
				throw new ArgumentOutOfRangeException(nameof(count), "Count should be more than 0");
			VERIFY_CHECK((offset + count - 1) >> 5 == offset >> 5);
			return (uint)((At(offset >> 5) >> (offset & 0x1F)) & ((1 << count) - 1));
		}
		internal readonly uint GetBitsVar(int offset, int count)
		{
			if (offset < 0)
				throw new ArgumentOutOfRangeException(nameof(offset), "Offset should be more than 0");
			if (count < 0)
				throw new ArgumentOutOfRangeException(nameof(count), "Count should be more than 0");
			if (count < 32)
				throw new ArgumentOutOfRangeException(nameof(count), "Count should be less than 32");
			if (offset + count <= 256)
				throw new ArgumentOutOfRangeException(nameof(count), "End index should be less than 256");
			if((offset + count - 1) >> 5 == offset >> 5)
			{
				return GetBits(offset, count);
			}
			else
			{
				VERIFY_CHECK((offset >> 5) + 1 < 8);
				return ((At(offset >> 5) >> (offset & 0x1F)) | (At((offset >> 5) + 1) << (32 - (offset & 0x1F)))) & ((((uint)1) << count) - 1);
			}
		}

		internal uint At(int index)
		{
			switch(index)
			{
				case 0:
					return d0;
				case 1:
					return d1;
				case 2:
					return d2;
				case 3:
					return d3;
				case 4:
					return d4;
				case 5:
					return d5;
				case 6:
					return d6;
				case 7:
					return d7;
				default:
					throw new ArgumentOutOfRangeException(nameof(index), "index should 0-7 inclusive");
			}
		}

		public readonly bool IsZero => (d0 | d1 | d2 | d3 | d4 | d5 | d6 | d7) == 0;

		public static Scalar operator *(in Scalar a, in Scalar b)
		{
			return new Scalar(ScalarOperation.Multiply, a, b, out _);
		}
		public static Scalar Multiply(in Scalar a, in Scalar b, out int overflow)
		{
			return new Scalar(ScalarOperation.Multiply, a, b, out overflow);
		}
		public static Scalar operator+(in Scalar a, in Scalar b)
		{
			return new Scalar(ScalarOperation.Add, a, b, out _);
		}
		public static Scalar Add(in Scalar a, in Scalar b, out int overflow)
		{
			return new Scalar(ScalarOperation.Add, a, b, out overflow);
		}
	}
}
