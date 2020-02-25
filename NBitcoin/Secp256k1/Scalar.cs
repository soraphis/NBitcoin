using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;

namespace NBitcoin.Secp256k1
{
	readonly struct Scalar : IEquatable<Scalar>
	{
		static readonly Scalar _Zero = new Scalar(0, 0, 0, 0, 0, 0, 0, 0);
		public static ref readonly Scalar Zero => ref _Zero;
		static readonly Scalar _One = new Scalar(1, 0, 0, 0, 0, 0, 0, 0);
		public static ref readonly Scalar One => ref _One;

		internal const uint SECP256K1_N_0 = 0xD0364141U;
		internal const uint SECP256K1_N_1 = 0xBFD25E8CU;
		internal const uint SECP256K1_N_2 = 0xAF48A03BU;
		internal const uint SECP256K1_N_3 = 0xBAAEDCE6U;

		internal const uint SECP256K1_N_4 = 0xFFFFFFFEU;
		internal const uint SECP256K1_N_5 = 0xFFFFFFFFU;
		internal const uint SECP256K1_N_6 = 0xFFFFFFFFU;
		internal const uint SECP256K1_N_7 = 0xFFFFFFFFU;
		internal const uint SECP256K1_N_C_0 = ~SECP256K1_N_0 + 1;
		internal const uint SECP256K1_N_C_1 = ~SECP256K1_N_1;
		internal const uint SECP256K1_N_C_2 = ~SECP256K1_N_2;
		internal const uint SECP256K1_N_C_3 = ~SECP256K1_N_3;
		internal const uint SECP256K1_N_C_4 = 1;


		/* Limbs of half the secp256k1 order. */
		internal const uint SECP256K1_N_H_0 = (0x681B20A0U);
		internal const uint SECP256K1_N_H_1 = (0xDFE92F46U);
		internal const uint SECP256K1_N_H_2 = (0x57A4501DU);
		internal const uint SECP256K1_N_H_3 = (0x5D576E73U);
		internal const uint SECP256K1_N_H_4 = (0xFFFFFFFFU);
		internal const uint SECP256K1_N_H_5 = (0xFFFFFFFFU);
		internal const uint SECP256K1_N_H_6 = (0xFFFFFFFFU);
		internal const uint SECP256K1_N_H_7 = (0x7FFFFFFFU);

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
		public Scalar(Span<uint> d)
		{
			this.d0 = d[0];
			this.d1 = d[1];
			this.d2 = d[2];
			this.d3 = d[3];
			this.d4 = d[4];
			this.d5 = d[5];
			this.d6 = d[6];
			this.d7 = d[7];
		}
		internal Scalar(uint value)
		{
			d0 = d1 = d2 = d3 = d4 = d5 = d6 = d7 = 0;
			d0 = value;
		}
		internal Scalar(ReadOnlySpan<byte> b32) : this(b32, out _)
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
			// Reduce(ref d0, ref d1, ref d2, ref d3, ref d4, ref d5, ref d6, ref d7, overflow);
			ulong t;
			VERIFY_CHECK(overflow == 0 || overflow == 1);
			t = (ulong)d0 + (uint)overflow * SECP256K1_N_C_0;
			d0 = (uint)t; t >>= 32;
			t += (ulong)d1 + (uint)overflow * SECP256K1_N_C_1;
			d1 = (uint)t; t >>= 32;
			t += (ulong)d2 + (uint)overflow * SECP256K1_N_C_2;
			d2 = (uint)t; t >>= 32;
			t += (ulong)d3 + (uint)overflow * SECP256K1_N_C_3;
			d3 = (uint)t; t >>= 32;
			t += (ulong)d4 + (uint)overflow * SECP256K1_N_C_4;
			d4 = (uint)t; t >>= 32;
			t += (ulong)d5;
			d5 = (uint)t; t >>= 32;
			t += (ulong)d6;
			d6 = (uint)t; t >>= 32;
			t += (ulong)d7;
			d7 = (uint)t;
		}

		internal readonly Scalar CAddBit(uint bit, int flag)
		{
			Span<uint> d = stackalloc uint[DCount];
			ulong t;
			VERIFY_CHECK(bit < 256);
			bit += ((uint)flag - 1) & 0x100;  /* forcing (bit >> 5) > 7 makes this a noop */
			t = (ulong)this.d0 + (((bit >> 5) == 0 ? 1U : 0) << (int)(bit & 0x1F));
			d[0] = (uint)t; t >>= 32;
			t += (ulong)this.d1 + (((bit >> 5) == 1 ? 1U : 0) << (int)(bit & 0x1F));
			d[1] = (uint)t; t >>= 32;
			t += (ulong)this.d2 + (((bit >> 5) == 2 ? 1U : 0) << (int)(bit & 0x1F));
			d[2] = (uint)t; t >>= 32;
			t += (ulong)this.d3 + (((bit >> 5) == 3 ? 1U : 0) << (int)(bit & 0x1F));
			d[3] = (uint)t; t >>= 32;
			t += (ulong)this.d4 + (((bit >> 5) == 4 ? 1U : 0) << (int)(bit & 0x1F));
			d[4] = (uint)t; t >>= 32;
			t += (ulong)this.d5 + (((bit >> 5) == 5 ? 1U : 0) << (int)(bit & 0x1F));
			d[5] = (uint)t; t >>= 32;
			t += (ulong)this.d6 + (((bit >> 5) == 6 ? 1U : 0) << (int)(bit & 0x1F));
			d[6] = (uint)t; t >>= 32;
			t += (ulong)this.d7 + (((bit >> 5) == 7 ? 1U : 0) << (int)(bit & 0x1F));
			d[7] = (uint)t;
			VERIFY_CHECK((t >> 32) == 0);
			var r = new Scalar(d);
			VERIFY_CHECK(!r.IsOverflow);
			return r;
		}

		private static int Reduce(Span<uint> d, int overflow)
		{
			ulong t;
			VERIFY_CHECK(overflow == 0 || overflow == 1);
			t = (ulong)d[0] + (uint)overflow * SECP256K1_N_C_0;
			d[0] = (uint)t; t >>= 32;
			t += (ulong)d[1] + (uint)overflow * SECP256K1_N_C_1;
			d[1] = (uint)t; t >>= 32;
			t += (ulong)d[2] + (uint)overflow * SECP256K1_N_C_2;
			d[2] = (uint)t; t >>= 32;
			t += (ulong)d[3] + (uint)overflow * SECP256K1_N_C_3;
			d[3] = (uint)t; t >>= 32;
			t += (ulong)d[4] + (uint)overflow * SECP256K1_N_C_4;
			d[4] = (uint)t; t >>= 32;
			t += (ulong)d[5];
			d[5] = (uint)t; t >>= 32;
			t += (ulong)d[6];
			d[6] = (uint)t; t >>= 32;
			t += (ulong)d[7];
			d[7] = (uint)t;
			return overflow;
		}

		private static void reduce_512(Span<uint> d, Span<uint> l)
		{
			ulong c;
			uint n0 = l[8], n1 = l[9], n2 = l[10], n3 = l[11], n4 = l[12], n5 = l[13], n6 = l[14], n7 = l[15];
			uint m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12;
			uint p0, p1, p2, p3, p4, p5, p6, p7, p8;

			/* 96 bit accumulator. */
			uint c0, c1, c2;

			/* Reduce 512 bits into 385. */
			/* m[0..12] = l[0..7] + n[0..7] * SECP256K1_N_C. */
			c0 = l[0]; c1 = 0; c2 = 0;
			muladd_fast(ref c0, ref c1, ref c2, n0, SECP256K1_N_C_0);
			extract_fast(ref c0, ref c1, ref c2, out m0);
			sumadd_fast(ref c0, ref c1, ref c2, l[1]);
			muladd(ref c0, ref c1, ref c2, n1, SECP256K1_N_C_0);
			muladd(ref c0, ref c1, ref c2, n0, SECP256K1_N_C_1);
			extract(ref c0, ref c1, ref c2, out m1);
			sumadd(ref c0, ref c1, ref c2, l[2]);
			muladd(ref c0, ref c1, ref c2, n2, SECP256K1_N_C_0);
			muladd(ref c0, ref c1, ref c2, n1, SECP256K1_N_C_1);
			muladd(ref c0, ref c1, ref c2, n0, SECP256K1_N_C_2);
			extract(ref c0, ref c1, ref c2, out m2);
			sumadd(ref c0, ref c1, ref c2, l[3]);
			muladd(ref c0, ref c1, ref c2, n3, SECP256K1_N_C_0);
			muladd(ref c0, ref c1, ref c2, n2, SECP256K1_N_C_1);
			muladd(ref c0, ref c1, ref c2, n1, SECP256K1_N_C_2);
			muladd(ref c0, ref c1, ref c2, n0, SECP256K1_N_C_3);
			extract(ref c0, ref c1, ref c2, out m3);
			sumadd(ref c0, ref c1, ref c2, l[4]);
			muladd(ref c0, ref c1, ref c2, n4, SECP256K1_N_C_0);
			muladd(ref c0, ref c1, ref c2, n3, SECP256K1_N_C_1);
			muladd(ref c0, ref c1, ref c2, n2, SECP256K1_N_C_2);
			muladd(ref c0, ref c1, ref c2, n1, SECP256K1_N_C_3);
			sumadd(ref c0, ref c1, ref c2, n0);
			extract(ref c0, ref c1, ref c2, out m4);
			sumadd(ref c0, ref c1, ref c2, l[5]);
			muladd(ref c0, ref c1, ref c2, n5, SECP256K1_N_C_0);
			muladd(ref c0, ref c1, ref c2, n4, SECP256K1_N_C_1);
			muladd(ref c0, ref c1, ref c2, n3, SECP256K1_N_C_2);
			muladd(ref c0, ref c1, ref c2, n2, SECP256K1_N_C_3);
			sumadd(ref c0, ref c1, ref c2, n1);
			extract(ref c0, ref c1, ref c2, out m5);
			sumadd(ref c0, ref c1, ref c2, l[6]);
			muladd(ref c0, ref c1, ref c2, n6, SECP256K1_N_C_0);
			muladd(ref c0, ref c1, ref c2, n5, SECP256K1_N_C_1);
			muladd(ref c0, ref c1, ref c2, n4, SECP256K1_N_C_2);
			muladd(ref c0, ref c1, ref c2, n3, SECP256K1_N_C_3);
			sumadd(ref c0, ref c1, ref c2, n2);
			extract(ref c0, ref c1, ref c2, out m6);
			sumadd(ref c0, ref c1, ref c2, l[7]);
			muladd(ref c0, ref c1, ref c2, n7, SECP256K1_N_C_0);
			muladd(ref c0, ref c1, ref c2, n6, SECP256K1_N_C_1);
			muladd(ref c0, ref c1, ref c2, n5, SECP256K1_N_C_2);
			muladd(ref c0, ref c1, ref c2, n4, SECP256K1_N_C_3);
			sumadd(ref c0, ref c1, ref c2, n3);
			extract(ref c0, ref c1, ref c2, out m7);
			muladd(ref c0, ref c1, ref c2, n7, SECP256K1_N_C_1);
			muladd(ref c0, ref c1, ref c2, n6, SECP256K1_N_C_2);
			muladd(ref c0, ref c1, ref c2, n5, SECP256K1_N_C_3);
			sumadd(ref c0, ref c1, ref c2, n4);
			extract(ref c0, ref c1, ref c2, out m8);
			muladd(ref c0, ref c1, ref c2, n7, SECP256K1_N_C_2);
			muladd(ref c0, ref c1, ref c2, n6, SECP256K1_N_C_3);
			sumadd(ref c0, ref c1, ref c2, n5);
			extract(ref c0, ref c1, ref c2, out m9);
			muladd(ref c0, ref c1, ref c2, n7, SECP256K1_N_C_3);
			sumadd(ref c0, ref c1, ref c2, n6);
			extract(ref c0, ref c1, ref c2, out m10);
			sumadd_fast(ref c0, ref c1, ref c2, n7);
			extract_fast(ref c0, ref c1, ref c2, out m11);
			VERIFY_CHECK(c0 <= 1);
			m12 = c0;

			/* Reduce 385 bits into 258. */
			/* p[0..8] = m[0..7] + m[8..12] * SECP256K1_N_C. */
			c0 = m0; c1 = 0; c2 = 0;
			muladd_fast(ref c0, ref c1, ref c2, m8, SECP256K1_N_C_0);
			extract_fast(ref c0, ref c1, ref c2, out p0);
			sumadd_fast(ref c0, ref c1, ref c2, m1);
			muladd(ref c0, ref c1, ref c2, m9, SECP256K1_N_C_0);
			muladd(ref c0, ref c1, ref c2, m8, SECP256K1_N_C_1);
			extract(ref c0, ref c1, ref c2, out p1);
			sumadd(ref c0, ref c1, ref c2, m2);
			muladd(ref c0, ref c1, ref c2, m10, SECP256K1_N_C_0);
			muladd(ref c0, ref c1, ref c2, m9, SECP256K1_N_C_1);
			muladd(ref c0, ref c1, ref c2, m8, SECP256K1_N_C_2);
			extract(ref c0, ref c1, ref c2, out p2);
			sumadd(ref c0, ref c1, ref c2, m3);
			muladd(ref c0, ref c1, ref c2, m11, SECP256K1_N_C_0);
			muladd(ref c0, ref c1, ref c2, m10, SECP256K1_N_C_1);
			muladd(ref c0, ref c1, ref c2, m9, SECP256K1_N_C_2);
			muladd(ref c0, ref c1, ref c2, m8, SECP256K1_N_C_3);
			extract(ref c0, ref c1, ref c2, out p3);
			sumadd(ref c0, ref c1, ref c2, m4);
			muladd(ref c0, ref c1, ref c2, m12, SECP256K1_N_C_0);
			muladd(ref c0, ref c1, ref c2, m11, SECP256K1_N_C_1);
			muladd(ref c0, ref c1, ref c2, m10, SECP256K1_N_C_2);
			muladd(ref c0, ref c1, ref c2, m9, SECP256K1_N_C_3);
			sumadd(ref c0, ref c1, ref c2, m8);
			extract(ref c0, ref c1, ref c2, out p4);
			sumadd(ref c0, ref c1, ref c2, m5);
			muladd(ref c0, ref c1, ref c2, m12, SECP256K1_N_C_1);
			muladd(ref c0, ref c1, ref c2, m11, SECP256K1_N_C_2);
			muladd(ref c0, ref c1, ref c2, m10, SECP256K1_N_C_3);
			sumadd(ref c0, ref c1, ref c2, m9);
			extract(ref c0, ref c1, ref c2, out p5);
			sumadd(ref c0, ref c1, ref c2, m6);
			muladd(ref c0, ref c1, ref c2, m12, SECP256K1_N_C_2);
			muladd(ref c0, ref c1, ref c2, m11, SECP256K1_N_C_3);
			sumadd(ref c0, ref c1, ref c2, m10);
			extract(ref c0, ref c1, ref c2, out p6);
			sumadd_fast(ref c0, ref c1, ref c2, m7);
			muladd_fast(ref c0, ref c1, ref c2, m12, SECP256K1_N_C_3);
			sumadd_fast(ref c0, ref c1, ref c2, m11);
			extract_fast(ref c0, ref c1, ref c2, out p7);
			p8 = c0 + m12;
			VERIFY_CHECK(p8 <= 2);

			/* Reduce 258 bits into 256. */
			/* r[0..7] = p[0..7] + p[8] * SECP256K1_N_C. */
			c = p0 + (ulong)SECP256K1_N_C_0 * p8;
			d[0] = (uint)c; c >>= 32;
			c += p1 + (ulong)SECP256K1_N_C_1 * p8;
			d[1] = (uint)c; c >>= 32;
			c += p2 + (ulong)SECP256K1_N_C_2 * p8;
			d[2] = (uint)c; c >>= 32;
			c += p3 + (ulong)SECP256K1_N_C_3 * p8;
			d[3] = (uint)c; c >>= 32;
			c += p4 + (ulong)p8;
			d[4] = (uint)c; c >>= 32;
			c += p5;
			d[5] = (uint)c; c >>= 32;
			c += p6;
			d[6] = (uint)c; c >>= 32;
			c += p7;
			d[7] = (uint)c; c >>= 32;

			/* Final reduction of r. */
			Reduce(d, (int)c + new Scalar(d).CheckOverflow());
		}

		internal int CondNegate(int flag, out Scalar r)
		{
			Span<uint> rd = stackalloc uint[DCount];
			Deconstruct(ref rd);
			/* If we are flag = 0, mask = 00...00 and this is a no-op;
     * if we are flag = 1, mask = 11...11 and this is identical to secp256k1_scalar_negate */
			uint mask = (flag == 0 ? 1U : 0) - 1;
			uint nonzero = 0xFFFFFFFFU * (IsZero ? 0U : 1);
			ulong t = (ulong)(rd[0] ^ mask) + ((SECP256K1_N_0 + 1) & mask);
			rd[0] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(rd[1] ^ mask) + (SECP256K1_N_1 & mask);
			rd[1] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(rd[2] ^ mask) + (SECP256K1_N_2 & mask);
			rd[2] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(rd[3] ^ mask) + (SECP256K1_N_3 & mask);
			rd[3] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(rd[4] ^ mask) + (SECP256K1_N_4 & mask);
			rd[4] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(rd[5] ^ mask) + (SECP256K1_N_5 & mask);
			rd[5] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(rd[6] ^ mask) + (SECP256K1_N_6 & mask);
			rd[6] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(rd[7] ^ mask) + (SECP256K1_N_7 & mask);
			rd[7] = (uint)(t & nonzero);
			r = new Scalar(rd);
			return 2 * (mask == 0 ? 1 : 0) - 1;
		}

		private static void mul_512(Span<uint> zz, in Scalar x, in Scalar b)
		{
			ulong y_0 = b.d0;
			ulong y_1 = b.d1;
			ulong y_2 = b.d2;
			ulong y_3 = b.d3;
			ulong y_4 = b.d4;
			ulong y_5 = b.d5;
			ulong y_6 = b.d6;
			ulong y_7 = b.d7;

			{
				ulong c = 0, x_0 = x.d0;
				c += x_0 * y_0;
				zz[0] = (uint)c;
				c >>= 32;
				c += x_0 * y_1;
				zz[1] = (uint)c;
				c >>= 32;
				c += x_0 * y_2;
				zz[2] = (uint)c;
				c >>= 32;
				c += x_0 * y_3;
				zz[3] = (uint)c;
				c >>= 32;
				c += x_0 * y_4;
				zz[4] = (uint)c;
				c >>= 32;
				c += x_0 * y_5;
				zz[5] = (uint)c;
				c >>= 32;
				c += x_0 * y_6;
				zz[6] = (uint)c;
				c >>= 32;
				c += x_0 * y_7;
				zz[7] = (uint)c;
				c >>= 32;
				zz[8] = (uint)c;
			}

			{
				int i = 1;
				ulong c = 0, x_i = x.d1;
				c += x_i * y_0 + zz[i + 0];
				zz[i + 0] = (uint)c;
				c >>= 32;
				c += x_i * y_1 + zz[i + 1];
				zz[i + 1] = (uint)c;
				c >>= 32;
				c += x_i * y_2 + zz[i + 2];
				zz[i + 2] = (uint)c;
				c >>= 32;
				c += x_i * y_3 + zz[i + 3];
				zz[i + 3] = (uint)c;
				c >>= 32;
				c += x_i * y_4 + zz[i + 4];
				zz[i + 4] = (uint)c;
				c >>= 32;
				c += x_i * y_5 + zz[i + 5];
				zz[i + 5] = (uint)c;
				c >>= 32;
				c += x_i * y_6 + zz[i + 6];
				zz[i + 6] = (uint)c;
				c >>= 32;
				c += x_i * y_7 + zz[i + 7];
				zz[i + 7] = (uint)c;
				c >>= 32;
				zz[i + 8] = (uint)c;
			}
			{
				int i = 2;
				ulong c = 0, x_i = x.d2;
				c += x_i * y_0 + zz[i + 0];
				zz[i + 0] = (uint)c;
				c >>= 32;
				c += x_i * y_1 + zz[i + 1];
				zz[i + 1] = (uint)c;
				c >>= 32;
				c += x_i * y_2 + zz[i + 2];
				zz[i + 2] = (uint)c;
				c >>= 32;
				c += x_i * y_3 + zz[i + 3];
				zz[i + 3] = (uint)c;
				c >>= 32;
				c += x_i * y_4 + zz[i + 4];
				zz[i + 4] = (uint)c;
				c >>= 32;
				c += x_i * y_5 + zz[i + 5];
				zz[i + 5] = (uint)c;
				c >>= 32;
				c += x_i * y_6 + zz[i + 6];
				zz[i + 6] = (uint)c;
				c >>= 32;
				c += x_i * y_7 + zz[i + 7];
				zz[i + 7] = (uint)c;
				c >>= 32;
				zz[i + 8] = (uint)c;
			}
			{
				int i = 3;
				ulong c = 0, x_i = x.d3;
				c += x_i * y_0 + zz[i + 0];
				zz[i + 0] = (uint)c;
				c >>= 32;
				c += x_i * y_1 + zz[i + 1];
				zz[i + 1] = (uint)c;
				c >>= 32;
				c += x_i * y_2 + zz[i + 2];
				zz[i + 2] = (uint)c;
				c >>= 32;
				c += x_i * y_3 + zz[i + 3];
				zz[i + 3] = (uint)c;
				c >>= 32;
				c += x_i * y_4 + zz[i + 4];
				zz[i + 4] = (uint)c;
				c >>= 32;
				c += x_i * y_5 + zz[i + 5];
				zz[i + 5] = (uint)c;
				c >>= 32;
				c += x_i * y_6 + zz[i + 6];
				zz[i + 6] = (uint)c;
				c >>= 32;
				c += x_i * y_7 + zz[i + 7];
				zz[i + 7] = (uint)c;
				c >>= 32;
				zz[i + 8] = (uint)c;
			}
			{
				int i = 4;
				ulong c = 0, x_i = x.d4;
				c += x_i * y_0 + zz[i + 0];
				zz[i + 0] = (uint)c;
				c >>= 32;
				c += x_i * y_1 + zz[i + 1];
				zz[i + 1] = (uint)c;
				c >>= 32;
				c += x_i * y_2 + zz[i + 2];
				zz[i + 2] = (uint)c;
				c >>= 32;
				c += x_i * y_3 + zz[i + 3];
				zz[i + 3] = (uint)c;
				c >>= 32;
				c += x_i * y_4 + zz[i + 4];
				zz[i + 4] = (uint)c;
				c >>= 32;
				c += x_i * y_5 + zz[i + 5];
				zz[i + 5] = (uint)c;
				c >>= 32;
				c += x_i * y_6 + zz[i + 6];
				zz[i + 6] = (uint)c;
				c >>= 32;
				c += x_i * y_7 + zz[i + 7];
				zz[i + 7] = (uint)c;
				c >>= 32;
				zz[i + 8] = (uint)c;
			}
			{
				int i = 5;
				ulong c = 0, x_i = x.d5;
				c += x_i * y_0 + zz[i + 0];
				zz[i + 0] = (uint)c;
				c >>= 32;
				c += x_i * y_1 + zz[i + 1];
				zz[i + 1] = (uint)c;
				c >>= 32;
				c += x_i * y_2 + zz[i + 2];
				zz[i + 2] = (uint)c;
				c >>= 32;
				c += x_i * y_3 + zz[i + 3];
				zz[i + 3] = (uint)c;
				c >>= 32;
				c += x_i * y_4 + zz[i + 4];
				zz[i + 4] = (uint)c;
				c >>= 32;
				c += x_i * y_5 + zz[i + 5];
				zz[i + 5] = (uint)c;
				c >>= 32;
				c += x_i * y_6 + zz[i + 6];
				zz[i + 6] = (uint)c;
				c >>= 32;
				c += x_i * y_7 + zz[i + 7];
				zz[i + 7] = (uint)c;
				c >>= 32;
				zz[i + 8] = (uint)c;
			}
			{
				int i = 6;
				ulong c = 0, x_i = x.d6;
				c += x_i * y_0 + zz[i + 0];
				zz[i + 0] = (uint)c;
				c >>= 32;
				c += x_i * y_1 + zz[i + 1];
				zz[i + 1] = (uint)c;
				c >>= 32;
				c += x_i * y_2 + zz[i + 2];
				zz[i + 2] = (uint)c;
				c >>= 32;
				c += x_i * y_3 + zz[i + 3];
				zz[i + 3] = (uint)c;
				c >>= 32;
				c += x_i * y_4 + zz[i + 4];
				zz[i + 4] = (uint)c;
				c >>= 32;
				c += x_i * y_5 + zz[i + 5];
				zz[i + 5] = (uint)c;
				c >>= 32;
				c += x_i * y_6 + zz[i + 6];
				zz[i + 6] = (uint)c;
				c >>= 32;
				c += x_i * y_7 + zz[i + 7];
				zz[i + 7] = (uint)c;
				c >>= 32;
				zz[i + 8] = (uint)c;
			}
			{
				int i = 7;
				ulong c = 0, x_i = x.d7;
				c += x_i * y_0 + zz[i + 0];
				zz[i + 0] = (uint)c;
				c >>= 32;
				c += x_i * y_1 + zz[i + 1];
				zz[i + 1] = (uint)c;
				c >>= 32;
				c += x_i * y_2 + zz[i + 2];
				zz[i + 2] = (uint)c;
				c >>= 32;
				c += x_i * y_3 + zz[i + 3];
				zz[i + 3] = (uint)c;
				c >>= 32;
				c += x_i * y_4 + zz[i + 4];
				zz[i + 4] = (uint)c;
				c >>= 32;
				c += x_i * y_5 + zz[i + 5];
				zz[i + 5] = (uint)c;
				c >>= 32;
				c += x_i * y_6 + zz[i + 6];
				zz[i + 6] = (uint)c;
				c >>= 32;
				c += x_i * y_7 + zz[i + 7];
				zz[i + 7] = (uint)c;
				c >>= 32;
				zz[i + 8] = (uint)c;
			}
		}
		private const ulong M = 0xFFFFFFFFUL;
		internal static void sqr_512(Span<uint> zz, in Scalar x)
		{
			ulong x_0 = x.d0;
			ulong zz_1;

			uint c = 0, w;

			int j = 16;
			ulong xVal, p;

			xVal = x.d7;
			p = xVal * xVal;
			zz[--j] = (c << 31) | (uint)(p >> 33);
			zz[--j] = (uint)(p >> 1);
			c = (uint)p;

			xVal = x.d6;
			p = xVal * xVal;
			zz[--j] = (c << 31) | (uint)(p >> 33);
			zz[--j] = (uint)(p >> 1);
			c = (uint)p;

			xVal = x.d5;
			p = xVal * xVal;
			zz[--j] = (c << 31) | (uint)(p >> 33);
			zz[--j] = (uint)(p >> 1);
			c = (uint)p;

			xVal = x.d4;
			p = xVal * xVal;
			zz[--j] = (c << 31) | (uint)(p >> 33);
			zz[--j] = (uint)(p >> 1);
			c = (uint)p;

			xVal = x.d3;
			p = xVal * xVal;
			zz[--j] = (c << 31) | (uint)(p >> 33);
			zz[--j] = (uint)(p >> 1);
			c = (uint)p;

			xVal = x.d2;
			p = xVal * xVal;
			zz[--j] = (c << 31) | (uint)(p >> 33);
			zz[--j] = (uint)(p >> 1);
			c = (uint)p;

			xVal = x.d1;
			p = xVal * xVal;
			zz[--j] = (c << 31) | (uint)(p >> 33);
			zz[--j] = (uint)(p >> 1);
			c = (uint)p;

			p = x_0 * x_0;
			zz_1 = (ulong)(c << 31) | (p >> 33);
			zz[0] = (uint)p;
			c = (uint)(p >> 32) & 1;


			ulong x_1 = x.d1;
			ulong zz_2 = zz[2];

			{
				zz_1 += x_1 * x_0;
				w = (uint)zz_1;
				zz[1] = (w << 1) | c;
				c = w >> 31;
				zz_2 += zz_1 >> 32;
			}

			ulong x_2 = x.d2;
			ulong zz_3 = zz[3];
			ulong zz_4 = zz[4];
			{
				zz_2 += x_2 * x_0;
				w = (uint)zz_2;
				zz[2] = (w << 1) | c;
				c = w >> 31;
				zz_3 += (zz_2 >> 32) + x_2 * x_1;
				zz_4 += zz_3 >> 32;
				zz_3 &= M;
			}

			ulong x_3 = x.d3;
			ulong zz_5 = zz[5] + (zz_4 >> 32); zz_4 &= M;
			ulong zz_6 = zz[6] + (zz_5 >> 32); zz_5 &= M;
			{
				zz_3 += x_3 * x_0;
				w = (uint)zz_3;
				zz[3] = (w << 1) | c;
				c = w >> 31;
				zz_4 += (zz_3 >> 32) + x_3 * x_1;
				zz_5 += (zz_4 >> 32) + x_3 * x_2;
				zz_4 &= M;
				zz_6 += zz_5 >> 32;
				zz_5 &= M;
			}

			ulong x_4 = x.d4;
			ulong zz_7 = zz[7] + (zz_6 >> 32); zz_6 &= M;
			ulong zz_8 = zz[8] + (zz_7 >> 32); zz_7 &= M;
			{
				zz_4 += x_4 * x_0;
				w = (uint)zz_4;
				zz[4] = (w << 1) | c;
				c = w >> 31;
				zz_5 += (zz_4 >> 32) + x_4 * x_1;
				zz_6 += (zz_5 >> 32) + x_4 * x_2;
				zz_5 &= M;
				zz_7 += (zz_6 >> 32) + x_4 * x_3;
				zz_6 &= M;
				zz_8 += zz_7 >> 32;
				zz_7 &= M;
			}

			ulong x_5 = x.d5;
			ulong zz_9 = zz[9] + (zz_8 >> 32); zz_8 &= M;
			ulong zz_10 = zz[10] + (zz_9 >> 32); zz_9 &= M;
			{
				zz_5 += x_5 * x_0;
				w = (uint)zz_5;
				zz[5] = (w << 1) | c;
				c = w >> 31;
				zz_6 += (zz_5 >> 32) + x_5 * x_1;
				zz_7 += (zz_6 >> 32) + x_5 * x_2;
				zz_6 &= M;
				zz_8 += (zz_7 >> 32) + x_5 * x_3;
				zz_7 &= M;
				zz_9 += (zz_8 >> 32) + x_5 * x_4;
				zz_8 &= M;
				zz_10 += zz_9 >> 32;
				zz_9 &= M;
			}

			ulong x_6 = x.d6;
			ulong zz_11 = zz[11] + (zz_10 >> 32); zz_10 &= M;
			ulong zz_12 = zz[12] + (zz_11 >> 32); zz_11 &= M;
			{
				zz_6 += x_6 * x_0;
				w = (uint)zz_6;
				zz[6] = (w << 1) | c;
				c = w >> 31;
				zz_7 += (zz_6 >> 32) + x_6 * x_1;
				zz_8 += (zz_7 >> 32) + x_6 * x_2;
				zz_7 &= M;
				zz_9 += (zz_8 >> 32) + x_6 * x_3;
				zz_8 &= M;
				zz_10 += (zz_9 >> 32) + x_6 * x_4;
				zz_9 &= M;
				zz_11 += (zz_10 >> 32) + x_6 * x_5;
				zz_10 &= M;
				zz_12 += zz_11 >> 32;
				zz_11 &= M;
			}

			ulong x_7 = x.d7;
			ulong zz_13 = zz[13] + (zz_12 >> 32); zz_12 &= M;
			ulong zz_14 = zz[14] + (zz_13 >> 32); zz_13 &= M;
			{
				zz_7 += x_7 * x_0;
				w = (uint)zz_7;
				zz[7] = (w << 1) | c;
				c = w >> 31;
				zz_8 += (zz_7 >> 32) + x_7 * x_1;
				zz_9 += (zz_8 >> 32) + x_7 * x_2;
				zz_10 += (zz_9 >> 32) + x_7 * x_3;
				zz_11 += (zz_10 >> 32) + x_7 * x_4;
				zz_12 += (zz_11 >> 32) + x_7 * x_5;
				zz_13 += (zz_12 >> 32) + x_7 * x_6;
				zz_14 += zz_13 >> 32;
			}

			w = (uint)zz_8;
			zz[8] = (w << 1) | c;
			c = w >> 31;
			w = (uint)zz_9;
			zz[9] = (w << 1) | c;
			c = w >> 31;
			w = (uint)zz_10;
			zz[10] = (w << 1) | c;
			c = w >> 31;
			w = (uint)zz_11;
			zz[11] = (w << 1) | c;
			c = w >> 31;
			w = (uint)zz_12;
			zz[12] = (w << 1) | c;
			c = w >> 31;
			w = (uint)zz_13;
			zz[13] = (w << 1) | c;
			c = w >> 31;
			w = (uint)zz_14;
			zz[14] = (w << 1) | c;
			c = w >> 31;
			w = zz[15] + (uint)(zz_14 >> 32);
			zz[15] = (w << 1) | c;
		}
		/** Add a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void muladd(ref uint c0, ref uint c1, ref uint c2, uint a, uint b)
		{
			uint tl, th;
			{
				ulong t = (ulong)a * b;
				th = (uint)(t >> 32);         /* at most 0xFFFFFFFE */
				tl = (uint)t;
			}
			c0 += tl;                 /* overflow is handled on the next line */
			th += (c0 < tl) ? 1U : 0;  /* at most 0xFFFFFFFF */
			c1 += th;                 /* overflow is handled on the next line */
			c2 += (c1 < th) ? 1U : 0;  /* never overflows by contract (verified in the next line) */
			VERIFY_CHECK((c1 >= th) || (c2 != 0));
		}

		/** Add a*b to the number defined by (c0,c1). c1 must never overflow. */
		[MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.AggressiveInlining)]
		static void muladd_fast(ref uint c0, ref uint c1, ref uint c2, uint a, uint b)
		{
			uint tl, th;
			{
				ulong t = (ulong)a * b;
				th = (uint)(t >> 32);         /* at most 0xFFFFFFFE */
				tl = (uint)t;
			}
			c0 += tl;                 /* overflow is handled on the next line */
			th += (c0 < tl) ? 1U : 0U;  /* at most 0xFFFFFFFF */
			c1 += th;                 /* never overflows by contract (verified in the next line) */
			VERIFY_CHECK(c1 >= th);
		}
		[MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.AggressiveInlining)]
		static void muladd2(ref uint c0, ref uint c1, ref uint c2, uint a, uint b)
		{
			uint tl, th, th2, tl2;
			{
				ulong t = (ulong)a * b;
				th = (uint)(t >> 32);               /* at most 0xFFFFFFFE */
				tl = (uint)t;
			}
			th2 = th + th;                  /* at most 0xFFFFFFFE (in case th was 0x7FFFFFFF) */
			c2 += (th2 < th) ? 1U : 0;       /* never overflows by contract (verified the next line) */
			VERIFY_CHECK((th2 >= th) || (c2 != 0));
			tl2 = tl + tl;                  /* at most 0xFFFFFFFE (in case the lowest 63 bits of tl were 0x7FFFFFFF) */
			th2 += (tl2 < tl) ? 1U : 0;      /* at most 0xFFFFFFFF */
			c0 += tl2;                      /* overflow is handled on the next line */
			th2 += (c0 < tl2) ? 1U : 0;      /* second overflow is handled on the next line */
			c2 += (c0 < tl2 ? 1U : 0) & (th2 == 0 ? 1U : 0);  /* never overflows by contract (verified the next line) */
			VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0));
			c1 += th2;                      /* overflow is handled on the next line */
			c2 += (c1 < th2) ? 1U : 0;       /* never overflows by contract (verified the next line) */
			VERIFY_CHECK((c1 >= th2) || (c2 != 0));
		}

		/** Add a to the number defined by (c0,c1,c2). c2 must never overflow. */
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void sumadd(ref uint c0, ref uint c1, ref uint c2, uint a)
		{
			uint over;
			c0 += (a);                  /* overflow is handled on the next line */
			over = (c0 < (a)) ? 1U : 0;
			c1 += over;                 /* overflow is handled on the next line */
			c2 += (c1 < over) ? 1U : 0;  /* never overflows by contract */
		}

		/** Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero. */
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void sumadd_fast(ref uint c0, ref uint c1, ref uint c2, uint a)
		{
			c0 += (a);                 /* overflow is handled on the next line */
			c1 += (c0 < (a)) ? 1U : 0;  /* never overflows by contract (verified the next line) */
			VERIFY_CHECK((c1 != 0) | (c0 >= (a)));
			VERIFY_CHECK(c2 == 0);
		}
		[MethodImpl(MethodImplOptions.NoOptimization)]
		public readonly Scalar Add(in Scalar b)
		{
			return Add(b, out _);
		}
		[MethodImpl(MethodImplOptions.NoOptimization)]
		public readonly Scalar Add(in Scalar b, out int overflow)
		{
			Span<uint> d = stackalloc uint[DCount];
			ref readonly Scalar a = ref this;
			ulong t = (ulong)a.d0 + b.d0;
			d[0] = (uint)t; t >>= 32;
			t += (ulong)a.d1 + b.d1;
			d[1] = (uint)t; t >>= 32;
			t += (ulong)a.d2 + b.d2;
			d[2] = (uint)t; t >>= 32;
			t += (ulong)a.d3 + b.d3;
			d[3] = (uint)t; t >>= 32;
			t += (ulong)a.d4 + b.d4;
			d[4] = (uint)t; t >>= 32;
			t += (ulong)a.d5 + b.d5;
			d[5] = (uint)t; t >>= 32;
			t += (ulong)a.d6 + b.d6;
			d[6] = (uint)t; t >>= 32;
			t += (ulong)a.d7 + b.d7;
			d[7] = (uint)t; t >>= 32;
			overflow = (int)(t + (uint)new Scalar(d).CheckOverflow());
			VERIFY_CHECK(overflow == 0 || overflow == 1);
			Reduce(d, overflow);
			return new Scalar(d);
		}
		/** Extract the lowest 32 bits of (c0,c1,c2) into n, and left shift the number 32 bits. */
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void extract(ref uint c0, ref uint c1, ref uint c2, out uint n)
		{
			(n) = c0;
			c0 = c1;
			c1 = c2;
			c2 = 0;
		}
		/** Extract the lowest 32 bits of (c0,c1,c2) into n, and left shift the number 32 bits. c2 is required to be zero. */
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void extract_fast(ref uint c0, ref uint c1, ref uint c2, out uint n)
		{
			(n) = c0;
			c0 = c1;
			c1 = 0;
			VERIFY_CHECK(c2 == 0);
		}

		[Conditional("SECP256K1_VERIFY")]
		private static void VERIFY_CHECK(bool value)
		{
			if (!value)
				throw new InvalidOperationException("VERIFY_CHECK failed (bug in C# secp256k1)");
		}

		public readonly bool IsOverflow
		{
			get
			{
				return CheckOverflow() != 0;
			}
		}

		[MethodImpl(MethodImplOptions.NoOptimization)]
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

		[MethodImpl(MethodImplOptions.NoOptimization)]
		internal readonly uint GetBits(int offset, int count)
		{
			if (offset < 0)
				throw new ArgumentOutOfRangeException(nameof(offset), "Offset should be more than 0");
			if (count < 0)
				throw new ArgumentOutOfRangeException(nameof(count), "Count should be more than 0");
			VERIFY_CHECK((offset + count - 1) >> 5 == offset >> 5);
			return (uint)((At(offset >> 5) >> (offset & 0x1F)) & ((1 << count) - 1));
		}
		internal readonly uint GetBitsVariable(int offset, int count)
		{
			if (offset < 0)
				throw new ArgumentOutOfRangeException(nameof(offset), "Offset should be more than 0");
			if (count < 0)
				throw new ArgumentOutOfRangeException(nameof(count), "Count should be more than 0");
			if (count >= 32)
				throw new ArgumentOutOfRangeException(nameof(count), "Count should be less than 32");
			if (offset + count > 256)
				throw new ArgumentOutOfRangeException(nameof(count), "End index should be less or eq to 256");
			if ((offset + count - 1) >> 5 == offset >> 5)
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
			switch (index)
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


		public readonly void Split128(out Scalar r1, out Scalar r2)
		{
			r1 = new Scalar(d0, d1, d2, d3, 0, 0, 0, 0);
			r2 = new Scalar(d4, d5, d6, d7, 0, 0, 0, 0);
		}

		/**
		* The Secp256k1 curve has an endomorphism, where lambda * (x, y) = (beta * x, y), where
		* lambda is {0x53,0x63,0xad,0x4c,0xc0,0x5c,0x30,0xe0,0xa5,0x26,0x1c,0x02,0x88,0x12,0x64,0x5a,
		*            0x12,0x2e,0x22,0xea,0x20,0x81,0x66,0x78,0xdf,0x02,0x96,0x7c,0x1b,0x23,0xbd,0x72}
		*
		* "Guide to Elliptic Curve Cryptography" (Hankerson, Menezes, Vanstone) gives an algorithm
		* (algorithm 3.74) to find k1 and k2 given k, such that k1 + k2 * lambda == k mod n, and k1
		* and k2 have a small size.
		* It relies on constants a1, b1, a2, b2. These constants for the value of lambda above are:
		*
		* - a1 =      {0x30,0x86,0xd2,0x21,0xa7,0xd4,0x6b,0xcd,0xe8,0x6c,0x90,0xe4,0x92,0x84,0xeb,0x15}
		* - b1 =     -{0xe4,0x43,0x7e,0xd6,0x01,0x0e,0x88,0x28,0x6f,0x54,0x7f,0xa9,0x0a,0xbf,0xe4,0xc3}
		* - a2 = {0x01,0x14,0xca,0x50,0xf7,0xa8,0xe2,0xf3,0xf6,0x57,0xc1,0x10,0x8d,0x9d,0x44,0xcf,0xd8}
		* - b2 =      {0x30,0x86,0xd2,0x21,0xa7,0xd4,0x6b,0xcd,0xe8,0x6c,0x90,0xe4,0x92,0x84,0xeb,0x15}
		*
		* The algorithm then computes c1 = round(b1 * k / n) and c2 = round(b2 * k / n), and gives
		* k1 = k - (c1*a1 + c2*a2) and k2 = -(c1*b1 + c2*b2). Instead, we use modular arithmetic, and
		* compute k1 as k - k2 * lambda, avoiding the need for constants a1 and a2.
		*
		* g1, g2 are precomputed constants used to replace division with a rounded multiplication
		* when decomposing the scalar for an endomorphism-based point multiplication.
		*
		* The possibility of using precomputed estimates is mentioned in "Guide to Elliptic Curve
		* Cryptography" (Hankerson, Menezes, Vanstone) in section 3.5.
		*
		* The derivation is described in the paper "Efficient Software Implementation of Public-Key
		* Cryptography on Sensor Networks Using the MSP430X Microcontroller" (Gouvea, Oliveira, Lopez),
		* Section 4.3 (here we use a somewhat higher-precision estimate):
		* d = a1*b2 - b1*a2
		* g1 = round((2^272)*b2/d)
		* g2 = round((2^272)*b1/d)
		*
		* (Note that 'd' is also equal to the curve order here because [a1,b1] and [a2,b2] are found
		* as outputs of the Extended Euclidean Algorithm on inputs 'order' and 'lambda').
		*
		* The function below splits a in r1 and r2, such that r1 + lambda * r2 == a (mod order).
*/

		public static Scalar SECP256K1_SCALAR_CONST(uint d7, uint d6, uint d5, uint d4, uint d3, uint d2, uint d1, uint d0)
		{
			return new Scalar(d0, d1, d2, d3, d4, d5, d6, d7);
		}
		static readonly Scalar minus_lambda = SECP256K1_SCALAR_CONST(
			0xAC9C52B3U, 0x3FA3CF1FU, 0x5AD9E3FDU, 0x77ED9BA4U,
			0xA880B9FCU, 0x8EC739C2U, 0xE0CFC810U, 0xB51283CFU
		);
		static readonly Scalar minus_b1 = SECP256K1_SCALAR_CONST(
			0x00000000U, 0x00000000U, 0x00000000U, 0x00000000U,
			0xE4437ED6U, 0x010E8828U, 0x6F547FA9U, 0x0ABFE4C3U
		);
		static readonly Scalar minus_b2 = SECP256K1_SCALAR_CONST(
			0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU,
			0x8A280AC5U, 0x0774346DU, 0xD765CDA8U, 0x3DB1562CU
		);
		static readonly Scalar g1 = SECP256K1_SCALAR_CONST(
			0x00000000U, 0x00000000U, 0x00000000U, 0x00003086U,
			0xD221A7D4U, 0x6BCDE86CU, 0x90E49284U, 0xEB153DABU
		);
		static readonly Scalar g2 = SECP256K1_SCALAR_CONST(
			0x00000000U, 0x00000000U, 0x00000000U, 0x0000E443U,
			0x7ED6010EU, 0x88286F54U, 0x7FA90ABFU, 0xE4C42212U
		);
		public bool IsEven
		{
			[MethodImpl(MethodImplOptions.AggressiveInlining)]
			get
			{
				return (d0 & 1) == 0;
			}
		}

		public bool IsHigh
		{
			get
			{
				int yes = 0;
				int no = 0;
				no |= (d7 < SECP256K1_N_H_7 ? 1 : 0);
				yes |= (d7 > SECP256K1_N_H_7 ? 1 : 0) & ~no;
				no |= (d6 < SECP256K1_N_H_6 ? 1 : 0) & ~yes; /* No need for a > check. */
				no |= (d5 < SECP256K1_N_H_5 ? 1 : 0) & ~yes; /* No need for a > check. */
				no |= (d4 < SECP256K1_N_H_4 ? 1 : 0) & ~yes; /* No need for a > check. */
				no |= (d3 < SECP256K1_N_H_3 ? 1 : 0) & ~yes;
				yes |= (d3 > SECP256K1_N_H_3 ? 1 : 0) & ~no;
				no |= (d2 < SECP256K1_N_H_2 ? 1 : 0) & ~yes;
				yes |= (d2 > SECP256K1_N_H_2 ? 1 : 0) & ~no;
				no |= (d1 < SECP256K1_N_H_1 ? 1 : 0) & ~yes;
				yes |= (d1 > SECP256K1_N_H_1 ? 1 : 0) & ~no;
				yes |= (d0 > SECP256K1_N_H_0 ? 1 : 0) & ~no;
				return yes != 0;
			}
		}

		public readonly void SplitLambda(out Scalar r1, out Scalar r2)
		{
			/* these _var calls are constant time since the shift amount is constant */
			Scalar c1 = this.MultiplyShiftVariable(g1, 272);
			Scalar c2 = this.MultiplyShiftVariable(g2, 272);
			c1 = c1 * minus_b1;
			c2 = c2 * minus_b2;
			r2 = c1 + c2;
			r1 = r2 * minus_lambda;
			r1 = r1 + this;
		}

		public readonly Scalar MultiplyShiftVariable(Scalar b, int shift)
		{
			Span<uint> l = stackalloc uint[16];
			int shiftlimbs;
			int shiftlow;
			int shifthigh;
			VERIFY_CHECK(shift >= 256);
			Scalar.mul_512(l, this, b);
			shiftlimbs = shift >> 5;
			shiftlow = shift & 0x1F;
			shifthigh = 32 - shiftlow;

			var r = new Scalar(
				shift < 512 ? (l[0 + shiftlimbs] >> shiftlow | (shift < 480 && shiftlow != 0 ? (l[1 + shiftlimbs] << shifthigh) : 0)) : 0,
				shift < 480 ? (l[1 + shiftlimbs] >> shiftlow | (shift < 448 && shiftlow != 0 ? (l[2 + shiftlimbs] << shifthigh) : 0)) : 0,
				shift < 448 ? (l[2 + shiftlimbs] >> shiftlow | (shift < 416 && shiftlow != 0 ? (l[3 + shiftlimbs] << shifthigh) : 0)) : 0,
				shift < 416 ? (l[3 + shiftlimbs] >> shiftlow | (shift < 384 && shiftlow != 0 ? (l[4 + shiftlimbs] << shifthigh) : 0)) : 0,
				shift < 384 ? (l[4 + shiftlimbs] >> shiftlow | (shift < 352 && shiftlow != 0 ? (l[5 + shiftlimbs] << shifthigh) : 0)) : 0,
				shift < 352 ? (l[5 + shiftlimbs] >> shiftlow | (shift < 320 && shiftlow != 0 ? (l[6 + shiftlimbs] << shifthigh) : 0)) : 0,
				shift < 320 ? (l[6 + shiftlimbs] >> shiftlow | (shift < 288 && shiftlow != 0 ? (l[7 + shiftlimbs] << shifthigh) : 0)) : 0,
				shift < 288 ? (l[7 + shiftlimbs] >> shiftlow) : 0
				);
			r = r.CAddBit(0, (int)((l[(shift - 1) >> 5] >> ((shift - 1) & 0x1f)) & 1));
			return r;
		}

		public readonly bool IsZero
		{
			[MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.AggressiveInlining)]
			get
			{
				return (d0 | d1 | d2 | d3 | d4 | d5 | d6 | d7) == 0;
			}
		}
		public readonly bool IsOne
		{
			[MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.AggressiveInlining)]
			get
			{
				return ((d0 ^ 1) | d1 | d2 | d3 | d4 | d5 | d6 | d7) == 0;
			}
		}

		const int DCount = 8;
		public readonly Scalar Sqr()
		{
			Span<uint> d = stackalloc uint[DCount];
			Deconstruct(ref d);
			Span<uint> l = stackalloc uint[16];
			sqr_512(l, this);
			reduce_512(d, l);
			return new Scalar(d);
		}

		public readonly Scalar Inverse()
		{
			ref readonly Scalar x = ref this;
			Scalar r = Scalar.Zero;
			int i;
			/* First compute xN as x ^ (2^N - 1) for some values of N,
			 * and uM as x ^ M for some values of M. */
			Scalar x2, x3, x6, x8, x14, x28, x56, x112, x126;
			Scalar u2, u5, u9, u11, u13;

			u2 = x.Sqr();
			x2 = u2 * x;
			u5 = u2 * x2;
			x3 = u5 * u2;
			u9 = x3 * u2;
			u11 = u9 * u2;
			u13 = u11 * u2;

			x6 = u13.Sqr();
			x6 = x6.Sqr();
			x6 = x6 * u11;

			x8 = x6.Sqr();
			x8 = x8.Sqr();
			x8 = x8 * x2;

			x14 = x8.Sqr();
			for (i = 0; i < 5; i++)
			{
				x14 = x14.Sqr();
			}
			x14 = x14 * x6;

			x28 = x14.Sqr();
			for (i = 0; i < 13; i++)
			{
				x28 = x28.Sqr();
			}
			x28 = x28 * x14;

			x56 = x28.Sqr();
			for (i = 0; i < 27; i++)
			{
				x56 = x56.Sqr();
			}
			x56 = x56 * x28;

			x112 = x56.Sqr();
			for (i = 0; i < 55; i++)
			{
				x112 = x112.Sqr();
			}
			x112 = x112 * x56;

			x126 = x112.Sqr();
			for (i = 0; i < 13; i++)
			{
				x126 = x126.Sqr();
			}
			x126 = x126 * x14;

			/* Then accumulate the final result (t starts at x126). */
			ref Scalar t = ref x126;
			for (i = 0; i < 3; i++)
			{
				t = t.Sqr();
			}
			t = t * u5; /* 101 */
			for (i = 0; i < 4; i++)
			{ /* 0 */
				t = t.Sqr();
			}
			t = t * x3; /* 111 */
			for (i = 0; i < 4; i++)
			{ /* 0 */
				t = t.Sqr();
			}
			t = t * u5; /* 101 */
			for (i = 0; i < 5; i++)
			{ /* 0 */
				t = t.Sqr();
			}
			t = t * u11; /* 1011 */
			for (i = 0; i < 4; i++)
			{
				t = t.Sqr();
			}
			t = t * u11; /* 1011 */
			for (i = 0; i < 4; i++)
			{ /* 0 */
				t = t.Sqr();
			}
			t = t * x3; /* 111 */
			for (i = 0; i < 5; i++)
			{ /* 00 */
				t = t.Sqr();
			}
			t = t * x3; /* 111 */
			for (i = 0; i < 6; i++)
			{ /* 00 */
				t = t.Sqr();
			}
			t = t * u13; /* 1101 */
			for (i = 0; i < 4; i++)
			{ /* 0 */
				t = t.Sqr();
			}
			t = t * u5; /* 101 */
			for (i = 0; i < 3; i++)
			{
				t = t.Sqr();
			}
			t = t * x3; /* 111 */
			for (i = 0; i < 5; i++)
			{ /* 0 */
				t = t.Sqr();
			}
			t = t * u9; /* 1001 */
			for (i = 0; i < 6; i++)
			{ /* 000 */
				t = t.Sqr();
			}
			t = t * u5; /* 101 */
			for (i = 0; i < 10; i++)
			{ /* 0000000 */
				t = t.Sqr();
			}
			t = t * x3; /* 111 */
			for (i = 0; i < 4; i++)
			{ /* 0 */
				t = t.Sqr();
			}
			t = t * x3; /* 111 */
			for (i = 0; i < 9; i++)
			{ /* 0 */
				t = t.Sqr();
			}
			t = t * x8; /* 11111111 */
			for (i = 0; i < 5; i++)
			{ /* 0 */
				t = t.Sqr();
			}
			t = t * u9; /* 1001 */
			for (i = 0; i < 6; i++)
			{ /* 00 */
				t = t.Sqr();
			}
			t = t * u11; /* 1011 */
			for (i = 0; i < 4; i++)
			{
				t = t.Sqr();
			}
			t = t * u13; /* 1101 */
			for (i = 0; i < 5; i++)
			{
				t = t.Sqr();
			}
			t = t * x2; /* 11 */
			for (i = 0; i < 6; i++)
			{ /* 00 */
				t = t.Sqr();
			}
			t = t * u13; /* 1101 */
			for (i = 0; i < 10; i++)
			{ /* 000000 */
				t = t.Sqr();
			}
			t = t * u13; /* 1101 */
			for (i = 0; i < 4; i++)
			{
				t = t.Sqr();
			}
			t = t * u9; /* 1001 */
			for (i = 0; i < 6; i++)
			{ /* 00000 */
				t = t.Sqr();
			}

			t = t * x; /* 1 */
			for (i = 0; i < 8; i++)
			{ /* 00 */
				t = t.Sqr();
			}
			r = t * x6; /* 111111 */
			return r;
		}

		public static Scalar operator *(in Scalar a, in Scalar b)
		{
			return a.Multiply(b);
		}
		public readonly Scalar Multiply(in Scalar b)
		{
			Span<uint> d = stackalloc uint[DCount];
			this.Deconstruct(ref d);
			Span<uint> l = stackalloc uint[16];
			mul_512(l, this, b);
			reduce_512(d, l);
			return new Scalar(d);
		}

		public readonly int ShrInt(int n, out Scalar ret)
		{
			VERIFY_CHECK(n > 0);
			VERIFY_CHECK(n < 16);
			var v = (int)(d0 & ((1 << n) - 1));
			ret = new Scalar
			(
				(d0 >> n) + (d1 << (32 - n)),
				(d1 >> n) + (d2 << (32 - n)),
				(d2 >> n) + (d3 << (32 - n)),
				(d3 >> n) + (d4 << (32 - n)),
				(d4 >> n) + (d5 << (32 - n)),
				(d5 >> n) + (d6 << (32 - n)),
				(d6 >> n) + (d7 << (32 - n)),
				(d7 >> n)
			);
			return v;
		}

		public readonly Scalar Negate()
		{
			Span<uint> d = stackalloc uint[DCount];
			ref readonly Scalar a = ref this;
			uint nonzero = 0xFFFFFFFFU * (a.IsZero ? 0U : 1);
			ulong t = (ulong)(~a.d0) + SECP256K1_N_0 + 1;
			d[0] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d1) + SECP256K1_N_1;
			d[1] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d2) + SECP256K1_N_2;
			d[2] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d3) + SECP256K1_N_3;
			d[3] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d4) + SECP256K1_N_4;
			d[4] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d5) + SECP256K1_N_5;
			d[5] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d6) + SECP256K1_N_6;
			d[6] = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d7) + SECP256K1_N_7;
			d[7] = (uint)(t & nonzero);
			return new Scalar(d);
		}

		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoOptimization)]
		public readonly bool Equals(Scalar b)
		{
			ref readonly Scalar a = ref this;
			return ((a.d0 ^ b.d0) | (a.d1 ^ b.d1) | (a.d2 ^ b.d2) | (a.d3 ^ b.d3) | (a.d4 ^ b.d4) | (a.d5 ^ b.d5) | (a.d6 ^ b.d6) | (a.d7 ^ b.d7)) == 0;
		}
		[System.Runtime.CompilerServices.MethodImpl(System.Runtime.CompilerServices.MethodImplOptions.NoOptimization)]
		public readonly override bool Equals(object obj)
		{
			if (obj is Scalar b)
			{
				ref readonly Scalar a = ref this;
				return ((a.d0 ^ b.d0) | (a.d1 ^ b.d1) | (a.d2 ^ b.d2) | (a.d3 ^ b.d3) | (a.d4 ^ b.d4) | (a.d5 ^ b.d5) | (a.d6 ^ b.d6) | (a.d7 ^ b.d7)) == 0;
			}
			return false;
		}

		public static bool operator ==(in Scalar a, in Scalar b)
		{
			return a.Equals(b);
		}
		public static bool operator !=(in Scalar a, in Scalar b)
		{
			return !a.Equals(b);
		}
		public static Scalar operator +(in Scalar a, in Scalar b)
		{
			return a.Add(b);
		}

		public readonly void Deconstruct(
				ref Span<uint> d)
		{
			d[0]= this.d0;
			d[1] = this.d1;
			d[2] = this.d2;
			d[3] = this.d3;
			d[4] = this.d4;
			d[5] = this.d5;
			d[6] = this.d6;
			d[7] = this.d7;
		}


		[MethodImpl(MethodImplOptions.NoOptimization)]
		public readonly override int GetHashCode()
		{
			unchecked
			{
				int hash = 17;
				hash = hash * 23 + d0.GetHashCode();
				hash = hash * 23 + d1.GetHashCode();
				hash = hash * 23 + d2.GetHashCode();
				hash = hash * 23 + d3.GetHashCode();
				hash = hash * 23 + d4.GetHashCode();
				hash = hash * 23 + d5.GetHashCode();
				hash = hash * 23 + d6.GetHashCode();
				hash = hash * 23 + d7.GetHashCode();
				return hash;
			}
		}
		public readonly Scalar InverseVariable()
		{
			return Inverse();
		}
		public readonly string ToC(string varname)
		{
			return $"secp256k1_scalar {varname} = {{ 0x{d0.ToString("X8")}UL, 0x{d1.ToString("X8")}UL, 0x{d2.ToString("X8")}UL, 0x{d3.ToString("X8")}UL, 0x{d4.ToString("X8")}UL, 0x{d5.ToString("X8")}UL, 0x{d6.ToString("X8")}UL, 0x{d7.ToString("X8")}UL }}";
		}
	}
}
