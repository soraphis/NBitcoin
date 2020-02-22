using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;

namespace NBitcoin.Secp256k1
{
	readonly struct Scalar : IEquatable<Scalar>
	{
		/** Add a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
		[MethodImpl(MethodImplOptions.NoOptimization)]
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
		[MethodImpl(MethodImplOptions.NoOptimization)]
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
		[MethodImpl(MethodImplOptions.NoOptimization)]
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
		[MethodImpl(MethodImplOptions.NoOptimization)]
		static void sumadd(ref uint c0, ref uint c1, ref uint c2, uint a)
		{
			uint over;
			c0 += (a);                  /* overflow is handled on the next line */
			over = (c0 < (a)) ? 1U : 0;
			c1 += over;                 /* overflow is handled on the next line */
			c2 += (c1 < over) ? 1U : 0;  /* never overflows by contract */
		}

		/** Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero. */
		[MethodImpl(MethodImplOptions.NoOptimization)]
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
			uint d0;
			uint d1;
			uint d2;
			uint d3;
			uint d4;
			uint d5;
			uint d6;
			uint d7;
			ref readonly Scalar a = ref this;
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
			overflow = (int)(t + (uint)new Scalar(d0, d1, d2, d3, d4, d5, d6, d7).CheckOverflow());
			VERIFY_CHECK(overflow == 0 || overflow == 1);
			Reduce(ref d0, ref d1, ref d2, ref d3, ref d4, ref d5, ref d6, ref d7, overflow);
			return new Scalar(d0, d1, d2, d3, d4, d5, d6, d7);
		}
		/** Extract the lowest 32 bits of (c0,c1,c2) into n, and left shift the number 32 bits. */
		[MethodImpl(MethodImplOptions.NoOptimization)]
		static void extract(ref uint c0, ref uint c1, ref uint c2, out uint n)
		{
			(n) = c0;
			c0 = c1;
			c1 = c2;
			c2 = 0;
		}
		/** Extract the lowest 32 bits of (c0,c1,c2) into n, and left shift the number 32 bits. c2 is required to be zero. */
		[MethodImpl(MethodImplOptions.NoOptimization)]
		static void extract_fast(ref uint c0, ref uint c1, ref uint c2, out uint n)
		{
			(n) = c0;
			c0 = c1;
			c1 = 0;
			VERIFY_CHECK(c2 == 0);
		}

		static readonly Scalar _Zero = new Scalar(0, 0, 0, 0, 0, 0, 0, 0);
		public static ref readonly Scalar Zero => ref _Zero;
		static readonly Scalar _One = new Scalar(1, 0, 0, 0, 0, 0, 0, 0);
		public static ref readonly Scalar One => ref _One;
		static readonly Scalar _N = new Scalar(SECP256K1_N_0, SECP256K1_N_1, SECP256K1_N_2, SECP256K1_N_3, SECP256K1_N_4, SECP256K1_N_5, SECP256K1_N_6, SECP256K1_N_7);
		public static ref readonly Scalar N => ref _N;
		static readonly Scalar _NC = new Scalar(SECP256K1_N_C_0, SECP256K1_N_C_1, SECP256K1_N_C_2, SECP256K1_N_C_3, SECP256K1_N_C_4, 0, 0, 0);
		public static ref readonly Scalar NC => ref _NC;

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
			Reduce(ref d0, ref d1, ref d2, ref d3, ref d4, ref d5, ref d6, ref d7, overflow);
		}
		[MethodImpl(MethodImplOptions.NoOptimization)]
		internal readonly Scalar CAddBit(uint bit, int flag)
		{
			uint d0, d1, d2, d3, d4, d5, d6, d7;
			ulong t;
			VERIFY_CHECK(bit < 256);
			bit += ((uint)flag - 1) & 0x100;  /* forcing (bit >> 5) > 7 makes this a noop */
			t = (ulong)this.d0 + (((bit >> 5) == 0 ? 1U : 0) << (int)(bit & 0x1F));
			d0 = (uint)t; t >>= 32;
			t += (ulong)this.d1 + (((bit >> 5) == 1 ? 1U : 0) << (int)(bit & 0x1F));
			d1 = (uint)t; t >>= 32;
			t += (ulong)this.d2 + (((bit >> 5) == 2 ? 1U : 0) << (int)(bit & 0x1F));
			d2 = (uint)t; t >>= 32;
			t += (ulong)this.d3 + (((bit >> 5) == 3 ? 1U : 0) << (int)(bit & 0x1F));
			d3 = (uint)t; t >>= 32;
			t += (ulong)this.d4 + (((bit >> 5) == 4 ? 1U : 0) << (int)(bit & 0x1F));
			d4 = (uint)t; t >>= 32;
			t += (ulong)this.d5 + (((bit >> 5) == 5 ? 1U : 0) << (int)(bit & 0x1F));
			d5 = (uint)t; t >>= 32;
			t += (ulong)this.d6 + (((bit >> 5) == 6 ? 1U : 0) << (int)(bit & 0x1F));
			d6 = (uint)t; t >>= 32;
			t += (ulong)this.d7 + (((bit >> 5) == 7 ? 1U : 0) << (int)(bit & 0x1F));
			d7 = (uint)t;
			VERIFY_CHECK((t >> 32) == 0);
			var r = new Scalar(d0, d1, d2, d3, d4, d5, d6, d7);
			VERIFY_CHECK(!r.IsOverflow);
			return r;
		}

		[MethodImpl(MethodImplOptions.NoOptimization)]
		private static int Reduce(ref uint d0, ref uint d1, ref uint d2, ref uint d3, ref uint d4, ref uint d5, ref uint d6, ref uint d7, int overflow)
		{
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
			return overflow;
		}
		[MethodImpl(MethodImplOptions.NoOptimization)]
		private static void reduce_512(ref uint d0, ref uint d1, ref uint d2, ref uint d3, ref uint d4, ref uint d5, ref uint d6, ref uint d7, Span<uint> l)
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
			d0 = (uint)c; c >>= 32;
			c += p1 + (ulong)SECP256K1_N_C_1 * p8;
			d1 = (uint)c; c >>= 32;
			c += p2 + (ulong)SECP256K1_N_C_2 * p8;
			d2 = (uint)c; c >>= 32;
			c += p3 + (ulong)SECP256K1_N_C_3 * p8;
			d3 = (uint)c; c >>= 32;
			c += p4 + (ulong)p8;
			d4 = (uint)c; c >>= 32;
			c += p5;
			d5 = (uint)c; c >>= 32;
			c += p6;
			d6 = (uint)c; c >>= 32;
			c += p7;
			d7 = (uint)c; c >>= 32;

			/* Final reduction of r. */
			Reduce(ref d0, ref d1, ref d2, ref d3, ref d4, ref d5, ref d6, ref d7, (int)c + new Scalar(d0, d1, d2, d3, d4, d5, d6, d7).CheckOverflow());
		}
		[MethodImpl(MethodImplOptions.NoOptimization)]
		private static void mul_512(Span<uint> l, in Scalar a, in Scalar b)
		{
			/* 96 bit accumulator. */
			uint c0 = 0, c1 = 0, c2 = 0;

			/* l[0..15] = a[0..7] * b[0..7]. */
			muladd_fast(ref c0, ref c1, ref c2, a.d0, b.d0);
			extract_fast(ref c0, ref c1, ref c2, out l[0]);
			muladd(ref c0, ref c1, ref c2, a.d0, b.d1);
			muladd(ref c0, ref c1, ref c2, a.d1, b.d0);
			extract(ref c0, ref c1, ref c2, out l[1]);
			muladd(ref c0, ref c1, ref c2, a.d0, b.d2);
			muladd(ref c0, ref c1, ref c2, a.d1, b.d1);
			muladd(ref c0, ref c1, ref c2, a.d2, b.d0);
			extract(ref c0, ref c1, ref c2, out l[2]);
			muladd(ref c0, ref c1, ref c2, a.d0, b.d3);
			muladd(ref c0, ref c1, ref c2, a.d1, b.d2);
			muladd(ref c0, ref c1, ref c2, a.d2, b.d1);
			muladd(ref c0, ref c1, ref c2, a.d3, b.d0);
			extract(ref c0, ref c1, ref c2, out l[3]);
			muladd(ref c0, ref c1, ref c2, a.d0, b.d4);
			muladd(ref c0, ref c1, ref c2, a.d1, b.d3);
			muladd(ref c0, ref c1, ref c2, a.d2, b.d2);
			muladd(ref c0, ref c1, ref c2, a.d3, b.d1);
			muladd(ref c0, ref c1, ref c2, a.d4, b.d0);
			extract(ref c0, ref c1, ref c2, out l[4]);
			muladd(ref c0, ref c1, ref c2, a.d0, b.d5);
			muladd(ref c0, ref c1, ref c2, a.d1, b.d4);
			muladd(ref c0, ref c1, ref c2, a.d2, b.d3);
			muladd(ref c0, ref c1, ref c2, a.d3, b.d2);
			muladd(ref c0, ref c1, ref c2, a.d4, b.d1);
			muladd(ref c0, ref c1, ref c2, a.d5, b.d0);
			extract(ref c0, ref c1, ref c2, out l[5]);
			muladd(ref c0, ref c1, ref c2, a.d0, b.d6);
			muladd(ref c0, ref c1, ref c2, a.d1, b.d5);
			muladd(ref c0, ref c1, ref c2, a.d2, b.d4);
			muladd(ref c0, ref c1, ref c2, a.d3, b.d3);
			muladd(ref c0, ref c1, ref c2, a.d4, b.d2);
			muladd(ref c0, ref c1, ref c2, a.d5, b.d1);
			muladd(ref c0, ref c1, ref c2, a.d6, b.d0);
			extract(ref c0, ref c1, ref c2, out l[6]);
			muladd(ref c0, ref c1, ref c2, a.d0, b.d7);
			muladd(ref c0, ref c1, ref c2, a.d1, b.d6);
			muladd(ref c0, ref c1, ref c2, a.d2, b.d5);
			muladd(ref c0, ref c1, ref c2, a.d3, b.d4);
			muladd(ref c0, ref c1, ref c2, a.d4, b.d3);
			muladd(ref c0, ref c1, ref c2, a.d5, b.d2);
			muladd(ref c0, ref c1, ref c2, a.d6, b.d1);
			muladd(ref c0, ref c1, ref c2, a.d7, b.d0);
			extract(ref c0, ref c1, ref c2, out l[7]);
			muladd(ref c0, ref c1, ref c2, a.d1, b.d7);
			muladd(ref c0, ref c1, ref c2, a.d2, b.d6);
			muladd(ref c0, ref c1, ref c2, a.d3, b.d5);
			muladd(ref c0, ref c1, ref c2, a.d4, b.d4);
			muladd(ref c0, ref c1, ref c2, a.d5, b.d3);
			muladd(ref c0, ref c1, ref c2, a.d6, b.d2);
			muladd(ref c0, ref c1, ref c2, a.d7, b.d1);
			extract(ref c0, ref c1, ref c2, out l[8]);
			muladd(ref c0, ref c1, ref c2, a.d2, b.d7);
			muladd(ref c0, ref c1, ref c2, a.d3, b.d6);
			muladd(ref c0, ref c1, ref c2, a.d4, b.d5);
			muladd(ref c0, ref c1, ref c2, a.d5, b.d4);
			muladd(ref c0, ref c1, ref c2, a.d6, b.d3);
			muladd(ref c0, ref c1, ref c2, a.d7, b.d2);
			extract(ref c0, ref c1, ref c2, out l[9]);
			muladd(ref c0, ref c1, ref c2, a.d3, b.d7);
			muladd(ref c0, ref c1, ref c2, a.d4, b.d6);
			muladd(ref c0, ref c1, ref c2, a.d5, b.d5);
			muladd(ref c0, ref c1, ref c2, a.d6, b.d4);
			muladd(ref c0, ref c1, ref c2, a.d7, b.d3);
			extract(ref c0, ref c1, ref c2, out l[10]);
			muladd(ref c0, ref c1, ref c2, a.d4, b.d7);
			muladd(ref c0, ref c1, ref c2, a.d5, b.d6);
			muladd(ref c0, ref c1, ref c2, a.d6, b.d5);
			muladd(ref c0, ref c1, ref c2, a.d7, b.d4);
			extract(ref c0, ref c1, ref c2, out l[11]);
			muladd(ref c0, ref c1, ref c2, a.d5, b.d7);
			muladd(ref c0, ref c1, ref c2, a.d6, b.d6);
			muladd(ref c0, ref c1, ref c2, a.d7, b.d5);
			extract(ref c0, ref c1, ref c2, out l[12]);
			muladd(ref c0, ref c1, ref c2, a.d6, b.d7);
			muladd(ref c0, ref c1, ref c2, a.d7, b.d6);
			extract(ref c0, ref c1, ref c2, out l[13]);
			muladd_fast(ref c0, ref c1, ref c2, a.d7, b.d7);
			extract_fast(ref c0, ref c1, ref c2, out l[14]);
			VERIFY_CHECK(c1 == 0);
			l[15] = c0;
		}
		[MethodImpl(MethodImplOptions.NoOptimization)]
		internal static void sqr_512(Span<uint> l, in Scalar a)
		{
			/* 96 bit accumulator. */
			uint c0 = 0, c1 = 0, c2 = 0;

			/* l[0..15] = a[0..7]^2. */
			muladd_fast(ref c0, ref c1, ref c2, a.d0, a.d0);
			extract_fast(ref c0, ref c1, ref c2, out l[0]);
			muladd2(ref c0, ref c1, ref c2, a.d0, a.d1);
			extract(ref c0, ref c1, ref c2, out l[1]);
			muladd2(ref c0, ref c1, ref c2, a.d0, a.d2);
			muladd(ref c0, ref c1, ref c2, a.d1, a.d1);
			extract(ref c0, ref c1, ref c2, out l[2]);
			muladd2(ref c0, ref c1, ref c2, a.d0, a.d3);
			muladd2(ref c0, ref c1, ref c2, a.d1, a.d2);
			extract(ref c0, ref c1, ref c2, out l[3]);
			muladd2(ref c0, ref c1, ref c2, a.d0, a.d4);
			muladd2(ref c0, ref c1, ref c2, a.d1, a.d3);
			muladd(ref c0, ref c1, ref c2, a.d2, a.d2);
			extract(ref c0, ref c1, ref c2, out l[4]);
			muladd2(ref c0, ref c1, ref c2, a.d0, a.d5);
			muladd2(ref c0, ref c1, ref c2, a.d1, a.d4);
			muladd2(ref c0, ref c1, ref c2, a.d2, a.d3);
			extract(ref c0, ref c1, ref c2, out l[5]);
			muladd2(ref c0, ref c1, ref c2, a.d0, a.d6);
			muladd2(ref c0, ref c1, ref c2, a.d1, a.d5);
			muladd2(ref c0, ref c1, ref c2, a.d2, a.d4);
			muladd(ref c0, ref c1, ref c2, a.d3, a.d3);
			extract(ref c0, ref c1, ref c2, out l[6]);
			muladd2(ref c0, ref c1, ref c2, a.d0, a.d7);
			muladd2(ref c0, ref c1, ref c2, a.d1, a.d6);
			muladd2(ref c0, ref c1, ref c2, a.d2, a.d5);
			muladd2(ref c0, ref c1, ref c2, a.d3, a.d4);
			extract(ref c0, ref c1, ref c2, out l[7]);
			muladd2(ref c0, ref c1, ref c2, a.d1, a.d7);
			muladd2(ref c0, ref c1, ref c2, a.d2, a.d6);
			muladd2(ref c0, ref c1, ref c2, a.d3, a.d5);
			muladd(ref c0, ref c1, ref c2, a.d4, a.d4);
			extract(ref c0, ref c1, ref c2, out l[8]);
			muladd2(ref c0, ref c1, ref c2, a.d2, a.d7);
			muladd2(ref c0, ref c1, ref c2, a.d3, a.d6);
			muladd2(ref c0, ref c1, ref c2, a.d4, a.d5);
			extract(ref c0, ref c1, ref c2, out l[9]);
			muladd2(ref c0, ref c1, ref c2, a.d3, a.d7);
			muladd2(ref c0, ref c1, ref c2, a.d4, a.d6);
			muladd(ref c0, ref c1, ref c2, a.d5, a.d5);
			extract(ref c0, ref c1, ref c2, out l[10]);
			muladd2(ref c0, ref c1, ref c2, a.d4, a.d7);
			muladd2(ref c0, ref c1, ref c2, a.d5, a.d6);
			extract(ref c0, ref c1, ref c2, out l[11]);
			muladd2(ref c0, ref c1, ref c2, a.d5, a.d7);
			muladd(ref c0, ref c1, ref c2, a.d6, a.d6);
			extract(ref c0, ref c1, ref c2, out l[12]);
			muladd2(ref c0, ref c1, ref c2, a.d6, a.d7);
			extract(ref c0, ref c1, ref c2, out l[13]);
			muladd_fast(ref c0, ref c1, ref c2, a.d7, a.d7);
			extract_fast(ref c0, ref c1, ref c2, out l[14]);
			VERIFY_CHECK(c1 == 0);
			l[15] = c0;
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

		public readonly void Deconstruct(
			out uint d0,
			out uint d1,
			out uint d2,
			out uint d3,
			out uint d4,
			out uint d5,
			out uint d6,
			out uint d7)
		{
			d0 = this.d0;
			d1 = this.d1;
			d2 = this.d2;
			d3 = this.d3;
			d4 = this.d4;
			d5 = this.d5;
			d6 = this.d6;
			d7 = this.d7;
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
		[MethodImpl(MethodImplOptions.NoOptimization)]
		public readonly Scalar Sqr()
		{
			var (d0, d1, d2, d3, d4, d5, d6, d7) = this;
			Span<uint> l = stackalloc uint[16];
			sqr_512(l, this);
			reduce_512(ref d0, ref d1, ref d2, ref d3, ref d4, ref d5, ref d6, ref d7, l);
			return new Scalar(d0, d1, d2, d3, d4, d5, d6, d7);
		}
		[MethodImpl(MethodImplOptions.NoOptimization)]
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
		public Scalar Multiply(in Scalar b)
		{
			var (d0, d1, d2, d3, d4, d5, d6, d7) = this;
			Span<uint> l = stackalloc uint[16];
			mul_512(l, this, b);
			reduce_512(ref d0, ref d1, ref d2, ref d3, ref d4, ref d5, ref d6, ref d7, l);
			return new Scalar(d0, d1, d2, d3, d4, d5, d6, d7);
		}

		public readonly Scalar Negate()
		{
			uint d0, d1, d2, d3, d4, d5, d6, d7;
			ref readonly Scalar a = ref this;
			uint nonzero = 0xFFFFFFFFU * (a.IsZero ? 0U : 1);
			ulong t = (ulong)(~a.d0) + SECP256K1_N_0 + 1;
			d0 = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d1) + SECP256K1_N_1;
			d1 = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d2) + SECP256K1_N_2;
			d2 = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d3) + SECP256K1_N_3;
			d3 = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d4) + SECP256K1_N_4;
			d4 = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d5) + SECP256K1_N_5;
			d5 = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d6) + SECP256K1_N_6;
			d6 = (uint)(t & nonzero); t >>= 32;
			t += (ulong)(~a.d7) + SECP256K1_N_7;
			d7 = (uint)(t & nonzero);
			return new Scalar(d0, d1, d2, d3, d4, d5, d6, d7);
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
	}
}
