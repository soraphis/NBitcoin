using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Text;

namespace NBitcoin.Secp256k1
{
	class ECPrivKey : IDisposable
	{
		Scalar sec;
		readonly Context ctx;

		public static bool TryCreateFromDer(ReadOnlySpan<byte> privkey, Context ctx, out ECPrivKey result)
		{
			result = null;
			Span<byte> out32 = stackalloc byte[32];
			int lenb = 0;
			int len = 0;
			out32.Fill(0);
			/* sequence header */
			if (privkey.Length < 1 || privkey[0] != 0x30)
			{
				return false;
			}
			privkey = privkey.Slice(1);
			/* sequence length constructor */
			if (privkey.Length < 1 || (privkey[0] & 0x80) == 0)
			{
				return false;
			}
			lenb = privkey[0] & ~0x80;
			privkey = privkey.Slice(1);
			if (lenb < 1 || lenb > 2)
			{
				return false;
			}
			if (privkey.Length < lenb)
			{
				return false;
			}
			/* sequence length */
			len = privkey[lenb - 1] | (lenb > 1 ? privkey[lenb - 2] << 8 : 0);
			privkey = privkey.Slice(lenb);
			if (privkey.Length < len)
			{
				return false;
			}
			/* sequence element 0: version number (=1) */
			if (privkey.Length < 3 || privkey[0] != 0x02 || privkey[1] != 0x01 || privkey[2] != 0x01)
			{
				return false;
			}
			privkey = privkey.Slice(3);
			/* sequence element 1: octet string, up to 32 bytes */
			if (privkey.Length < 2 || privkey[0] != 0x04 || privkey[1] > 0x20 || privkey.Length < 2 + privkey[1])
			{
				return false;
			}
			privkey.Slice(2, privkey[1]).CopyTo(out32.Slice(32 - privkey[1]));
			var s = new Scalar(out32);
			if (!Scalar.IsValid(s))
			{
				out32.Fill(0);
				result.Clear();
				result = null;
				return false;
			}
			result = new ECPrivKey(s, ctx);
			return true;
		}

		public void Clear()
		{
			sec = default;
		}
		public ECPrivKey(in Scalar scalar, Context ctx)
		{
			if (scalar.IsZero || scalar.IsOverflow)
				throw new ArgumentException(paramName: nameof(scalar), message: "Invalid privkey");
			sec = scalar;
			this.ctx = ctx ?? Context.Instance;
		}
		public ECPrivKey(ReadOnlySpan<byte> b32, Context ctx)
		{
			if (b32.Length != 32)
				throw new ArgumentException(paramName: nameof(b32), message: "b32 should be of length 32");
			sec = new Scalar(b32, out int overflow);
			if (overflow != 0 || sec.IsZero)
				throw new ArgumentException(paramName: nameof(b32), message: "Invalid privkey");
			this.ctx = ctx ?? Context.Instance;
		}

		private static InvalidOperationException InvalidECPrivKeyException()
		{
			return new InvalidOperationException("Invalid ECPrivKey");
		}

		public ECPubKey CreatePubKey()
		{
			GroupElementJacobian pj;
			GroupElement p;
			ECPubKey pubKey = null;
			ctx.ECMultiplicationGeneratorContext.secp256k1_ecmult_gen(out pj, sec);
			p = pj.ToGroupElement();
			pubKey = new ECPubKey(p, ctx);
			return pubKey;
		}

		public ECPrivKey TryAddTweak(ReadOnlySpan<byte> tweak)
		{
			if (TryAddTweak(tweak, out var r))
				return r;
			throw new ArgumentException(paramName: nameof(tweak), message: "Invalid tweak");
		}
		public bool TryAddTweak(ReadOnlySpan<byte> tweak, out ECPrivKey tweakedPrivKey)
		{
			tweakedPrivKey = null;
			if (tweak.Length < 32)
				return false;
			Scalar term;
			ECPrivKey seckey;
			bool ret;
			int overflow = 0;
			term = new Scalar(tweak, out overflow);

			Scalar sec = this.sec;
			ret = overflow == 0 && secp256k1_eckey_privkey_tweak_add(ref sec, term);
			if (ret)
			{
				seckey = new ECPrivKey(sec, ctx);
				tweakedPrivKey = seckey;
			}
			sec = default;
			term = default;
			return ret;
		}

		private bool secp256k1_eckey_privkey_tweak_add(ref Scalar key, in Scalar tweak)
		{
			key += tweak;
			return !key.IsZero;
		}

		public void WriteDerToSpan(bool compressed, Span<byte> derOutput, out int length)
		{
			ECPubKey pubkey = CreatePubKey();
			if (compressed)
			{
				Span<byte> begin = stackalloc byte[] { 0x30,0x81,0xD3,0x02,0x01,0x01,0x04,0x20 };
				Span<byte> middle = stackalloc byte[] {
			0xA0,0x81,0x85,0x30,0x81,0x82,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
			0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
			0x21,0x02,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
			0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
			0x17,0x98,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
			0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x24,0x03,0x22,0x00
				};
				var ptr = derOutput;
				begin.CopyTo(ptr);
				ptr = ptr.Slice(begin.Length);
				sec.WriteToSpan(ptr);
				ptr = ptr.Slice(32);
				middle.CopyTo(ptr);
				ptr = ptr.Slice(middle.Length);
				pubkey.WriteToSpan(true, ptr, out var lenptr);
				length = begin.Length + 32 + middle.Length + lenptr;
			}
			else
			{
				Span<byte> begin = stackalloc byte[]{ 0x30,0x82,0x01,0x13,0x02,0x01,0x01,0x04,0x20 };
				Span<byte> middle = stackalloc byte[]{
			 0xA0,0x81,0xA5,0x30,0x81,0xA2,0x02,0x01,0x01,0x30,0x2C,0x06,0x07,0x2A,0x86,0x48,
            0xCE,0x3D,0x01,0x01,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFE,0xFF,0xFF,0xFC,0x2F,0x30,0x06,0x04,0x01,0x00,0x04,0x01,0x07,0x04,
            0x41,0x04,0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,
            0x0B,0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
            0x17,0x98,0x48,0x3A,0xDA,0x77,0x26,0xA3,0xC4,0x65,0x5D,0xA4,0xFB,0xFC,0x0E,0x11,
            0x08,0xA8,0xFD,0x17,0xB4,0x48,0xA6,0x85,0x54,0x19,0x9C,0x47,0xD0,0x8F,0xFB,0x10,
            0xD4,0xB8,0x02,0x21,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
            0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,
            0x8C,0xD0,0x36,0x41,0x41,0x02,0x01,0x01,0xA1,0x44,0x03,0x42,0x00
				};
				var ptr = derOutput;
				begin.CopyTo(ptr);
				ptr = ptr.Slice(begin.Length);
				sec.WriteToSpan(ptr);
				ptr = ptr.Slice(32);
				middle.CopyTo(ptr);
				ptr = ptr.Slice(middle.Length);
				pubkey.WriteToSpan(false, ptr, out var lenptr);
				length = begin.Length + 32 + middle.Length + lenptr;
			}
		}


		public override bool Equals(object obj)
		{
			ECPrivKey item = obj as ECPrivKey;
			if (item == null)
				return false;
			return this == item;
		}
		public static bool operator ==(ECPrivKey a, ECPrivKey b)
		{
			if (a is ECPrivKey aa && b is ECPrivKey bb)
			{
				return aa.sec == bb.sec;
			}
			return a is null && b is null;
		}

		public static bool operator !=(ECPrivKey a, ECPrivKey b)
		{
			return !(a == b);
		}

		public override int GetHashCode()
		{
			return sec.GetHashCode();
		}

		public ECPrivKey MultTweak(ReadOnlySpan<byte> tweak)
		{
			if (TryMultTweak(tweak, out var r))
				return r;
			throw new ArgumentException(paramName: nameof(tweak), message: "Invalid tweak");
		}

		public bool TryMultTweak(ReadOnlySpan<byte> tweak, out ECPrivKey tweakedPrivkey)
		{
			tweakedPrivkey = null;
			if (tweak.Length < 32)
				return false;
			Scalar factor;
			bool ret = false;
			int overflow = 0;
			factor = new Scalar(tweak, out overflow);
			var sec = this.sec;
			ret = overflow == 0 && secp256k1_eckey_privkey_tweak_mul(ref sec, factor);
			if (ret)
			{
				tweakedPrivkey =  new ECPrivKey(sec, ctx);
			}
			sec = default;
			factor = default;
			return ret;
		}

		private bool secp256k1_eckey_privkey_tweak_mul(ref Scalar key, in Scalar tweak)
		{
			if (tweak.IsZero)
				return false;
			key *= tweak;
			return true;
		}

		public void Dispose()
		{
			Clear();
		}
	}
}
