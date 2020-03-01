using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	class ECPubKey
	{
		readonly GroupElement Q;
		readonly Context ctx;
		public ECPubKey(in GroupElement groupElement, Context context)
		{
			if (groupElement.IsInfinity)
			{
				throw new InvalidOperationException("A pubkey can't be an infinite group element");
			}
			var x = groupElement.x.NormalizeVariable();
			var y = groupElement.y.NormalizeVariable();
			Q = new GroupElement(x, y);
			this.ctx = context ?? Context.Instance;
		}

		public void WriteToSpan(bool compressed, Span<byte> output, out int length)
		{
			length = 0;
			var len = (compressed ? 33 : 65);
			if (output.Length < len)
				throw new ArgumentException(paramName: nameof(output), message: $"output should be at least {len} bytes");

			// We are already normalized, the constructor enforce it.
			// var elemx = Q.x.NormalizeVariable();
			// var elemy = Q.y.NormalizeVariable();

			Q.x.WriteToSpan(output.Slice(1));
			if (compressed)
			{
				length = 33;
				output[0] = Q.y.IsOdd ? EC.SECP256K1_TAG_PUBKEY_ODD : EC.SECP256K1_TAG_PUBKEY_EVEN;
			}
			else
			{
				length = 65;
				output[0] = EC.SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
				Q.y.WriteToSpan(output.Slice(33));
			}
		}

		public static bool TryCreate(ReadOnlySpan<byte> input, Context ctx, out ECPubKey pubkey)
		{
			GroupElement Q;
			pubkey = null;
			if (!EC.Pubkey_parse(input, out Q))
				return false;
			pubkey = new ECPubKey(Q, ctx);
			Q = default;
			return true;
		}
		public static bool TryCreateRawFormat(ReadOnlySpan<byte> input, Context ctx, out ECPubKey pubkey)
		{
			if (input.Length != 64)
			{
				pubkey = default;
				return false;
			}
			if (FieldElement.TryCreate(input.Slice(0, 32), out var x) &&
				FieldElement.TryCreate(input.Slice(32), out var y))
			{
				pubkey = new ECPubKey(new GroupElement(x, y), ctx);
				return true;
			}
			pubkey = default;
			return false;
		}

		public ECPubKey Negate()
		{
			return new ECPubKey(Q.Negate(), ctx);
		}


		public override bool Equals(object obj)
		{
			ECPubKey item = obj as ECPubKey;
			if (item == null)
				return false;
			return this == item;
		}
		public static bool operator ==(ECPubKey a, ECPubKey b)
		{
			if (a is ECPubKey aa && b is ECPubKey bb)
			{
				// Need to be constant time so no &&
				return aa.Q.x == bb.Q.x & aa.Q.y == bb.Q.y;
			}
			return a is null && b is null;
		}

		public static bool operator !=(ECPubKey a, ECPubKey b)
		{
			return !(a == b);
		}

		public override int GetHashCode()
		{
			unchecked
			{
				int hash = 17;
				hash = hash * 23 + Q.x.GetHashCode();
				hash = hash * 23 + Q.y.GetHashCode();
				return hash;
			}
		}

		public ECPubKey AddTweak(ReadOnlySpan<byte> tweak)
		{
			if (TryAddTweak(tweak, out var r))
				return r;
			throw new ArgumentException(paramName: nameof(tweak), message: "Invalid tweak");
		}
		public bool TryAddTweak(ReadOnlySpan<byte> tweak, out ECPubKey tweakedPubKey)
		{
			tweakedPubKey = null;
			if (tweak.Length < 32)
				return false;
			Scalar term;
			bool ret = false;
			int overflow = 0;
			term = new Scalar(tweak, out overflow);
			ret = overflow == 0;
			var p = Q;
			if (ret)
			{
				if (secp256k1_eckey_pubkey_tweak_add(ctx.ECMultiplicationContext, ref p, term))
				{
					tweakedPubKey = new ECPubKey(p, ctx);
				}
				else
				{
					ret = false;
				}
			}
			return ret;
		}

		private bool secp256k1_eckey_pubkey_tweak_add(ECMultiplicationContext ctx, ref GroupElement key, in Scalar tweak)
		{
			GroupElementJacobian pt;
			Scalar one;
			pt = key.ToGroupElementJacobian();
			one = Scalar.One;

			pt = ctx.ECMultiply(pt, one, tweak);

			if (pt.IsInfinity)
			{
				return false;
			}
			key = pt.ToGroupElement();
			return true;
		}

		public ECPubKey MultTweak(ReadOnlySpan<byte> tweak)
		{
			if (TryMultTweak(tweak, out var r))
				return r;
			throw new ArgumentException(paramName: nameof(tweak), message: "Invalid tweak");
		}
		public bool TryMultTweak(ReadOnlySpan<byte> tweak, out ECPubKey tweakedPubKey)
		{
			tweakedPubKey = null;
			if (tweak.Length < 32)
				return false;
			Scalar factor;
			bool ret = false;
			int overflow = 0;

			factor = new Scalar(tweak, out overflow);
			ret = overflow == 0;
			var p = Q;
			if (ret)
			{
				if (secp256k1_eckey_pubkey_tweak_mul(ctx.ECMultiplicationContext, ref p, factor))
				{
					tweakedPubKey = new ECPubKey(p, ctx);
				}
				else
				{
					ret = false;
				}
			}

			return ret;
		}

		private static bool secp256k1_eckey_pubkey_tweak_mul(ECMultiplicationContext ctx, ref GroupElement key, in Scalar tweak)
		{
			Scalar zero;
			GroupElementJacobian pt;
			if (tweak.IsZero)
			{
				return false;
			}
			zero = Scalar.Zero;
			pt = key.ToGroupElementJacobian();
			pt = ctx.ECMultiply(pt, tweak, zero);
			key = pt.ToGroupElement();
			return true;
		}
	}
}
