using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	class ECPubKey
	{
		byte[] _data;
		Context ctx;
		public ECPubKey(Context context)
		{
			if (context == null)
				throw new ArgumentNullException(nameof(context));
			_data = new byte[64];
			this.ctx = context ?? Context.Instance;
		}
		public ECPubKey(Span<byte> data, Context context)
		{
			if (data.Length != 64)
				throw new ArgumentException(paramName: nameof(data), message: "data should be of length 64");
			_data = new byte[64];
			this.ctx = context ?? Context.Instance;
			data.CopyTo(_data);
		}
		public ECPubKey(in GroupElement groupElement, Context context)
		{
			if (groupElement.IsInfinity)
			{
				throw new InvalidOperationException("A pubkey can't be an infinite group element");
			}
			var x = groupElement.x.NormalizeVariable();
			var y = groupElement.y.NormalizeVariable();
			_data = new byte[64];
			this.ctx = context ?? Context.Instance;
			var datas = _data.AsSpan();
			x.WriteToSpan(datas);
			y.WriteToSpan(datas.Slice(32));
		}

		// secp256k1_pubkey_load
		public bool TryLoad(out GroupElement groupElement)
		{
			/* Otherwise, fall back to 32-byte big endian for X and Y. */
			FieldElement x, y;
			var datas = _data.AsSpan();
			if (FieldElement.TryCreate(datas.Slice(0, 32), out x) &&
				FieldElement.TryCreate(datas.Slice(32), out y))
			{
				groupElement = new GroupElement(x, y);
				return true;
			}
			groupElement = default;
			return false;

		}

		public void WriteToSpan(bool compressed, Span<byte> output, out int length)
		{
			GroupElement Q;
			length = 0;
			var len = (compressed ? 33 : 65);
			if (output.Length < len)
				throw new ArgumentException(paramName: nameof(output), message: $"output should be at least {len} bytes");
			if (TryLoad(out Q))
			{
				if (Q.IsInfinity)
				{
					throw InvalidECPubKeyException();
				}
				var elemx = Q.x.NormalizeVariable();
				var elemy = Q.y.NormalizeVariable();

				elemx.WriteToSpan(output.Slice(1));
				if (compressed)
				{
					length = 33;
					output[0] = elemy.IsOdd ? EC.SECP256K1_TAG_PUBKEY_ODD : EC.SECP256K1_TAG_PUBKEY_EVEN;
				}
				else
				{
					length = 65;
					output[0] = EC.SECP256K1_TAG_PUBKEY_UNCOMPRESSED;
					elemy.WriteToSpan(output.Slice(33));
				}
			}
			else
			{
				throw InvalidECPubKeyException();
			}
		}

		private static InvalidOperationException InvalidECPubKeyException()
		{
			return new InvalidOperationException("Invalid ECPubKey");
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

		public ECPubKey Negate()
		{
			if (!this.TryLoad(out var Q))
				return null;
			Q = Q.Negate();
			return new ECPubKey(Q, ctx);
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
				bool ret = true;
				for (int i = 0; i < 64; i++)
				{
					ret &= aa._data[i] == bb._data[i];
				}
				return ret;
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
				for (int i = 0; i < 64; i++)
				{
					hash = hash * 23 + _data[i];
				}
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
			GroupElement p;
			Scalar term;
			bool ret = false;
			int overflow = 0;
			term = new Scalar(tweak, out overflow);
			ret = overflow == 0;
			if (ret)
			{
				if (TryLoad(out p) && secp256k1_eckey_pubkey_tweak_add(ctx.ECMultiplicationContext, ref p, term))
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
			GroupElement p;
			Scalar factor;
			bool ret = false;
			int overflow = 0;

			factor = new Scalar(tweak, out overflow);
			ret = overflow == 0;
			if (ret)
			{
				if (TryLoad(out p) && secp256k1_eckey_pubkey_tweak_mul(ctx.ECMultiplicationContext, ref p, factor))
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
