using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	class Context
	{
		static readonly Lazy<Context> _Instance = new Lazy<Context>(CreateInstance, true);
		static Context CreateInstance()
		{
			return new Context();
		}
		public static Context Instance => _Instance.Value;

		public ECMultiplicationContext ECMultiplicationContext { get; }
		internal ECMultiplicationGeneratorContext ECMultiplicationGeneratorContext { get; }

		public Context() : this(null, null)
		{
			
		}
		public Context(ECMultiplicationContext ctx, ECMultiplicationGeneratorContext genCtx)
		{
			ECMultiplicationContext = ctx ?? ECMultiplicationContext.Instance;
			ECMultiplicationGeneratorContext = genCtx ?? ECMultiplicationGeneratorContext.Instance;
		}

		public ECPrivKey CreateECPrivKey(in Scalar scalar)
		{
			return new ECPrivKey(scalar, this);
		}
		public ECPrivKey CreateECPrivKey(ReadOnlySpan<byte> b32)
		{
			return new ECPrivKey(b32, this);
		}
		
		public bool TryCreatePubKey(ReadOnlySpan<byte> input, out ECPubKey pubkey)
		{
			return ECPubKey.TryCreate(input, this, out pubkey);
		}
		public bool TryCreatePrivKeyFromDer(ReadOnlySpan<byte> input, out ECPrivKey privkey)
		{
			return ECPrivKey.TryCreateFromDer(input, this, out privkey);
		}
	}
}
