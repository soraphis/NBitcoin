using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	public readonly struct FieldElementStorage
	{
		readonly uint n0, n1, n2, n3, n4, n5, n6, n7;

		public FieldElementStorage(uint n0, uint n1, uint n2, uint n3, uint n4, uint n5, uint n6, uint n7)
		{
			this.n0 = n0;
			this.n1 = n1;
			this.n2 = n2;
			this.n3 = n3;
			this.n4 = n4;
			this.n5 = n5;
			this.n6 = n6;
			this.n7 = n7;
		}

		public readonly FieldElement ToFieldElement()
		{
			ref readonly FieldElementStorage a = ref this;
			uint n0, n1, n2, n3, n4, n5, n6, n7, n8, n9;
			int magnitude;
			bool normalized;
			n0 = a.n0 & 0x3FFFFFFU;
			n1 = a.n0 >> 26 | ((a.n1 << 6) & 0x3FFFFFFU);
			n2 = a.n1 >> 20 | ((a.n2 << 12) & 0x3FFFFFFU);
			n3 = a.n2 >> 14 | ((a.n3 << 18) & 0x3FFFFFFU);
			n4 = a.n3 >> 8 | ((a.n4 << 24) & 0x3FFFFFFU);
			n5 = (a.n4 >> 2) & 0x3FFFFFFU;
			n6 = a.n4 >> 28 | ((a.n5 << 4) & 0x3FFFFFFU);
			n7 = a.n5 >> 22 | ((a.n6 << 10) & 0x3FFFFFFU);
			n8 = a.n6 >> 16 | ((a.n7 << 16) & 0x3FFFFFFU);
			n9 = a.n7 >> 10;
			magnitude = 1;
			normalized = true;
			return new FieldElement(n0, n1, n2, n3, n4, n5, n6, n7, n8, n9, magnitude, normalized);
		}
		private static void VERIFY_CHECK(bool value)
		{
			if (!value)
				throw new InvalidOperationException("VERIFY_CHECK failed (bug in C# secp256k1)");
		}
	}
}
