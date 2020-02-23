using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	readonly struct GroupElementStorage
	{
		internal readonly FieldElementStorage x;
		internal readonly FieldElementStorage y;
		public GroupElementStorage(in FieldElement x, in FieldElement y)
		{
			this.x = x.Normalize().ToStorage();
			this.y = y.Normalize().ToStorage();
		}
		public GroupElementStorage(in FieldElementStorage x, in FieldElementStorage y)
		{
			this.x = x;
			this.y = y;
		}

		public readonly GroupElement ToGroupElement()
		{
			return new GroupElement(this.x.ToFieldElement(), this.y.ToFieldElement(), false);
		}
	}
}
