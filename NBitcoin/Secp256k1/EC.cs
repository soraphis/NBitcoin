using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	static class EC
	{
		public static readonly GroupElement G = GroupElement.SECP256K1_GE_CONST(
			0x79BE667EU, 0xF9DCBBACU, 0x55A06295U, 0xCE870B07U,
			0x029BFCDBU, 0x2DCE28D9U, 0x59F2815BU, 0x16F81798U,
			0x483ADA77U, 0x26A3C465U, 0x5DA4FBFCU, 0x0E1108A8U,
			0xFD17B448U, 0xA6855419U, 0x9C47D08FU, 0xFB10D4B8U
		);
	}
}
