﻿using System;
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
		public static readonly Scalar N = new Scalar(Scalar.SECP256K1_N_0, Scalar.SECP256K1_N_1, Scalar.SECP256K1_N_2, Scalar.SECP256K1_N_3, Scalar.SECP256K1_N_4, Scalar.SECP256K1_N_5, Scalar.SECP256K1_N_6, Scalar.SECP256K1_N_7);
		public static readonly Scalar NC = new Scalar(Scalar.SECP256K1_N_C_0, Scalar.SECP256K1_N_C_1, Scalar.SECP256K1_N_C_2, Scalar.SECP256K1_N_C_3, Scalar.SECP256K1_N_C_4, 0, 0, 0);
		public const uint CURVE_B = 7;
		/** Prefix byte used to tag various encoded curvepoints for specific purposes */
		public const byte SECP256K1_TAG_PUBKEY_EVEN = 0x02;
		public const byte SECP256K1_TAG_PUBKEY_ODD = 0x03;
		public const byte SECP256K1_TAG_PUBKEY_UNCOMPRESSED = 0x04;
		public const byte SECP256K1_TAG_PUBKEY_HYBRID_EVEN = 0x06;
		public const byte SECP256K1_TAG_PUBKEY_HYBRID_ODD = 0x07;

		public static bool Pubkey_parse(ReadOnlySpan<byte> pub, out GroupElement elem)
		{
			elem = default;
			if (pub.Length == 33 && (pub[0] == SECP256K1_TAG_PUBKEY_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_ODD))
			{
				return
					FieldElement.TryCreate(pub.Slice(1), out var x) &&
					GroupElement.TryCreateXOVariable(x, pub[0] == SECP256K1_TAG_PUBKEY_ODD, out elem);
			}
			else if (pub.Length == 65 && (pub[0] == SECP256K1_TAG_PUBKEY_UNCOMPRESSED || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD))
			{
				if (!FieldElement.TryCreate(pub.Slice(1), out var x) || !FieldElement.TryCreate(pub.Slice(33), out var y))
				{
					return false;
				}
				elem = new GroupElement(x, y);
				if ((pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_EVEN || pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD) &&
					y.IsOdd != (pub[0] == SECP256K1_TAG_PUBKEY_HYBRID_ODD))
				{
					return false;
				}
				return elem.IsValidVariable;
			}
			else
			{
				return false;
			}
		}

	}
}
