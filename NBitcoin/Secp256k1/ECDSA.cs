using System;
using System.Collections.Generic;
using System.Text;

namespace NBitcoin.Secp256k1
{
	class ECDSA
	{
		static readonly Lazy<ECDSA> _Instance = new Lazy<ECDSA>(CreateInstance, true);
		static ECDSA CreateInstance()
		{
			return new ECDSA();
		}
		public static ECDSA Instance => _Instance.Value;

		/** Group order for secp256k1 defined as 'n' in "Standards for Efficient Cryptography" (SEC2) 2.7.1
 *  sage: for t in xrange(1023, -1, -1):
 *     ..   p = 2**256 - 2**32 - t
 *     ..   if p.is_prime():
 *     ..     print '%x'%p
 *     ..     break
 *   'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f'
 *  sage: a = 0
 *  sage: b = 7
 *  sage: F = FiniteField (p)
 *  sage: '%x' % (EllipticCurve ([F (a), F (b)]).order())
 *   'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'
 */
		private static readonly FieldElement order_as_fe = FieldElement.SECP256K1_FE_CONST(
			0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFEU,
			0xBAAEDCE6U, 0xAF48A03BU, 0xBFD25E8CU, 0xD0364141U
		);


		/** Difference between field and order, values 'p' and 'n' values defined in
 *  "Standards for Efficient Cryptography" (SEC2) 2.7.1.
 *  sage: p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
 *  sage: a = 0
 *  sage: b = 7
 *  sage: F = FiniteField (p)
 *  sage: '%x' % (p - EllipticCurve ([F (a), F (b)]).order())
 *   '14551231950b75fc4402da1722fc9baee'
 */
		private static readonly FieldElement p_minus_order = FieldElement.SECP256K1_FE_CONST(
			0, 0, 0, 1, 0x45512319U, 0x50B75FC4U, 0x402DA172U, 0x2FC9BAEEU
		);
		private readonly ECMultiplicationContext ctx;
		public ECDSA() : this(null)
		{

		}
		public ECDSA(ECMultiplicationContext ctx)
		{
			this.ctx = ctx ?? ECMultiplicationContext.Instance;
		}

		public bool SigVerify(in Scalar sigr, in Scalar sigs, in GroupElement pubkey, in Scalar message)
		{
			Span<byte> c = stackalloc byte[32];
			Scalar sn, u1, u2;
			FieldElement xr;
			GroupElementJacobian pubkeyj;
			GroupElementJacobian pr;

			if (sigr.IsZero || sigs.IsZero)
			{
				return false;
			}

			sn = sigs.InverseVariable();
			u1 = sn * message;
			u2 = sn * sigr;
			pubkeyj = pubkey.ToGroupElementJacobian();
			pr = ctx.ECMultiply(pubkeyj, u2, u1);
			if (pr.IsInfinity)
			{
				return false;
			}
			sigr.WriteToSpan(c);
			xr = new FieldElement(c);

			/* We now have the recomputed R point in pr, and its claimed x coordinate (modulo n)
			 *  in xr. Naively, we would extract the x coordinate from pr (requiring a inversion modulo p),
			 *  compute the remainder modulo n, and compare it to xr. However:
			 *
			 *        xr == X(pr) mod n
			 *    <=> exists h. (xr + h * n < p && xr + h * n == X(pr))
			 *    [Since 2 * n > p, h can only be 0 or 1]
			 *    <=> (xr == X(pr)) || (xr + n < p && xr + n == X(pr))
			 *    [In Jacobian coordinates, X(pr) is pr.x / pr.z^2 mod p]
			 *    <=> (xr == pr.x / pr.z^2 mod p) || (xr + n < p && xr + n == pr.x / pr.z^2 mod p)
			 *    [Multiplying both sides of the equations by pr.z^2 mod p]
			 *    <=> (xr * pr.z^2 mod p == pr.x) || (xr + n < p && (xr + n) * pr.z^2 mod p == pr.x)
			 *
			 *  Thus, we can avoid the inversion, but we have to check both cases separately.
			 *  secp256k1_gej_eq_x implements the (xr * pr.z^2 mod p == pr.x) test.
			 */
			if (xr.EqualsXVariable(pr))
			{
				/* xr * pr.z^2 mod p == pr.x, so the signature is valid. */
				return true;
			}
			if (xr.CompareToVariable(p_minus_order) >= 0)
			{
				/* xr + n >= p, so we can skip testing the second case. */
				return false;
			}
			xr += order_as_fe;
			if (xr.EqualsXVariable(pr))
			{
				/* (xr + n) * pr.z^2 mod p == pr.x, so the signature is valid. */
				return true;
			}
			return false;
		}

		static int DerReadLen(ref ReadOnlySpan<byte> sig)
		{
			int lenleft, b1;
			int ret = 0;
			if (sig.Length == 0)
			{
				return -1;
			}
			b1 = sig[0];
			sig = sig.Slice(1);
			if (b1 == 0xFF)
			{
				/* X.690-0207 8.1.3.5.c the value 0xFF shall not be used. */
				return -1;
			}
			if ((b1 & 0x80) == 0)
			{
				/* X.690-0207 8.1.3.4 short form length octets */
				return b1;
			}
			if (b1 == 0x80)
			{
				/* Indefinite length is not allowed in DER. */
				return -1;
			}
			/* X.690-207 8.1.3.5 long form length octets */
			lenleft = b1 & 0x7F;
			if (lenleft > sig.Length)
			{
				return -1;
			}
			if (sig[0] == 0)
			{
				/* Not the shortest possible length encoding. */
				return -1;
			}
			if (lenleft > sizeof(uint))
			{
				/* The resulting length would exceed the range of a size_t, so
				 * certainly longer than the passed array size.
				 */
				return -1;
			}
			while (lenleft > 0)
			{
				ret = (ret << 8) | sig[0];
				if (ret + lenleft > sig.Length)
				{
					/* Result exceeds the length of the passed array. */
					return -1;
				}
				sig = sig.Slice(1);
				lenleft--;
			}
			if (ret < 128)
			{
				/* Not the shortest possible length encoding. */
				return -1;
			}
			return ret;
		}

		static bool DerParseInteger(out Scalar r, ref ReadOnlySpan<byte> sig)
		{
			r = default;
			int overflow = 0;
			Span<byte> ra = stackalloc byte[32];
			int rlen;

			if (sig.Length == 0 || sig[0] != 0x02)
			{
				r = default;
				/* Not a primitive integer (X.690-0207 8.3.1). */
				return false;
			}
			sig = sig.Slice(1);
			rlen = DerReadLen(ref sig);
			if (rlen <= 0 || rlen > sig.Length)
			{
				/* Exceeds bounds or not at least length 1 (X.690-0207 8.3.1).  */
				return false;
			}
			if (sig[0] == 0x00 && rlen > 1 && ((sig[1]) & 0x80) == 0x00)
			{
				/* Excessive 0x00 padding. */
				return false;
			}
			if (sig[0] == 0xFF && rlen > 1 && ((sig[1]) & 0x80) == 0x80)
			{
				/* Excessive 0xFF padding. */
				return false;
			}
			if ((sig[0] & 0x80) == 0x80)
			{
				/* Negative. */
				overflow = 1;
			}
			while (rlen > 0 && sig[0] == 0)
			{
				/* Skip leading zero bytes */
				rlen--;
				sig = sig.Slice(1);
			}
			if (rlen > 32)
			{
				overflow = 1;
			}
			if (overflow == 0)
			{
				sig.Slice(0, rlen).CopyTo(ra.Slice(32 - rlen));
				r = new Scalar(ra, out overflow);
			}

			if (overflow == 1)
			{
				r = new Scalar(0);
			}
			sig = sig.Slice(rlen);
			return true;
		}
		public static bool DerParseSigParse(out Scalar rr, out Scalar rs, ReadOnlySpan<byte> sig)
		{
			int rlen;
			rr = rs = default;
			if (sig.Length == 0 || sig[0] != 0x30)
			{
				/* The encoding doesn't start with a constructed sequence (X.690-0207 8.9.1). */
				return false;
			}
			sig = sig.Slice(1);
			rlen = DerReadLen(ref sig);
			if (rlen < 0 || rlen > sig.Length)
			{
				/* Tuple exceeds bounds */
				return false;
			}
			if (rlen != sig.Length)
			{
				/* Garbage after tuple. */
				return false;
			}

			if (!DerParseInteger(out rr, ref sig))
			{
				return false;
			}
			if (!DerParseInteger(out rs, ref sig))
			{
				return false;
			}

			if (sig.Length != 0)
			{
				/* Trailing garbage inside tuple. */
				return false;
			}

			return true;
		}
	}
}
