using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Text;

namespace NBitcoin.Secp256k1
{
	public readonly struct GroupElement
	{
		internal readonly FieldElement x;
		internal readonly FieldElement y;
		internal readonly bool infinity; /* whether this represents the point at infinity */
		static readonly GroupElement _Infinity = new GroupElement(FieldElement.Zero, FieldElement.Zero, true);
		public static ref readonly GroupElement Infinity => ref _Infinity;
		public readonly bool IsInfinity
		{
			get
			{
				return infinity;
			}
		}

		static readonly GroupElement _Zero = new GroupElement(FieldElement.Zero, FieldElement.Zero, false);
		public static ref readonly GroupElement Zero => ref _Zero;

		public bool IsValidVariable
		{
			get
			{
				FieldElement y2, x3, c;
				if (infinity)
				{
					return false;
				}
				/* y^2 = x^3 + 7 */
				y2 = y.Sqr();
				x3 = x.Sqr();
				x3 = x3 * x;
				c = new FieldElement(FieldElement.CURVE_B);
				x3 += c;
				x3 = x3.NormalizeWeak();
				return y2.EqualsVariable(x3);
			}
		}

		const int SIZE_MAX = int.MaxValue;
		public static void SetAllGroupElementJacobianVariable(GroupElement[] r, GroupElementJacobian[] a, int len)
		{
			FieldElement u;
			int i;
			int last_i = SIZE_MAX;

			for (i = 0; i < len; i++)
			{
				if (!a[i].infinity)
				{
					/* Use destination's x coordinates as scratch space */
					if (last_i == SIZE_MAX)
					{
						r[i] = new GroupElement(a[i].z, r[i].y, r[i].infinity);
					}
					else
					{
						FieldElement rx = r[last_i].x * a[i].z;
						r[i] = new GroupElement(rx, r[i].y, r[i].infinity);
					}
					last_i = i;
				}
			}
			if (last_i == SIZE_MAX)
			{
				return;
			}
			u = r[last_i].x.InverseVariable();

			i = last_i;
			while (i > 0)
			{
				i--;
				if (!a[i].infinity)
				{
					FieldElement rx = r[i].x * u;
					r[last_i] = new GroupElement(rx, r[last_i].y, r[last_i].infinity);
					u = u * a[last_i].z;
					last_i = i;
				}
			}
			VERIFY_CHECK(!a[last_i].infinity);
			r[last_i] = new GroupElement(u, r[last_i].y, r[last_i].infinity);

			for (i = 0; i < len; i++)
			{
				r[i] = new GroupElement(r[i].x, r[i].y, a[i].infinity);
				if (!a[i].infinity)
				{
					r[i] = a[i].ToGroupElementZInv(r[i].x);
				}
			}
		}

		[Conditional("SECP256K1_VERIFY")]
		private static void VERIFY_CHECK(bool value)
		{
			if (!value)
				throw new InvalidOperationException("VERIFY_CHECK failed (bug in C# secp256k1)");
		}

		public static bool TryCreateXQuad(FieldElement x, out GroupElement result)
		{
			result = GroupElement.Zero;
			FieldElement rx, ry;
			bool rinfinity;
			FieldElement x2, x3, c;
			rx = x;
			x2 = x.Sqr();
			x3 = x * x2;
			rinfinity = false;
			c = new FieldElement(FieldElement.CURVE_B);
			c += x3;
			if (!c.Sqrt(out ry))
				return false;
			result = new GroupElement(rx, ry, rinfinity);
			return true;
		}
		public static bool TryCreateXOVariable(FieldElement x, bool odd, out GroupElement result)
		{
			if (!TryCreateXQuad(x, out result))
				return false;
			var ry = result.y.NormalizeVariable();
			if (ry.IsOdd != odd)
			{
				ry = ry.Negate(1);
			}
			result = new GroupElement(result.x, ry, result.infinity);
			return true;
		}

		static readonly FieldElement beta = FieldElement.SECP256K1_FE_CONST(
	0x7ae96a2bu, 0x657c0710u, 0x6e64479eu, 0xac3434e9u,
	0x9cf04975u, 0x12f58995u, 0xc1396c28u, 0x719501eeu
		);
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public readonly GroupElement MultiplyLambda()
		{
			return new GroupElement(x * beta, y, infinity);
		}

		public GroupElement(in FieldElement x, in FieldElement y, bool infinity)
		{
			this.x = x;
			this.y = y;
			this.infinity = infinity;
		}
		public GroupElement(in FieldElement x, in FieldElement y)
		{
			this.x = x;
			this.y = y;
			this.infinity = false;
		}

		public readonly void Deconstruct(out FieldElement x, out FieldElement y, out bool infinity)
		{
			x = this.x;
			y = this.y;
			infinity = this.infinity;
		}

		public readonly GroupElement ZInv(in GroupElement a, in FieldElement zi)
		{
			var (x, y, infinity) = this;
			FieldElement zi2 = zi.Sqr();
			FieldElement zi3 = zi2 * zi;
			x = a.x * zi2;
			y = a.y * zi3;
			infinity = a.infinity;
			return new GroupElement(x, y, infinity);
		}

		[MethodImpl(MethodImplOptions.NoOptimization | MethodImplOptions.AggressiveInlining)]
		public readonly GroupElement NormalizeY()
		{
			return new GroupElement(x, this.y.Normalize(), infinity);
		}
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public readonly GroupElement NormalizeYVariable()
		{
			return new GroupElement(x, this.y.NormalizeVariable(), infinity);
		}

		public readonly GroupElement Negate()
		{
			var ry = y.NormalizeWeak();
			ry = ry.Negate(1);
			return new GroupElement(x, ry, infinity);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public readonly GroupElementJacobian ToGroupElementJacobian()
		{
			return new GroupElementJacobian(x, y, new FieldElement(1), infinity);
		}

		public readonly string ToC(string varName)
		{
			StringBuilder b = new StringBuilder();
			b.AppendLine(x.ToC($"{varName}x"));
			b.AppendLine(y.ToC($"{varName}y"));
			var infinitystr = infinity ? 1 : 0;
			b.AppendLine($"int {varName}infinity = {infinitystr};");
			b.AppendLine($"secp256k1_ge {varName} = {{ {varName}x, {varName}y, {varName}infinity }};");
			return b.ToString();
		}
	}
}
