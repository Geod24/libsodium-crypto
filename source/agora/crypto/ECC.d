/*******************************************************************************

    Elliptic-curve primitives

    Those primitives are used for Schnorr signatures.

    See_Also: https://en.wikipedia.org/wiki/EdDSA#Ed25519

    Copyright:
        Copyright (c) 2019-2021 BOS Platform Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.crypto.ECC;

import agora.crypto.Hash;
import agora.crypto.Types;

import geod24.bitblob;
import libsodium;

import std.format;

///
nothrow @nogc unittest
{
    const Scalar s1 = Scalar.random();
    const Scalar s2 = Scalar.random();
    const Scalar s3 = s1 + s2;

    assert(s3 - s1 == s2);
    assert(s3 - s2 == s1);
    assert(s3 - s3 == Scalar.init);
    assert(-s3 == -s1 - s2);
    assert(-s3 == -s2 - s1);

    Scalar s4 = s1;
    s4 += s2;
    assert(s4 == s3);
    s4 -= s1;
    assert(s4 == s2);

    const Scalar Zero = (s3 + (-s3));
    assert(Zero == Scalar.init);

    const Scalar One = (s3 + (~s3));
    assert(One * One == One);

    // Identity addition for Scalar
    assert(Zero + One == One);
    assert(One + Zero == One);

    // Get the generator
    const Point G = One.toPoint();
    assert(G + G == (One + One).toPoint());

    const Point p1 = s1.toPoint();
    const Point p2 = s2.toPoint();
    const Point p3 = s3.toPoint();

    assert(s1.toPoint() == p1);
    assert(p3 - p1 == p2);
    assert(p3 - p2 == p1);

    Point p4 = p1;
    p4 += p2;
    assert(p4 == p3);
    p4 -= p1;
    assert(p4 == p2);
    p4 *= s1;

    assert(s1 * p2 + s2 * p2 == s3 * p2);

    // Identity addition for Point
    const Point pZero = Point.init;

    assert(pZero + G == G);
    assert(G + pZero == G);
}

/// Contains a scalar and its projection on the elliptic curve (`v` and `v.G`)
public struct Pair
{
    /// A PRNGenerated number
    public Scalar v;
    /// v.G
    public Point V;

    /// Construct a Pair from a Scalar
    public static Pair fromScalar (in Scalar v) nothrow @nogc @safe
    {
        return Pair(v, v.toPoint());
    }

    /// Generate a random value `v` and a point on the curve `V` where `V = v.G`
    public static Pair random () nothrow @nogc @safe
    {
        return Pair.fromScalar(Scalar.random());
    }
}

// Test constructing Pair from scalar
unittest
{
    const Scalar s = Scalar.random();
    const pair1 = Pair(s, s.toPoint());
    const pair2 = Pair.fromScalar(s);
    assert(pair1 == pair2);
}

/*******************************************************************************

    A field element in the finite field of order 2^255-19

    Scalar are used as private key and source of noise for signatures.

*******************************************************************************/

public struct Scalar
{
    @safe:

    /// Internal state
    package BitBlob!(crypto_core_ed25519_SCALARBYTES) data;

    /***************************************************************************

        Print the scalar

        By default, this function prints the hidden version of the scalar.
        Changing the mode to `Clear` makes it print the original value.
        This mode is intended for debugging.

        Params:
          sink = The sink to write the piecemeal string data to
          mode = The `PrintMode` to use for printing the content.
                 By default, the hidden value is printed.

    ***************************************************************************/

    public void toString (scope void delegate(in char[]) @safe sink)
        const
    {
        FormatSpec!char spec;
        this.toString(sink, spec);
    }

    /// Ditto
    public void toString (scope void delegate(in char[]) @safe sink,
                          in FormatSpec!char spec) const
    {
        switch (spec.spec)
        {
        // Default to obfuscated print mode
        case 's':
        default:
            formattedWrite(sink, "**SCALAR**");
            break;

        // Clear text was explicitly requested
        case 'c':
            this.data.toString(sink);
            break;

        // Modes supported by BitBlob
        case 'x':
        case 'X':
            this.data.toString(sink, spec);
            break;
        }
    }

    /// Ditto
    public string toString (PrintMode mode = PrintMode.Obfuscated) const
    {
        string result;
        FormatSpec!char spec;
        spec.spec = (mode == PrintMode.Clear) ? 'c' : 's';
        this.toString((in data) { result ~= data; }, spec);
        return result;
    }

    ///
    unittest
    {
        static immutable ClearText =
            "0x0e00a8df701806cb4deac9bb09cc85b097ee713e055b9d2bf1daf668b3f63778";

        auto s = Scalar(ClearText);

        assert(s.toString(PrintMode.Obfuscated) == "**SCALAR**");
        assert(s.toString(PrintMode.Clear) == ClearText);

        // Test default formatting behavior with writeln & format
        import std.format : format;
        assert(format("%s", s) == "**SCALAR**");
        assert(format("%q", s) == "**SCALAR**");
        assert(format("%c", s) == ClearText);
        assert(format("%x", s) == ClearText[2 .. $]);
    }

    /// Vibe.d deserialization
    public static Scalar fromString (in char[] str)
    {
        return Scalar(typeof(this.data).fromString(str));
    }

    nothrow @nogc:

    private this (typeof(this.data) data) inout pure
    {
        this.data = data;
    }

    /// Construct from its string representation or a fixed length array
    public this (T) (T param)
    {
        this.data = typeof(this.data)(param);
    }

    /// Construct from a dynamic array of the correct length
    public this (ubyte[data.sizeof] param) inout pure
    {
        this.data = param;
    }

    // test constructors
    unittest
    {
        const ubyte[32] fixed = [57, 34, 14, 84, 18, 175, 101, 64, 121, 181, 212, 78, 23, 148, 180, 7, 9, 105, 237, 155, 78, 161, 191, 27, 97, 130, 209, 44, 202, 245, 208, 13];
        const ubyte[34] fixed2 = [57, 34, 14, 84, 18, 175, 101, 64, 121, 181, 212, 78, 23, 148, 180, 7, 9, 105, 237, 155, 78, 161, 191, 27, 97, 130, 209, 44, 202, 245, 208, 13, 0, 0];
        const from_fixed_array = Scalar(fixed);
        const from_slice = Scalar(fixed2[0 .. 32]);
        const from_ubytes = Scalar([57, 34, 14, 84, 18, 175, 101, 64, 121, 181, 212, 78, 23, 148, 180, 7, 9, 105, 237, 155, 78, 161, 191, 27, 97, 130, 209, 44, 202, 245, 208, 13]);
        auto from_hex_str = Scalar("0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216");
    }

    /// Reduce the hash to a scalar
    public this (Hash param) @trusted
    {
        static assert(typeof(data).sizeof == 32);
        static assert(Hash.sizeof == 64);
        crypto_core_ed25519_scalar_reduce(this.data[].ptr, param[].ptr);
    }

    /// Operator overloads for `+`, `-`, `*`
    public Scalar opBinary (string op)(in Scalar rhs) const @trusted
    {
        // Point.init is Identity for functional operations
        if (this == Scalar.init)
            return rhs;
        if (rhs == Scalar.init)
            return this;
        Scalar result = void;
        static if (op == "+")
            crypto_core_ed25519_scalar_add(
                result.data[].ptr, this.data[].ptr, rhs.data[].ptr);
        else static if (op == "-")
            crypto_core_ed25519_scalar_sub(
                result.data[].ptr, this.data[].ptr, rhs.data[].ptr);
        else static if (op == "*")
            crypto_core_ed25519_scalar_mul(
                result.data[].ptr, this.data[].ptr, rhs.data[].ptr);
        else
            static assert(0, "Binary operator `" ~ op ~ "` not implemented");
        return result;
    }

    /// Operator overloads for `+=` & other supported binary operations
    public ref Scalar opOpAssign (string op)(in Scalar rhs) return @safe
    {
        this.data = this.opBinary!op(rhs).data;
        return this;
    }

    /// Get the complement of this scalar
    public Scalar opUnary (string s) () const @trusted
    {
        Scalar result = void;
        static if (s == "-")
            crypto_core_ed25519_scalar_negate(result.data[].ptr, this.data[].ptr);
        else static if (s == "~")
            crypto_core_ed25519_scalar_complement(result.data[].ptr, this.data[].ptr);
        else
            static assert(0, "Unary operator `" ~ op ~ "` not implemented");
        return result;
    }

    /***************************************************************************

        Returns:
            the inverted scalar.

        See_Also:
            https://libsodium.gitbook.io/doc/advanced/point-arithmetic
            https://tlu.tarilabs.com/cryptography/digital_signatures/introduction_schnorr_signatures.html#why-do-we-need-the-nonce

    ***************************************************************************/

    public Scalar invert () const @trusted
    {
        Scalar scalar = this;  // copy
        if (crypto_core_ed25519_scalar_invert(scalar.data[].ptr, this.data[].ptr) != 0)
            assert(0);
        return scalar;
    }

    /// Generate a random scalar
    public static Scalar random () @trusted
    {
        Scalar ret = void;
        crypto_core_ed25519_scalar_random(ret.data[].ptr);
        return ret;
    }

    /// Scalar should be greater than zero and less than L:2^252 + 27742317777372353535851937790883648493
    public bool isValid () const
    {
        const auto ED25519_L =  BitBlob!32("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");
        const auto ZERO =       BitBlob!32("0x0000000000000000000000000000000000000000000000000000000000000000");
        return this.data > ZERO && this.data < ED25519_L;
    }

    /// Return the point corresponding to this scalar multiplied by the generator
    public Point toPoint () const @trusted
    {
        Point ret = void;
        if (crypto_scalarmult_ed25519_base_noclamp(ret.data[].ptr, this.data[].ptr) != 0)
            assert(0, "Provided Scalar is not valid");
        if (!ret.isValid)
            assert(0, "libsodium generated invalid Point from valid Scalar!");
        return ret;
    }

    /// Convenience overload to allow this to be passed to libsodium & co
    public inout(ubyte)[] opSlice () inout return pure
    {
        return this.data[];
    }
}

// Test Scalar fromString / toString functions
@safe unittest
{
    static immutable string s = "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ec";
    assert(Scalar.fromString(s).toString(PrintMode.Clear) == s);
}

// Test valid Scalars
nothrow @nogc @safe unittest
{
    assert(Scalar(`0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ec`).isValid);
    assert(Scalar(`0x0eadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`).isValid);
    assert(Scalar(`0x0000000000000000000000000000000000000000000000000000000000000001`).isValid);
}

// Test invalid Scalars
nothrow @nogc @safe unittest
{
    assert(!Scalar().isValid);
    assert(!Scalar(`0x0000000000000000000000000000000000000000000000000000000000000000`).isValid);
    assert(!Scalar(`0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed`).isValid);
    assert(!Scalar(`0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`).isValid);
    assert(!Scalar(`0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff`).isValid);
}

/*******************************************************************************

    Represent a point on Curve25519

    A point is an element of the cyclic subgroup formed from the elliptic curve:
    x^2 + y^2 = 1 - (121665 / 1216666) * x^2 * y^2
    And the base point `B` where By=4/5 and Bx > 0.

*******************************************************************************/

public struct Point
{
    @safe:

    /// Internal state
    package BitBlob!(crypto_core_ed25519_BYTES) data;

    /// Expose `toString`
    public void toString (scope void delegate(in char[]) @safe dg)
        const
    {
        this.data.toString(dg);
    }

    /// Ditto
    public string toString () const
    {
        return this.data.toString();
    }

    /// Vibe.d deserialization
    public static Point fromString (in char[] str)
    {
        return Point(typeof(this.data).fromString(str));
    }

    nothrow @nogc:

    private this (typeof(this.data) data) inout pure
    {
        this.data = data;
    }

    /// Construct from its string representation or a fixed length array
    public this (T) (T param)
    {
        this.data = typeof(this.data)(param);
    }

    /// Construct from a dynamic array of the correct length
    public this (ubyte[data.sizeof] param) inout pure
    {
        this.data = param;
    }

    // test constructors
    unittest
    {
        const ubyte[32] fixed = [204, 70, 146, 92, 85, 207, 248, 193, 36, 92, 220, 216, 252, 242, 170, 37, 89, 67, 175, 116, 170, 18, 89, 113, 241, 8, 132, 47, 250, 62, 184, 130];
        const ubyte[34] fixed2 = [204, 70, 146, 92, 85, 207, 248, 193, 36, 92, 220, 216, 252, 242, 170, 37, 89, 67, 175, 116, 170, 18, 89, 113, 241, 8, 132, 47, 250, 62, 184, 130, 0, 0];
        const from_fixed_array = Point(fixed);
        const from_slice = Point(fixed2[0 .. 32]);
        const from_ubytes = Point([204, 70, 146, 92, 85, 207, 248, 193, 36, 92, 220, 216, 252, 242, 170, 37, 89, 67, 175, 116, 170, 18, 89, 113, 241, 8, 132, 47, 250, 62, 184, 130]);
        auto from_hex_str = Point("0x921405afbfa97813293770efd55865c01055f39ad2a70f2b7a04ac043766a693");

    }

    /// Operator overloads for points additions
    public Point opBinary (string op)(in Point rhs) const @trusted
        if (op == "+" || op == "-")
    {
        // Point.init is Identity for functional operations
        if (this == Point.init)
            return rhs;
        if (rhs == Point.init)
            return this;
        Point result = void;
        static if (op == "+")
        {
            if (crypto_core_ed25519_add(
                    result.data[].ptr, this.data[].ptr, rhs.data[].ptr))
                assert(0);
        }
        else static if (op == "-")
        {
            if (crypto_core_ed25519_sub(
                    result.data[].ptr, this.data[].ptr, rhs.data[].ptr))
                assert(0);
        }
        else static assert(0, "Unhandled `" ~ op ~ "` operator for Point");
        return result;
    }

    /// Operator overloads for supported binary operations on points
    public ref Point opOpAssign (string op)(in Point rhs) return @safe
        if (op == "+" || op == "-")
    {
        this.data = this.opBinary!op(rhs).data;
        return this;
    }

    /// Operator overloads for scalar multiplication
    public Point opBinary (string op)(in Scalar rhs) const @trusted
        if (op == "*")
    {
        Point result = void;
        if (crypto_scalarmult_ed25519_noclamp(
                result.data[].ptr, rhs.data[].ptr, this.data[].ptr))
            assert(0);
        return result;
    }

    /// Ditto
    public Point opBinaryRight (string op)(in Scalar lhs) const @trusted
        if (op == "*")
    {
        Point result = void;
        if (crypto_scalarmult_ed25519_noclamp(
                result.data[].ptr, lhs.data[].ptr, this.data[].ptr))
            assert(0);
        return result;
    }

    /// Operator overloads for supported binary operations on Scalars
    public ref Point opOpAssign (string op)(in Scalar rhs) return @safe
        if (op == "*")
    {
        this.data = this.opBinary!op(rhs).data;
        return this;
    }

    /// Convenience overload to allow this to be passed to libsodium & co
    public inout(ubyte)[] opSlice () inout return pure
    {
        return this.data[];
    }

    /// Support for comparison
    public int opCmp (ref const typeof(this) s) const
    {
        return this.data.opCmp(s.data);
    }

    /// Support for comparison (rvalue overload)
    public int opCmp (const typeof(this) s) const
    {
        return this.data.opCmp(s.data);
    }

    // Validation that it is a valid point using libsodium
    public bool isValid () const @trusted
    {
        return (crypto_core_ed25519_is_valid_point(this.data[].ptr) == 1);
    }
}

// Test sorting (`opCmp`)
unittest
{
    Point[] points = [
        Point.fromString(
            "0x44404b654d6ddf71e2446eada6acd1f462348b1b17272ff8f36dda3248e08c81"),
        Point.fromString(
            "0x37e8a197247dd01cc27c178dc0465ce826b4f6e312f3ee4c1df0623ef38c51c5")];

    import std.algorithm : sort;
    points.sort;
    assert(points[0] == Point.fromString(
            "0x37e8a197247dd01cc27c178dc0465ce826b4f6e312f3ee4c1df0623ef38c51c5"));
}

// Test validation
unittest
{
    auto valid = Point.fromString("0xab4f6f6e85b8d0d38f5d5798a4bdc4dd444c8909c8a5389d3bb209a18610511b");
    assert(valid.isValid());

    // Add 1 to last byte of valid serialized Point to make it invalid
    auto invalid = Point.fromString("0xab4f6f6e85b8d0d38f5d5798a4bdc4dd444c8909c8a5389d3bb209a18610511c");
    assert(!invalid.isValid());

    // Test initialized with no data is invalid
    auto invalid2 = Point.init;
    assert(!invalid2.isValid());
}
