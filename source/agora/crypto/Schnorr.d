/*******************************************************************************

    Low level utilities to perform Schnorr signatures on Curve25519.

    Through this module, lowercase letters represent scalars and uppercase
    letters represent points. Multiplication of a scalar by a point,
    which is adding a point to itself multiple times, is represented with '*',
    e.g. `a * G`. Uppercase letters are point representations of scalars,
    that is, the scalar multipled by the generator, e.g. `r == r * G`.
    `x` is the private key, `X` is the public key, and `H()` is the Blake2b
    512 bits hash reduced to a scalar in the field.

    Following the Schnorr BIP (see links), signatures are of the form
    `(R,s)` and satisfy `s * G = R + H(X || R || m) * X`.
    `r` is refered to as the nonce and is a cryptographically randomly
    generated number that should neither be reused nor leaked.

    Signature_Aggregation:
    Since Schnorr signatures use a linear equation, they can be simply
    combined with addition, enabling `O(1)` signature verification
    time and `O(1)` and `O(1)` signature size.
    Additionally, since the `c` factor does not depend on EC operation,
    we can do batch verification, enabling us to speed up verification
    when verifying large amount of data (e.g. a block).

    See_Also:
      - https://en.wikipedia.org/wiki/Curve25519
      - https://en.wikipedia.org/wiki/Schnorr_signature
      - https://medium.com/blockstream/reducing-bitcoin-transaction-sizes-with-x-only-pubkeys-f86476af05d7

    TODO:
      - Audit GDC and LDC generated code
      - Proper audit

    Copyright:
        Copyright (c) 2019-2021 BOS Platform Foundation
        All rights reserved.

    License:
        MIT License. See LICENSE for details.

*******************************************************************************/

module agora.crypto.Schnorr;

import agora.crypto.Types;
import agora.crypto.Hash;
import agora.crypto.ECC;

import std.algorithm;
import std.format;
import std.range;


/// Single signature example
nothrow @nogc @safe unittest
{
    Pair kp = Pair.random();
    auto signature = sign(kp, "Hello world");
    assert(verify(kp.V, signature, "Hello world"));
}

/// Multi-signature example where all must sign
nothrow @nogc @safe unittest
{
    // Setup
    static immutable string secret = "BOSAGORA for the win";
    Pair kp1 = Pair.random();
    Pair kp2 = Pair.random();
    Pair R1 = Pair.random();
    Pair R2 = Pair.random();
    Point R = R1.V + R2.V;
    Point X = kp1.V + kp2.V;

    const sig1 = sign(kp1.v, X, R, R1.v, secret);
    const sig2 = sign(kp2.v, X, R, R2.v, secret);
    const sig3 = Signature(R, sig1.s + sig2.s);

    // No one can verify any of those individually
    assert(!verify(kp1.V, sig1, secret));
    assert(!verify(kp1.V, sig2, secret));
    assert(!verify(kp2.V, sig2, secret));
    assert(!verify(kp2.V, sig1, secret));
    assert(!verify(kp1.V, sig3, secret));
    assert(!verify(kp2.V, sig3, secret));

    // But multisig works
    assert(verify(X, sig3, secret));
}

///
@safe @nogc nothrow /*pure*/ unittest
{
    const R = Pair.random();
    const kp = Pair.random();
    const sig = sign(kp.v, kp.V, R.V, R.v, "foo");
    assert(sig.R == R.V);
}

/// Represent a schnorr signature (R, s)
public struct Signature
{
    @safe:

    /// Commitment
    public Point R;
    /// Proof
    public Scalar s;

    /***************************************************************************

        Print the signature in a human-readable representation

        This prints the signature as a lowercase hexadecimal string,
        which starts with `0x` and is the hex string of the point followed by
        the hex string of the scalar.

    ***************************************************************************/

    public void toString (scope void delegate(in char[]) @safe sink) const
    {
        this.R.data.toString(sink);
        FormatSpec!char spec;
        spec.spec = 'x';
        this.s.data.toString(sink, spec);
    }

    /// Ditto
    public string toString () const
    {
        string result;
        this.toString((in data) { result ~= data; });
        return result;
    }

    ///
    unittest
    {
        const signature = Signature(
            Point("0x921405afbfa97813293770efd55865c01055f39ad2a70f2b7a04ac043766a693"),
            Scalar("0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216"));
        assert(signature.toString() == "0x921405afbfa97813293770efd55865c01055f39ad2a70f2b7a04ac043766a693074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216", signature.toString());
    }

    /// construct from Point and Scalar
    public this (in Point R, in Scalar s) pure nothrow @nogc
    {
        this.R = R;
        this.s = s;
    }

    /// Construct from a dynamic array of the correct length
    public this (in ubyte[Signature.sizeof] param) inout pure nothrow @nogc
    {
        this.R = param[0 .. param.sizeof / 2];
        this.s = param[param.sizeof / 2 .. param.sizeof];
    }

    /// construct from hex string
    static Signature fromString (scope const(char)[] hex_str) pure
    {
        import geod24.bitblob;

        // the bytes are little endian
        const bytes = BitBlob!(Signature.sizeof).fromString(hex_str);
        const Scalar s = bytes[0 .. Scalar.sizeof];
        const Point R = bytes[Scalar.sizeof .. $];
        return Signature(R, s);
    }

    ///
    pure unittest
    {
        const sig = Signature(
            Point("0x921405afbfa97813293770efd55865c01055f39ad2a70f2b7a04ac043766a693"),
            Scalar("0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216"));
        const signature = Signature.fromString("0x921405afbfa97813293770efd55865c01055f39ad2a70f2b7a04ac043766a693074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216");
        assert(sig == signature);
    }
}

unittest
{
    import libsodium: crypto_sign_ed25519_BYTES;
    static assert(Signature.sizeof == crypto_sign_ed25519_BYTES);
}

/// Represent the message to hash (part of `c`)
private struct Message (T)
{
    public Point X;
    public Point R;
    public T     message;
}

/// Single-signer trivial API
public Signature sign (T) (in Pair kp, in T data)
{
    const R = Pair.random();
    return sign!T(kp.v, kp.V, R.V, R.v, data);
}

/// Single-signer privkey API
public Signature sign (T) (in Scalar privateKey, in T data)
{
    const R = Pair.random();
    return sign!T(privateKey, privateKey.toPoint(), R.V, R.v, data);
}

/// Sign with a given `r` (warning: `r` should never be reused with `x`)
public Signature sign (T) (in Pair kp, in Pair r, in T data)
{
    return sign!T(kp.v, kp.V, r.V, r.v, data);
}

/// Complex API, allow multisig (not including multisig threshold)
public Signature sign (T) (
    in Scalar x, in Point X, in Point R, in Scalar r, in T data)
{
    /*
      G := Generator point:
      15112221349535400772501151409588531511454012693041857206046113283949847762202,
      46316835694926478169428394003475163141307993866256225615783033603165251855960
      x := private key
      X := public key (x.G)
      r := random number
      R := commitment (r.G)
      c := Hash(X || R || message)

      Proof = (R, s)
      Signature/Verify: R + c*X == s.G
      Multisig:
      R = (r0 + r1 + rn).G == (R0 + R1 + Rn)
      X = (X0 + X1 + Xn)
      To get `c`, need to precommit `R`
     */
    // Compute the challenge and reduce the hash to a scalar
    const Scalar c = hashFull(const(Message!T)(X, R, data));
    return sign(x, R, r, c);
}

/// sign with prepared message hash `c` (used for multisig with threshold)
public Signature sign (in Scalar x, in Point R, in Scalar r, in Scalar c)
    nothrow @nogc @safe
{
    /*
      G := Generator point:
      15112221349535400772501151409588531511454012693041857206046113283949847762202,
      46316835694926478169428394003475163141307993866256225615783033603165251855960
      x := private key
      r := random noise private
      r := random noise p
      c := hashed message

      Proof = (R, s): R = r.G
      Signature/Verify: R + c*X == s.G
     */
    // Compute `s` part of the proof
    Scalar s = r + (c * x);
    return Signature(R, s);
}
/*******************************************************************************

    Verify that a signature matches the provided data

    Params:
      T = Type of data being signed
      X = The point corresponding to the public key
      sig = Signature to verify
      data = Data to sign (the hash will be signed)

    Returns:
      Whether or not the signature is valid for (X, s, data).

*******************************************************************************/

public bool verify (T) (in Point X, in Signature sig, in T data)
{
    // Compute the challenge and reduce the hash to a scalar
    Scalar c = hashFull(const(Message!T)(X, sig.R, data));
    return verify(sig, c, X);
}
/// verify with predefined message hash `c` (required for threshold multisig)
public bool verify (in Signature sig, in Scalar c, in Point X)
    nothrow @nogc @safe
{
    // First check if Scalar from signature is valid
    if (!sig.s.isValid())
        return false;
    // Now check that provided Point X is valid
    if (!X.isValid())
        return false;
    /// Compute `s.G`
    auto S = sig.s.toPoint();
    // Also check the Point R from the Signature
    if (!sig.R.isValid())
        return false;
    // Compute `R + c*X`
    Point RcX = sig.R + (c * X);
    return S == RcX;
}

// Valid signing test with valid scalar
nothrow @nogc @safe unittest
{
    Pair kp = Pair.fromScalar(Scalar(`0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216`));
    static immutable string message = "Bosagora:-)";
    auto signature = sign(kp, message);
    assert(verify(kp.V, signature, message));
}

// Valid with scalar value 1
nothrow @nogc @safe unittest
{
    Pair kp = Pair.fromScalar(Scalar(`0x0000000000000000000000000000000000000000000000000000000000000001`));
    static immutable string message = "Bosagora:-)";
    auto signature = sign(kp, message);
    assert(verify(kp.V, signature, message));
}

// Largest value for Scalar. One less than Ed25519 prime order l where l=2^252 + 27742317777372353535851937790883648493
nothrow @nogc @safe unittest
{
    Pair kp = Pair.fromScalar(Scalar(`0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ec`));
    static immutable string message = "Bosagora:-)";
    auto signature = sign(kp, message);
    assert(verify(kp.V, signature, message));
}

// Not valid with blank signature
nothrow @nogc @safe unittest
{
    Pair kp = Pair.fromScalar(Scalar(`0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216`));
    static immutable string message = "Bosagora:-)";
    Signature signature;
    assert(!verify(kp.V, signature, message));
}

nothrow @nogc @safe unittest
{
    static immutable string secret = "BOSAGORA for the win";
    Pair kp1 = Pair.random();
    Pair kp2 = Pair.random();
    auto sig1 = sign(kp1, secret);
    auto sig2 = sign(kp2, secret);
    assert(verify(kp1.V, sig1, secret));
    assert(!verify(kp1.V, sig2, secret));
    assert(verify(kp2.V, sig2, secret));
    assert(!verify(kp2.V, sig1, secret));
}

// invalid signing test with invalid Public Key Point X
nothrow @nogc @safe unittest
{
    Pair kp = Pair.fromScalar(Scalar(`0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216`));
    static immutable string message = "Bosagora:-)";
    auto signature = sign(kp, message);
    auto invalid = Point("0xab4f6f6e85b8d0d38f5d5798a4bdc4dd444c8909c8a5389d3bb209a18610511c");
    assert(!verify(invalid, signature, message));
    assert(verify(kp.V, signature, message));
}

// invalid signing test with invalid Point R in Signature
nothrow @nogc @safe unittest
{
    Pair kp = Pair.fromScalar(Scalar(`0x074360d5eab8e888df07d862c4fc845ebd10b6a6c530919d66221219bba50216`));
    static immutable string message = "Bosagora:-)";
    auto signature = sign(kp, message);
    Signature invalid_sig = Signature(Point("0xab4f6f6e85b8d0d38f5d5798a4bdc4dd444c8909c8a5389d3bb209a18610511c"),
        signature.s);
    assert(verify(kp.V, signature, message));
    assert(!verify(kp.V, invalid_sig, message));
}

// example of extracting the private key from an insecure signature scheme
// which did not include 'r' during the signing
// https://tlu.tarilabs.com/cryptography/digital_signatures/introduction_schnorr_signatures.html#why-do-we-need-the-nonce
/*@nogc*/ @safe unittest
{
    static immutable string message = "BOSAGORA for the win";

    Pair kp = Pair.random();  // key-pair
    Scalar c = hashFull(message);  // challenge
    Scalar s = (kp.v * c);  // signature

    // known public data of the node
    Point K = kp.V;

    // other nodes verify
    assert(s.toPoint() == K * c);

    // but the other node can also extract the private key!
    Scalar stolen_key = s * c.invert();
    assert(stolen_key == kp.v);
}

// possibly secure signature scheme (requires proving ownership of private key)
/*@nogc*/ @safe unittest
{
    static immutable string message = "BOSAGORA for the win";

    Pair kp = Pair.random();  // key-pair
    Pair Rp = Pair.random();  // (R, r), the public and private nonce
    Scalar c = hashFull(message);  // challenge
    Scalar s = Rp.v + (kp.v * c);  // signature

    // known public data of the node
    Point K = kp.V;
    Point R = Rp.V;

    // other nodes verify
    assert(s.toPoint() == R + (K * c));

    // other nodes cannot extract the private key, they don't know 'r'
    Scalar stolen_key = s * c.invert();
    assert(stolen_key != kp.v);
}

/// multi-sig combine
public Signature multiSigCombine (S)(S sigs) nothrow @nogc @safe
{
    static assert(isInputRange!S);
    Point sum_R = sigs.map!(x => x.R).sum(Point.init);
    Scalar sum_s = sigs.map!(x => x.s).sum(Scalar.init);
    return Signature(sum_R, sum_s);
}

/// testing multiSig for block signing
/*@nogc*/ @safe unittest
{
    static immutable string message = "BOSAGORA for the win";

    const Scalar data = hashFull(message);  // challenge

    // We have three potential signers with keyPair and Noise keyPair
    const kp1_X = Pair.random();
    const kp2_X = Pair.random();
    const kp3_X = Pair.random();

    const kp1_R = Pair.random();
    const kp2_R = Pair.random();
    const kp3_R = Pair.random();

    const Point sum_X = kp1_X.V + kp2_X.V + kp3_X.V;
    const Point sum_R = kp1_R.V + kp2_R.V + kp3_R.V;

    Scalar c = hashFull(const(Message!Scalar)(sum_X, sum_R, data));

    // first signer
    const Signature sig1 = sign(kp1_X.v, kp1_R.V, kp1_R.v, c);

    // second signer
    const Signature sig2 = sign(kp2_X.v, kp2_R.V, kp2_R.v, c);

    // verification of individual signatures
    assert(verify(sig1, c, kp1_X.V));
    assert(verify(sig2, c, kp2_X.V));

    // "multi-sig" - collection of one or more signatures
    Signature two_sigs = multiSigCombine([ sig1, sig2 ]);

    // should also work with ranges
    assert(multiSigCombine(sig1.only.chain(sig2.only)) == two_sigs);
    Signature[int] map = [1: sig1, 2: sig2];
    assert(multiSigCombine(map.byValue) == two_sigs);

    // verification of two combined signatures
    assert(verify(two_sigs, c, kp1_X.V + kp2_X.V));

    // Now add one more signature
    const Signature sig3 = sign(kp3_X.v, kp3_R.V, kp3_R.v, c);

    // add third sig to the already combined two sigs
    Signature three_sigs = multiSigCombine([ two_sigs, sig3 ]);

    assert(verify(three_sigs, c, sum_X));

    // also adding the three works
    assert(verify(multiSigCombine([ sig3, sig2, sig1 ]), c, sum_X));
}

// rogue-key attack
// see: https://tlu.tarilabs.com/cryptography/digital_signatures/introduction_schnorr_signatures.html#key-cancellation-attack
// see: https://blockstream.com/2018/01/23/en-musig-key-aggregation-schnorr-signatures/#:~:text=not%20secure.
@safe unittest
{
    static immutable string message = "BOSAGORA for the win";

    // alice
    const Pair kp1 = Pair.random(); // key-pair
    const Pair R1 = Pair.random();  // (R, r), the public and private nonce

    // bob
    const Pair kp2 = Pair.random(); // ditto
    const Pair R2 = Pair.random();  // ditto

    auto R = R1.V + R2.V;
    auto X = kp1.V + kp2.V;
    Scalar c = hashMulti(X, R, message);  // challenge

    Scalar s1 = R1.v + (kp1.v * c);
    Scalar s2 = R2.v + (kp2.v * c);
    Scalar multi_sig = s1 + s2;
    assert(multi_sig.toPoint() == R + (X * c));

    // now assume that bob lied about his V and R during the co-operative phase.
    auto bobV = kp2.V - kp1.V;
    auto bobR = R2.V - R1.V;
    X = kp1.V + bobV;
    R = R1.V + bobR;
    c = Scalar(hashMulti(X, R, message));

    // bob signed the message alone, without co-operation from alice. it passes!
    Scalar bob_sig = R2.v + (kp2.v * c);
    assert(bob_sig.toPoint() == R + (X * c));
}

// ditto, but using multi-sig
/*@nogc*/ @safe unittest
{
    static immutable string message = "BOSAGORA for the win";

    Scalar c = hashFull(message);  // challenge

    Pair kp_1 = Pair.random();  // key-pair
    Pair Rp_1 = Pair.random();  // (R, r), the public and private nonce
    Scalar s_1 = Rp_1.v + (kp_1.v * c);  // signature

    Pair kp_2 = Pair.random();  // key-pair
    Pair Rp_2 = Pair.random();  // (R, r), the public and private nonce
    Scalar s_2 = Rp_2.v + (kp_2.v * c);  // signature

    // known public data of the nodes
    Point K_1 = kp_1.V;
    Point R_1 = Rp_1.V;

    Point K_2 = kp_2.V;
    Point R_2 = Rp_2.V;

    // verification of individual signatures
    assert(s_1.toPoint() == R_1 + (K_1 * c));
    assert(s_2.toPoint() == R_2 + (K_2 * c));

    // "multi-sig" - collection of one or more signatures
    auto sum_s = s_1 + s_2;
    assert(sum_s.toPoint() ==
        (R_1 + (K_1 * c)) +
        (R_2 + (K_2 * c)));

    // Or the equivalent:
    assert(sum_s.toPoint() ==
        (R_1 + R_2) + (K_1 * c) + (K_2 * c));
}
