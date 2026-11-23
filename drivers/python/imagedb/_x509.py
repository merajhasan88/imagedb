"""The two facts the driver reads from the server's certificate (its DER, from the TLS session), by a small strict DER
walker: the SubjectPublicKeyInfo's bytes (a pin is their SHA-256, as server/tls.c's spki_pin: i2d_X509_PUBKEY) and the
certificate's signature algorithm (RFC 5929's tls-server-end-point hashes the certificate by its signature's hash, MD5
and SHA-1 taken to SHA-256; docs/n1-design.md section 8f: a server allowing that binding takes only SHA-256)."""

import hashlib


class CertError(ValueError):
    pass


def _tlv(b, pos, end):
    """one DER element at pos: (tag, the value's start, its end); single-byte tags, definite minimal lengths"""
    if end - pos < 2:
        raise CertError("a certificate's element cut short")
    tag = b[pos]
    if tag & 0x1F == 0x1F:
        raise CertError("a certificate's element of a high tag number")
    n = b[pos + 1]
    pos += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or end - pos < k:
            raise CertError("a certificate's element of an indefinite or overlong length")
        n = int.from_bytes(b[pos:pos + k], "big")
        if b[pos] == 0 or n < 0x80:
            raise CertError("a certificate's element of a length not in its minimal form")
        pos += k
    if n > end - pos:
        raise CertError("a certificate's element past its parent")
    return tag, pos, pos + n


def parse(der):
    """(the SubjectPublicKeyInfo's DER, the signatureAlgorithm's OID bytes) of an X.509 certificate's DER"""
    der = bytes(der)
    tag, s, e = _tlv(der, 0, len(der))
    if tag != 0x30 or e != len(der):
        raise CertError("a certificate is one SEQUENCE")
    tag, ts, te = _tlv(der, s, e)  # tbsCertificate
    if tag != 0x30:
        raise CertError("a certificate's tbsCertificate")
    tag, a, ae = _tlv(der, te, e)  # signatureAlgorithm
    if tag != 0x30:
        raise CertError("a certificate's signatureAlgorithm")
    tag, o, oe = _tlv(der, a, ae)
    if tag != 0x06:
        raise CertError("a certificate's signatureAlgorithm OID")
    oid = der[o:oe]
    tag, bs, be = _tlv(der, ae, e)  # signatureValue
    if tag != 0x03 or be != e:
        raise CertError("a certificate's signatureValue")
    p = ts
    tag, _, ve = _tlv(der, p, te)
    if tag == 0xA0:  # [0] EXPLICIT version
        p = ve
    want = (0x02, 0x30, 0x30, 0x30, 0x30)  # serialNumber, signature, issuer, validity, subject
    for t in want:
        tag, _, ve = _tlv(der, p, te)
        if tag != t:
            raise CertError("a certificate's tbsCertificate fields")
        p = ve
    tag, _, ve = _tlv(der, p, te)
    if tag != 0x30:
        raise CertError("a certificate's subjectPublicKeyInfo")
    return der[p:ve], oid


def spki_pin(der):
    """the server key's SPKI SHA-256: what `imagedb-server cert` prints (unchanged by `cert --renew`)"""
    return hashlib.sha256(parse(der)[0]).digest()


# signatureAlgorithm OIDs (DER value bytes) whose one hash is SHA-256, or MD5 or SHA-1 (taken to SHA-256 by RFC 5929)
_SHA256_SIGS = {
    bytes.fromhex("2a8648ce3d040302"): "ecdsa-with-SHA256",
    bytes.fromhex("2a864886f70d01010b"): "sha256WithRSAEncryption",
    bytes.fromhex("608648016503040302"): "dsa-with-sha256",
    bytes.fromhex("2a864886f70d010104"): "md5WithRSAEncryption",
    bytes.fromhex("2a864886f70d010105"): "sha1WithRSAEncryption",
    bytes.fromhex("2a8648ce3d0401"): "ecdsa-with-SHA1",
    bytes.fromhex("2a8648ce380403"): "dsa-with-sha1",
}


def end_point(der):
    """RFC 5929's tls-server-end-point value: the certificate's SHA-256, for a certificate whose signature's one hash is
    SHA-256 (or MD5 or SHA-1); CertError for any other (no driver computes another hash: section 8f)"""
    _, oid = parse(der)
    if oid not in _SHA256_SIGS:
        raise CertError("tls-server-end-point: the server's certificate is not signed with SHA-256 (OID %s)" % oid.hex())
    return hashlib.sha256(der).digest()
