@value
@register_passable("trivial")
struct TLSVersions:
    var value: UInt16
    alias SSL_V30 = Self(0x0300)
    alias TLS_V10 = Self(0x0301)
    alias TLS_V11 = Self(0x0302)
    alias TLS_V12 = Self(0x0303)
    alias TLS_V13 = Self(0x0304)
    alias DTLS_V10 = Self(0xFEFF)
    alias DTLS_V12 = Self(0xFEFD)
    alias DTLS_V13 = Self(0xFEFC)


@value
@register_passable("trivial")
struct TLSResult:
    var value: Int32
    alias NEED_MORE_DATA = Self(0)
    alias GENERIC_ERROR = Self(-1)
    alias BROKEN_PACKET = Self(-2)
    alias NOT_UNDERSTOOD = Self(-3)
    alias NOT_SAFE = Self(-4)
    alias NO_COMMON_CIPHER = Self(-5)
    alias UNEXPECTED_MESSAGE = Self(-6)
    alias CLOSE_CONNECTION = Self(-7)
    alias COMPRESSION_NOT_SUPPORTED = Self(-8)
    alias NO_MEMORY = Self(-9)
    alias NOT_VERIFIED = Self(-10)
    alias INTEGRITY_FAILED = Self(-11)
    alias ERROR_ALERT = Self(-12)
    alias BROKEN_CONNECTION = Self(-13)
    alias BAD_CERTIFICATE = Self(-14)
    alias UNSUPPORTED_CERTIFICATE = Self(-15)
    alias NO_RENEGOTIATION = Self(-16)
    alias FEATURE_NOT_SUPPORTED = Self(-17)
    alias DECRYPTION_FAILED = Self(-20)


# Useful for checking ciphersuites: https://ciphersuite.info/cs/
@value
@register_passable("trivial")
struct TLS13CipherSuites:
    var value: UInt16
    alias TLS_AES_128_GCM_SHA256 = Self(0x1301)
    alias TLS_AES_256_GCM_SHA384 = Self(0x1302)
    alias TLS_CHACHA20_POLY1305_SHA256 = Self(0x1303)
    alias TLS_AES_128_CCM_SHA256 = Self(0x1304)
    alias TLS_AES_128_CCM_8_SHA256 = Self(0x1305)


@value
@register_passable("trivial")
struct RSACipherSuites:
    var value: UInt16
    alias TLS_RSA_WITH_AES_128_CBC_SHA = Self(0x002F)
    alias TLS_RSA_WITH_AES_256_CBC_SHA = Self(0x0035)
    alias TLS_RSA_WITH_AES_128_CBC_SHA256 = Self(0x003C)
    alias TLS_RSA_WITH_AES_256_CBC_SHA256 = Self(0x003D)
    alias TLS_RSA_WITH_AES_128_GCM_SHA256 = Self(0x009C)
    alias TLS_RSA_WITH_AES_256_GCM_SHA384 = Self(0x009D)


@value
@register_passable("trivial")
struct DHERSACipherSuites:
    """Forward secrecy."""

    var value: UInt16
    alias TLS_DHE_RSA_WITH_AES_128_CBC_SHA = Self(0x0033)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_DHE_RSA_WITH_AES_256_CBC_SHA = Self(0x0039)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = Self(0x0067)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = Self(0x006B)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 = Self(0x009E)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 = Self(0x009F)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""


@value
@register_passable("trivial")
struct ECDHERSACipherSuites:
    var value: UInt16
    alias TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = Self(0xC013)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = Self(0xC014)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 = Self(0xC027)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = Self(0xC02F)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = Self(0xC030)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""


@value
@register_passable("trivial")
struct ECDHEECDSACipherSuites:
    var value: UInt16
    alias TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = Self(0xC009)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = Self(0xC00A)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = Self(0xC023)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 = Self(0xC024)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = Self(0xC02B)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""
    alias TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = Self(0xC02C)
    """Supports TLS1.0, TLS1.1, TLS1.2, TLS1.3"""


@value
@register_passable("trivial")
struct TLS1213CipherSuites:
    var value: UInt16
    alias TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = Self(0xCCA8)
    """Supports TLS1.2, TLS1.3"""
    alias TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = Self(0xCCA9)
    """Supports TLS1.2, TLS1.3"""
    alias TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = Self(0xCCAA)
    """Supports TLS1.2, TLS1.3"""


alias TLS_FALLBACK_SCSV = 0x5600

# define TLS_UNSUPPORTED_ALGORITHM   0x00
# define TLS_RSA_SIGN_RSA            0x01
# define TLS_RSA_SIGN_MD5            0x04
# define TLS_RSA_SIGN_SHA1           0x05
# define TLS_RSA_SIGN_SHA224         0x0A
# define TLS_RSA_SIGN_SHA256         0x0B
# define TLS_RSA_SIGN_SHA384         0x0C
# define TLS_RSA_SIGN_SHA512         0x0D
# define TLS_ECDSA_SIGN_SHA256       0x0E
# define TLS_ECDSA_SIGN_SHA224       0x0F
# define TLS_ECDSA_SIGN_SHA384       0x10
# define TLS_ECDSA_SIGN_SHA512       0x1A

# define TLS_EC_PUBLIC_KEY           0x11
# define TLS_EC_prime192v1           0x12
# define TLS_EC_prime192v2           0x13
# define TLS_EC_prime192v3           0x14
# define TLS_EC_prime239v1           0x15
# define TLS_EC_prime239v2           0x16
# define TLS_EC_prime239v3           0x17
# define TLS_EC_prime256v1           0x18
# define TLS_EC_secp224r1            21
# define TLS_EC_secp256r1            23
# define TLS_EC_secp384r1            24
# define TLS_EC_secp521r1            25

# define TLS_ALERT_WARNING           0x01
# define TLS_ALERT_CRITICAL          0x02

# define SRTP_AES128_CM_HMAC_SHA1_80 0x0001
# define SRTP_AES128_CM_HMAC_SHA1_32 0x0002
# define SRTP_NULL_HMAC_SHA1_80      0x0005
# define SRTP_NULL_HMAC_SHA1_32      0x0006
# define SRTP_AEAD_AES_128_GCM       0x0007
# define SRTP_AEAD_AES_256_GCM       0x0008

# define SRTP_NULL           0
# define SRTP_AES_CM         1
# define SRTP_AUTH_NULL      0
# define SRTP_AUTH_HMAC_SHA1 1


@value
@register_passable("trivial")
struct Result:
    var value: Int32
    alias CLOSE_NOTIFY = Self(0)
    alias UNEXPECTED_MESSAGE = Self(10)
    alias BAD_RECORD_MAC = Self(20)
    alias DECRYPTION_FAILED = Self(21)
    alias RECORD_OVERFLOW = Self(22)
    alias DECOMPRESSION_FAILURE = Self(30)
    alias HANDSHAKE_FAILURE = Self(40)
    alias NO_CERTIFICATE = Self(41)
    alias BAD_CERTIFICATE = Self(42)
    alias UNSUPPORTED_CERTIFICATE = Self(43)
    alias CERTIFICATE_REVOKED = Self(44)
    alias CERTIFICATE_EXPIRED = Self(45)
    alias CERTIFICATE_UNKNOWN = Self(46)
    alias ILLEGAL_PARAMETER = Self(47)
    alias UNKNOWN_CA = Self(48)
    alias ACCESS_DENIED = Self(49)
    alias DECODE_ERROR = Self(50)
    alias DECRYPT_ERROR = Self(51)
    alias EXPORT_RESTRICTION = Self(60)
    alias PROTOCOL_VERSION = Self(70)
    alias INSUFFICIENT_SECURITY = Self(71)
    alias INTERNAL_ERROR = Self(80)
    alias INAPPROPRIATE_FALLBACK = Self(86)
    alias USER_CANCELED = Self(90)
    alias NO_RENEGOTIATION = Self(100)
    alias UNSUPPORTED_EXTENSION = Self(110)
    alias NO_ERROR = Self(255)
