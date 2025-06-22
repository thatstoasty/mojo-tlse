@fieldwise_init
@register_passable("trivial")
struct TLSVersions:
    """TLS protocol versions for secure communication."""
    var value: UInt16
    """Value of the TLS version."""
    alias SSL_V30 = Self(0x0300)
    """SSL 3.0 protocol version."""
    alias TLS_V10 = Self(0x0301)
    """TLS 1.0 protocol version."""
    alias TLS_V11 = Self(0x0302)
    """TLS 1.1 protocol version."""
    alias TLS_V12 = Self(0x0303)
    """TLS 1.2 protocol version."""
    alias TLS_V13 = Self(0x0304)
    """TLS 1.3 protocol version."""
    alias DTLS_V10 = Self(0xFEFF)
    """DTLS 1.0 protocol version."""
    alias DTLS_V12 = Self(0xFEFD)
    """DTLS 1.2 protocol version."""
    alias DTLS_V13 = Self(0xFEFC)
    """DTLS 1.3 protocol version."""


@fieldwise_init
@register_passable("trivial")
struct TLSResult:
    """Result codes for TLS operations."""
    var value: Int32
    """Value of the TLS result."""
    alias NEED_MORE_DATA = Self(0)
    """Indicates that more data is needed to complete the operation."""
    alias GENERIC_ERROR = Self(-1)
    """Generic error code for TLS operations."""
    alias BROKEN_PACKET = Self(-2)
    """Packet is broken or malformed."""
    alias NOT_UNDERSTOOD = Self(-3)
    """Operation is not understood by the TLS implementation."""
    alias NOT_SAFE = Self(-4)
    """Operation is not safe to perform."""
    alias NO_COMMON_CIPHER = Self(-5)
    """Indicates that there is no common cipher suite between the client and server."""
    alias UNEXPECTED_MESSAGE = Self(-6)
    """Indicates that an unexpected message was received during the TLS handshake."""
    alias CLOSE_CONNECTION = Self(-7)
    """Connection should be closed."""
    alias COMPRESSION_NOT_SUPPORTED = Self(-8)
    """Indicates that compression is not supported by the TLS implementation."""
    alias NO_MEMORY = Self(-9)
    """Indicates that there is not enough memory to complete the operation."""
    alias NOT_VERIFIED = Self(-10)
    """Certificate verification failed."""
    alias INTEGRITY_FAILED = Self(-11)
    """Integrity check of the data failed."""
    alias ERROR_ALERT = Self(-12)
    """Indicates that an error alert was received during the TLS handshake."""
    alias BROKEN_CONNECTION = Self(-13)
    """Connection is broken or has been closed unexpectedly."""
    alias BAD_CERTIFICATE = Self(-14)
    """Certificate is invalid or not trusted."""
    alias UNSUPPORTED_CERTIFICATE = Self(-15)
    """Certificate is not supported by the TLS implementation."""
    alias NO_RENEGOTIATION = Self(-16)
    """Indicates that renegotiation is not supported by the TLS implementation."""
    alias FEATURE_NOT_SUPPORTED = Self(-17)
    """Requested feature is not supported by the TLS implementation."""
    alias DECRYPTION_FAILED = Self(-20)
    """Indicates that decryption of the data failed."""


# Useful for checking ciphersuites: https://ciphersuite.info/cs/
@fieldwise_init
@register_passable("trivial")
struct TLS13CipherSuites:
    """TLS 1.3 cipher suites for secure communication."""

    var value: UInt16
    """Value of the cipher suite."""
    alias TLS_AES_128_GCM_SHA256 = Self(0x1301)
    """TLS 1.3 cipher suite with AES 128 GCM and SHA256."""
    alias TLS_AES_256_GCM_SHA384 = Self(0x1302)
    """TLS 1.3 cipher suite with AES 256 GCM and SHA384."""
    alias TLS_CHACHA20_POLY1305_SHA256 = Self(0x1303)
    """TLS 1.3 cipher suite with ChaCha20 Poly1305 and SHA256."""
    alias TLS_AES_128_CCM_SHA256 = Self(0x1304)
    """TLS 1.3 cipher suite with AES 128 CCM and SHA256."""
    alias TLS_AES_128_CCM_8_SHA256 = Self(0x1305)
    """TLS 1.3 cipher suite with AES 128 CCM-8 and SHA256."""


@fieldwise_init
@register_passable("trivial")
struct RSACipherSuites:
    """RSA cipher suites for secure communication."""

    var value: UInt16
    """Value of the cipher suite."""
    alias TLS_RSA_WITH_AES_128_CBC_SHA = Self(0x002F)
    """TLS RSA cipher suite with AES 128 CBC and SHA."""
    alias TLS_RSA_WITH_AES_256_CBC_SHA = Self(0x0035)
    """TLS RSA cipher suite with AES 256 CBC and SHA."""
    alias TLS_RSA_WITH_AES_128_CBC_SHA256 = Self(0x003C)
    """TLS RSA cipher suite with AES 128 CBC and SHA256."""
    alias TLS_RSA_WITH_AES_256_CBC_SHA256 = Self(0x003D)
    """TLS RSA cipher suite with AES 256 CBC and SHA256."""
    alias TLS_RSA_WITH_AES_128_GCM_SHA256 = Self(0x009C)
    """TLS RSA cipher suite with AES 128 GCM and SHA256."""
    alias TLS_RSA_WITH_AES_256_GCM_SHA384 = Self(0x009D)
    """TLS RSA cipher suite with AES 256 GCM and SHA384."""


@fieldwise_init
@register_passable("trivial")
struct DHERSACipherSuites:
    """DHE RSA cipher suites for secure communication."""

    var value: UInt16
    """Value of the cipher suite."""
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


@fieldwise_init
@register_passable("trivial")
struct ECDHERSACipherSuites:
    """ECDHE RSA cipher suites for secure communication."""

    var value: UInt16
    """Value of the cipher suite."""
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


@fieldwise_init
@register_passable("trivial")
struct ECDHEECDSACipherSuites:
    """ECDHE ECDSA cipher suites for secure communication."""

    var value: UInt16
    """Value of the cipher suite."""
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


@fieldwise_init
@register_passable("trivial")
struct TLS1213CipherSuites:
    """Cipher suites that support both TLS 1.2 and TLS 1.3."""

    var value: UInt16
    """Value of the cipher suite."""
    alias TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = Self(0xCCA8)
    """Supports TLS1.2, TLS1.3"""
    alias TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = Self(0xCCA9)
    """Supports TLS1.2, TLS1.3"""
    alias TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = Self(0xCCAA)
    """Supports TLS1.2, TLS1.3"""


alias TLS_FALLBACK_SCSV = 0x5600
"""TLS Fallback Signaling Cipher Suite Value (SCSV) for preventing protocol downgrade attacks."""

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


@fieldwise_init
@register_passable("trivial")
struct Result:
    """Result Enum."""
    var value: Int32
    """Value of the result."""
    alias CLOSE_NOTIFY = Self(0)
    """Connection should be closed gracefully."""
    alias UNEXPECTED_MESSAGE = Self(10)
    """Indicates that an unexpected message was received."""
    alias BAD_RECORD_MAC = Self(20)
    """Message authentication code (MAC) of a record is invalid."""
    alias DECRYPTION_FAILED = Self(21)
    """Indicates that decryption of a record failed."""
    alias RECORD_OVERFLOW = Self(22)
    """Record overflow occurred."""
    alias DECOMPRESSION_FAILURE = Self(30)
    """Decompression of a record failed."""
    alias HANDSHAKE_FAILURE = Self(40)
    """TLS handshake failed."""
    alias NO_CERTIFICATE = Self(41)
    """Certificate was provided during the handshake."""
    alias BAD_CERTIFICATE = Self(42)
    """Certificate is invalid or not trusted."""
    alias UNSUPPORTED_CERTIFICATE = Self(43)
    """Certificate is not supported by the TLS implementation."""
    alias CERTIFICATE_REVOKED = Self(44)
    """Certificate has been revoked."""
    alias CERTIFICATE_EXPIRED = Self(45)
    """Certificate has expired."""
    alias CERTIFICATE_UNKNOWN = Self(46)
    """Certificate is unknown or not recognized."""
    alias ILLEGAL_PARAMETER = Self(47)
    """Illegal parameter was provided during the TLS handshake."""
    alias UNKNOWN_CA = Self(48)
    """Certificate authority (CA) is unknown or not recognized."""
    alias ACCESS_DENIED = Self(49)
    """Access to the requested resource was denied."""
    alias DECODE_ERROR = Self(50)
    """Error occurred while decoding a record."""
    alias DECRYPT_ERROR = Self(51)
    """Error occurred while decrypting a record."""
    alias EXPORT_RESTRICTION = Self(60)
    """Export restriction was encountered."""
    alias PROTOCOL_VERSION = Self(70)
    """Protocol version is not supported or recognized."""
    alias INSUFFICIENT_SECURITY = Self(71)
    """Insufficient security for the requested operation."""
    alias INTERNAL_ERROR = Self(80)
    """Internal error occurred in the TLS implementation."""
    alias INAPPROPRIATE_FALLBACK = Self(86)
    """Inappropriate fallback to a less secure protocol version."""
    alias USER_CANCELED = Self(90)
    """User canceled the TLS operation."""
    alias NO_RENEGOTIATION = Self(100)
    """Renegotiation is not supported or allowed."""
    alias UNSUPPORTED_EXTENSION = Self(110)
    """TLS extension is not supported or recognized."""
    alias NO_ERROR = Self(255)
    """No error occurred during the TLS operation."""
