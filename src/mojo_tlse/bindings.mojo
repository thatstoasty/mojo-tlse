import os
import pathlib
from sys import ffi
from sys.ffi import OpaquePointer
from memory import UnsafePointer

alias c_void = UInt8
alias c_char = UInt8
alias c_schar = Int8
alias c_uchar = UInt8
alias c_short = Int16
alias c_ushort = UInt16
alias c_int = Int32
alias c_uint = UInt32
alias c_long = Int64
alias c_ulong = UInt64
alias c_float = Float32
alias c_double = Float64

# `Int` is known to be machine's width
alias c_size_t = Int
alias c_ssize_t = Int

alias ptrdiff_t = Int64
alias intptr_t = Int64
alias uintptr_t = UInt64


@value
struct TLSContext:
    """Read only, the `TLSContext` struct is defined in C and is opaque to Mojo. A pointer to this is functionally an OpaquePointer.

    Pointers to `TLSContext` should never be dereferenced.
    """
    pass


@value
struct TLSCertificate:
    """Read only, the `TLSCertificate` struct is defined in C and is opaque to Mojo. A pointer to this is functionally an OpaquePointer.

    Pointers to `TLSCertificate` should never be dereferenced.
    """

    pass


struct TLSPacket:
    """Read only, the `TLSPacket` struct is defined in C and is opaque to Mojo. A pointer to this is functionally an OpaquePointer.

    Pointers to `TLSPacket` should never be dereferenced.
    """

    pass


struct ECCCurveParameters:
    """Read only, the `ECCCurveParameters` struct is defined in C and is opaque to Mojo. A pointer to this is functionally an OpaquePointer.

    Pointers to `ECCCurveParameters` should never be dereferenced.
    """

    pass


struct TLSRTCPeerConnection:
    """Read only, the `TLSRTCPeerConnection` struct is defined in C and is opaque to Mojo. A pointer to this is functionally an OpaquePointer.

    Pointers to `TLSRTCPeerConnection` should never be dereferenced.
    """

    pass


alias TLSValidationFn = fn (UnsafePointer[TLSContext], UnsafePointer[UnsafePointer[TLSCertificate]], c_int) -> c_int
alias TLSPeerConnectionWriteFn = fn (UnsafePointer[TLSRTCPeerConnection], UnsafePointer[c_uchar], c_int) -> c_int


struct TLSE:
    var _handle: ffi.DLHandle

    fn __init__(out self) raises:
        var path = os.getenv("TLSE_LIB_PATH")

        # If its not explicitly set, then assume the program is running from the root of the project.
        if path == "":
            path = String(pathlib.cwd() / ".magic/envs/default/lib/libtlse.dylib")
        self._handle = ffi.DLHandle(path, ffi.RTLD.LAZY)
    
    fn __moveinit__(out self, owned other: TLSE):
        self._handle = other._handle

    fn tls_create_context(
        self,
        is_server: c_uchar,
        version: c_ushort,
    ) -> UnsafePointer[TLSContext]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSContext *tls_create_context(unsigned char is_server, unsigned short version);
        ```
        """
        var f = self._handle.get_function[fn (c_char, c_ushort) -> UnsafePointer[TLSContext]]("tls_create_context")
        return f(is_server, version)

    fn tls_make_exportable(
        self,
        context: UnsafePointer[TLSContext],
        exportable_flag: c_uchar,
    ):
        """Set the context as serializable or not. Must be called before negotiation.
        Exportable contexts use a bit more memory, to be able to hold the keys.

        Note that imported keys are not reexportable unless TLS_REEXPORTABLE is set.
        #### C Function
        ```c
        voidtls_make_exportable(struct TLSContext *context, unsigned char exportable_flag)
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_uchar)]("tls_make_exportable")(
            context, exportable_flag
        )

    fn tls_sni_set(
        self,
        context: UnsafePointer[TLSContext],
        sni: UnsafePointer[c_char],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_sni_set(struct TLSContext *context, const char *sni);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_char]) -> c_int]("tls_sni_set")(
            context, sni
        )

    fn tls_client_connect(
        self,
        context: UnsafePointer[TLSContext],
    ) -> c_int:
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_client_connect")(context)

    fn tls_get_write_buffer(
        self,
        context: UnsafePointer[TLSContext],
        outlen: UnsafePointer[c_uint],
    ) -> UnsafePointer[c_uchar]:
        """Get encrypted data to write, if any. Once you've sent all of it, call
        `tls_buffer_clear()`.

        #### C Function
        ```c
        const unsigned char *tls_get_write_buffer(struct TLSContext *context, unsigned int *outlen);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uint]) -> UnsafePointer[c_uchar]
        ]("tls_get_write_buffer")(context, outlen)

    fn tls_buffer_clear(self, context: UnsafePointer[TLSContext]):
        """Documentation to come.

        #### C Function
        ```c
        void tls_buffer_clear(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext])]("tls_buffer_clear")(context)

    fn tls_established(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Returns 1 for established, 0 for not established yet, and -1 for a critical error.

        #### C Function
        ```c
        int tls_established(struct TLSContext *context).
        ```"""
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_established")(context)

    fn tls_consume_stream(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar],
        buf_len: c_int,
        certificate_verify: TLSValidationFn,
    ) -> c_int:
        """Process a given number of input bytes from a socket. If the other side just
        presented a certificate and certificate_verify is not NULL, it will be called.

        Returns 0 if there's no data ready yet, a negative value (see
        TLS_GENERIC_ERROR etc.) for an error, or a positive value (the number of bytes
        used from buf) if one or more complete TLS messages were received. The data
        is copied into an internal buffer even if not all of it was consumed,
        so you should not re-send it the next time.

        Decrypted data, if any, should be read back with tls_read(). Can change the
        status of tls_established(). If the library has anything to send back on the
        socket (e.g. as part of the handshake), tls_get_write_buffer() will return
        non-NULL.

        #### C Function
        ```c
        int tls_consume_stream(struct TLSContext *context, const unsigned char *buf, int buf_len, tls_validation_function certificate_verify);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int, TLSValidationFn) -> c_int
        ]("tls_consume_stream")(context, buf, buf_len, certificate_verify)

    fn tls_read(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar],
        size: c_uint,
    ) -> c_int:
        """Reads any unread decrypted data (see tls_consume_stream). If you don't read all of it,
        the remainder will be left in the internal buffers for next tls_read(). Returns -1 for
        fatal error, 0 for no more data, or otherwise the number of bytes copied into the buffer
        (up to a maximum of the given size).

        #### C Function
        ```c
        int tls_read(struct TLSContext *context, unsigned char *buf, unsigned int size);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_uint) -> c_int](
            "tls_read"
        )(context, buf, size)

    fn tls_write(
        self,
        context: UnsafePointer[TLSContext],
        data: UnsafePointer[c_uchar],
        len: c_uint,
    ) -> c_int:
        """Writes data to the TLS connection. Returns -1 for fatal error, 0 for no more data, or
        otherwise the number of bytes written (up to a maximum of the given size).

        #### C Function
        ```c
        int tls_write(struct TLSContext *context, const unsigned char *data, unsigned int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_uint) -> c_int](
            "tls_write"
        )(context, data, len)

    fn tls_certificate_is_valid(self, cert: UnsafePointer[TLSCertificate]) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_certificate_is_valid(struct TLSCertificate *cert);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate]) -> c_int]("tls_certificate_is_valid")(cert)

    fn tls_certificate_chain_is_valid(
        self,
        certificates: UnsafePointer[UnsafePointer[TLSCertificate]],
        len: c_int,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_certificate_chain_is_valid(struct TLSCertificate **certificates, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[UnsafePointer[TLSCertificate]], c_int) -> c_int](
            "tls_certificate_chain_is_valid"
        )(certificates, len)

    fn tls_certificate_valid_subject(
        self,
        cert: UnsafePointer[TLSCertificate],
        subject: UnsafePointer[c_char],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_certificate_valid_subject(struct TLSCertificate *cert, const char *subject);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[c_char]) -> c_int](
            "tls_certificate_valid_subject"
        )(cert, subject)

    fn tls_sni(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[c_char]:
        """Documentation to come.

        #### C Function
        ```c
        const char *tls_sni(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[c_char]]("tls_sni")(context)

    fn tls_choose_cipher(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar],
        buf_len: c_int,
        scsv_set: UnsafePointer[c_int],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_choose_cipher(struct TLSContext *context, const unsigned char *buf, int buf_len, int *scsv_set);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int, UnsafePointer[c_int]) -> c_int
        ]("tls_choose_cipher")(context, buf, buf_len, scsv_set)



    fn tls_init(self):
        """Global initialization. Optional, as it will be called automatically;
        however, the initialization is not thread-safe, so if you intend to use TLSe
        from multiple threads, you'll need to call tls_init() once, from a single thread,
        before using the library.

        #### C Function
        ```c
        void tls_init();
        ```
        """
        return self._handle.get_function[fn ()]("tls_init")()

    fn tls_pem_decode(
        self,
        data_in: UnsafePointer[c_uchar],
        input_length: c_uint,
        cert_index: c_int,
        output_len: UnsafePointer[c_uint],
    ) -> UnsafePointer[c_uchar]:
        """Documentation to come.
        
        #### C Function
        ```c
        unsigned char *tls_pem_decode(const unsigned char *data_in, unsigned int input_length, int cert_index, unsigned int *output_len);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[c_uchar], c_uint, c_int, UnsafePointer[c_uint]) -> UnsafePointer[c_uchar]
        ]("tls_pem_decode")(data_in, input_length, cert_index, output_len)

    fn tls_create_certificate(self) -> UnsafePointer[TLSCertificate]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSCertificate *tls_create_certificate();
        ```
        """
        return self._handle.get_function[fn () -> UnsafePointer[TLSCertificate]]("tls_create_certificate")()

    fn tls_certificate_valid_subject_name(
        self,
        cert_subject: UnsafePointer[c_uchar],
        subject: UnsafePointer[c_char],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_certificate_valid_subject_name(const unsigned char *cert_subject, const char *subject);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[c_uchar], UnsafePointer[c_char]) -> c_int](
            "tls_certificate_valid_subject_name"
        )(cert_subject, subject)

    fn tls_certificate_set_copy(
        self,
        member: UnsafePointer[UnsafePointer[c_uchar]],
        val: UnsafePointer[c_uchar],
        len: c_int,
    ):
        """Documentation to come.

        #### C Function
        ```c
        void tls_certificate_set_copy(unsigned char **member, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[UnsafePointer[c_uchar]], UnsafePointer[c_uchar], c_int)](
            "tls_certificate_set_copy"
        )(member, val, len)

    fn tls_certificate_set_copy_date(
        self,
        member: UnsafePointer[UnsafePointer[c_uchar]],
        val: UnsafePointer[c_uchar],
        len: c_int,
    ):
        """Documentation to come.

        #### C Function
        ```c
        void tls_certificate_set_copy_date(unsigned char **member, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[UnsafePointer[c_uchar]], UnsafePointer[c_uchar], c_int)](
            "tls_certificate_set_copy_date"
        )(member, val, len)

    fn tls_certificate_set_key(
        self,
        cert: UnsafePointer[TLSCertificate],
        val: UnsafePointer[c_uchar],
        len: c_int,
    ):
        """Documentation to come.

        #### C Function
        ```c
        void tls_certificate_set_key(struct TLSCertificate *cert, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[c_uchar], c_int)](
            "tls_certificate_set_key"
        )(cert, val, len)

    fn tls_certificate_set_priv(
        self,
        cert: UnsafePointer[TLSCertificate],
        val: UnsafePointer[c_uchar],
        len: c_int,
    ):
        """Documentation to come.

        #### C Function
        ```c
        void tls_certificate_set_priv(struct TLSCertificate *cert, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[c_uchar], c_int)](
            "tls_certificate_set_priv"
        )(cert, val, len)

    fn tls_certificate_set_sign_key(
        self,
        cert: UnsafePointer[TLSCertificate],
        val: UnsafePointer[c_uchar],
        len: c_int,
    ):
        """Documentation to come.

        #### C Function
        ```c
        void tls_certificate_set_sign_key(struct TLSCertificate *cert, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[c_uchar], c_int)](
            "tls_certificate_set_sign_key"
        )(cert, val, len)

    fn tls_certificate_to_string(
        self,
        cert: UnsafePointer[TLSCertificate],
        buffer: UnsafePointer[c_char],
        len: c_int,
    ) -> UnsafePointer[c_char]:
        """Documentation to come.

        #### C Function
        ```c
        char *tls_certificate_to_string(struct TLSCertificate *cert, char *buffer, int len);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSCertificate], UnsafePointer[c_char], c_int) -> UnsafePointer[c_char]
        ]("tls_certificate_to_string")(cert, buffer, len)

    fn tls_certificate_set_exponent(
        self,
        cert: UnsafePointer[TLSCertificate],
        val: UnsafePointer[c_uchar],
        len: c_int,
    ):
        """Documentation to come.

        #### C Function
        ```c
        void tls_certificate_set_exponent(struct TLSCertificate *cert, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[c_uchar], c_int)](
            "tls_certificate_set_exponent"
        )(cert, val, len)

    fn tls_certificate_set_serial(
        self,
        cert: UnsafePointer[TLSCertificate],
        val: UnsafePointer[c_uchar],
        len: c_int,
    ):
        """Documentation to come.

        #### C Function
        ```c
        void tls_certificate_set_serial(struct TLSCertificate *cert, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[c_uchar], c_int)](
            "tls_certificate_set_serial"
        )(cert, val, len)

    fn tls_certificate_set_algorithm(
        self,
        context: UnsafePointer[TLSContext],
        algorithm: UnsafePointer[c_uint],
        val: UnsafePointer[c_uchar],
        len: c_int,
    ):
        """Documentation to come.

        #### C Function
        ```c
        void tls_certificate_set_algorithm(struct TLSContext *context, unsigned int *algorithm, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uint], UnsafePointer[c_uchar], c_int)
        ]("tls_certificate_set_algorithm")(context, algorithm, val, len)

    fn tls_destroy_certificate(self, cert: UnsafePointer[TLSCertificate]):
        """Documentation to come.

        #### C Function
        ```c
        void tls_destroy_certificate(struct TLSCertificate *cert);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate])]("tls_destroy_certificate")(cert)

    fn tls_create_packet(
        self,
        context: UnsafePointer[TLSContext],
        type: c_uchar,
        version: c_ushort,
        payload_size_hint: c_int,
    ) -> UnsafePointer[TLSPacket]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSPacket *tls_create_packet(struct TLSContext *context, unsigned char type, unsigned short version, int payload_size_hint);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], c_uchar, c_ushort, c_int) -> UnsafePointer[TLSPacket]
        ]("tls_create_packet")(context, type, version, payload_size_hint)

    fn tls_destroy_packet(self, packet: UnsafePointer[TLSPacket]):
        """Documentation to come.

        #### C Function
        ```c
        void tls_destroy_packet(struct TLSPacket *packet);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket])]("tls_destroy_packet")(packet)

    fn tls_packet_update(self, packet: UnsafePointer[TLSPacket]):
        """Documentation to come.

        #### C Function
        ```c
        void tls_packet_update(struct TLSPacket *packet);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket])]("tls_packet_update")(packet)

    fn tls_packet_append(
        self,
        packet: UnsafePointer[TLSPacket],
        buf: UnsafePointer[c_uchar],
        len: c_uint,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_packet_append(struct TLSPacket *packet, const unsigned char *buf, unsigned int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket], UnsafePointer[c_uchar], c_uint) -> c_int](
            "tls_packet_append"
        )(packet, buf, len)

    fn tls_packet_uint8(self, packet: UnsafePointer[TLSPacket], i: c_uchar) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_packet_uint8(struct TLSPacket *packet, unsigned char i);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket], c_uchar) -> c_int]("tls_packet_uint8")(packet, i)

    fn tls_packet_uint16(self, packet: UnsafePointer[TLSPacket], i: c_ushort) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_packet_uint16(struct TLSPacket *packet, unsigned short i);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket], c_ushort) -> c_int]("tls_packet_uint16")(
            packet, i
        )

    fn tls_packet_uint32(self, packet: UnsafePointer[TLSPacket], i: c_uint) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_packet_uint32(struct TLSPacket *packet, unsigned int i);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket], c_uint) -> c_int]("tls_packet_uint32")(packet, i)

    fn tls_packet_uint24(self, packet: UnsafePointer[TLSPacket], i: c_uint) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_packet_uint24(struct TLSPacket *packet, unsigned int i);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket], c_uint) -> c_int]("tls_packet_uint24")(packet, i)

    fn tls_random(self, key: UnsafePointer[c_uchar], len: c_int) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_random(unsigned char *key, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[c_uchar], c_int) -> c_int]("tls_random")(key, len)

    fn tls_destroy(self):
        """Documentation to come.

        #### C Function
        ```c
        void tls_destroy();
        ```
        """
        return self._handle.get_function[fn ()]("tls_destroy")()

    fn tls_set_curve(
        self,
        context: UnsafePointer[TLSContext],
        curve: UnsafePointer[UnsafePointer[c_uchar]],
    ) -> UnsafePointer[ECCCurveParameters]:
        """Documentation to come.

        #### C Function
        ```c
        const struct ECCCurveParameters *tls_set_curve(struct TLSContext *context, const struct ECCCurveParameters *curve);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[UnsafePointer[c_uchar]]) -> UnsafePointer[ECCCurveParameters]
        ]("tls_set_curve")(context, curve)

    fn tls_set_default_dhe_pg(
        self,
        context: UnsafePointer[TLSContext],
        p_hex_str: UnsafePointer[c_char],
        g_hex_str: UnsafePointer[c_char],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_set_default_dhe_pg(struct TLSContext *context, const char *p_hex_str, const char *g_hex_str);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_char], UnsafePointer[c_char]) -> c_int
        ]("tls_set_default_dhe_pg")(context, p_hex_str, g_hex_str)

    fn tls_destroy_context(self, context: UnsafePointer[TLSContext]):
        """Documentation to come.

        #### C Function
        ```c
        void tls_destroy_context(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext])]("tls_destroy_context")(context)

    fn tls_cipher_supported(self, context: UnsafePointer[TLSContext], cipher: c_ushort) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_cipher_supported(struct TLSContext *context, unsigned short cipher);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_ushort) -> c_int]("tls_cipher_supported")(
            context, cipher
        )

    fn tls_cipher_is_fs(self, context: UnsafePointer[TLSContext], cipher: c_ushort) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_cipher_is_fs(struct TLSContext *context, unsigned short cipher);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_ushort) -> c_int]("tls_cipher_is_fs")(
            context, cipher
        )

    fn tls_cipher_is_ephemeral(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_cipher_is_ephemeral(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_cipher_is_ephemeral")(context)

    fn tls_cipher_name(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[c_char]:
        """Documentation to come.

        #### C Function
        ```c
        const char *tls_cipher_name(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[c_char]]("tls_cipher_name")(
            context
        )

    fn tls_is_ecdsa(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_is_ecdsa(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_is_ecdsa")(context)

    fn tls_build_client_key_exchange(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSPacket *tls_build_client_key_exchange(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]](
            "tls_build_client_key_exchange"
        )(context)

    fn tls_build_server_key_exchange(
        self, context: UnsafePointer[TLSContext], method: c_int
    ) -> UnsafePointer[TLSPacket]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSPacket *tls_build_server_key_exchange(struct TLSContext *context, int method);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_int) -> UnsafePointer[TLSPacket]](
            "tls_build_server_key_exchange"
        )(context, method)

    fn tls_build_hello(self, context: UnsafePointer[TLSContext], tls13_downgrade: c_int) -> UnsafePointer[TLSPacket]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSPacket *tls_build_hello(struct TLSContext *context, int tls13_downgrade);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_int) -> UnsafePointer[TLSPacket]](
            "tls_build_hello"
        )(context, tls13_downgrade)

    fn tls_certificate_request(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSPacket *tls_certificate_request(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]](
            "tls_certificate_request"
        )(context)

    fn tls_build_verify_request(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSPacket *tls_build_verify_request(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]](
            "tls_build_verify_request"
        )(context)

    fn tls_parse_hello(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar],
        buf_len: c_int,
        write_packets: UnsafePointer[c_uint],
        dtls_verified: UnsafePointer[c_uint],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_parse_hello(struct TLSContext *context, const unsigned char *buf, int buf_len, unsigned int *write_packets, unsigned int *dtls_verified);
        ```
        """
        return self._handle.get_function[
            fn (
                UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int, UnsafePointer[c_uint], UnsafePointer[c_uint]
            ) -> c_int
        ]("tls_parse_hello")(context, buf, buf_len, write_packets, dtls_verified)

    fn tls_parse_certificate(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar],
        buf_len: c_int,
        is_client: c_int,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_parse_certificate(struct TLSContext *context, const unsigned char *buf, int buf_len, int is_client);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int, c_int) -> c_int](
            "tls_parse_certificate"
        )(context, buf, buf_len, is_client)

    fn tls_parse_server_key_exchange(
        self, context: UnsafePointer[TLSContext], buf: UnsafePointer[c_uchar], buf_len: c_int
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_parse_server_key_exchange(struct TLSContext *context, const unsigned char *buf, int buf_len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int) -> c_int](
            "tls_parse_server_key_exchange"
        )(context, buf, buf_len)

    fn tls_parse_client_key_exchange(
        self, context: UnsafePointer[TLSContext], buf: UnsafePointer[c_uchar], buf_len: c_int
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_parse_client_key_exchange(struct TLSContext *context, const unsigned char *buf, int buf_len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int) -> c_int](
            "tls_parse_client_key_exchange"
        )(context, buf, buf_len)

    fn tls_parse_server_hello_done(
        self, context: UnsafePointer[TLSContext], buf: UnsafePointer[c_uchar], buf_len: c_int
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_parse_server_hello_done(struct TLSContext *context, const unsigned char *buf, int buf_len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int) -> c_int](
            "tls_parse_server_hello_done"
        )(context, buf, buf_len)

    fn tls_parse_finished(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar],
        buf_len: c_int,
        write_packets: UnsafePointer[c_uint],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_parse_finished(struct TLSContext *context, const unsigned char *buf, int buf_len, unsigned int *write_packets);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int, UnsafePointer[c_uint]) -> c_int
        ]("tls_parse_finished")(context, buf, buf_len, write_packets)

    fn tls_parse_verify(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar],
        buf_len: c_int,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_parse_verify(struct TLSContext *context, const unsigned char *buf, int buf_len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int) -> c_int](
            "tls_parse_verify"
        )(context, buf, buf_len)

    fn tls_parse_payload(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar],
        buf_len: c_int,
        certificate_verify: TLSValidationFn,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_parse_payload(struct TLSContext *context, const unsigned char *buf, int buf_len, tls_validation_function certificate_verify);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int, TLSValidationFn) -> c_int
        ]("tls_parse_payload")(context, buf, buf_len, certificate_verify)

    fn tls_parse_message(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar],
        buf_len: c_int,
        certificate_verify: TLSValidationFn,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_parse_message(struct TLSContext *context, unsigned char *buf, int buf_len, tls_validation_function certificate_verify);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int, TLSValidationFn) -> c_int
        ]("tls_parse_message")(context, buf, buf_len, certificate_verify)

    fn tls_certificate_verify_signature(
        self,
        cert: UnsafePointer[TLSCertificate],
        parent: UnsafePointer[TLSCertificate],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_certificate_verify_signature(struct TLSCertificate *cert, struct TLSCertificate *parent);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[TLSCertificate]) -> c_int](
            "tls_certificate_verify_signature"
        )(cert, parent)

    fn tls_certificate_chain_is_valid(
        self,
        context: UnsafePointer[TLSContext],
        certificates: UnsafePointer[UnsafePointer[TLSCertificate]],
        len: c_int,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_certificate_chain_is_valid(struct TLSContext *context, struct TLSCertificate **certificates, int len);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[UnsafePointer[TLSCertificate]], c_int) -> c_int
        ]("tls_certificate_chain_is_valid")(context, certificates, len)

    fn tls_certificate_chain_is_valid_root(
        self,
        context: UnsafePointer[TLSContext],
        certificates: UnsafePointer[UnsafePointer[TLSCertificate]],
        len: c_int,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_certificate_chain_is_valid_root(struct TLSContext *context, struct TLSCertificate **certificates, int len);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[UnsafePointer[TLSCertificate]], c_int) -> c_int
        ]("tls_certificate_chain_is_valid_root")(context, certificates, len)

    fn tls_load_certificates(
        self,
        context: UnsafePointer[TLSContext],
        pem_buffer: UnsafePointer[c_uchar],
        pem_size: c_int,
    ) -> c_int:
        """Add a certificate or a certificate chain to the given context, in PEM form.
        Returns a negative value (TLS_GENERIC_ERROR etc.) on error, 0 if there were no
        certificates in the buffer, or the number of loaded certificates on success.

        #### C Function
        ```c
        int tls_load_certificates(struct TLSContext *context, const unsigned char *pem_buffer, int pem_size);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int) -> c_int](
            "tls_load_certificates"
        )(context, pem_buffer, pem_size)

    fn tls_load_private_key(
        self,
        context: UnsafePointer[TLSContext],
        pem_buffer: UnsafePointer[c_uchar],
        pem_size: c_int,
    ) -> c_int:
        """Add a private key to the given context, in PEM form. Returns a negative value
        (`TLSResult.GENERIC_ERROR` etc.) on error, 0 if there was no private key in the
        buffer, or 1 on success.

        #### C Function
        ```c
        int tls_load_private_key(struct TLSContext *context, const unsigned char *pem_buffer, int pem_size);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int) -> c_int](
            "tls_load_private_key"
        )(context, pem_buffer, pem_size)

    fn tls_build_certificate(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSPacket *tls_build_certificate(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]](
            "tls_build_certificate"
        )(context)

    fn tls_build_finished(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSPacket *tls_build_finished(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]](
            "tls_build_finished"
        )(context)

    fn tls_build_change_cipher_spec(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSPacket *tls_build_change_cipher_spec(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]](
            "tls_build_change_cipher_spec"
        )(context)

    fn tls_build_done(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSPacket *tls_build_done(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]]("tls_build_done")(
            context
        )

    fn tls_build_message(
        self,
        context: UnsafePointer[TLSContext],
        data: UnsafePointer[c_uchar],
        len: c_uint,
    ) -> UnsafePointer[TLSPacket]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSPacket *tls_build_message(struct TLSContext *context, const unsigned char *data, unsigned int len);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_uint) -> UnsafePointer[TLSPacket]
        ]("tls_build_message")(context, data, len)

    fn tls_build_alert(
        self,
        context: UnsafePointer[TLSContext],
        critical: c_char,
        code: c_uchar,
    ) -> UnsafePointer[TLSPacket]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSPacket *tls_build_alert(struct TLSContext *context, char critical, unsigned char code);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_char, c_uchar) -> UnsafePointer[TLSPacket]](
            "tls_build_alert"
        )(context, critical, code)

    fn tls_close_notify(self, context: UnsafePointer[TLSContext]):
        """Documentation to come.

        #### C Function
        ```c
        void tls_close_notify(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext])]("tls_close_notify")(context)

    fn tls_alert(
        self,
        context: UnsafePointer[TLSContext],
        critical: c_char,
        code: c_int,
    ):
        """Documentation to come.

        #### C Function
        ```c
        void tls_alert(struct TLSContext *context, unsigned char critical, int code);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_char, c_int)]("tls_alert")(
            context, critical, code
        )

    fn tls_pending(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Whether `tls_consume_stream()` has data in its buffer that is not processed yet.

        #### C Function
        ```c
        int tls_pending(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_pending")(context)

    fn tls_export_context(
        self,
        context: UnsafePointer[TLSContext],
        buffer: UnsafePointer[c_uchar],
        buf_len: c_uint,
        small_version: c_uchar,
    ) -> c_uint:
        """Documentation to come.

        #### C Function
        ```c
        unsigned int tls_export_context(struct TLSContext *context, unsigned char *buffer, unsigned int buf_len, unsigned char small_version);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_uint, c_uchar) -> c_uint
        ]("tls_export_context")(context, buffer, buf_len, small_version)

    fn tls_import_context(
        self,
        buffer: UnsafePointer[c_uchar],
        buf_len: c_uint,
    ) -> TLSContext:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSContext *tls_import_context(const unsigned char *buffer, unsigned int buf_len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[c_uchar], c_uint) -> TLSContext](
            "tls_import_context"
        )(buffer, buf_len)

    fn tls_is_broken(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_is_broken(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_is_broken")(context)

    fn tls_request_client_certificate(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_request_client_certificate(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_request_client_certificate")(
            context
        )

    fn tls_client_verified(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_client_verified(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_client_verified")(context)

    fn tls_sni_nset(
        self,
        context: UnsafePointer[TLSContext],
        sni: UnsafePointer[c_char],
        len: c_uint,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_sni_nset(struct TLSContext *context, const char *sni, unsigned int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_char], c_uint) -> c_int](
            "tls_sni_nset"
        )(context, sni, len)

    fn tls_srtp_set(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Set DTLS-SRTP mode for DTLS context.

        #### C Function
        ```c
        int tls_srtp_set(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_srtp_set")(context)

    fn tls_srtp_key(
        self,
        context: UnsafePointer[TLSContext],
        buffer: UnsafePointer[c_uchar],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_srtp_key(struct TLSContext *context, unsigned char *buffer);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar]) -> c_int](
            "tls_srtp_key"
        )(context, buffer)

    fn tls_stun_parse(
        self,
        msg: UnsafePointer[c_uchar],
        len: c_int,
        pwd: UnsafePointer[c_char],
        pwd_len: c_int,
        is_ipv6: c_uchar,
        addr: UnsafePointer[c_uchar],
        port: c_uint,
        response_buffer: UnsafePointer[c_uchar],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_stun_parse(unsigned char *msg, int len, char *pwd, int pwd_len, unsigned char is_ipv6, unsigned char *addr, unsigned int port, unsigned char *response_buffer);
        ```
        """
        return self._handle.get_function[
            fn (
                UnsafePointer[c_uchar],
                c_int,
                UnsafePointer[c_char],
                c_int,
                c_uchar,
                UnsafePointer[c_uchar],
                c_uint,
                UnsafePointer[c_uchar],
            ) -> c_int
        ]("tls_stun_parse")(msg, len, pwd, pwd_len, is_ipv6, addr, port, response_buffer)

    fn tls_stun_build(
        self,
        transaction_id: UnsafePointer[c_uchar],
        username: UnsafePointer[c_char],
        username_len: c_int,
        pwd: UnsafePointer[c_char],
        pwd_len: c_int,
        msg: UnsafePointer[c_uchar],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_stun_build(unsigned char transaction_id[12], char *username, int username_len, char *pwd, int pwd_len, unsigned char *msg);
        ```
        """
        return self._handle.get_function[
            fn (
                UnsafePointer[c_uchar],
                UnsafePointer[c_char],
                c_int,
                UnsafePointer[c_char],
                c_int,
                UnsafePointer[c_uchar],
            ) -> c_int
        ]("tls_stun_build")(transaction_id, username, username_len, pwd, pwd_len, msg)

    fn tls_is_stun(self, msg: UnsafePointer[c_uchar], len: c_int) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_is_stun(const unsigned char *msg, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[c_uchar], c_int) -> c_int]("tls_is_stun")(msg, len)

    fn tls_peerconnection_context(
        self,
        active: c_uchar,
        certificate_verify: TLSValidationFn,
        userdata: UnsafePointer[c_void],
    ) -> UnsafePointer[TLSRTCPeerConnection]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSRTCPeerConnection *tls_peerconnection_context(unsigned char active, tls_validation_function certificate_verify, void *userdata);
        ```
        """
        return self._handle.get_function[
            fn (c_uchar, TLSValidationFn, UnsafePointer[c_void]) -> UnsafePointer[TLSRTCPeerConnection]
        ]("tls_peerconnection_context")(active, certificate_verify, userdata)

    fn tls_peerconnection_duplicate(
        self,
        channel: UnsafePointer[TLSRTCPeerConnection],
        userdata: UnsafePointer[c_void],
    ) -> UnsafePointer[TLSRTCPeerConnection]:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSRTCPeerConnection *tls_peerconnection_duplicate(struct TLSRTCPeerConnection *channel, void *userdata);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSRTCPeerConnection], UnsafePointer[c_void]) -> UnsafePointer[TLSRTCPeerConnection]
        ]("tls_peerconnection_duplicate")(channel, userdata)

    fn tls_peerconnection_dtls_context(
        self,
        channel: UnsafePointer[TLSRTCPeerConnection],
    ) -> TLSContext:
        """Documentation to come.

        #### C Function
        ```c
        struct TLSContext *tls_peerconnection_dtls_context(struct TLSRTCPeerConnection *channel);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection]) -> TLSContext](
            "tls_peerconnection_dtls_context"
        )(channel)

    fn tls_peerconnection_remote_credentials(
        self,
        channel: UnsafePointer[TLSRTCPeerConnection],
        remote_username: UnsafePointer[c_char],
        remote_username_len: c_int,
        remote_pwd: UnsafePointer[c_char],
        remote_pwd_len: c_int,
        remote_fingerprint: UnsafePointer[c_char],
        remote_fingerprint_len: c_int,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_peerconnection_remote_credentials(struct TLSRTCPeerConnection *channel, char *remote_username, int remote_username_len, char *remote_pwd, int remote_pwd_len, char *remote_fingerprint, int remote_fingerprint_len);
        ```
        """
        return self._handle.get_function[
            fn (
                UnsafePointer[TLSRTCPeerConnection],
                UnsafePointer[c_char],
                c_int,
                UnsafePointer[c_char],
                c_int,
                UnsafePointer[c_char],
                c_int,
            ) -> c_int
        ]("tls_peerconnection_remote_credentials")(
            channel,
            remote_username,
            remote_username_len,
            remote_pwd,
            remote_pwd_len,
            remote_fingerprint,
            remote_fingerprint_len,
        )

    fn tls_peerconnection_local_pwd(self, channel: UnsafePointer[TLSRTCPeerConnection]) -> UnsafePointer[c_char]:
        """Documentation to come.

        #### C Function
        ```c
        const char *tls_peerconnection_local_pwd(struct TLSRTCPeerConnection *channel);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection]) -> UnsafePointer[c_char]](
            "tls_peerconnection_local_pwd"
        )(channel)

    fn tls_peerconnection_local_username(self, channel: UnsafePointer[TLSRTCPeerConnection]) -> UnsafePointer[c_char]:
        """Documentation to come.

        #### C Function
        ```c
        const char *tls_peerconnection_local_username(struct TLSRTCPeerConnection *channel);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection]) -> UnsafePointer[c_char]](
            "tls_peerconnection_local_username"
        )(channel)

    fn tls_peerconnection_userdata(self, channel: UnsafePointer[TLSRTCPeerConnection]) -> UnsafePointer[c_void]:
        """Documentation to come.

        #### C Function
        ```c
        void *tls_peerconnection_userdata(struct TLSRTCPeerConnection *channel);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection]) -> UnsafePointer[c_void]](
            "tls_peerconnection_userdata"
        )(channel)

    fn tls_peerconnection_load_keys(
        self,
        channel: UnsafePointer[TLSRTCPeerConnection],
        pem_pub_key: UnsafePointer[c_uchar],
        pem_pub_key_size: c_int,
        pem_priv_key: UnsafePointer[c_uchar],
        pem_priv_key_size: c_int,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_peerconnection_load_keys(struct TLSRTCPeerConnection *channel, const unsigned char *pem_pub_key, int pem_pub_key_size, const unsigned char *pem_priv_key, int pem_priv_key_size);
        ```
        """
        return self._handle.get_function[
            fn (
                UnsafePointer[TLSRTCPeerConnection], UnsafePointer[c_uchar], c_int, UnsafePointer[c_uchar], c_int
            ) -> c_int
        ]("tls_peerconnection_load_keys")(channel, pem_pub_key, pem_pub_key_size, pem_priv_key, pem_priv_key_size)

    fn tls_peerconnection_connect(
        self,
        channel: UnsafePointer[TLSRTCPeerConnection],
        write_function: TLSPeerConnectionWriteFn,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_peerconnection_connect(struct TLSRTCPeerConnection *channel, tls_peerconnection_write_function write_function);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection], TLSPeerConnectionWriteFn) -> c_int](
            "tls_peerconnection_connect"
        )(channel, write_function)

    fn tls_peerconnection_iterate(
        self,
        channel: UnsafePointer[TLSRTCPeerConnection],
        buf: UnsafePointer[c_uchar],
        buf_len: c_int,
        addr: UnsafePointer[c_uchar],
        port: c_int,
        is_ipv6: c_uchar,
        write_function: TLSPeerConnectionWriteFn,
        validate_addr: UnsafePointer[c_int],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_peerconnection_iterate(struct TLSRTCPeerConnection *channel, unsigned char *buf, int buf_len, unsigned char *addr, int port, unsigned char is_ipv6, tls_peerconnection_write_function write_function, int *validate_addr);
        ```
        """
        return self._handle.get_function[
            fn (
                UnsafePointer[TLSRTCPeerConnection],
                UnsafePointer[c_uchar],
                c_int,
                UnsafePointer[c_uchar],
                c_int,
                c_uchar,
                TLSPeerConnectionWriteFn,
                UnsafePointer[c_int],
            ) -> c_int
        ]("tls_peerconnection_iterate")(channel, buf, buf_len, addr, port, is_ipv6, write_function, validate_addr)

    fn tls_peerconnection_get_write_msg(
        self,
        channel: UnsafePointer[TLSRTCPeerConnection],
        buf: UnsafePointer[c_uchar],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_peerconnection_get_write_msg(struct TLSRTCPeerConnection *channel, unsigned char *buf);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection], UnsafePointer[c_uchar]) -> c_int](
            "tls_peerconnection_get_write_msg"
        )(channel, buf)

    fn tls_peerconnection_get_read_msg(
        self,
        channel: UnsafePointer[TLSRTCPeerConnection],
        buf: UnsafePointer[c_uchar],
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_peerconnection_get_read_msg(struct TLSRTCPeerConnection *channel, unsigned char *buf);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection], UnsafePointer[c_uchar]) -> c_int](
            "tls_peerconnection_get_read_msg"
        )(channel, buf)

    fn tls_peerconnection_status(self, channel: UnsafePointer[TLSRTCPeerConnection]) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_peerconnection_status(struct TLSRTCPeerConnection *channel);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection]) -> c_int](
            "tls_peerconnection_status"
        )(channel)

    fn tls_destroy_peerconnection(self, channel: UnsafePointer[TLSRTCPeerConnection]):
        """Documentation to come.

        #### C Function
        ```c
        void tls_destroy_peerconnection(struct TLSRTCPeerConnection *channel);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection])]("tls_destroy_peerconnection")(
            channel
        )

    fn tls_cert_fingerprint(
        self,
        pem_data: UnsafePointer[c_uchar],
        len: c_int,
        buffer: UnsafePointer[c_char],
        buf_len: c_uint,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_cert_fingerprint(const char *pem_data, int len, char *buffer, unsigned int buf_len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[c_uchar], c_int, UnsafePointer[c_char], c_uint) -> c_int](
            "tls_cert_fingerprint"
        )(pem_data, len, buffer, buf_len)

    fn tls_load_root_certificates(
        self,
        context: UnsafePointer[TLSContext],
        pem_buffer: UnsafePointer[c_uchar],
        pem_size: c_int,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_load_root_certificates(struct TLSContext *context, const unsigned char *pem_buffer, int pem_size);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int) -> c_int](
            "tls_load_root_certificates"
        )(context, pem_buffer, pem_size)

    fn tls_default_verify(
        self,
        context: UnsafePointer[TLSContext],
        certificate_chain: UnsafePointer[UnsafePointer[TLSCertificate]],
        len: c_int,
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_default_verify(struct TLSContext *context, struct TLSCertificate **certificate_chain, int len);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[UnsafePointer[TLSCertificate]], c_int) -> c_int
        ]("tls_default_verify")(context, certificate_chain, len)

    fn tls_print_certificate(self, fname: UnsafePointer[c_char]):
        """Documentation to come.

        #### C Function
        ```c
        void tls_print_certificate(const char *fname);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[c_char])]("tls_print_certificate")(fname)

    fn tls_add_alpn(self, context: UnsafePointer[TLSContext], alpn: UnsafePointer[c_char]) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_add_alpn(struct TLSContext *context, const char *alpn);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_char]) -> c_int](
            "tls_add_alpn"
        )(context, alpn)

    fn tls_alpn_contains(
        self, context: UnsafePointer[TLSContext], alpn: UnsafePointer[c_char], alpn_size: c_uchar
    ) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_alpn_contains(struct TLSContext *context, const char *alpn, unsigned char alpn_size);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_char], c_uchar) -> c_int](
            "tls_alpn_contains"
        )(context, alpn, alpn_size)

    fn tls_alpn(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[c_char]:
        """Documentation to come.

        #### C Function
        ```c
        const char *tls_alpn(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[c_char]]("tls_alpn")(context)

    fn tls_clear_certificates(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_clear_certificates(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_clear_certificates")(context)

    fn tls_make_ktls(self, context: UnsafePointer[TLSContext], socket: c_int) -> c_int:
        """Documentation to come.

        #### C Function
        ```c
        int tls_make_ktls(struct TLSContext *context, int socket);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_int) -> c_int]("tls_make_ktls")(
            context, socket
        )

    fn tls_unmake_ktls(self, context: UnsafePointer[TLSContext], socket: c_int) -> c_int:
        """Documentation to come.


        ```c
        int tls_unmake_ktls(struct TLSContext *context, int socket);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_int) -> c_int]("tls_unmake_ktls")(
            context, socket
        )

    fn dtls_reset_cookie_secret(self):
        """Creates a new DTLS random cookie secret to be used in HelloVerifyRequest (server-side).
        It is recommended to call this function from time to time, to protect against some
        DoS attacks."""
        return self._handle.get_function[fn ()]("dtls_reset_cookie_secret")()

    fn tls_remote_error(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Documentation to come.

        Args:
            context: Wrapper around the TLSContext pointer.

        #### C Function
        ```c
        int tls_remote_error(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_remote_error")(context)
