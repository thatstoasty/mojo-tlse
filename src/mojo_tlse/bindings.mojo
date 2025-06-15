import os
import pathlib
from sys import ffi
from sys.param_env import env_get_string
from sys.ffi import OpaquePointer, c_char, c_uchar, c_int, c_uint, c_size_t, c_ushort
from memory import UnsafePointer

alias c_void = UInt8


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
"""TLS validation function signature."""
alias TLSPeerConnectionWriteFn = fn (UnsafePointer[TLSRTCPeerConnection], UnsafePointer[c_uchar], c_int) -> c_int


@fieldwise_init
struct TLSE(Movable):
    var _handle: ffi.DLHandle
    """The handle to the TLSE library, used for dynamic linking."""

    fn __init__(out self) raises:
        """"Initialize the TLSE Wrapper.

        This will attempt to load the TLSE library from the path specified by the `TLSE_LIB_PATH` environment variable
        or compilation parameter.

        If the path is not set, it will default to `.pixi/envs/default/lib/libtlse.dylib` relative to the current working directory.

        Raises:
            Error: If the TLSE library cannot be found at the specified path.
        """
        var path = String(env_get_string["TLSE_LIB_PATH", ""]())

        # If the program was not compiled with a specific path, then check if it was set via environment variable.
        if path == "":
            path = os.getenv("TLSE_LIB_PATH")

        # If its not explicitly set, then assume the program is running from the root of the project.
        if path == "":
            path = String(pathlib.cwd() / ".pixi/envs/default/lib/libtlse.dylib")
        
        if not pathlib.Path(path).exists():
            raise Error(
                "The path to the TLSE library is not set. Set the path as either a compilation variable with `-D TLSE_LIB_PATH=/path/to/libtlse.dylib`"
                " or environment variable with `TLSE_LIB_PATH=/path/to/libtlse.dylib`. Please set the TLSE_LIB_PATH environment variable to the path of the TLSE library."
                " The default path is `.pixi/envs/default/lib/libtlse.dylib`, but this error indicates that the dylib did not exist at that location."
            )
        self._handle = ffi.DLHandle(path, ffi.RTLD.LAZY)

    fn tls_create_context(
        self,
        is_server: c_uchar,
        version: c_ushort,
    ) -> UnsafePointer[TLSContext]:
        """Create a new TLS context.

        Args:
            is_server: 1 if the context is for a server, 0 if for a client.
            version: The TLS version to use (e.g., TLSv1.2, TLSv1.3).

        #### C Function
        ```c
        struct TLSContext *tls_create_context(unsigned char is_server, unsigned short version);
        ```
        """
        var f = self._handle.get_function[fn (c_uchar, c_ushort) -> UnsafePointer[TLSContext]]("tls_create_context")
        return f(is_server, version)

    fn tls_make_exportable(
        self,
        context: UnsafePointer[TLSContext],
        exportable_flag: c_uchar,
    ):
        """Set the context as serializable or not. Must be called before negotiation.
        Exportable contexts use a bit more memory, to be able to hold the keys.

        Note that imported keys are not reexportable unless `TLS_REEXPORTABLE` is set.

        Args:
            context: The TLS context to modify.
            exportable_flag: 1 to make the context exportable, 0 otherwise.

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
        sni: UnsafePointer[c_char, mut=False],
    ) -> c_int:
        """Set the Server Name Indication (SNI) for the TLS context.
        
        This is used to indicate the hostname being connected to.

        Args:
            context: The TLS context to modify.
            sni: The server name indication string (hostname).
        
        Returns:
            An integer indicating success (0) or failure (non-zero).

        #### C Function
        ```c
        int tls_sni_set(struct TLSContext *context, const char *sni);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_char, mut=False]) -> c_int
        ]("tls_sni_set")(context, sni)

    fn tls_client_connect(
        self,
        context: UnsafePointer[TLSContext],
    ) -> c_int:
        """Connect to a TLS server. This is the first step in the TLS handshake.

        Args:
            context: The TLS context to use for the connection.
        
        Returns:
            An integer indicating success (0) or failure (non-zero).

        #### C Function
        ```c
        int tls_client_connect(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_client_connect")(context)

    fn tls_get_write_buffer(
        self,
        context: UnsafePointer[TLSContext],
        outlen: UnsafePointer[c_uint],
    ) -> UnsafePointer[c_uchar, mut=False]:
        """Get encrypted data to write, if any. Once you've sent all of it, call
        `tls_buffer_clear()`.

        Args:
            context: The TLS context to retrieve the write buffer from.
            outlen: A pointer to an unsigned integer that will receive the length of the buffer.
        
        Returns:
            A pointer to the write buffer containing encrypted data, or NULL if there's no data to write.

        #### C Function
        ```c
        const unsigned char *tls_get_write_buffer(struct TLSContext *context, unsigned int *outlen);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uint]) -> UnsafePointer[c_uchar, mut=False]
        ]("tls_get_write_buffer")(context, outlen)

    fn tls_buffer_clear(self, context: UnsafePointer[TLSContext]):
        """Clear the write buffer of the TLS context. This should be called after
        sending all data retrieved from `tls_get_write_buffer()`.

        Args:
            context: The TLS context whose write buffer should be cleared.

        #### C Function
        ```c
        void tls_buffer_clear(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext])]("tls_buffer_clear")(context)

    fn tls_established(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Check if the TLS handshake has been completed.

        Returns:
            1 for established, 0 for not established yet, and -1 for a critical error.

        #### C Function
        ```c
        int tls_established(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_established")(context)

    fn tls_consume_stream(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar, mut=False],
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

        Args:
            context: The TLS context to use for consuming the stream.
            buf: A pointer to the buffer containing the data to consume.
            buf_len: The length of the buffer.
            certificate_verify: A function pointer for certificate validation, or NULL if not needed.
        
        Returns:
            An integer indicating the number of bytes consumed from the buffer, or a negative value for an error.

        #### C Function
        ```c
        int tls_consume_stream(struct TLSContext *context, const unsigned char *buf, int buf_len, tls_validation_function certificate_verify);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar, mut=False], c_int, TLSValidationFn) -> c_int
        ]("tls_consume_stream")(context, buf, buf_len, certificate_verify)

    fn tls_read(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar],
        size: c_uint,
    ) -> c_int:
        """Reads any unread decrypted data (see `tls_consume_stream`). If you don't read all of it,
        the remainder will be left in the internal buffers for next tls_read(). Returns -1 for
        fatal error, 0 for no more data, or otherwise the number of bytes copied into the buffer
        (up to a maximum of the given size).

        Args:
            context: The TLS context to read from.
            buf: A pointer to the buffer where the read data will be stored.
            size: The maximum number of bytes to read into the buffer.
        
        Returns:
            An integer indicating the number of bytes read, or a negative value for an error.

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
        data: UnsafePointer[c_uchar, mut=False],
        len: c_uint,
    ) -> c_int:
        """Writes data to the TLS connection. Returns -1 for fatal error, 0 for no more data, or
        otherwise the number of bytes written (up to a maximum of the given size).

        Args:
            context: The TLS context to write to.
            data: A pointer to the data to write.
            len: The length of the data to write.
        
        Returns:
            An integer indicating the number of bytes written, or a negative value for an error.

        #### C Function
        ```c
        int tls_write(struct TLSContext *context, const unsigned char *data, unsigned int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar, mut=False], c_uint) -> c_int](
            "tls_write"
        )(context, data, len)

    fn tls_certificate_is_valid(self, cert: UnsafePointer[TLSCertificate]) -> c_int:
        """Check if the given TLS certificate is valid.

        Args:
            cert: A pointer to the `TLSCertificate` to validate.

        Returns:
            1 if the certificate is valid, 0 if it is not, and -1 for a critical error.

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
        """Check if the given TLS certificate chain is valid.

        Args:
            certificates: A pointer to an array of pointers to `TLSCertificate` objects.
            len: The number of certificates in the chain.
        
        Returns:
            1 if the certificate chain is valid, 0 if it is not, and -1 for a critical error.

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
        subject: UnsafePointer[c_char, mut=False],
    ) -> c_int:
        """Check if the certificate's subject matches the given subject.

        Args:
            cert: A pointer to the `TLSCertificate` to validate.
            subject: A pointer to the subject string to check against the certificate's subject.
        
        Returns:
            1 if the subject matches, 0 if it does not, and -1 for a critical error.

        #### C Function
        ```c
        int tls_certificate_valid_subject(struct TLSCertificate *cert, const char *subject);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[c_char, mut=False]) -> c_int](
            "tls_certificate_valid_subject"
        )(cert, subject)

    fn tls_sni(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[c_char]:
        """Get the Server Name Indication (SNI) set for the TLS context.

        Args:
            context: The TLS context to retrieve the SNI from.
        
        Returns:
            A pointer to the SNI string, or NULL if no SNI is set.

        #### C Function
        ```c
        const char *tls_sni(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[c_char]]("tls_sni")(context)

    fn tls_choose_cipher(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar, mut=False],
        buf_len: c_int,
        scsv_set: UnsafePointer[c_int],
    ) -> c_int:
        """Choose a cipher suite based on the provided buffer and context.

        This function is typically used during the TLS handshake to select a cipher suite
        based on the client's preferences and the server's capabilities.

        Args:
            context: The TLS context in which the cipher suite will be chosen.
            buf: A pointer to the buffer containing the client's cipher preferences.
            buf_len: The length of the buffer.
            scsv_set: A pointer to an integer that will be set if a SCSV (Signaling Cipher Suite Value) is used.
        
        Returns:
            An integer indicating the chosen cipher suite, or a negative value for an error.

        #### C Function
        ```c
        int tls_choose_cipher(struct TLSContext *context, const unsigned char *buf, int buf_len, int *scsv_set);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar], c_int, UnsafePointer[c_int]) -> c_int
        ]("tls_choose_cipher")(context, buf, buf_len, scsv_set)

    fn tls_init(self):
        """Global initialization.
        
        Optional, as it will be called automatically;
        The initialization is not thread-safe, so if you intend to use TLSe
        from multiple threads, you'll need to call `tls_init()` once, from a single thread,
        before using the library.

        #### C Function
        ```c
        void tls_init();
        ```
        """
        return self._handle.get_function[fn ()]("tls_init")()

    fn tls_pem_decode(
        self,
        data_in: UnsafePointer[c_uchar, mut=False],
        input_length: c_uint,
        cert_index: c_int,
        output_len: UnsafePointer[c_uint],
    ) -> UnsafePointer[c_uchar]:
        """Decode a PEM-encoded certificate or key.

        Args:
            data_in: A pointer to the PEM-encoded data.
            input_length: The length of the input data.
            cert_index: The index of the certificate to decode (0 for the first certificate).
            output_len: A pointer to an unsigned integer that will receive the length of the output data.
        
        Returns:
            A pointer to the decoded data. The caller is responsible for freeing this memory.
        
        #### C Function
        ```c
        unsigned char *tls_pem_decode(const unsigned char *data_in, unsigned int input_length, int cert_index, unsigned int *output_len);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[c_uchar, mut=False], c_uint, c_int, UnsafePointer[c_uint]) -> UnsafePointer[c_uchar]
        ]("tls_pem_decode")(data_in, input_length, cert_index, output_len)

    fn tls_create_certificate(self) -> UnsafePointer[TLSCertificate]:
        """Create a new TLS certificate.

        This function initializes a new TLSCertificate structure, which can be used to store
        certificate data such as public keys, private keys, and other relevant information.

        Returns:
            A pointer to the newly created TLSCertificate structure.

        #### C Function
        ```c
        struct TLSCertificate *tls_create_certificate();
        ```
        """
        return self._handle.get_function[fn () -> UnsafePointer[TLSCertificate]]("tls_create_certificate")()

    fn tls_certificate_valid_subject_name(
        self,
        cert_subject: UnsafePointer[c_uchar, mut=False],
        subject: UnsafePointer[c_char, mut=False],
    ) -> c_int:
        """Check if the certificate's subject name matches the given subject.

        Args:
            cert_subject: A pointer to the certificate's subject name.
            subject: A pointer to the subject name to check against the certificate's subject.
        
        Returns:
            1 if the subject name matches, 0 if it does not, and -1 for a critical error.

        #### C Function
        ```c
        int tls_certificate_valid_subject_name(const unsigned char *cert_subject, const char *subject);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[c_uchar, mut=False], UnsafePointer[c_char, mut=False]) -> c_int](
            "tls_certificate_valid_subject_name"
        )(cert_subject, subject)

    fn tls_certificate_set_copy(
        self,
        member: UnsafePointer[UnsafePointer[c_uchar]],
        val: UnsafePointer[c_uchar, mut=False],
        len: c_int,
    ):
        """Set a copy of a member variable in the TLS certificate.

        This function allocates memory for a copy of the provided value and sets the member
        variable to point to this new copy.

        Args:
            member: A pointer to the member variable in the TLS certificate structure.
            val: A pointer to the value to copy.
            len: The length of the value to copy.

        #### C Function
        ```c
        void tls_certificate_set_copy(unsigned char **member, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[UnsafePointer[c_uchar]], UnsafePointer[c_uchar, mut=False], c_int)](
            "tls_certificate_set_copy"
        )(member, val, len)

    fn tls_certificate_set_copy_date(
        self,
        member: UnsafePointer[UnsafePointer[c_uchar]],
        val: UnsafePointer[c_uchar, mut=False],
        len: c_int,
    ):
        """Set a copy of the date member variable in the TLS certificate.
        This function allocates memory for a copy of the provided date value and sets the member
        variable to point to this new copy.

        Args:
            member: A pointer to the member variable in the TLS certificate structure.
            val: A pointer to the date value to copy.
            len: The length of the date value to copy.

        #### C Function
        ```c
        void tls_certificate_set_copy_date(unsigned char **member, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[UnsafePointer[c_uchar]], UnsafePointer[c_uchar, mut=False], c_int)](
            "tls_certificate_set_copy_date"
        )(member, val, len)

    fn tls_certificate_set_key(
        self,
        cert: UnsafePointer[TLSCertificate],
        val: UnsafePointer[c_uchar, mut=False],
        len: c_int,
    ):
        """Set the key for the TLS certificate.
        This function sets the key for the TLS certificate, which is used for encryption and decryption.

        Args:
            cert: A pointer to the TLS certificate structure.
            val: A pointer to the key value to set.
            len: The length of the key value.

        #### C Function
        ```c
        void tls_certificate_set_key(struct TLSCertificate *cert, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[c_uchar, mut=False], c_int)](
            "tls_certificate_set_key"
        )(cert, val, len)

    fn tls_certificate_set_priv(
        self,
        cert: UnsafePointer[TLSCertificate],
        val: UnsafePointer[c_uchar, mut=False],
        len: c_int,
    ):
        """Set the private key for the TLS certificate.

        This function sets the private key for the TLS certificate, which is used for signing and decryption.

        Args:
            cert: A pointer to the TLS certificate structure.
            val: A pointer to the private key value to set.
            len: The length of the private key value.

        #### C Function
        ```c
        void tls_certificate_set_priv(struct TLSCertificate *cert, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[c_uchar, mut=False], c_int)](
            "tls_certificate_set_priv"
        )(cert, val, len)

    fn tls_certificate_set_sign_key(
        self,
        cert: UnsafePointer[TLSCertificate],
        val: UnsafePointer[c_uchar, mut=False],
        len: c_int,
    ):
        """Set the signing key for the TLS certificate.

        This function sets the signing key for the TLS certificate, which is used for signing data.

        Args:
            cert: A pointer to the TLS certificate structure.
            val: A pointer to the signing key value to set.
            len: The length of the signing key value.

        #### C Function
        ```c
        void tls_certificate_set_sign_key(struct TLSCertificate *cert, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[c_uchar, mut=False], c_int)](
            "tls_certificate_set_sign_key"
        )(cert, val, len)

    fn tls_certificate_to_string(
        self,
        cert: UnsafePointer[TLSCertificate],
        buffer: UnsafePointer[c_char],
        len: c_int,
    ) -> UnsafePointer[c_char]:
        """Convert a TLS certificate to a string representation.
        This function serializes the TLS certificate into a human-readable string format.

        Args:
            cert: A pointer to the TLS certificate structure.
            buffer: A pointer to a buffer where the string representation will be stored.
            len: The length of the buffer.
        
        Returns:
            A pointer to the string representation of the TLS certificate.

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
        val: UnsafePointer[c_uchar, mut=False],
        len: c_int,
    ):
        """Set the exponent for the TLS certificate.

        This function sets the exponent for the TLS certificate, which is used for encryption and decryption.

        Args:
            cert: A pointer to the TLS certificate structure.
            val: A pointer to the exponent value to set.
            len: The length of the exponent value.

        #### C Function
        ```c
        void tls_certificate_set_exponent(struct TLSCertificate *cert, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[c_uchar, mut=False], c_int)](
            "tls_certificate_set_exponent"
        )(cert, val, len)

    fn tls_certificate_set_serial(
        self,
        cert: UnsafePointer[TLSCertificate],
        val: UnsafePointer[c_uchar, mut=False],
        len: c_int,
    ):
        """Set the serial number for the TLS certificate.

        This function sets the serial number for the TLS certificate, which is used to uniquely identify the certificate.

        Args:
            cert: A pointer to the TLS certificate structure.
            val: A pointer to the serial number value to set.
            len: The length of the serial number value.

        #### C Function
        ```c
        void tls_certificate_set_serial(struct TLSCertificate *cert, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSCertificate], UnsafePointer[c_uchar, mut=False], c_int)](
            "tls_certificate_set_serial"
        )(cert, val, len)

    fn tls_certificate_set_algorithm(
        self,
        context: UnsafePointer[TLSContext],
        algorithm: UnsafePointer[c_uint],
        val: UnsafePointer[c_uchar, mut=False],
        len: c_int,
    ):
        """Set the algorithm for the TLS certificate.

        Args:
            context: The TLS context in which the certificate is being used.
            algorithm: A pointer to an unsigned integer representing the algorithm to set.
            val: A pointer to the value associated with the algorithm.
            len: The length of the value.

        #### C Function
        ```c
        void tls_certificate_set_algorithm(struct TLSContext *context, unsigned int *algorithm, const unsigned char *val, int len);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uint], UnsafePointer[c_uchar, mut=False], c_int)
        ]("tls_certificate_set_algorithm")(context, algorithm, val, len)

    fn tls_destroy_certificate(self, cert: UnsafePointer[TLSCertificate]):
        """Destroy a TLS certificate.
        This function frees the memory associated with the TLS certificate and its contents.

        Args:
            cert: A pointer to the TLS certificate to destroy.

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
        """Create a new TLS packet.

        Args:
            context: The TLS context in which the packet is being created.
            type: The type of the TLS packet.
            version: The version of the TLS protocol to use.
            payload_size_hint: A hint for the size of the payload.

        Returns:
            A pointer to the newly created `TLSPacket`.

        #### C Function
        ```c
        struct TLSPacket *tls_create_packet(struct TLSContext *context, unsigned char type, unsigned short version, int payload_size_hint);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], c_uchar, c_ushort, c_int) -> UnsafePointer[TLSPacket]
        ]("tls_create_packet")(context, type, version, payload_size_hint)

    fn tls_destroy_packet(self, packet: UnsafePointer[TLSPacket]):
        """Destroy a TLS packet.
        This function frees the memory associated with the TLS packet and its contents.

        Args:
            packet: A pointer to the `TLSPacket` to destroy.

        #### C Function
        ```c
        void tls_destroy_packet(struct TLSPacket *packet);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket])]("tls_destroy_packet")(packet)

    fn tls_packet_update(self, packet: UnsafePointer[TLSPacket]):
        """Update a TLS packet.

        This function updates the internal state of the TLS packet, typically after appending data or modifying its contents.

        Args:
            packet: A pointer to the `TLSPacket` to update.

        #### C Function
        ```c
        void tls_packet_update(struct TLSPacket *packet);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket])]("tls_packet_update")(packet)

    fn tls_packet_append(
        self,
        packet: UnsafePointer[TLSPacket],
        buf: UnsafePointer[c_uchar, mut=False],
        len: c_uint,
    ) -> c_int:
        """Append data to a TLS packet.
        This function appends the specified data to the TLS packet, updating its internal state.

        Args:
            packet: A pointer to the `TLSPacket` to which data will be appended.
            buf: A pointer to the buffer containing the data to append.
            len: The length of the data to append.

        Returns:
            An integer indicating success (0) or failure (non-zero).

        #### C Function
        ```c
        int tls_packet_append(struct TLSPacket *packet, const unsigned char *buf, unsigned int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket], UnsafePointer[c_uchar, mut=False], c_uint) -> c_int](
            "tls_packet_append"
        )(packet, buf, len)

    fn tls_packet_uint8(self, packet: UnsafePointer[TLSPacket], i: c_uchar) -> c_int:
        """Append an unsigned 8-bit integer to a TLS packet.

        This function appends a single byte to the TLS packet, typically used for small values or flags.

        Args:
            packet: A pointer to the `TLSPacket` to which the integer will be appended.
            i: The unsigned 8-bit integer to append.
        
        Returns:
            An integer indicating success (0) or failure (non-zero).

        #### C Function
        ```c
        int tls_packet_uint8(struct TLSPacket *packet, unsigned char i);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket], c_uchar) -> c_int]("tls_packet_uint8")(packet, i)

    fn tls_packet_uint16(self, packet: UnsafePointer[TLSPacket], i: c_ushort) -> c_int:
        """Append an unsigned 16-bit integer to a TLS packet.

        This function appends two bytes to the TLS packet, typically used for small values or flags.

        Args:
            packet: A pointer to the `TLSPacket` to which the integer will be appended.
            i: The unsigned 16-bit integer to append.

        Returns:
            An integer indicating success (0) or failure (non-zero).

        #### C Function
        ```c
        int tls_packet_uint16(struct TLSPacket *packet, unsigned short i);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket], c_ushort) -> c_int]("tls_packet_uint16")(
            packet, i
        )

    fn tls_packet_uint32(self, packet: UnsafePointer[TLSPacket], i: c_uint) -> c_int:
        """Append an unsigned 32-bit integer to a TLS packet.
        This function appends four bytes to the TLS packet, typically used for larger values.

        Args:
            packet: A pointer to the `TLSPacket` to which the integer will be appended.
            i: The unsigned 32-bit integer to append.

        Returns:
            An integer indicating success (0) or failure (non-zero).

        #### C Function
        ```c
        int tls_packet_uint32(struct TLSPacket *packet, unsigned int i);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket], c_uint) -> c_int]("tls_packet_uint32")(packet, i)

    fn tls_packet_uint24(self, packet: UnsafePointer[TLSPacket], i: c_uint) -> c_int:
        """Append an unsigned 24-bit integer to a TLS packet.
        This function appends three bytes to the TLS packet, typically used for medium-sized values.

        Args:
            packet: A pointer to the `TLSPacket` to which the integer will be appended.
            i: The unsigned 24-bit integer to append.
        
        Returns:
            An integer indicating success (0) or failure (non-zero).

        #### C Function
        ```c
        int tls_packet_uint24(struct TLSPacket *packet, unsigned int i);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSPacket], c_uint) -> c_int]("tls_packet_uint24")(packet, i)

    fn tls_random(self, key: UnsafePointer[c_uchar], len: c_int) -> c_int:
        """Generate random bytes.

        This function fills the provided buffer with random bytes.

        Args:
            key: A pointer to the buffer to fill with random bytes.
            len: The length of the buffer.

        Returns:
            An integer indicating success (0) or failure (non-zero).

        #### C Function
        ```c
        int tls_random(unsigned char *key, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[c_uchar], c_int) -> c_int]("tls_random")(key, len)

    fn tls_set_curve(
        self,
        context: UnsafePointer[TLSContext],
        curve: UnsafePointer[ECCCurveParameters, mut=False],
    ) -> UnsafePointer[ECCCurveParameters, mut=False]:
        """Set the elliptic curve parameters for the TLS context.

        This function configures the TLS context to use the specified elliptic curve parameters
        for key exchange and other cryptographic operations.

        Args:
            context: A pointer to the `TLSContext` to modify.
            curve: A pointer to the `ECCCurveParameters` to use.

        Returns:
            A pointer to the `ECCCurveParameters` that were set.

        #### C Function
        ```c
        const struct ECCCurveParameters *tls_set_curve(struct TLSContext *context, const struct ECCCurveParameters *curve);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[ECCCurveParameters, mut=False]) -> UnsafePointer[ECCCurveParameters, mut=False]
        ]("tls_set_curve")(context, curve)

    fn tls_set_default_dhe_pg(
        self,
        context: UnsafePointer[TLSContext],
        p_hex_str: UnsafePointer[c_char, mut=False],
        g_hex_str: UnsafePointer[c_char, mut=False],
    ) -> c_int:
        """Set the default DHE parameters for the TLS context.

        This function configures the TLS context to use the specified DHE parameters
        for key exchange and other cryptographic operations.

        Args:
            context: A pointer to the `TLSContext` to modify.
            p_hex_str: A pointer to the hexadecimal string representation of the prime `p`.
            g_hex_str: A pointer to the hexadecimal string representation of the generator `g`.

        Returns:
            An integer indicating success (0) or failure (non-zero).

        #### C Function
        ```c
        int tls_set_default_dhe_pg(struct TLSContext *context, const char *p_hex_str, const char *g_hex_str);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_char, mut=False], UnsafePointer[c_char, mut=False]) -> c_int
        ]("tls_set_default_dhe_pg")(context, p_hex_str, g_hex_str)

    fn tls_destroy_context(self, context: UnsafePointer[TLSContext]):
        """Destroy the TLS library context.

        This function cleans up any resources used by the TLS library. It should be called when
        the TLS library is no longer needed, typically at the end of the program.
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext])]("tls_destroy_context")(context)

    fn tls_cipher_supported(self, context: UnsafePointer[TLSContext], cipher: c_ushort) -> c_int:
        """Check if a cipher is supported.

        This function checks if the specified cipher is supported by the TLS context.

        Args:
            context: A pointer to the `TLSContext` to check.
            cipher: The cipher to check.

        Returns:
            An integer indicating success (0) or failure (non-zero).

        #### C Function
        ```c
        int tls_cipher_supported(struct TLSContext *context, unsigned short cipher);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_ushort) -> c_int]("tls_cipher_supported")(
            context, cipher
        )

    fn tls_cipher_is_fs(self, context: UnsafePointer[TLSContext], cipher: c_ushort) -> c_int:
        """Check if a cipher is a forward-secure cipher.
        This function checks if the specified cipher is a forward-secure cipher in the TLS context.

        Args:
            context: A pointer to the `TLSContext` to check.
            cipher: The cipher to check.
        
        Returns:
            An integer indicating whether the cipher is forward-secure (1) or not (0), or a negative value for an error.

        #### C Function
        ```c
        int tls_cipher_is_fs(struct TLSContext *context, unsigned short cipher);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_ushort) -> c_int]("tls_cipher_is_fs")(
            context, cipher
        )

    fn tls_cipher_is_ephemeral(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Check if the cipher is ephemeral.
        This function checks if the cipher used in the TLS context is ephemeral, meaning it is not reused across sessions.

        Args:
            context: A pointer to the `TLSContext` to check.

        Returns:
            An integer indicating whether the cipher is ephemeral (1) or not (0), or a negative value for an error.

        #### C Function
        ```c
        int tls_cipher_is_ephemeral(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_cipher_is_ephemeral")(context)

    fn tls_cipher_name(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[c_char, mut=False]:
        """Get the name of the cipher used in the TLS context.

        Args:
            context: A pointer to the `TLSContext` to check.
        
        Returns:
            A pointer to a string containing the name of the cipher used in the TLS context.

        #### C Function
        ```c
        const char *tls_cipher_name(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[c_char, mut=False]]("tls_cipher_name")(
            context
        )

    fn tls_is_ecdsa(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Check if the TLS context is using ECDSA.
        This function checks if the TLS context is configured to use ECDSA (Elliptic Curve Digital Signature Algorithm)
        for its cryptographic operations.

        Args:
            context: A pointer to the `TLSContext` to check.
        
        Returns:
            An integer indicating whether ECDSA is used (1) or not (0), or a negative value for an error.

        #### C Function
        ```c
        int tls_is_ecdsa(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_is_ecdsa")(context)

    fn tls_build_client_key_exchange(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Build a TLS Client Key Exchange packet.

        Constructs a TLS Client Key Exchange packet, which is used by the client to send
        key exchange information to the server during the TLS handshake.

        Args:
            context: A pointer to the `TLSContext` in which the key exchange will be built.
        
        Returns:
            A pointer to the newly created `TLSPacket` containing the client key exchange data.

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
        """Build a TLS Server Key Exchange packet.
        Constructs a TLS Server Key Exchange packet, which is used by the server to send
        key exchange information to the client during the TLS handshake.

        Args:
            context: A pointer to the `TLSContext` in which the key exchange will be built.
            method: An integer indicating the key exchange method to use (e.g., DHE, ECDHE).
        
        Returns:
            A pointer to the newly created `TLSPacket` containing the server key exchange data.

        #### C Function
        ```c
        struct TLSPacket *tls_build_server_key_exchange(struct TLSContext *context, int method);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_int) -> UnsafePointer[TLSPacket]](
            "tls_build_server_key_exchange"
        )(context, method)

    fn tls_build_hello(self, context: UnsafePointer[TLSContext], tls13_downgrade: c_int) -> UnsafePointer[TLSPacket]:
        """Build a TLS Hello packet.
        Constructs a TLS Hello packet, which is the first message sent by the client
        during the TLS handshake. It contains information about the client's supported protocols and ciphers.

        Args:
            context: A pointer to the `TLSContext` in which the hello packet will be built.
            tls13_downgrade: An integer indicating whether to downgrade to TLS 1.3 (1) or not (0).
        
        Returns:
            A pointer to the newly created `TLSPacket` containing the hello data.
        
        #### C Function
        ```c
        struct TLSPacket *tls_build_hello(struct TLSContext *context, int tls13_downgrade);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_int) -> UnsafePointer[TLSPacket]](
            "tls_build_hello"
        )(context, tls13_downgrade)

    fn tls_certificate_request(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Request a TLS certificate from the client.
        Constructs a TLS Certificate Request packet, which is sent by the server to the client
        during the TLS handshake to request the client's certificate for authentication.

        Args:
            context: A pointer to the `TLSContext` in which the certificate request will be built.
        
        Returns:
            A pointer to the newly created `TLSPacket` containing the certificate request data.

        #### C Function
        ```c
        struct TLSPacket *tls_certificate_request(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]](
            "tls_certificate_request"
        )(context)

    fn tls_build_verify_request(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Build a TLS Verify Request packet.
        Constructs a TLS Verify Request packet, which is used by the server to request
        a signature from the client to verify its identity during the TLS handshake.

        Args:
            context: A pointer to the `TLSContext` in which the verify request will be built.
        
        Returns:
            A pointer to the newly created `TLSPacket` containing the verify request data.

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
        buf: UnsafePointer[c_uchar, mut=False],
        buf_len: c_int,
        write_packets: UnsafePointer[c_uint],
        dtls_verified: UnsafePointer[c_uint],
    ) -> c_int:
        """Parse a TLS Hello packet.
        This function processes a TLS Hello packet received from the client or server,
        extracting the necessary information such as supported protocols, ciphers, and extensions.

        Args:
            context: A pointer to the `TLSContext` in which the hello packet will be parsed.
            buf: A pointer to the buffer containing the hello packet data.
            buf_len: The length of the buffer containing the hello packet data.
            write_packets: A pointer to an unsigned integer that will receive the number of packets written.
            dtls_verified: A pointer to an unsigned integer that will receive verification status for DTLS.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates a critical error.

        #### C Function
        ```c
        int tls_parse_hello(struct TLSContext *context, const unsigned char *buf, int buf_len, unsigned int *write_packets, unsigned int *dtls_verified);
        ```
        """
        return self._handle.get_function[
            fn (
                UnsafePointer[TLSContext], UnsafePointer[c_uchar, mut=False], c_int, UnsafePointer[c_uint], UnsafePointer[c_uint]
            ) -> c_int
        ]("tls_parse_hello")(context, buf, buf_len, write_packets, dtls_verified)

    fn tls_parse_certificate(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar, mut=False],
        buf_len: c_int,
        is_client: c_int,
    ) -> c_int:
        """Parse a TLS Certificate packet.
        This function processes a TLS Certificate packet received from the client or server,
        extracting the certificate data and validating it against the context's expectations.

        Args:
            context: A pointer to the `TLSContext` in which the certificate packet will be parsed.
            buf: A pointer to the buffer containing the certificate packet data.
            buf_len: The length of the buffer containing the certificate packet data.
            is_client: An integer indicating whether the certificate is from a client (1) or server (0).
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates a critical error.

        #### C Function
        ```c
        int tls_parse_certificate(struct TLSContext *context, const unsigned char *buf, int buf_len, int is_client);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar, mut=False], c_int, c_int) -> c_int](
            "tls_parse_certificate"
        )(context, buf, buf_len, is_client)

    fn tls_parse_server_key_exchange(
        self, context: UnsafePointer[TLSContext], buf: UnsafePointer[c_uchar, mut=False], buf_len: c_int
    ) -> c_int:
        """Parse a TLS Server Key Exchange packet.
        This function processes a TLS Server Key Exchange packet received from the server,
        extracting the key exchange parameters and validating them against the context's expectations.

        Args:
            context: A pointer to the `TLSContext` in which the server key exchange packet will be parsed.
            buf: A pointer to the buffer containing the server key exchange packet data.
            buf_len: The length of the buffer containing the server key exchange packet data.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates a critical error.

        #### C Function
        ```c
        int tls_parse_server_key_exchange(struct TLSContext *context, const unsigned char *buf, int buf_len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar, mut=False], c_int) -> c_int](
            "tls_parse_server_key_exchange"
        )(context, buf, buf_len)

    fn tls_parse_client_key_exchange(
        self, context: UnsafePointer[TLSContext], buf: UnsafePointer[c_uchar, mut=False], buf_len: c_int
    ) -> c_int:
        """Parse a TLS Client Key Exchange packet.
        This function processes a TLS Client Key Exchange packet received from the client,
        extracting the key exchange parameters and validating them against the context's expectations.

        Args:
            context: A pointer to the `TLSContext` in which the client key exchange packet will be parsed.
            buf: A pointer to the buffer containing the client key exchange packet data.
            buf_len: The length of the buffer containing the client key exchange packet data.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates a critical error.

        #### C Function
        ```c
        int tls_parse_client_key_exchange(struct TLSContext *context, const unsigned char *buf, int buf_len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar, mut=False], c_int) -> c_int](
            "tls_parse_client_key_exchange"
        )(context, buf, buf_len)

    fn tls_parse_server_hello_done(
        self, context: UnsafePointer[TLSContext], buf: UnsafePointer[c_uchar, mut=False], buf_len: c_int
    ) -> c_int:
        """Parse a TLS Server Hello Done packet.
        This function processes a TLS Server Hello Done packet received from the server,
        indicating that the server has completed its part of the handshake.

        Args:
            context: A pointer to the `TLSContext` in which the server hello done packet will be parsed.
            buf: A pointer to the buffer containing the server hello done packet data.
            buf_len: The length of the buffer containing the server hello done packet data.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates a critical error.

        #### C Function
        ```c
        int tls_parse_server_hello_done(struct TLSContext *context, const unsigned char *buf, int buf_len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar, mut=False], c_int) -> c_int](
            "tls_parse_server_hello_done"
        )(context, buf, buf_len)

    fn tls_parse_finished(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar, mut=False],
        buf_len: c_int,
        write_packets: UnsafePointer[c_uint],
    ) -> c_int:
        """Parse a TLS Finished packet.
        This function processes a TLS Finished packet received from the client or server,
        which contains a hash of all previous handshake messages to verify the integrity of the handshake.

        Args:
            context: A pointer to the `TLSContext` in which the finished packet will be parsed.
            buf: A pointer to the buffer containing the finished packet data.
            buf_len: The length of the buffer containing the finished packet data.
            write_packets: A pointer to an unsigned integer that will receive the number of packets written.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates a critical error.

        #### C Function
        ```c
        int tls_parse_finished(struct TLSContext *context, const unsigned char *buf, int buf_len, unsigned int *write_packets);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar, mut=False], c_int, UnsafePointer[c_uint]) -> c_int
        ]("tls_parse_finished")(context, buf, buf_len, write_packets)

    fn tls_parse_verify(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar, mut=False],
        buf_len: c_int,
    ) -> c_int:
        """Parse a TLS Verify packet.
        This function processes a TLS Verify packet received from the client, which contains
        a signature to verify the client's identity during the TLS handshake.

        Args:
            context: A pointer to the `TLSContext` in which the verify packet will be parsed.
            buf: A pointer to the buffer containing the verify packet data.
            buf_len: The length of the buffer containing the verify packet data.

        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates a critical error.

        #### C Function
        ```c
        int tls_parse_verify(struct TLSContext *context, const unsigned char *buf, int buf_len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar, mut=False], c_int) -> c_int](
            "tls_parse_verify"
        )(context, buf, buf_len)

    fn tls_parse_payload(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar, mut=False],
        buf_len: c_int,
        certificate_verify: TLSValidationFn,
    ) -> c_int:
        """Parse a TLS payload.
        This function processes a TLS payload, which may contain various types of data such as
        application data, alerts, or handshake messages. It validates the payload and updates the context accordingly.

        Args:
            context: A pointer to the `TLSContext` in which the payload will be parsed.
            buf: A pointer to the buffer containing the payload data.
            buf_len: The length of the buffer containing the payload data.
            certificate_verify: A function pointer for certificate validation.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates a critical error.

        #### C Function
        ```c
        int tls_parse_payload(struct TLSContext *context, const unsigned char *buf, int buf_len, tls_validation_function certificate_verify);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar, mut=False], c_int, TLSValidationFn) -> c_int
        ]("tls_parse_payload")(context, buf, buf_len, certificate_verify)

    fn tls_parse_message(
        self,
        context: UnsafePointer[TLSContext],
        buf: UnsafePointer[c_uchar],
        buf_len: c_int,
        certificate_verify: TLSValidationFn,
    ) -> c_int:
        """Parse a TLS message.
        This function processes a TLS message, which may contain various types of data such as
        application data, alerts, or handshake messages. It validates the message and updates the context accordingly.

        Args:
            context: A pointer to the `TLSContext` in which the message will be parsed.
            buf: A pointer to the buffer containing the message data.
            buf_len: The length of the buffer containing the message data.
            certificate_verify: A function pointer for certificate validation.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates a critical error.

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
        """Verify the signature of a TLS certificate against its parent certificate.
        This function checks if the signature of the given TLS certificate is valid according to the
        parent certificate's public key. It is typically used during the certificate validation process.

        Args:
            cert: A pointer to the `TLSCertificate` whose signature is to be verified.
            parent: A pointer to the `TLSCertificate` that serves as the parent for verification.

        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates a critical error.

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
        """Check if a certificate chain is valid.
        This function verifies the validity of a chain of TLS certificates against the context's expectations.

        Args:
            context: A pointer to the `TLSContext` in which the certificate chain will be validated.
            certificates: A pointer to an array of pointers to `TLSCertificate` objects representing the chain.
            len: The length of the certificate chain (number of certificates).

        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates a critical error.

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
        """Check if a certificate chain is valid as a root.
        This function verifies if a chain of TLS certificates can be considered valid as a root certificate chain.

        Args:
            context: A pointer to the `TLSContext` in which the certificate chain will be validated.
            certificates: A pointer to an array of pointers to `TLSCertificate` objects representing the chain.
            len: The length of the certificate chain (number of certificates).
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates a critical error.

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
        pem_buffer: UnsafePointer[c_uchar, mut=False],
        pem_size: c_int,
    ) -> c_int:
        """Add a certificate or a certificate chain to the given context, in PEM form.
        Returns a negative value (TLS_GENERIC_ERROR etc.) on error, 0 if there were no
        certificates in the buffer, or the number of loaded certificates on success.

        Args:
            context: A pointer to the `TLSContext` to which the certificates will be added.
            pem_buffer: A pointer to the buffer containing the PEM-encoded certificates.
            pem_size: The size of the PEM buffer.
        
        Returns:
            An integer indicating the number of certificates loaded (positive value), 0 if no certificates were found,
            or a negative value indicating an error.

        #### C Function
        ```c
        int tls_load_certificates(struct TLSContext *context, const unsigned char *pem_buffer, int pem_size);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar, mut=False], c_int) -> c_int](
            "tls_load_certificates"
        )(context, pem_buffer, pem_size)

    fn tls_load_private_key(
        self,
        context: UnsafePointer[TLSContext],
        pem_buffer: UnsafePointer[c_uchar, mut=False],
        pem_size: c_int,
    ) -> c_int:
        """Add a private key to the given context, in PEM form. Returns a negative value
        (`TLSResult.GENERIC_ERROR` etc.) on error, 0 if there was no private key in the
        buffer, or 1 on success.

        Args:
            context: A pointer to the `TLSContext` to which the private key will be added.
            pem_buffer: A pointer to the buffer containing the PEM-encoded private key.
            pem_size: The size of the PEM buffer.
        
        Returns:
            An integer indicating success (1) if a private key was loaded, 0 if no private key was found,
            or a negative value indicating an error.

        #### C Function
        ```c
        int tls_load_private_key(struct TLSContext *context, const unsigned char *pem_buffer, int pem_size);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar, mut=False], c_int) -> c_int](
            "tls_load_private_key"
        )(context, pem_buffer, pem_size)

    fn tls_build_certificate(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Build a TLS Certificate packet.
        Constructs a TLS Certificate packet, which is used by the server to send its certificate
        to the client during the TLS handshake.

        Args:
            context: A pointer to the `TLSContext` in which the certificate will be built.

        Returns:
            A pointer to the newly created `TLSPacket` containing the certificate data.

        #### C Function
        ```c
        struct TLSPacket *tls_build_certificate(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]](
            "tls_build_certificate"
        )(context)

    fn tls_build_finished(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Build a TLS Finished packet.
        Constructs a TLS Finished packet, which is used to indicate that the handshake is complete
        and that the client or server has verified all previous handshake messages.

        Args:
            context: A pointer to the `TLSContext` in which the finished packet will be built.
        
        Returns:
            A pointer to the newly created `TLSPacket` containing the finished data.

        #### C Function
        ```c
        struct TLSPacket *tls_build_finished(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]](
            "tls_build_finished"
        )(context)

    fn tls_build_change_cipher_spec(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Build a TLS Change Cipher Spec packet.
        Constructs a TLS Change Cipher Spec packet, which is used to indicate that the sender
        is switching to the newly negotiated cipher suite.

        Args:
            context: A pointer to the `TLSContext` in which the change cipher spec packet will be built.

        Returns:
            A pointer to the newly created `TLSPacket` containing the change cipher spec data.

        #### C Function
        ```c
        struct TLSPacket *tls_build_change_cipher_spec(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]](
            "tls_build_change_cipher_spec"
        )(context)

    fn tls_build_done(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[TLSPacket]:
        """Build a TLS Done packet.
        Constructs a TLS Done packet, which is used to indicate that the sender has finished
        its part of the handshake.

        Args:
            context: A pointer to the `TLSContext` in which the done packet will be built.

        Returns:
            A pointer to the newly created `TLSPacket` containing the done data.

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
        """Build a TLS Message packet.
        Constructs a TLS Message packet, which is used to encapsulate application data
        to be sent over the TLS connection.

        Args:
            context: A pointer to the `TLSContext` in which the message will be built.
            data: A pointer to the buffer containing the application data.
            len: The length of the application data.

        Returns:
            A pointer to the newly created `TLSPacket` containing the message data.

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
        """Build a TLS Alert packet.
        Constructs a TLS Alert packet, which is used to convey alert messages
        between the client and server.

        Args:
            context: A pointer to the `TLSContext` in which the alert packet will be built.
            critical: A flag indicating whether the alert is critical (1) or not (0).
            code: The alert code to be sent.

        Returns:
            A pointer to the newly created `TLSPacket` containing the alert data.

        #### C Function
        ```c
        struct TLSPacket *tls_build_alert(struct TLSContext *context, char critical, unsigned char code);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_char, c_uchar) -> UnsafePointer[TLSPacket]](
            "tls_build_alert"
        )(context, critical, code)

    fn tls_close_notify(self, context: UnsafePointer[TLSContext]) -> None:
        """Build a TLS Close Notify packet.
        Constructs a TLS Close Notify packet, which is used to indicate that the sender
        is closing the TLS connection.

        Args:
            context: A pointer to the `TLSContext` in which the close notify packet will be built.

        #### C Function
        ```c
        void tls_close_notify(struct TLSContext *context);
        ```
        """
        _ = self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_void]("tls_close_notify")(context)

    fn tls_alert(
        self,
        context: UnsafePointer[TLSContext],
        critical: c_char,
        code: c_int,
    ) -> None:
        """Send a TLS Alert.
        This function sends a TLS Alert message, which can be used to notify the peer about
        an error or a specific condition in the TLS connection.

        Args:
            context: A pointer to the `TLSContext` in which the alert will be sent.
            critical: A flag indicating whether the alert is critical (1) or not (0).
            code: The alert code to be sent.

        #### C Function
        ```c
        void tls_alert(struct TLSContext *context, unsigned char critical, int code);
        ```
        """
        _ = self._handle.get_function[fn (UnsafePointer[TLSContext], c_char, c_int) -> c_void]("tls_alert")(
            context, critical, code
        )

    fn tls_pending(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Checks whether `tls_consume_stream()` has data in its buffer that is not processed yet.

        Args:
            context: A pointer to the `TLSContext` to check for pending data.
        
        Returns:
            An integer indicating the number of bytes pending in the TLS context. A value of 0 indicates no pending data.

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
        """Exports the TLS context to a buffer.

        Args:
            context: A pointer to the `TLSContext` to export.
            buffer: A pointer to the buffer to receive the exported data.
            buf_len: The length of the buffer.
            small_version: A flag indicating whether to use the small version of the context.

        Returns:
            The length of the exported data.

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
        buffer: UnsafePointer[c_uchar, mut=False],
        buf_len: c_uint,
    ) -> TLSContext:
        """Imports a TLS context from a buffer.

        Args:
            buffer: A pointer to the buffer containing the exported TLS context data.
            buf_len: The length of the buffer.

        Returns:
            A pointer to the newly created `TLSContext` containing the imported data.

        #### C Function
        ```c
        struct TLSContext *tls_import_context(const unsigned char *buffer, unsigned int buf_len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[c_uchar, mut=False], c_uint) -> TLSContext](
            "tls_import_context"
        )(buffer, buf_len)

    fn tls_is_broken(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Checks whether the TLS connection is broken.

        Args:
            context: A pointer to the `TLSContext` to check for a broken connection.
        
        Returns:
            An integer indicating whether the TLS connection is broken (1) or not (0). A negative value indicates an error.

        #### C Function
        ```c
        int tls_is_broken(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_is_broken")(context)

    fn tls_request_client_certificate(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Requests a client certificate.

        Args:
            context: A pointer to the `TLSContext` in which the request will be made.

        Returns:
            An integer indicating the result of the operation.

        #### C Function
        ```c
        int tls_request_client_certificate(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_request_client_certificate")(
            context
        )

    fn tls_client_verified(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Checks whether the client certificate has been verified.

        Args:
            context: A pointer to the `TLSContext` to check for client certificate verification.

        Returns:
            An integer indicating whether the client certificate is verified (1) or not (0). A negative value indicates an error.

        #### C Function
        ```c
        int tls_client_verified(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_client_verified")(context)

    fn tls_sni_nset(
        self,
        context: UnsafePointer[TLSContext],
        sni: UnsafePointer[c_char, mut=False],
        len: c_uint,
    ) -> c_int:
        """Sets the Server Name Indication (SNI) for the TLS context.

        Args:
            context: A pointer to the `TLSContext` to modify.
            sni: A pointer to the SNI string.
            len: The length of the SNI string.

        Returns:
            An integer indicating the result of the operation.

        #### C Function
        ```c
        int tls_sni_nset(struct TLSContext *context, const char *sni, unsigned int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_char, mut=False], c_uint) -> c_int](
            "tls_sni_nset"
        )(context, sni, len)

    fn tls_srtp_set(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Set DTLS-SRTP mode for DTLS context.

        Args:
            context: A pointer to the `TLSContext` in which SRTP mode will be set.

        Returns:
            An integer indicating the result of the operation.

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
        """Retrieves the SRTP key for the DTLS context.

        Args:
            context: A pointer to the `TLSContext` to retrieve the SRTP key from.
            buffer: A pointer to the buffer to receive the SRTP key.

        Returns:
            An integer indicating the result of the operation.

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
        """Parses a STUN message.
        This function processes a STUN message, extracting relevant information such as the
        username, password, and other parameters needed for STUN communication.

        Args:
            msg: A pointer to the buffer containing the STUN message.
            len: The length of the STUN message.
            pwd: A pointer to the password used for STUN authentication.
            pwd_len: The length of the password.
            is_ipv6: A flag indicating whether the address is IPv6 (1) or not (0).
            addr: A pointer to the buffer to receive the address.
            port: The port number associated with the STUN message.
            response_buffer: A pointer to the buffer to receive the response.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

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
        """Builds a STUN message.
        This function constructs a STUN message using the provided transaction ID, username, password,
        and other parameters. The resulting message can be used for STUN communication.

        Args:
            transaction_id: A pointer to the buffer containing the transaction ID.
            username: A pointer to the username string.
            username_len: The length of the username string.
            pwd: A pointer to the password string.
            pwd_len: The length of the password string.
            msg: A pointer to the buffer to receive the constructed STUN message.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

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

    fn tls_is_stun(self, msg: UnsafePointer[c_uchar, mut=False], len: c_int) -> c_int:
        """Checks whether the message is a STUN message.

        Args:
            msg: A pointer to the buffer containing the message to check.
            len: The length of the message buffer.
        
        Returns:
            An integer indicating whether the message is a STUN message (1) or not (0). A negative value indicates an error.

        #### C Function
        ```c
        int tls_is_stun(const unsigned char *msg, int len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[c_uchar, mut=False], c_int) -> c_int]("tls_is_stun")(msg, len)

    fn tls_peerconnection_context(
        self,
        active: c_uchar,
        certificate_verify: TLSValidationFn,
        userdata: UnsafePointer[c_void],
    ) -> UnsafePointer[TLSRTCPeerConnection]:
        """Create a new TLS RTCPeerConnection context.
        This function initializes a new TLS RTCPeerConnection context, which is used for secure communication
        over the Real-Time Transport Protocol (RTP) using DTLS.

        Args:
            active: A flag indicating whether the connection is active (1) or not (0).
            certificate_verify: A function pointer for certificate validation.
            userdata: A pointer to user-defined data that can be associated with the connection.

        Returns:
            A pointer to the newly created `TLSRTCPeerConnection` context.

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
        """Duplicate a TLS RTCPeerConnection context.
        This function creates a duplicate of an existing TLS RTCPeerConnection context, allowing for
        multiple connections to be managed independently while sharing the same underlying context.

        Args:
            channel: A pointer to the existing `TLSRTCPeerConnection` context to duplicate.
            userdata: A pointer to user-defined data that can be associated with the new connection.

        Returns:
            A pointer to the newly created `TLSRTCPeerConnection` context that is a duplicate of the original.

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
        """Retrieve the DTLS context from a TLS RTCPeerConnection.
        This function returns the DTLS context associated with a given TLS RTCPeerConnection.

        Args:
            channel: A pointer to the `TLSRTCPeerConnection` context from which to retrieve the DTLS context.

        Returns:
            A pointer to the `TLSContext` associated with the specified TLS RTCPeerConnection.

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
        """Set remote credentials for a TLS RTCPeerConnection.
        This function sets the remote username, password, and fingerprint for a TLS RTCPeerConnection,
        which are used for authentication and secure communication.

        Args:
            channel: A pointer to the `TLSRTCPeerConnection` context for which to set the remote credentials.
            remote_username: A pointer to the remote username string.
            remote_username_len: The length of the remote username string.
            remote_pwd: A pointer to the remote password string.
            remote_pwd_len: The length of the remote password string.
            remote_fingerprint: A pointer to the remote fingerprint string.
            remote_fingerprint_len: The length of the remote fingerprint string.

        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

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

    fn tls_peerconnection_local_pwd(self, channel: UnsafePointer[TLSRTCPeerConnection]) -> UnsafePointer[c_char, mut=False]:
        """Documentation to come.
        This function retrieves the local password (PWD) used for authentication in a TLS RTCPeerConnection.

        Args:
            channel: A pointer to the `TLSRTCPeerConnection` context from which to retrieve the local password.

        Returns:
            A pointer to the local password string used in the TLS RTCPeerConnection.

        #### C Function
        ```c
        const char *tls_peerconnection_local_pwd(struct TLSRTCPeerConnection *channel);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection]) -> UnsafePointer[c_char, mut=False]](
            "tls_peerconnection_local_pwd"
        )(channel)

    fn tls_peerconnection_local_username(self, channel: UnsafePointer[TLSRTCPeerConnection]) -> UnsafePointer[c_char, mut=False]:
        """Checks the local username of a TLS RTCPeerConnection.
        This function retrieves the local username used for authentication in a TLS RTCPeerConnection.

        Args:
            channel: A pointer to the `TLSRTCPeerConnection` context from which to retrieve the local username.
        
        Returns:
            A pointer to the local username string used in the TLS RTCPeerConnection.

        #### C Function
        ```c
        const char *tls_peerconnection_local_username(struct TLSRTCPeerConnection *channel);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection]) -> UnsafePointer[c_char, mut=False]](
            "tls_peerconnection_local_username"
        )(channel)

    fn tls_peerconnection_userdata(self, channel: UnsafePointer[TLSRTCPeerConnection]) -> UnsafePointer[c_void]:
        """Retrieve user-defined data associated with a TLS RTCPeerConnection.

        Args:
            channel: A pointer to the `TLSRTCPeerConnection` context from which to retrieve the user data.

        Returns:
            A pointer to the user-defined data associated with the specified TLS RTCPeerConnection.

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
        pem_pub_key: UnsafePointer[c_uchar, mut=False],
        pem_pub_key_size: c_int,
        pem_priv_key: UnsafePointer[c_uchar, mut=False],
        pem_priv_key_size: c_int,
    ) -> c_int:
        """Load public and private keys into a TLS RTCPeerConnection.
        This function loads the public and private keys in PEM format into a TLS RTCPeerConnection context,
        which is necessary for establishing secure communication.

        Args:
            channel: A pointer to the `TLSRTCPeerConnection` context into which the keys will be loaded.
            pem_pub_key: A pointer to the buffer containing the PEM-encoded public key.
            pem_pub_key_size: The size of the PEM public key buffer.
            pem_priv_key: A pointer to the buffer containing the PEM-encoded private key.
            pem_priv_key_size: The size of the PEM private key buffer.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

        #### C Function
        ```c
        int tls_peerconnection_load_keys(struct TLSRTCPeerConnection *channel, const unsigned char *pem_pub_key, int pem_pub_key_size, const unsigned char *pem_priv_key, int pem_priv_key_size);
        ```
        """
        return self._handle.get_function[
            fn (
                UnsafePointer[TLSRTCPeerConnection], UnsafePointer[c_uchar, mut=False], c_int, UnsafePointer[c_uchar, mut=False], c_int
            ) -> c_int
        ]("tls_peerconnection_load_keys")(channel, pem_pub_key, pem_pub_key_size, pem_priv_key, pem_priv_key_size)

    fn tls_peerconnection_connect(
        self,
        channel: UnsafePointer[TLSRTCPeerConnection],
        write_function: TLSPeerConnectionWriteFn,
    ) -> c_int:
        """Establish a connection for a TLS RTCPeerConnection.
        This function initiates the connection process for a TLS RTCPeerConnection, allowing it to
        communicate securely over the network.

        Args:
            channel: A pointer to the `TLSRTCPeerConnection` context to connect.
            write_function: A function pointer that will be called to write data to the network.

        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

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
        """Iterate over the network addresses for a TLS RTCPeerConnection.
        This function processes the network addresses associated with a TLS RTCPeerConnection,
        allowing for secure communication over the specified addresses.

        Args:
            channel: A pointer to the `TLSRTCPeerConnection` context to iterate.
            buf: A pointer to the buffer to store the serialized address information.
            buf_len: The length of the buffer.
            addr: A pointer to the address to iterate.
            port: The port number to use for the connection.
            is_ipv6: A flag indicating whether the address is IPv6.
            write_function: A function pointer to the write function to use for the connection.
            validate_addr: A pointer to an integer to store the validation result.

        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

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
        """Get the next message to write for a TLS RTCPeerConnection.
        This function retrieves the next message that needs to be written to the network for a TLS RTCPeerConnection.

        Args:
            channel: A pointer to the `TLSRTCPeerConnection` context from which to retrieve the write message.
            buf: A pointer to the buffer to receive the write message.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

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
        """Get the next message to read for a TLS RTCPeerConnection.
        This function retrieves the next message that has been read from the network for a TLS RTCPeerConnection.

        Args:
            channel: A pointer to the `TLSRTCPeerConnection` context from which to retrieve the read message.
            buf: A pointer to the buffer to receive the read message.

        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

        #### C Function
        ```c
        int tls_peerconnection_get_read_msg(struct TLSRTCPeerConnection *channel, unsigned char *buf);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection], UnsafePointer[c_uchar]) -> c_int](
            "tls_peerconnection_get_read_msg"
        )(channel, buf)

    fn tls_peerconnection_status(self, channel: UnsafePointer[TLSRTCPeerConnection]) -> c_int:
        """Get the status of a TLS RTCPeerConnection.
        This function retrieves the current status of a TLS RTCPeerConnection, which can indicate whether
        the connection is active, closed, or in an error state.

        Args:
            channel: A pointer to the `TLSRTCPeerConnection` context for which to retrieve the status.

        Returns:
            An integer indicating the status of the TLS RTCPeerConnection. A value of 0 indicates success, while
            other values may indicate different states or errors.

        #### C Function
        ```c
        int tls_peerconnection_status(struct TLSRTCPeerConnection *channel);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection]) -> c_int](
            "tls_peerconnection_status"
        )(channel)

    fn tls_destroy_peerconnection(self, channel: UnsafePointer[TLSRTCPeerConnection]) -> None:
        """Destroy a TLS RTCPeerConnection context.
        This function releases the resources associated with a TLS RTCPeerConnection context,
        effectively closing the connection and freeing any allocated memory.

        Args:
            channel: A pointer to the `TLSRTCPeerConnection` context to destroy.

        #### C Function
        ```c
        void tls_destroy_peerconnection(struct TLSRTCPeerConnection *channel);
        ```
        """
        _ = self._handle.get_function[fn (UnsafePointer[TLSRTCPeerConnection]) -> c_void]("tls_destroy_peerconnection")(
            channel
        )

    fn tls_cert_fingerprint(
        self,
        pem_data: UnsafePointer[c_uchar, mut=False],
        len: c_int,
        buffer: UnsafePointer[c_char],
        buf_len: c_uint,
    ) -> c_int:
        """Get the fingerprint of a TLS certificate.
        This function computes the fingerprint of a TLS certificate in PEM format and stores it in the provided buffer.

        Args:
            pem_data: A pointer to the buffer containing the PEM-encoded certificate data.
            len: The length of the PEM data buffer.
            buffer: A pointer to the buffer where the fingerprint will be stored.
            buf_len: The length of the buffer for the fingerprint.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

        #### C Function
        ```c
        int tls_cert_fingerprint(const char *pem_data, int len, char *buffer, unsigned int buf_len);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[c_uchar, mut=False], c_int, UnsafePointer[c_char], c_uint) -> c_int](
            "tls_cert_fingerprint"
        )(pem_data, len, buffer, buf_len)

    fn tls_load_root_certificates(
        self,
        context: UnsafePointer[TLSContext],
        pem_buffer: UnsafePointer[c_uchar, mut=False],
        pem_size: c_int,
    ) -> c_int:
        """Load root certificates into a TLS context.
        This function loads root certificates from a PEM-encoded buffer into the specified TLS context,
        allowing the context to verify the authenticity of peer certificates during TLS handshakes.

        Args:
            context: A pointer to the `TLSContext` in which the root certificates will be loaded.
            pem_buffer: A pointer to the buffer containing the PEM-encoded root certificates.
            pem_size: The size of the PEM buffer.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

        #### C Function
        ```c
        int tls_load_root_certificates(struct TLSContext *context, const unsigned char *pem_buffer, int pem_size);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_uchar, mut=False], c_int) -> c_int](
            "tls_load_root_certificates"
        )(context, pem_buffer, pem_size)

    fn tls_default_verify(
        self,
        context: UnsafePointer[TLSContext],
        certificate_chain: UnsafePointer[UnsafePointer[TLSCertificate]],
        len: c_int,
    ) -> c_int:
        """Verify a certificate chain using the default verification method.
        This function checks the validity of a certificate chain against the trusted root certificates
        loaded into the specified TLS context.

        Args:
            context: A pointer to the `TLSContext` in which the verification will be performed.
            certificate_chain: A pointer to an array of pointers to `TLSCertificate` structures representing the certificate chain.
            len: The number of certificates in the chain.
        
        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

        #### C Function
        ```c
        int tls_default_verify(struct TLSContext *context, struct TLSCertificate **certificate_chain, int len);
        ```
        """
        return self._handle.get_function[
            fn (UnsafePointer[TLSContext], UnsafePointer[UnsafePointer[TLSCertificate]], c_int) -> c_int
        ]("tls_default_verify")(context, certificate_chain, len)

    fn tls_print_certificate(self, fname: UnsafePointer[c_char, mut=False]) -> None:
        """Print a TLS certificate to a file.

        Args:
            fname: A pointer to the filename where the certificate will be printed.

        #### C Function
        ```c
        void tls_print_certificate(const char *fname);
        ```
        """
        _ = self._handle.get_function[fn (UnsafePointer[c_char, mut=False]) -> c_void]("tls_print_certificate")(fname)

    fn tls_add_alpn(self, context: UnsafePointer[TLSContext], alpn: UnsafePointer[c_char, mut=False]) -> c_int:
        """Add an ALPN (Application-Layer Protocol Negotiation) identifier to a TLS context.
        This function allows the application to specify the protocols it supports for negotiation
        during the TLS handshake.

        Args:
            context: A pointer to the `TLSContext` to which the ALPN identifier will be added.
            alpn: A pointer to the ALPN identifier string.

        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

        #### C Function
        ```c
        int tls_add_alpn(struct TLSContext *context, const char *alpn);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_char, mut=False]) -> c_int](
            "tls_add_alpn"
        )(context, alpn)

    fn tls_alpn_contains(
        self, context: UnsafePointer[TLSContext], alpn: UnsafePointer[c_char], alpn_size: c_uchar
    ) -> c_int:
        """Checks if a TLS context contains a specific ALPN (Application-Layer Protocol Negotiation) identifier.

        Args:
            context: A pointer to the `TLSContext` to check for the ALPN identifier.
            alpn: A pointer to the ALPN identifier string.
            alpn_size: The size of the ALPN identifier string.
        
        Returns:
            An integer indicating whether the ALPN identifier is present (1) or not (0). A negative value indicates an error.

        #### C Function
        ```c
        int tls_alpn_contains(struct TLSContext *context, const char *alpn, unsigned char alpn_size);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], UnsafePointer[c_char], c_uchar) -> c_int](
            "tls_alpn_contains"
        )(context, alpn, alpn_size)

    fn tls_alpn(self, context: UnsafePointer[TLSContext]) -> UnsafePointer[c_char, mut=False]:
        """Retrieves the ALPN (Application-Layer Protocol Negotiation) identifier from a TLS context.

        Args:
            context: A pointer to the `TLSContext` from which to retrieve the ALPN identifier.
        
        Returns:
            A pointer to the ALPN identifier string associated with the TLS context.

        #### C Function
        ```c
        const char *tls_alpn(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> UnsafePointer[c_char, mut=False]]("tls_alpn")(context)

    fn tls_clear_certificates(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Clears all certificates from a TLS context.

        Args:
            context: A pointer to the `TLSContext` from which to clear the certificates.

        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

        #### C Function
        ```c
        int tls_clear_certificates(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_clear_certificates")(context)

    fn tls_make_ktls(self, context: UnsafePointer[TLSContext], socket: c_int) -> c_int:
        """Enables kernel TLS (kTLS) for a given socket.

        Args:
            context: A pointer to the `TLSContext` to use for the kTLS session.
            socket: The file descriptor of the socket to enable kTLS on.

        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

        #### C Function
        ```c
        int tls_make_ktls(struct TLSContext *context, int socket);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_int) -> c_int]("tls_make_ktls")(
            context, socket
        )

    fn tls_unmake_ktls(self, context: UnsafePointer[TLSContext], socket: c_int) -> c_int:
        """Disables kernel TLS (kTLS) for a given socket.

        Args:
            context: A pointer to the `TLSContext` to use for the kTLS session.
            socket: The file descriptor of the socket to disable kTLS on.

        Returns:
            An integer indicating success (0) or failure (non-zero). A negative value indicates an error.

        #### C Function
        ```c
        int tls_unmake_ktls(struct TLSContext *context, int socket);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext], c_int) -> c_int]("tls_unmake_ktls")(
            context, socket
        )

    fn dtls_reset_cookie_secret(self) -> None:
        """Creates a new DTLS random cookie secret to be used in HelloVerifyRequest (server-side).
        It is recommended to call this function from time to time, to protect against some
        DoS attacks.
        
        #### C Function
        ```c
        void dtls_reset_cookie_secret(void);
        ```
        """
        _ = self._handle.get_function[fn () -> c_void]("dtls_reset_cookie_secret")()

    fn tls_remote_error(self, context: UnsafePointer[TLSContext]) -> c_int:
        """Retrieves the remote error code from a TLS context.
        This function checks for any errors that occurred during the TLS handshake or communication
        and returns the corresponding error code.

        Args:
            context: Wrapper around the TLSContext pointer.
        
        Returns:
            An integer representing the remote error code. A value of 0 indicates no error, while
            other values indicate specific errors that occurred during the TLS operation.

        #### C Function
        ```c
        int tls_remote_error(struct TLSContext *context);
        ```
        """
        return self._handle.get_function[fn (UnsafePointer[TLSContext]) -> c_int]("tls_remote_error")(context)
