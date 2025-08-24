from sys.ffi import _get_global

from memory import UnsafePointer
from mojo_tlse.bindings import TLSE


fn _init_global() -> UnsafePointer[NoneType]:
    var ptr = UnsafePointer[TLSE].alloc(1)
    ptr[] = TLSE()
    return ptr.bitcast[NoneType]()


fn _destroy_global(lib: UnsafePointer[NoneType]):
    var p = lib.bitcast[TLSE]()
    p[]._handle.close()
    lib.free()


@always_inline
fn _get_global_tlse_itf() -> _TLSEInterfaceImpl:
    var ptr = _get_global["TLSE", _init_global, _destroy_global]()
    return _TLSEInterfaceImpl(ptr.bitcast[TLSE]())


struct _TLSEInterfaceImpl:
    """TLSE Global Wrapper."""

    var _tlse: UnsafePointer[TLSE]

    fn __init__(out self, sqlite: UnsafePointer[TLSE]):
        self._tlse = sqlite

    fn __copyinit__(out self, existing: Self):
        self._tlse = existing._tlse

    fn tlse(self) -> ref [self._tlse] TLSE:
        return self._tlse[]


fn _impl() -> TLSE:
    return _get_global_tlse_itf().tlse().copy()
