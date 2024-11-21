import logging
from typing import Iterator, Optional, Tuple, Union, List, Any
from . import exceptions
logger = logging.getLogger(__name__)
_TupleAtomPart = Union[None, int, bytes]
_TupleAtom = Tuple[Union[_TupleAtomPart, '_TupleAtom'], ...]

def assert_imap_protocol(condition: bool, message: Optional[bytes] = None) -> None:
    if not condition:
        raise exceptions.ProtocolError(message)

def to_unicode(s: Union[str, bytes]) -> str:
    """Convert a bytes object to a unicode string."""
    if isinstance(s, bytes):
        return s.decode('utf-8')
    return s

def to_bytes(s: Union[str, bytes, int]) -> bytes:
    """Convert a string, number or bytes to bytes."""
    if isinstance(s, bytes):
        return s
    if isinstance(s, int):
        return str(s).encode('ascii')
    return s.encode('utf-8')

def chunk(lst: List[Any], size: int) -> Iterator[List[Any]]:
    """Split a list into chunks of a given size."""
    for i in range(0, len(lst), size):
        yield lst[i:i + size]