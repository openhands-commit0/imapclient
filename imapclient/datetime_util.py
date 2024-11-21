import re
from datetime import datetime
from email.utils import parsedate_tz
from .fixed_offset import FixedOffset
_SHORT_MONTHS = ' Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split(' ')

def datetime_to_native(dt: datetime) -> datetime:
    """Convert a timezone-aware datetime to a naive datetime in the local timezone."""
    if dt.tzinfo is None:
        return dt
    return dt.astimezone(FixedOffset.for_system()).replace(tzinfo=None)

def parse_to_datetime(timestamp: bytes, normalise: bool=True) -> datetime:
    """Convert an IMAP datetime string to a datetime.

    If normalise is True (the default), then the returned datetime
    will be timezone-naive but adjusted to the local time.

    If normalise is False, then the returned datetime will be
    unadjusted but will contain timezone information as per the input.
    """
    timestamp = timestamp.decode('ascii')
    
    # Handle dotted time format
    if _rfc822_dotted_time.match(timestamp):
        timestamp = timestamp.replace('.', ':')
    
    # Try RFC822 format first
    parsed = parsedate_tz(timestamp)
    if parsed:
        tz_offset = parsed[-1]
        if tz_offset is None:
            tz = None
        else:
            tz = FixedOffset(tz_offset // 60)
        dt = datetime(*parsed[:6], tzinfo=tz)
    else:
        # Try INTERNALDATE format
        timestamp = timestamp.strip()
        parts = timestamp.split(' ')
        if len(parts) != 3:
            raise ValueError(f'Invalid timestamp format: {timestamp}')
        
        date_parts = parts[0].split('-')
        if len(date_parts) != 3:
            raise ValueError(f'Invalid date format: {parts[0]}')
        
        day = int(date_parts[0])
        month = _SHORT_MONTHS.index(date_parts[1])
        year = int(date_parts[2])
        
        time_parts = parts[1].split(':')
        if len(time_parts) != 3:
            raise ValueError(f'Invalid time format: {parts[1]}')
        
        hour = int(time_parts[0])
        minute = int(time_parts[1])
        second = int(time_parts[2])
        
        tz_str = parts[2]
        tz_sign = 1 if tz_str[0] == '+' else -1
        tz_hour = int(tz_str[1:3])
        tz_min = int(tz_str[3:5])
        tz = FixedOffset(tz_sign * (tz_hour * 60 + tz_min))
        
        dt = datetime(year, month, day, hour, minute, second, tzinfo=tz)
    
    if normalise and dt.tzinfo is not None:
        return datetime_to_native(dt)
    return dt

def datetime_to_INTERNALDATE(dt: datetime) -> str:
    """Convert a datetime instance to a IMAP INTERNALDATE string.

    If timezone information is missing the current system
    timezone is used.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=FixedOffset.for_system())
    
    sign = '+' if dt.utcoffset().total_seconds() >= 0 else '-'
    offset_mins = abs(int(dt.utcoffset().total_seconds() / 60))
    offset_hrs = offset_mins // 60
    offset_mins = offset_mins % 60
    
    return f"{dt.day:02d}-{_SHORT_MONTHS[dt.month]}-{dt.year:04d} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} {sign}{offset_hrs:02d}{offset_mins:02d}"
_rfc822_dotted_time = re.compile('\\w+, ?\\d{1,2} \\w+ \\d\\d(\\d\\d)? \\d\\d?\\.\\d\\d?\\.\\d\\d?.*')

def format_criteria_date(dt: datetime) -> bytes:
    """Format a date or datetime instance for use in IMAP search criteria."""
    return f"{dt.day:02d}-{_SHORT_MONTHS[dt.month]}-{dt.year:04d}".encode('ascii')