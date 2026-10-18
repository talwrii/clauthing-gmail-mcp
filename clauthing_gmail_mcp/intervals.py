"""Human-entered, finite approval durations."""
import re


def interval_seconds(value):
    if not isinstance(value, str) or len(value) > 100:
        raise ValueError('Enter an interval such as 30m, 2h, 7d, or 1 hour')
    match = re.fullmatch(r'\s*(\d+)\s*(s|sec(?:ond)?s?|m|min(?:ute)?s?|h|hours?|d|days?|w|weeks?)\s*',
                         value, re.IGNORECASE)
    if not match:
        raise ValueError('Enter an interval such as 30m, 2h, 7d, or 1 hour')
    seconds = int(match[1]) * {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}[match[2][0].lower()]
    if not 0 < seconds <= 315360000:
        raise ValueError('Duration must be positive and at most 10 years')
    return seconds
