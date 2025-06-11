import re
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional



WINDOW_SIZE = timedelta(minutes=5)
ERROR_RATE_THRESHOLD = 0.10

@dataclass
class Log:
    timestamp: datetime
    status: int

class Window:
    def __init__(self, start_time: datetime, size: timedelta):
        self.start_time = start_time
        self.size = size
        self.data: list[Log] = []

    def add(self, log: Log):
        self.data.append(log)

    def is_within_window(self, timestamp: datetime) -> bool:
        return timestamp - self.start_time <= self.size

    def calculate_error_rate(self) -> float:
        total = len(self.data)
        if total == 0:
            return 0.0
        errors = sum(1 for log in self.data if is_error_status(log.status))
        return errors / total


def parse_log_line(log_line: str) -> Optional[Log]:
    pattern = r'(\d+\.\d+\.\d+\.\d+) - (\w+) \[(\d{2}\/\w{3}\/\d{4}:\d{2}:\d{2}:\d{2} \+\d{4})\] "([^"]+)" "([^"]+)" (\d+) (\d+) (\d+)'
    match = re.match(pattern, log_line)
    # "(\w+\.\w+\.\w+)" - Breaks if more than 3 subdomains or special characters (dashes) in domain: "([^"]+)"
    # "(\w+ /.+ HTTP/\d\.\d)" - Way too specific format, we card about the whole thing in this feildL: "([^"]+)"

    if not match: 
        return None

    # Most of the variables are not used. Could be added to the Log class
    _, _, timestamp_str, _, _, status, _, _ = match.groups()
    timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')

    return Log(
        timestamp=timestamp,
        status=int(status),
    )


def is_error_status(status: int) -> bool:
    return 400 <= status <= 599


def alert_on_treshold(window: Window) -> None:
    error_rate = window.calculate_error_rate()
    if error_rate > ERROR_RATE_THRESHOLD:
        print(f"Alert! Error rate {error_rate:.2%}% exceeds threshold at {window.start_time}")


def monitor_logs(log_file: str) -> None:
    with open(log_file, 'r') as f:
        logs_parsed: list[Optional[Log]] = [parse_log_line(line.strip()) for line in f]

    logs: list[Log] = [log for log in logs_parsed if log is not None]
    logs.sort(key=lambda log: log.timestamp)

    window: Optional[Window] = None

    for log in logs:
        if (window is None) or (not window.is_within_window(log.timestamp)):
            if window and window.data:
                alert_on_treshold(window)

            window = Window(start_time=log.timestamp, size=WINDOW_SIZE)

        window.add(log)

    # Final window check
    if window and window.data:
        alert_on_treshold(window)


if __name__ == "__main__":
    monitor_logs('nginx_access.log')
