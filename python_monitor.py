import re
from collections import Counter
from datetime import datetime, timedelta
from dataclasses import dataclass
from typing import Optional



WINDOW_SIZE = timedelta(minutes=5)
ERROR_RATE_THRESHOLD = 0.10

@dataclass
class Log:
    timestamp: datetime
    ip: str
    action: str
    domain: str
    request: str
    status: int
    bytes_sent: int
    request_time_ms: int

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

    if not match:
        return None

    ip, action, timestamp_str, domain, request, status, bytes_sent, request_time = match.groups()
    timestamp = datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')

    return Log(
        timestamp=timestamp,
        ip=ip,
        action=action,
        domain=domain,
        request=request,
        status=int(status),
        bytes_sent=int(bytes_sent),
        request_time_ms=int(request_time),
    )


def is_error_status(status: int) -> bool:
    return 400 <= status <= 599


def alert_on_treshold(window: Window) -> None:
    error_rate = window.calculate_error_rate()
    if error_rate > ERROR_RATE_THRESHOLD:
        print(f"ALERT! Error rate {error_rate:.2%} exceeds threshold at {window.start_time}")


def run_alerting(logs: list[Log]) -> None:
    window: Optional[Window] = None
    for log in logs:
        if (window is None) or (not window.is_within_window(log.timestamp)):
            if window and window.data:
                alert_on_treshold(window)

            window = Window(start_time=log.timestamp, size=WINDOW_SIZE)

        window.add(log)

    if window and window.data:
        alert_on_treshold(window)


def print_log_statistics(logs: list[Log]) -> None:
    print("\n=== Log Statistics Summary ===")

    # Identify the top 5 IP addresses by request count. 
    ip_counter = Counter(log.ip for log in logs)
    top_5_ips = ip_counter.most_common(5)
    print("\nTop 5 IPs by request count:")
    for ip, count in top_5_ips:
        print(f"{ip}: {count} requests")

    # Calculate the percentage of requests with status codes in the 400-599 range.
    total_requests = len(logs)
    total_errors = sum(1 for log in logs if is_error_status(log.status))
    error_percentage = (total_errors / total_requests) * 100 if total_requests else 0
    print(f"\nError responses in the 400-599 range: {error_percentage:.2f}%")

    # Find the average response size in bytes for GET requests
    get_logs = [log for log in logs if log.request.startswith("GET")]
    total_size = sum(log.bytes_sent for log in get_logs)
    average_size = total_size / len(get_logs) if get_logs else 0
    print(f"\nAverage response size for GET requests: {average_size:.2f} bytes")


def monitor_logs(log_file: str) -> None:
    with open(log_file, 'r') as f:
        logs_parsed: list[Optional[Log]] = [parse_log_line(line.strip()) for line in f]

    logs: list[Log] = [log for log in logs_parsed if log is not None]
    logs.sort(key=lambda log: log.timestamp)

    # run_alerting(logs)

    # Task 1   
    print_log_statistics(logs)


if __name__ == "__main__":
    monitor_logs('nginx_access.log')
