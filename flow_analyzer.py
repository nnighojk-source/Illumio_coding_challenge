#!/usr/bin/env python3

from collections import defaultdict
import logging
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# protocol mapping (source: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
PROTOCOL_MAP = {
    '0': 'hopopt',  # IPv6 Hop-by-Hop Option
    '1': 'icmp',  # Internet Control Message
    '2': 'igmp',  # Internet Group Management
    '3': 'ggp',  # Gateway-to-Gateway Protocol
    '4': 'ipv4',  # IPv4 encapsulation
    '5': 'st',  # Stream
    '6': 'tcp',  # Transmission Control Protocol
    '17': 'udp',  # User Datagram Protocol
    '41': 'ipv6',  # IPv6 encapsulation
    '43': 'ipv6-route',  # Routing Header for IPv6
    '44': 'ipv6-frag',  # Fragment Header for IPv6
    '47': 'gre',  # Generic Routing Encapsulation
    '50': 'esp',  # Encap Security Payload
    '51': 'ah',  # Authentication Header
    '58': 'ipv6-icmp',  # ICMP for IPv6
    '89': 'ospf',  # OSPF IGP
    '103': 'pim',  # Protocol Independent Multicast
    '132': 'sctp'  # Stream Control Transmission Protocol
}

class LogAnalyzer:
    def __init__(self, lookup_table_file: str, has_headers: bool = True):
        """
        Initialize LogAnalyzer.

        Args:
            lookup_table_file: Path to the lookup table CSV
            has_headers: Boolean indicating if CSV files have headers (default: True)
        """
        self.has_headers = has_headers
        self.port_rule_dictionary = defaultdict(set)
        self.parse_lookup_table(lookup_table_file)

    def parse_lookup_table(self, lookup_table_file):
        """Parse the lookup table file."""
        try:
            with open(lookup_table_file, 'r') as f:
                # Read all lines
                lines = f.readlines()

                # Skip header if present
                if self.has_headers:
                    lines = lines[1:]

                for line in lines:
                    # Split by comma
                    row = [field.strip() for field in line.strip().split(',')]

                    if len(row) < 3:
                        logger.warning(f'Skipping malformed line: {line.strip()}')
                        continue

                    try:
                        port = int(row[0])
                        protocol = row[1].lower()
                        tag = row[2]

                        key = (port, protocol)
                        if key not in self.port_rule_dictionary:
                            self.port_rule_dictionary[key] = set()
                        self.port_rule_dictionary[key].add(tag)

                    except (ValueError, IndexError) as e:
                        logger.warning(f'Error processing line: {line.strip()}, Error: {str(e)}')
                        continue

        except FileNotFoundError:
            logger.error(f'Could not find {lookup_table_file}')
            sys.exit(1)
        except Exception as e:
            logger.error(f'Error loading lookup table: {str(e)}')
            sys.exit(1)

    def log_parser(self, log_file):
        """
        Parse flow logs and count tag matches.

        Args:
            log_file: Path to the flow log file

        Returns:
            tuple: (tag_counts, port_protocol_counts)
        """
        tag_count = defaultdict(int)
        port_protocol_count = defaultdict(int)

        try:
            with open(log_file, 'r') as file:
                if self.has_headers:
                    next(file)

                for line in file:
                    # Use space as delimiter
                    fields = line.strip().split()
                    if len(fields) < 14:
                        logger.warning(f'Skipping malformed line: {line.strip()}')
                        continue

                    try:
                        dst_port = int(fields[6])  # Field 7 is destination port
                        protocol = fields[7]       # Field 8 is protocol

                        # Convert protocol number to lowercase string for matching
                        protocol = PROTOCOL_MAP.get(protocol, protocol.lower())
                        port_protocol_count[(dst_port, protocol)] += 1

                        key = (dst_port, protocol)
                        tags = self.port_rule_dictionary.get(key, set())

                        if tags:
                            for tag in tags:
                                tag_count[tag] += 1
                        else:
                            tag_count['Untagged'] += 1

                    except ValueError as e:
                        logger.warning(f'Unable to process line: {line.strip()}, Error: {str(e)}')
                        continue

        except FileNotFoundError:
            logger.error(f'Could not find {log_file}')
            sys.exit(1)
        except Exception as e:
            logger.error(f'Error processing file {log_file}: {str(e)}')
            sys.exit(1)

        return dict(tag_count), dict(port_protocol_count)

    def write_results(self, output_file, tag_count, port_protocol_count):
        """Write analysis results to output file."""
        try:
            with open(output_file, 'w') as f:
                # Write tag counts
                f.write("Tag Counts:\n")
                f.write("Tag,Count\n")
                for tag, count in sorted(tag_count.items()):
                    f.write(f"{tag},{count}\n")

                f.write("\n")

                # Write port/protocol combination counts
                f.write("Port/Protocol Combination Counts:\n")
                f.write("Port,Protocol,Count\n")

                # Process counts
                sorted_counts = []
                for (port, protocol), count in port_protocol_count.items():
                    # Use the protocol as is, or find its name in PROTOCOL_MAP
                    protocol_name = protocol
                    # Check if the protocol is a numeric key in PROTOCOL_MAP
                    for key, value in PROTOCOL_MAP.items():
                        if value == protocol:
                            protocol_name = value
                            break

                    sorted_counts.append((port, protocol_name, count))

                # Sort by port number and write
                for port, protocol, count in sorted(sorted_counts, key=lambda x: int(x[0])):
                    f.write(f"{port},{protocol},{count}\n")

        except Exception as e:
            logger.error(f"Error writing results to {output_file}: {str(e)}")
            sys.exit(1)

def main():
    # Check number of arguments
    if len(sys.argv) not in [4, 5]:
        print("Usage: python illumio.py <lookup_table_file> <log_file> <output_file> [--no-headers]")
        sys.exit(1)

    lookup_file = sys.argv[1]
    flow_log_file = sys.argv[2]
    output_file = sys.argv[3]

    # Check if --no-headers flag is present
    has_headers = True
    if len(sys.argv) == 5 and sys.argv[4] == '--no-headers':
        has_headers = False

    try:
        # Create analyzer with specified headers option
        analyzer = LogAnalyzer(lookup_file, has_headers)

        # Process logs
        tag_count, port_protocol_count = analyzer.log_parser(flow_log_file)

        # Write results
        analyzer.write_results(output_file, tag_count, port_protocol_count)

        logger.info(f'Analysis complete. Results written to {output_file}')

    except Exception as e:
        logger.error(f'Error processing files: {str(e)}')
        sys.exit(1)

if __name__ == '__main__':
    main()