import os
import shutil
import unittest
import tempfile
from flow_analyzer import LogAnalyzer

class TestLogAnalyzer(unittest.TestCase):
    def setUp(self):
        """Set up test environment with temporary files."""
        # Create a temporary directory
        self.test_dir = tempfile.mkdtemp()

    def tearDown(self):
        """
        Clean up temporary files and directories after each test.
        Ensures that all temporary files are removed, even if a test fails.
        """
        try:
            # Remove the entire temporary directory and its contents
            shutil.rmtree(self.test_dir)
        except Exception as e:
            # Log the error, but don't raise it to prevent masking the original test error
            print(f"Error during cleanup: {e}")

    def create_temp_file(self, filename, content):
        """
        Helper method to create a temporary file.

        Args:
            filename (str): Name of the file to create
            content (str): Content to write to the file

        Returns:
            str: Full path to the created temporary file
        """
        filepath = os.path.join(self.test_dir, filename)
        with open(filepath, 'w') as f:
            f.write(content)
        return filepath

    def test_case_insensitive_protocol_matching_with_headers(self):
        """
        Test case insensitive protocol matching with headers.
        Verify that protocols match regardless of case.
        """
        # Different case variations for the same protocol
        test_cases = [
            ("dstport,protocol,tag\n80,TCP,web\n443,tcp,ssl\n22,TcP,ssh"),
            ("dstport,protocol,tag\n80,tcp,web\n443,TCP,ssl\n22,Tcp,ssh")
        ]

        for lookup_content in test_cases:
            lookup_file = self.create_temp_file('lookup_table.csv', lookup_content)
            analyzer = LogAnalyzer(lookup_file)

            # Check case insensitive protocol matching
            self.assertIn((80, 'tcp'), analyzer.port_rule_dictionary)
            self.assertIn((443, 'tcp'), analyzer.port_rule_dictionary)
            self.assertIn((22, 'tcp'), analyzer.port_rule_dictionary)

            # Verify tags
            self.assertEqual(analyzer.port_rule_dictionary[(80, 'tcp')], {'web'})
            self.assertEqual(analyzer.port_rule_dictionary[(443, 'tcp')], {'ssl'})
            self.assertEqual(analyzer.port_rule_dictionary[(22, 'tcp')], {'ssh'})

    def test_case_insensitive_protocol_matching_without_headers(self):
        """
        Test case insensitive protocol matching without headers.
        Verify that protocols match regardless of case.
        """
        # Different case variations for the same protocol
        test_cases = [
            "80,TCP,web\n443,tcp,ssl\n22,TcP,ssh",
            "80,tcp,web\n443,TCP,ssl\n22,Tcp,ssh"
        ]

        for lookup_content in test_cases:
            lookup_file = self.create_temp_file('lookup_table.csv', lookup_content)
            analyzer = LogAnalyzer(lookup_file, has_headers=False)

            # Check case insensitive protocol matching
            self.assertIn((80, 'tcp'), analyzer.port_rule_dictionary)
            self.assertIn((443, 'tcp'), analyzer.port_rule_dictionary)
            self.assertIn((22, 'tcp'), analyzer.port_rule_dictionary)

            # Verify tags
            self.assertEqual(analyzer.port_rule_dictionary[(80, 'tcp')], {'web'})
            self.assertEqual(analyzer.port_rule_dictionary[(443, 'tcp')], {'ssl'})
            self.assertEqual(analyzer.port_rule_dictionary[(22, 'tcp')], {'ssh'})

    def test_log_parsing_case_insensitive_tag_matching(self):
        """
        Test log parsing with case-insensitive protocol matching.
        """
        # Create lookup table with mixed case protocols
        lookup_content = "dstport,protocol,tag\n80,TCP,web\n443,tcp,ssl"
        lookup_file = self.create_temp_file('lookup_table.csv', lookup_content)

        # Create log file with mixed case protocol numbers
        log_content = (
            "version account_id interface_id srcaddr dstaddr "
            "srcport 80 6 packets bytes start end action log_status\n"
            "1 123 eth0 192.168.1.1 10.0.0.1 1234 80 6 10 1000 1610000000 1610000010 ACCEPT OK\n"
        )
        log_file = self.create_temp_file('flow_log.csv', log_content)

        # Create analyzer and parse logs
        analyzer = LogAnalyzer(lookup_file)
        tag_count, port_protocol_count = analyzer.log_parser(log_file)

        # Verify tag and port/protocol counts
        self.assertEqual(tag_count, {'web': 1})
        self.assertEqual(port_protocol_count, {(80, 'tcp'): 1})

    def test_protocol_number_mapping(self):
        """
        Test protocol number to name mapping.
        """
        # Create lookup table with protocol numbers
        lookup_content = "dstport,protocol,tag\n80,tcp,web\n53,17,dns"
        lookup_file = self.create_temp_file('lookup_table.csv', lookup_content)

        # Create log file with protocol numbers
        log_content = (
            "version account_id interface_id srcaddr dstaddr "
            "srcport 80 6 packets bytes start end action log_status\n"
            "1 123 eth0 192.168.1.1 10.0.0.1 1234 80 6 10 1000 1610000000 1610000010 ACCEPT OK\n"
        )
        log_file = self.create_temp_file('flow_log.csv', log_content)

        # Create analyzer and parse logs
        analyzer = LogAnalyzer(lookup_file)
        tag_count, port_protocol_count = analyzer.log_parser(log_file)

        # Verify tag and port/protocol counts
        self.assertEqual(tag_count, {'web': 1})
        self.assertEqual(port_protocol_count, {(80, 'tcp'): 1})

    def test_untagged_ports(self):
        """
        Test handling of untagged ports.
        """
        # Create lookup table with specific tags
        lookup_content = "dstport,protocol,tag\n80,tcp,web"
        lookup_file = self.create_temp_file('lookup_table.csv', lookup_content)

        # Create log file with untagged port
        log_content = (
            "version account_id interface_id srcaddr dstaddr "
            "srcport 8080 17 packets bytes start end action log_status\n"
            "1 123 eth0 192.168.1.1 10.0.0.1 1234 8080 17 10 1000 1610000000 1610000010 ACCEPT OK\n"
        )
        log_file = self.create_temp_file('flow_log.csv', log_content)

        # Create analyzer and parse logs
        analyzer = LogAnalyzer(lookup_file)
        tag_count, port_protocol_count = analyzer.log_parser(log_file)

        # Verify untagged count
        self.assertEqual(tag_count, {'Untagged': 1})
        self.assertEqual(port_protocol_count, {(8080, 'udp'): 1})

    def test_multiple_tags_same_port_protocol(self):
        """
        Test multiple tags for the same port and protocol.
        """
        # Create lookup table with multiple tags for same port/protocol
        lookup_content = "dstport,protocol,tag\n80,tcp,web\n80,tcp,http"
        lookup_file = self.create_temp_file('lookup_table.csv', lookup_content)

        # Create log file
        log_content = (
            "version account_id interface_id srcaddr dstaddr "
            "srcport 80 6 packets bytes start end action log_status\n"
            "1 123 eth0 192.168.1.1 10.0.0.1 1234 80 6 10 1000 1610000000 1610000010 ACCEPT OK\n"
        )
        log_file = self.create_temp_file('flow_log.csv', log_content)

        # Create analyzer and parse logs
        analyzer = LogAnalyzer(lookup_file)
        tag_count, port_protocol_count = analyzer.log_parser(log_file)

        # Verify multiple tags
        self.assertEqual(tag_count, {'web': 1, 'http': 1})
        self.assertEqual(port_protocol_count, {(80, 'tcp'): 1})

if __name__ == '__main__':
    unittest.main()