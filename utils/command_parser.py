import argparse
import sys

class CommandParser:
    """
    Parses command line arguments for the Universal CLI Utility
    """
    def __init__(self):
        self.parser = argparse.ArgumentParser(
            description='Universal CLI Utility for system management and automation',
            usage='ucli <command> [<subcommand>] [options]'
        )
        self.subparsers = self.parser.add_subparsers(dest='command')
        self._setup_parsers()

    def _setup_parsers(self):
        # File Operations
        file_parser = self.subparsers.add_parser('file', help='File operations')
        file_subparsers = file_parser.add_subparsers(dest='subcommand')
        
        # File GUI
        file_subparsers.add_parser('gui', help='Launch file operations GUI')

        # File search
        search_parser = file_subparsers.add_parser('search', help='Search for files')
        search_parser.add_argument('-p', '--pattern', required=True, help='Search pattern')
        search_parser.add_argument('-d', '--directory', default='.', help='Directory to search in')
        search_parser.add_argument('-r', '--recursive', action='store_true', help='Search recursively')
        
        # File analyze
        analyze_parser = file_subparsers.add_parser('analyze', help='Analyze file contents')
        analyze_parser.add_argument('-f', '--file', required=True, help='File to analyze')
        analyze_parser.add_argument('-t', '--type', choices=['text', 'binary', 'auto'], default='auto', help='File type')
        
        # File monitor
        monitor_parser = file_subparsers.add_parser('monitor', help='Monitor file changes')
        monitor_parser.add_argument('-p', '--path', required=True, help='Path to monitor')
        monitor_parser.add_argument('-i', '--interval', type=int, default=1, help='Check interval in seconds')

        # Process Management
        proc_parser = self.subparsers.add_parser('proc', help='Process management')
        proc_subparsers = proc_parser.add_subparsers(dest='subcommand')
        
        # Process list
        list_parser = proc_subparsers.add_parser('list', help='List processes')
        list_parser.add_argument('-f', '--filter', help='Filter processes by name')
        list_parser.add_argument('-s', '--sort', choices=['cpu', 'mem', 'pid', 'name'], default='cpu', help='Sort by field')
        
        # Process kill
        kill_parser = proc_subparsers.add_parser('kill', help='Kill a process')
        kill_parser.add_argument('-p', '--pid', type=int, help='Process ID to kill')
        kill_parser.add_argument('-n', '--name', help='Process name to kill')
        kill_parser.add_argument('-f', '--force', action='store_true', help='Force kill')

        # Network Utilities
        net_parser = self.subparsers.add_parser('net', help='Network utilities')
        net_subparsers = net_parser.add_subparsers(dest='subcommand')
        
        # Network scan
        scan_parser = net_subparsers.add_parser('scan', help='Scan network')
        scan_parser.add_argument('-t', '--target', required=True, help='Target to scan (IP or domain)')
        scan_parser.add_argument('-p', '--ports', help='Ports to scan (comma separated)')
        
        # Network monitor
        net_monitor_parser = net_subparsers.add_parser('monitor', help='Monitor network traffic')
        net_monitor_parser.add_argument('-i', '--interface', help='Network interface to monitor')
        net_monitor_parser.add_argument('-f', '--filter', help='Packet filter expression')
        
        # Security Checks
        sec_parser = self.subparsers.add_parser('sec', help='Security checks')
        sec_subparsers = sec_parser.add_subparsers(dest='subcommand')
        
        # Security scan
        sec_scan_parser = sec_subparsers.add_parser('scan', help='Security scan')
        sec_scan_parser.add_argument('-t', '--target', required=True, help='Target to scan')
        sec_scan_parser.add_argument('-l', '--level', choices=['basic', 'full'], default='basic', help='Scan level')
        
        # Security monitor
        sec_monitor_parser = sec_subparsers.add_parser('monitor', help='Security monitoring')
        sec_monitor_parser.add_argument('-l', '--log', help='Log file to monitor')
        sec_monitor_parser.add_argument('-a', '--alerts', action='store_true', help='Show only alerts')

        # Automation
        auto_parser = self.subparsers.add_parser('auto', help='Task automation')
        auto_subparsers = auto_parser.add_subparsers(dest='subcommand')
        
        # Automation task
        task_parser = auto_subparsers.add_parser('task', help='Run automated task')
        task_parser.add_argument('-n', '--name', required=True, help='Task name')
        task_parser.add_argument('-p', '--params', help='Task parameters (JSON format)')
        
        # Automation schedule
        schedule_parser = auto_subparsers.add_parser('schedule', help='Schedule automated task')
        schedule_parser.add_argument('-n', '--name', required=True, help='Task name')
        schedule_parser.add_argument('-t', '--time', required=True, help='Schedule time (cron format)')
        schedule_parser.add_argument('-p', '--params', help='Task parameters (JSON format)')

    def parse_args(self, args=None):
        """
        Parse command line arguments
        """
        if args is None:
            args = sys.argv[1:]

        # Special case for just 'file' command - will be handled in main.py
        if len(args) == 1 and args[0] == 'file':
            parsed_args = self.parser.parse_args(['file', 'gui'])
            return parsed_args
            
        if not args:
            self.parser.print_help()
            sys.exit(1)
            
        args = self.parser.parse_args(args)
        
        # Validate that a subcommand is provided
        if hasattr(args, 'subcommand') and args.subcommand is None:
            if args.command == 'file':
                self.subparsers.choices['file'].print_help()
            elif args.command == 'proc':
                self.subparsers.choices['proc'].print_help()
            elif args.command == 'net':
                self.subparsers.choices['net'].print_help()
            elif args.command == 'sec':
                self.subparsers.choices['sec'].print_help()
            elif args.command == 'auto':
                self.subparsers.choices['auto'].print_help()
            sys.exit(1)
            
        return args