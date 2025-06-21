#!/usr/bin/env python3
"""
Universal CLI Utility - A unified command-line tool for system management,
automation, and security monitoring.
"""

import sys
import os
import logging

# Add parent directory to path to allow importing modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.command_parser import CommandParser
from modules.file_ops import FileOperations
from modules.process_mgmt import ProcessManager
from modules.network_utils import NetworkUtilities


def main():
    """
    Main entry point for the Universal CLI Utility
    """
    # Set up logging
    
    logger = logging.getLogger('ucli')
    
    # Parse command line arguments
    parser = CommandParser()
    args = parser.parse_args()
    
    try:
        # Route to appropriate module based on command
        if args.command == 'file':
            file_ops = FileOperations()
            if args.subcommand == 'search':
                file_ops.search(args.pattern, args.directory, args.recursive)
            elif args.subcommand == 'analyze':
                file_ops.analyze(args.file, args.type)
            elif args.subcommand == 'monitor':
                file_ops.monitor(args.path, args.interval)
                
        elif args.command == 'proc':
            proc_mgr = ProcessManager()
            if args.subcommand == 'list':
                proc_mgr.list_processes(args.filter, args.sort)
            elif args.subcommand == 'kill':
                proc_mgr.kill_process(args.pid, args.name, args.force)
                
        elif args.command == 'net':
            net_utils = NetworkUtilities()
            if args.subcommand == 'scan':
                net_utils.scan(args.target, args.ports)
            elif args.subcommand == 'monitor':
                net_utils.monitor(args.interface, args.filter)
                
        
                
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        return 1
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main())