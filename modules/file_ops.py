"""
File operations module for Universal CLI Utility
"""

import os
import re
import time
import logging
import fnmatch
import json
from datetime import datetime

class FileOperations:
    """
    Provides file management operations
    """
    def __init__(self):
        self.logger = logging.getLogger('ucli.file')
        
    def search(self, pattern, directory='.', recursive=False):
        """Search for files matching a pattern in a directory"""
        self.logger.info(f"Searching for '{pattern}' in {directory} (recursive={recursive})")
        
        matches = []
        try:
            if recursive:
                for root, dirnames, filenames in os.walk(directory):
                    for filename in fnmatch.filter(filenames, pattern):
                        matches.append(os.path.join(root, filename))
            else:
                for filename in os.listdir(directory):
                    if fnmatch.fnmatch(filename, pattern):
                        matches.append(os.path.join(directory, filename))
                        
            if matches:
                print(f"Found {len(matches)} matching files:")
                for match in matches:
                    file_info = os.stat(match)
                    size = file_info.st_size
                    mod_time = datetime.fromtimestamp(file_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    print(f"{match} (Size: {self._format_size(size)}, Modified: {mod_time})")
            else:
                print(f"No files matching '{pattern}' found in {directory}")
                
        except Exception as e:
            self.logger.error(f"Error searching for files: {str(e)}")
            print(f"Error searching for files: {str(e)}")
    
    def analyze(self, filepath, file_type='auto'):
        """Analyze file contents and properties"""
        self.logger.info(f"Analyzing file: {filepath}")
        
        try:
            if not os.path.exists(filepath):
                print(f"Error: File '{filepath}' asd dsfasd")
                return
                
            file_info = os.stat(filepath)
            
            # Basic file info
            file_data = {
                'filename': os.path.basename(filepath),
                'path': os.path.abspath(filepath),
                'size': file_info.st_size,
                'size_human': self._format_size(file_info.st_size),
                'created': datetime.fromtimestamp(file_info.st_ctime).strftime('%Y-%m-%d %H:%M:%S'),
                'modified': datetime.fromtimestamp(file_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
                'accessed': datetime.fromtimestamp(file_info.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
            }
            
            # Determine file type if auto
            if file_type == 'auto':
                # Simple check for text files (could be improved)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        f.read(1024)  # Try reading as text
                    file_type = 'text'
                except UnicodeDecodeError:
                    file_type = 'binary'
            
            # Additional analysis based on file type
            if file_type == 'text':
                with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read()
                    
                line_count = len(content.splitlines())
                word_count = len(content.split())
                char_count = len(content)
                
                file_data.update({
                    'type': 'text',
                    'lines': line_count,
                    'words': word_count,
                    'characters': char_count,
                })
                
            elif file_type == 'binary':
                file_data['type'] = 'binary'
                
                # Get file signature (first 8 bytes as hex)
                with open(filepath, 'rb') as f:
                    signature = f.read(8).hex()
                
                file_data['signature'] = signature
            
            # Print analysis results
            print("\nFile Analysis:")
            print(f"Name: {file_data['filename']}")
            print(f"Path: {file_data['path']}")
            print(f"Size: {file_data['size_human']} ({file_data['size']} bytes)")
            print(f"Created: {file_data['created']}")
            print(f"Modified: {file_data['modified']}")
            print(f"Accessed: {file_data['accessed']}")
            
            if file_type == 'text':
                print(f"\nText Analysis:")
                print(f"Lines: {file_data['lines']}")
                print(f"Words: {file_data['words']}")
                print(f"Characters: {file_data['characters']}")
            elif file_type == 'binary':
                print(f"\nBinary Analysis:")
                print(f"Signature (hex): {file_data['signature']}")
                
        except Exception as e:
            self.logger.error(f"Error analyzing file: {str(e)}")
            print(f"Error analyzing file: {str(e)}")
    
    def monitor(self, path, interval=1):
        """Monitor a file or directory for changes"""
        self.logger.info(f"Starting file monitor on {path} (interval: {interval}s)")
        
        try:
            if not os.path.exists(path):
                print(f"Error: Path '{path}' not found")
                return
                
            print(f"Monitoring {path} for changes (Press Ctrl+C to stop)...")
            
            # Store initial state
            if os.path.isdir(path):
                # For directories, store modification times for all files
                file_states = {}
                for root, dirs, files in os.walk(path):
                    for file in files:
                        full_path = os.path.join(root, file)
                        try:
                            file_states[full_path] = os.path.getmtime(full_path)
                        except:
                            # Skip files that can't be accessed
                            pass
            else:
                # For single file, store its modification time
                file_states = {path: os.path.getmtime(path)}
                
            try:
                while True:
                    time.sleep(interval)
                    changes = []
                    
                    # Check for changes in existing files
                    for filepath, mtime in list(file_states.items()):
                        try:
                            current_mtime = os.path.getmtime(filepath)
                            if current_mtime != mtime:
                                changes.append(('modified', filepath))
                                file_states[filepath] = current_mtime
                        except FileNotFoundError:
                            changes.append(('deleted', filepath))
                            del file_states[filepath]
                    
                    # Check for new files if monitoring a directory
                    if os.path.isdir(path):
                        for root, dirs, files in os.walk(path):
                            for file in files:
                                full_path = os.path.join(root, file)
                                if full_path not in file_states:
                                    try:
                                        file_states[full_path] = os.path.getmtime(full_path)
                                        changes.append(('created', full_path))
                                    except:
                                        # Skip files that can't be accessed
                                        pass
                    
                    # Report changes
                    if changes:
                        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                        for change_type, filepath in changes:
                            print(f"[{timestamp}] {change_type.upper()}: {filepath}")
                        
            except KeyboardInterrupt:
                print("\nMonitoring stopped")
                
        except Exception as e:
            self.logger.error(f"Error in file monitor: {str(e)}")
            print(f"Error in file monitor: {str(e)}")
    
    def _format_size(self, size_bytes):
        """Format file size in human-readable format"""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            return f"{size_bytes / 1024:.2f} KB"
        elif size_bytes < 1024 * 1024 * 1024:
            return f"{size_bytes / (1024 * 1024):.2f} MB"
        else:
            return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"