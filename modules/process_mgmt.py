"""
Process management module for Universal CLI Utility
"""

import os
import sys
import signal
import logging
import psutil
from datetime import datetime

class ProcessManager:
    """
    Handles process listing, monitoring, and management
    """
    def __init__(self):
        self.logger = logging.getLogger('ucli.proc')
        
    def list_processes(self, filter_name=None, sort_by='cpu'):
        """List processes with optional filtering and sorting"""
        self.logger.info(f"Listing processes (filter: {filter_name}, sort: {sort_by})")
        
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'create_time', 'status']):
                try:
                    # Apply filter if specified
                    if filter_name and filter_name.lower() not in proc.info['name'].lower():
                        continue
                        
                    # Get process details
                    proc_info = proc.info
                    proc_info['cpu_percent'] = proc.cpu_percent(interval=0.1)
                    proc_info['memory_percent'] = proc.memory_percent()
                    
                    # Calculate running time
                    create_time = datetime.fromtimestamp(proc_info['create_time'])
                    running_time = datetime.now() - create_time
                    hours, remainder = divmod(running_time.total_seconds(), 3600)
                    minutes, seconds = divmod(remainder, 60)
                    proc_info['running_time'] = f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
                    
                    processes.append(proc_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                    
            # Sort processes
            if sort_by == 'cpu':
                processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            elif sort_by == 'mem':
                processes.sort(key=lambda x: x['memory_percent'], reverse=True)
            elif sort_by == 'pid':
                processes.sort(key=lambda x: x['pid'])
            elif sort_by == 'name':
                processes.sort(key=lambda x: x['name'].lower())
                
            # Print process information
            if not processes:
                if filter_name:
                    print(f"No processes matching '{filter_name}' found")
                else:
                    print("No processes found")
                return
                
            # Format output
            print(f"{'PID':<8} {'CPU%':<8} {'MEM%':<8} {'STATUS':<10} {'USER':<15} {'RUNNING':<15} {'NAME':<30}")
            print("-" * 90)
            
            for proc in processes[:50]:  # Limit to top 50 processes to avoid overwhelming output
                print(f"{proc['pid']:<8} {proc['cpu_percent']:6.1f}% {proc['memory_percent']:6.1f}% "
                      f"{proc['status']:<10} {proc['username'][:15]:<15} {proc['running_time']:<15} {proc['name'][:30]}")
                
            if len(processes) > 50:
                print(f"\n(Showing top 50 of {len(processes)} processes)")
                
        except Exception as e:
            self.logger.error(f"Error listing processes: {str(e)}")
            print(f"Error listing processes: {str(e)}")
            
    def kill_process(self, pid=None, name=None, force=False):
        """Kill a process by PID or name"""
        if pid is None and name is None:
            print("Error: Either PID or process name must be specified")
            return
            
        self.logger.info(f"Killing process (pid: {pid}, name: {name}, force: {force})")
        
        try:
            processes_to_kill = []
            
            # Find processes to kill
            if pid is not None:
                try:
                    proc = psutil.Process(pid)
                    processes_to_kill.append(proc)
                except psutil.NoSuchProcess:
                    print(f"Error: No process with PID {pid} found")
                    return
            elif name is not None:
                matching_processes = []
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if name.lower() in proc.info['name'].lower():
                            matching_processes.append(proc)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                        
                if not matching_processes:
                    print(f"Error: No processes matching '{name}' found")
                    return
                    
                if len(matching_processes) > 1:
                    print(f"Found {len(matching_processes)} processes matching '{name}':")
                    for proc in matching_processes:
                        print(f"  PID {proc.info['pid']}: {proc.info['name']}")
                        
                    confirm = input(f"Kill all {len(matching_processes)} processes? (y/n): ")
                    if confirm.lower() != 'y':
                        print("Operation cancelled")
                        return
                        
                processes_to_kill = matching_processes
            
            # Kill processes
            for proc in processes_to_kill:
                try:
                    process_name = proc.name()
                    process_pid = proc.pid
                    
                    if force:
                        proc.kill()  # SIGKILL
                    else:
                        proc.terminate()  # SIGTERM
                        
                    print(f"Process {process_name} (PID {process_pid}) {'killed' if force else 'terminated'}")
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
                    print(f"Error killing process (PID {proc.pid}): {str(e)}")
                    
        except Exception as e:
            self.logger.error(f"Error killing process: {str(e)}")
            print(f"Error killing process: {str(e)}")
            
    def monitor_process(self, pid=None, name=None, interval=1):
        """Monitor a specific process or processes"""
        if pid is None and name is None:
            print("Error: Either PID or process name must be specified")
            return
            
        self.logger.info(f"Monitoring process (pid: {pid}, name: {name}, interval: {interval})")
        
        try:
            target_pids = []
            
            # Get target process(es)
            if pid is not None:
                try:
                    proc = psutil.Process(pid)
                    target_pids.append(pid)
                    print(f"Monitoring process {proc.name()} (PID {pid})")
                except psutil.NoSuchProcess:
                    print(f"Error: No process with PID {pid} found")
                    return
            elif name is not None:
                for proc in psutil.process_iter(['pid', 'name']):
                    try:
                        if name.lower() in proc.info['name'].lower():
                            target_pids.append(proc.info['pid'])
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                        
                if not target_pids:
                    print(f"Error: No processes matching '{name}' found")
                    return
                    
                print(f"Monitoring {len(target_pids)} processes matching '{name}'")
                
            print("Press Ctrl+C to stop monitoring\n")
            print(f"{'PID':<8} {'CPU%':<8} {'MEM%':<8} {'THREADS':<8} {'IO READ':<12} {'IO WRITE':<12} {'NAME'}")
            print("-" * 80)
            
            try:
                while True:
                    current_pids = []
                    
                    for target_pid in target_pids[:]:
                        try:
                            proc = psutil.Process(target_pid)
                            current_pids.append(target_pid)
                            
                            # Get process metrics
                            cpu_percent = proc.cpu_percent(interval=interval)
                            mem_percent = proc.memory_percent()
                            threads = proc.num_threads()
                            
                            try:
                                io_counters = proc.io_counters()
                                read_bytes = self._format_bytes(io_counters.read_bytes)
                                write_bytes = self._format_bytes(io_counters.write_bytes)
                            except (psutil.AccessDenied, AttributeError):
                                read_bytes = "N/A"
                                write_bytes = "N/A"
                                
                            name = proc.name()
                            
                            print(f"{target_pid:<8} {cpu_percent:6.1f}% {mem_percent:6.1f}% {threads:<8} "
                                  f"{read_bytes:<12} {write_bytes:<12} {name}")
                                  
                        except psutil.NoSuchProcess:
                            target_pids.remove(target_pid)
                            print(f"Process PID {target_pid} has terminated")
                    
                    # All processes terminated
                    if not current_pids:
                        print("All monitored processes have terminated")
                        break
                        
            except KeyboardInterrupt:
                print("\nMonitoring stopped")
                
        except Exception as e:
            self.logger.error(f"Error monitoring process: {str(e)}")
            print(f"Error monitoring process: {str(e)}")
    
    def _format_bytes(self, bytes_value):
        """Format bytes in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024:
                return f"{bytes_value:.1f}{unit}"
            bytes_value /= 1024
        return f"{bytes_value:.1f}PB"