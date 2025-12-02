#!/usr/bin/env python3
"""
Load Testing Script for WebSocket Vulnerability Scanner
Tests concurrent connections, multiple scans, and system performance
"""

import asyncio
import aiohttp
import websockets
import json
import time
import logging
import statistics
import random
from typing import List, Dict, Any
from dataclasses import dataclass, field
from datetime import datetime
import concurrent.futures
import threading

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class ConnectionMetrics:
    """Metrics for a single WebSocket connection"""
    connection_id: str
    connect_time: float
    total_messages: int = 0
    scan_start_time: float = 0.0
    scan_end_time: float = 0.0
    scan_duration: float = 0.0
    events_received: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    scan_completed: bool = False
    vulnerabilities_found: int = 0

@dataclass
class LoadTestResults:
    """Overall load test results"""
    total_connections: int
    concurrent_scans: int
    test_duration: float
    successful_connections: int
    failed_connections: int
    successful_scans: int
    failed_scans: int
    avg_scan_duration: float
    min_scan_duration: float
    max_scan_duration: float
    total_vulnerabilities: int
    connection_metrics: List[ConnectionMetrics] = field(default_factory=list)
    server_errors: List[str] = field(default_factory=list)

class WebSocketLoadTester:
    """Load tester for WebSocket vulnerability scanner"""
    
    def __init__(self, server_url: str = "http://localhost:8000", ws_url: str = "ws://localhost:8000/ws"):
        self.server_url = server_url
        self.ws_url = ws_url
        self.test_directory = "C:/temp"  # Change this to your test directory
        self.connection_metrics: Dict[str, ConnectionMetrics] = {}
        self.active_connections = []
        self.completed_scans = 0
        self.failed_scans = 0
        
    async def check_server_health(self) -> bool:
        """Check if server is responding"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.server_url}/api/health", timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        logger.info(f"Server health check passed: {data.get('scanner')}")
                        return True
                    else:
                        logger.error(f"Server health check failed: {response.status}")
                        return False
        except Exception as e:
            logger.error(f"Cannot connect to server: {e}")
            return False
    
    async def single_websocket_client(self, client_id: int, test_duration: int = 60) -> ConnectionMetrics:
        """Single WebSocket client that performs scanning operations"""
        connection_id = f"load_test_client_{client_id}"
        metrics = ConnectionMetrics(connection_id=connection_id, connect_time=time.time())
        
        try:
            # Connect to WebSocket
            websocket = await websockets.connect(self.ws_url)
            logger.debug(f"Client {client_id} connected to WebSocket")
            
            # Listen for messages in background
            async def message_listener():
                try:
                    async for message in websocket:
                        data = json.loads(message)
                        metrics.total_messages += 1
                        metrics.events_received.append(data)
                        
                        event_type = data.get("event_type", "unknown")
                        
                        if event_type == "connection_established":
                            metrics.connection_id = data.get("connection_id", connection_id)
                        
                        elif event_type == "status_change":
                            status = data.get("status")
                            if status == "started":
                                metrics.scan_start_time = time.time()
                            elif status == "completed":
                                metrics.scan_end_time = time.time()
                                metrics.scan_duration = metrics.scan_end_time - metrics.scan_start_time
                                metrics.scan_completed = True
                                metrics.vulnerabilities_found = data.get("vulnerabilities_found", 0)
                                
                        elif event_type == "error":
                            error_msg = data.get("message", "Unknown error")
                            metrics.errors.append(error_msg)
                            
                except websockets.exceptions.ConnectionClosed:
                    logger.debug(f"Client {client_id} WebSocket connection closed")
                except Exception as e:
                    logger.error(f"Client {client_id} message listener error: {e}")
                    metrics.errors.append(f"Message listener error: {e}")
            
            # Start message listener
            listener_task = asyncio.create_task(message_listener())
            
            # Wait for connection establishment
            await asyncio.sleep(1)
            
            # Start a scan
            try:
                scan_request = {
                    "scan_type": "directory",
                    "paths": [self.test_directory],
                    "recursive": True
                }
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(f"{self.server_url}/api/scan", 
                                          json=scan_request, 
                                          timeout=30) as response:
                        if response.status == 200:
                            scan_data = await response.json()
                            scan_id = scan_data.get("scan_id")
                            
                            # Subscribe to scan updates
                            subscribe_msg = {
                                "action": "subscribe",
                                "scan_id": scan_id
                            }
                            await websocket.send(json.dumps(subscribe_msg))
                            logger.debug(f"Client {client_id} started scan {scan_id}")
                            
                        else:
                            error_msg = f"Failed to start scan: {response.status}"
                            metrics.errors.append(error_msg)
                            logger.error(f"Client {client_id}: {error_msg}")
            
            except Exception as e:
                error_msg = f"Scan request failed: {e}"
                metrics.errors.append(error_msg)
                logger.error(f"Client {client_id}: {error_msg}")
            
            # Wait for test duration or scan completion
            start_time = time.time()
            while time.time() - start_time < test_duration:
                if metrics.scan_completed:
                    break
                await asyncio.sleep(1)
            
            # Cleanup
            listener_task.cancel()
            await websocket.close()
            
            logger.info(f"Client {client_id} completed: {metrics.total_messages} messages, "
                       f"scan completed: {metrics.scan_completed}, "
                       f"vulnerabilities: {metrics.vulnerabilities_found}")
            
            return metrics
            
        except Exception as e:
            error_msg = f"Client {client_id} failed: {e}"
            metrics.errors.append(error_msg)
            logger.error(error_msg)
            return metrics
    
    async def concurrent_load_test(self, num_clients: int, test_duration: int = 120) -> LoadTestResults:
        """Run concurrent load test with multiple WebSocket clients"""
        logger.info(f"Starting load test: {num_clients} concurrent clients for {test_duration} seconds")
        
        start_time = time.time()
        
        # Create concurrent client tasks
        tasks = []
        for i in range(num_clients):
            # Stagger connection attempts
            if i > 0 and i % 10 == 0:
                await asyncio.sleep(1)  # Brief pause every 10 connections
            
            task = asyncio.create_task(self.single_websocket_client(i, test_duration))
            tasks.append(task)
        
        # Wait for all clients to complete
        logger.info("Waiting for all clients to complete...")
        client_metrics = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.time()
        total_test_duration = end_time - start_time
        
        # Process results
        successful_connections = 0
        failed_connections = 0
        successful_scans = 0
        failed_scans = 0
        scan_durations = []
        total_vulnerabilities = 0
        valid_metrics = []
        
        for i, result in enumerate(client_metrics):
            if isinstance(result, Exception):
                logger.error(f"Client {i} failed with exception: {result}")
                failed_connections += 1
                continue
            
            if isinstance(result, ConnectionMetrics):
                valid_metrics.append(result)
                
                if result.errors:
                    failed_connections += 1
                else:
                    successful_connections += 1
                
                if result.scan_completed:
                    successful_scans += 1
                    scan_durations.append(result.scan_duration)
                    total_vulnerabilities += result.vulnerabilities_found
                else:
                    failed_scans += 1
            else:
                failed_connections += 1
        
        # Calculate statistics
        avg_scan_duration = statistics.mean(scan_durations) if scan_durations else 0.0
        min_scan_duration = min(scan_durations) if scan_durations else 0.0
        max_scan_duration = max(scan_durations) if scan_durations else 0.0
        
        # Create results
        results = LoadTestResults(
            total_connections=num_clients,
            concurrent_scans=num_clients,
            test_duration=total_test_duration,
            successful_connections=successful_connections,
            failed_connections=failed_connections,
            successful_scans=successful_scans,
            failed_scans=failed_scans,
            avg_scan_duration=avg_scan_duration,
            min_scan_duration=min_scan_duration,
            max_scan_duration=max_scan_duration,
            total_vulnerabilities=total_vulnerabilities,
            connection_metrics=valid_metrics
        )
        
        return results
    
    async def stress_test_websocket_connections(self, max_connections: int = 100, step_size: int = 10):
        """Progressive stress test to find connection limits"""
        logger.info(f"Starting WebSocket stress test: up to {max_connections} connections")
        
        stress_results = []
        
        for num_connections in range(step_size, max_connections + 1, step_size):
            logger.info(f"Testing {num_connections} concurrent connections...")
            
            try:
                # Run shorter tests for stress testing
                results = await self.concurrent_load_test(num_connections, test_duration=30)
                
                stress_results.append({
                    'connections': num_connections,
                    'successful': results.successful_connections,
                    'failed': results.failed_connections,
                    'success_rate': results.successful_connections / num_connections * 100,
                    'avg_scan_duration': results.avg_scan_duration,
                    'total_vulnerabilities': results.total_vulnerabilities
                })
                
                logger.info(f"Result: {results.successful_connections}/{num_connections} successful "
                           f"({results.successful_connections/num_connections*100:.1f}%)")
                
                # If success rate drops below 80%, consider this the limit
                if results.successful_connections / num_connections < 0.8:
                    logger.warning(f"Success rate dropped below 80% at {num_connections} connections")
                    break
                    
                # Brief pause between stress test rounds
                await asyncio.sleep(5)
                
            except Exception as e:
                logger.error(f"Stress test failed at {num_connections} connections: {e}")
                break
        
        return stress_results
    
    def print_load_test_results(self, results: LoadTestResults):
        """Print formatted load test results"""
        print("\n" + "=" * 80)
        print("WEBSOCKET VULNERABILITY SCANNER - LOAD TEST RESULTS")
        print("=" * 80)
        
        print(f"Test Configuration:")
        print(f"  Target Directory: {self.test_directory}")
        print(f"  Concurrent Clients: {results.total_connections}")
        print(f"  Test Duration: {results.test_duration:.2f} seconds")
        
        print(f"\nConnection Results:")
        print(f"  Successful Connections: {results.successful_connections}")
        print(f"  Failed Connections: {results.failed_connections}")
        print(f"  Connection Success Rate: {results.successful_connections/results.total_connections*100:.1f}%")
        
        print(f"\nScan Results:")
        print(f"  Successful Scans: {results.successful_scans}")
        print(f"  Failed Scans: {results.failed_scans}")
        print(f"  Scan Success Rate: {results.successful_scans/results.concurrent_scans*100:.1f}%")
        
        print(f"\nPerformance Metrics:")
        print(f"  Average Scan Duration: {results.avg_scan_duration:.2f} seconds")
        print(f"  Fastest Scan: {results.min_scan_duration:.2f} seconds")
        print(f"  Slowest Scan: {results.max_scan_duration:.2f} seconds")
        print(f"  Total Vulnerabilities Found: {results.total_vulnerabilities}")
        
        if results.successful_scans > 0:
            avg_vulns_per_scan = results.total_vulnerabilities / results.successful_scans
            print(f"  Average Vulnerabilities per Scan: {avg_vulns_per_scan:.1f}")
        
        # Message statistics
        total_messages = sum(m.total_messages for m in results.connection_metrics)
        if total_messages > 0:
            avg_messages = total_messages / len(results.connection_metrics)
            print(f"  Total WebSocket Messages: {total_messages}")
            print(f"  Average Messages per Connection: {avg_messages:.1f}")
        
        # Error summary
        total_errors = sum(len(m.errors) for m in results.connection_metrics)
        if total_errors > 0:
            print(f"\nErrors Encountered:")
            print(f"  Total Errors: {total_errors}")
            
            # Show most common errors
            all_errors = []
            for m in results.connection_metrics:
                all_errors.extend(m.errors)
            
            error_counts = {}
            for error in all_errors:
                error_counts[error] = error_counts.get(error, 0) + 1
            
            for error, count in sorted(error_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
                print(f"    {error}: {count} times")
        
        print("=" * 80)

    async def run_performance_benchmark(self):
        """Run comprehensive performance benchmark"""
        logger.info("Starting comprehensive performance benchmark...")
        
        # Check server health first
        if not await self.check_server_health():
            logger.error("Server health check failed. Make sure the server is running.")
            return
        
        benchmarks = []
        
        # Test 1: Single connection baseline
        print("\n[1/4] Baseline Test: Single Connection")
        results = await self.concurrent_load_test(1, test_duration=60)
        benchmarks.append(("Single Connection", results))
        self.print_load_test_results(results)
        
        # Test 2: Moderate load
        print("\n[2/4] Moderate Load Test: 10 Concurrent Connections")
        results = await self.concurrent_load_test(10, test_duration=60)
        benchmarks.append(("Moderate Load", results))
        self.print_load_test_results(results)
        
        # Test 3: High load
        print("\n[3/4] High Load Test: 25 Concurrent Connections")
        results = await self.concurrent_load_test(25, test_duration=60)
        benchmarks.append(("High Load", results))
        self.print_load_test_results(results)
        
        # Test 4: Stress test to find limits
        print("\n[4/4] Stress Test: Finding Connection Limits")
        stress_results = await self.stress_test_websocket_connections(50, 5)
        
        print("\nSTRESS TEST RESULTS:")
        print("-" * 60)
        for result in stress_results:
            print(f"Connections: {result['connections']:2d} | "
                  f"Success: {result['successful']:2d}/{result['connections']:2d} "
                  f"({result['success_rate']:5.1f}%) | "
                  f"Avg Duration: {result['avg_scan_duration']:5.2f}s | "
                  f"Vulnerabilities: {result['total_vulnerabilities']:3d}")
        
        # Summary
        print("\n" + "=" * 80)
        print("BENCHMARK SUMMARY")
        print("=" * 80)
        
        for name, result in benchmarks:
            success_rate = result.successful_scans / result.concurrent_scans * 100
            print(f"{name:20s}: {result.successful_scans:2d}/{result.concurrent_scans:2d} scans "
                  f"({success_rate:5.1f}%), avg {result.avg_scan_duration:5.2f}s, "
                  f"{result.total_vulnerabilities:3d} vulnerabilities")
        
        return benchmarks, stress_results


async def main():
    """Main function for load testing"""
    print("WebSocket Vulnerability Scanner - Load Testing Tool")
    print("=" * 60)
    
    tester = WebSocketLoadTester()
    
    # Interactive menu
    while True:
        print("\nLoad Test Options:")
        print("1. Quick Load Test (5 concurrent connections)")
        print("2. Moderate Load Test (15 concurrent connections)")
        print("3. High Load Test (30 concurrent connections)")
        print("4. Custom Load Test")
        print("5. Full Performance Benchmark")
        print("6. WebSocket Stress Test")
        print("7. Exit")
        
        choice = input("\nSelect option (1-7): ").strip()
        
        if choice == "1":
            print("\nRunning Quick Load Test...")
            results = await tester.concurrent_load_test(5, 60)
            tester.print_load_test_results(results)
            
        elif choice == "2":
            print("\nRunning Moderate Load Test...")
            results = await tester.concurrent_load_test(15, 90)
            tester.print_load_test_results(results)
            
        elif choice == "3":
            print("\nRunning High Load Test...")
            results = await tester.concurrent_load_test(30, 120)
            tester.print_load_test_results(results)
            
        elif choice == "4":
            try:
                num_clients = int(input("Number of concurrent connections: "))
                duration = int(input("Test duration (seconds): "))
                results = await tester.concurrent_load_test(num_clients, duration)
                tester.print_load_test_results(results)
            except ValueError:
                print("Invalid input. Please enter numbers.")
                
        elif choice == "5":
            await tester.run_performance_benchmark()
            
        elif choice == "6":
            max_conn = int(input("Maximum connections to test (default 50): ") or "50")
            stress_results = await tester.stress_test_websocket_connections(max_conn)
            print("\nStress test completed. See results above.")
            
        elif choice == "7":
            print("Exiting load tester...")
            break
            
        else:
            print("Invalid choice. Please select 1-7.")


if __name__ == "__main__":
    # Update test directory
    test_dir = input("Enter test directory path (default: C:/temp): ").strip()
    if test_dir:
        # Update the test directory in the tester
        import inspect
        
    asyncio.run(main())