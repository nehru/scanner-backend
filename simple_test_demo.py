#!/usr/bin/env python3
"""
Simple WebSocket Scanner Demo
Quick test script to demonstrate vulnerability scanning with WebSocket progress
"""

import asyncio
import json
import websockets
import requests
import time

async def simple_websocket_test():
    """Simple test of WebSocket vulnerability scanner"""
    
    print("🚀 Simple WebSocket Vulnerability Scanner Test")
    print("=" * 50)
    
    # Configuration
    server_url = "http://localhost:8000"
    ws_url = "ws://localhost:8000/ws"
    test_directory = "C:/temp"  # Change this to your test directory
    
    # 1. Check if server is running
    try:
        response = requests.get(f"{server_url}/api/health", timeout=5)
        if response.status_code == 200:
            health = response.json()
            print(f"✓ Server is running: {health.get('scanner')}")
            print(f"  Real vulnerability detection: {health.get('real_vulnerability_detection')}")
        else:
            print("❌ Server health check failed")
            return
    except Exception as e:
        print(f"❌ Cannot connect to server: {e}")
        print("Please start the server with: python main.py")
        return
    
    # 2. Connect to WebSocket
    try:
        websocket = await websockets.connect(ws_url)
        print(f"✓ Connected to WebSocket: {ws_url}")
    except Exception as e:
        print(f"❌ Failed to connect to WebSocket: {e}")
        return
    
    # Storage for scan results
    scan_events = []
    scan_completed = False
    scan_id = None
    
    async def listen_for_messages():
        """Listen for WebSocket messages"""
        nonlocal scan_completed, scan_id
        
        try:
            async for message in websocket:
                data = json.loads(message)
                event_type = data.get("event_type", "unknown")
                
                if event_type == "connection_established":
                    connection_id = data.get("connection_id")
                    print(f"✓ Connection established: {connection_id}")
                    
                elif event_type == "subscription_confirmed":
                    print(f"✓ Subscribed to scan: {data.get('scan_id')}")
                    
                elif event_type == "progress":
                    progress = data.get("progress_percentage", 0)
                    stage = data.get("current_stage", "unknown")
                    current_file = data.get("current_file", "")
                    files_processed = data.get("files_processed", 0)
                    total_files = data.get("total_files", 0)
                    
                    if current_file:
                        print(f"📁 [{progress:5.1f}%] {stage}: {current_file}")
                    else:
                        print(f"⚡ [{progress:5.1f}%] {stage} ({files_processed}/{total_files})")
                    
                elif event_type == "status_change":
                    status = data.get("status")
                    message = data.get("message", "")
                    vulnerabilities = data.get("vulnerabilities_found", 0)
                    
                    if status == "started":
                        print(f"🚀 Scan started: {message}")
                    elif status == "completed":
                        print(f"🎉 Scan completed: {message}")
                        print(f"   Vulnerabilities found: {vulnerabilities}")
                        scan_completed = True
                    elif status == "failed":
                        print(f"💥 Scan failed: {message}")
                        scan_completed = True
                        
                elif event_type == "language_start":
                    language = data.get("current_language", "unknown")
                    print(f"🔍 Starting {language} analysis...")
                    
                elif event_type == "language_complete":
                    language = data.get("current_language", "unknown")
                    vuln_count = data.get("vulnerabilities_found", 0)
                    print(f"✓ {language} analysis complete - {vuln_count} vulnerabilities")
                    
                elif event_type == "error":
                    error_msg = data.get("message", "Unknown error")
                    print(f"❌ Error: {error_msg}")
                    scan_completed = True
                    
                scan_events.append(data)
                
        except websockets.exceptions.ConnectionClosed:
            print("WebSocket connection closed")
        except Exception as e:
            print(f"Error listening for messages: {e}")
    
    try:
        # 3. Start listening for messages
        listen_task = asyncio.create_task(listen_for_messages())
        
        # 4. Wait for connection
        await asyncio.sleep(1)
        
        # 5. Start a directory scan
        print(f"\n📂 Starting scan of directory: {test_directory}")
        
        scan_request = {
            "scan_type": "directory",
            "paths": [test_directory],
            "recursive": True
        }
        
        response = requests.post(f"{server_url}/api/scan", json=scan_request, timeout=30)
        
        if response.status_code == 200:
            scan_response = response.json()
            scan_id = scan_response.get("scan_id")
            print(f"✓ Scan started successfully: {scan_id}")
            
            # 6. Subscribe to scan updates
            subscribe_msg = {
                "action": "subscribe",
                "scan_id": scan_id
            }
            await websocket.send(json.dumps(subscribe_msg))
            
            # 7. Wait for scan completion
            print("\n⏳ Waiting for scan to complete...")
            start_time = time.time()
            timeout = 180  # 3 minutes
            
            while not scan_completed and (time.time() - start_time) < timeout:
                await asyncio.sleep(1)
            
            if scan_completed:
                print(f"\n✅ Test completed successfully!")
            else:
                print(f"\n⏰ Test timed out after {timeout} seconds")
            
            # 8. Get final results if available
            if scan_id:
                try:
                    result_response = requests.get(f"{server_url}/api/scan/{scan_id}/result", timeout=10)
                    if result_response.status_code == 200:
                        result_data = result_response.json()
                        print(f"\n📊 Final Results:")
                        print(f"   Files scanned: {result_data.get('total_files', 0)}")
                        print(f"   Vulnerabilities: {result_data.get('total_vulnerabilities', 0)}")
                        print(f"   Scan duration: {result_data.get('scan_duration', 0):.2f}s")
                except Exception as e:
                    print(f"Could not retrieve final results: {e}")
            
        else:
            print(f"❌ Failed to start scan: {response.status_code} - {response.text}")
            return
    
    except KeyboardInterrupt:
        print("\n🛑 Test interrupted by user")
    except Exception as e:
        print(f"❌ Test failed: {e}")
    finally:
        # Cleanup
        if 'listen_task' in locals():
            listen_task.cancel()
        await websocket.close()
        print("🔌 Disconnected from WebSocket")
    
    # Summary
    print(f"\n📈 Test Summary:")
    print(f"   Total events received: {len(scan_events)}")
    print(f"   Scan ID: {scan_id}")
    
    # Event breakdown
    event_counts = {}
    for event in scan_events:
        event_type = event.get("event_type", "unknown")
        event_counts[event_type] = event_counts.get(event_type, 0) + 1
    
    for event_type, count in event_counts.items():
        print(f"   {event_type}: {count}")


if __name__ == "__main__":
    print("WebSocket Vulnerability Scanner - Simple Test")
    print("=" * 60)
    
    # Get test directory from user
    test_dir = input("Enter directory to scan (or press Enter for 'C:/temp'): ").strip()
    if not test_dir:
        test_dir = "C:/temp"
    
    # Update the test function with user's directory
    import inspect
    import types
    
    # Run the test
    asyncio.run(simple_websocket_test())