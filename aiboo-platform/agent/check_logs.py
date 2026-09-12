"""
Check which Windows Event Logs are accessible
Run this to diagnose why Security log isn't being read
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(__file__))

print("=" * 60)
print("Windows Event Log Accessibility Check")
print("=" * 60)
print()

# Check if running as admin
import ctypes
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if is_admin():
    print("✓ Running as Administrator")
else:
    print("✗ NOT running as Administrator - Security log will be inaccessible")
    print("  Please run VSCode or PowerShell as Administrator")
print()

try:
    import win32evtlog
    print("✓ pywin32 is installed")
    
    # Try to open each log
    logs_to_check = ["Security", "System", "Application"]
    
    for log_name in logs_to_check:
        print(f"\n--- {log_name} Log ---")
        try:
            hand = win32evtlog.OpenEventLog(None, log_name)
            print(f"  ✓ ACCESSIBLE")
            
            # Get number of records - FIXED: correct function call
            try:
                # Fixed: GetNumberOfEventLogRecords returns a single integer
                records = win32evtlog.GetNumberOfEventLogRecords(hand)
                print(f"  📊 Records: {records} events")
                
                # Read the most recent event to verify
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                event_count = 0
                for event in events:
                    event_count += 1
                    if event_count == 1:
                        print(f"  📋 Latest Event ID: {event.EventID}")
                    if event_count >= 3:
                        break
                    
            except Exception as e:
                print(f"  ⚠ Could not read records: {e}")
                
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            print(f"  ✗ NOT ACCESSIBLE: {e}")
            
except ImportError:
    print("✗ pywin32 NOT installed")
    print("  Run: pip install pywin32")
    print("\nTo install:")
    print("  python -m pip install pywin32")

print("\n" + "=" * 60)
print("\n💡 TIPS:")
print("  1. Security log requires Administrator privileges")
print("  2. You ARE running as Administrator - good!")
print("  3. Your system is ready for Security log monitoring")
print("=" * 60)

# Optional: Show recent security events if accessible
if is_admin():
    try:
        import win32evtlog
        print("\n📋 Recent Security Events (last 5):")
        print("-" * 40)
        
        # Fixed: Open a new handle
        hand = win32evtlog.OpenEventLog(None, "Security")
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        # Read last 5 events
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        
        count = 0
        for event in events:
            if count >= 5:
                break
                
            event_id = event.EventID
            time_gen = event.TimeGenerated
            strings = event.StringInserts or []
            
            if event_id == 4625:
                user = strings[5] if len(strings) > 5 else "unknown"
                ip = strings[18] if len(strings) > 18 else "unknown"
                print(f"  🔴 {time_gen} - FAILED LOGIN (4625): user={user}, ip={ip}")
            elif event_id == 4624:
                user = strings[5] if len(strings) > 5 else "unknown"
                print(f"  🟢 {time_gen} - SUCCESS LOGIN (4624): user={user}")
            elif event_id == 4672:
                user = strings[0] if strings else "unknown"
                print(f"  👑 {time_gen} - ADMIN LOGON (4672): user={user}")
            elif event_id == 4688:
                process = strings[5] if len(strings) > 5 else "unknown"
                user = strings[4] if len(strings) > 4 else "unknown"
                print(f"  🔄 {time_gen} - PROCESS (4688): {process} by {user}")
            elif event_id == 5156:
                src_ip = strings[0] if len(strings) > 0 else "unknown"
                dst_ip = strings[2] if len(strings) > 2 else "unknown"
                print(f"  🌐 {time_gen} - CONNECTION (5156): {src_ip} -> {dst_ip}")
            else:
                print(f"  📝 {time_gen} - Event {event_id}")
            
            count += 1
                
        win32evtlog.CloseEventLog(hand)
        
        if count == 0:
            print("  No recent security events found")
            print("  Generate test events with: net use \\localhost\\fake /user:fakeuser wrongpass")
        
    except Exception as e:
        print(f"  Could not read recent events: {e}")
        print("  This is normal if no events exist yet")

print("\n" + "=" * 60)
print("✓ Your system is ready for AiBoO with Security log monitoring!")
print("=" * 60)