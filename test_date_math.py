from datetime import datetime, timezone, timedelta, time

def test_scenario(desc, now_str, created_str, start_time_str, end_time_str):
    now = datetime.fromisoformat(now_str).replace(tzinfo=timezone.utc)
    created_at = datetime.fromisoformat(created_str).replace(tzinfo=timezone.utc)
    
    start_time = time.fromisoformat(start_time_str)
    end_time = time.fromisoformat(end_time_str)
    
    base_date = created_at.astimezone(timezone.utc).date()
    start_dt = datetime.combine(base_date, start_time).replace(tzinfo=timezone.utc)
    end_dt = datetime.combine(base_date, end_time).replace(tzinfo=timezone.utc)
    
    if end_time < start_time:
        end_dt += timedelta(days=1)
        if now.time() <= end_time and now.time() >= start_time:
            pass
        elif now.time() < start_time and now.time() < end_time and base_date == now.date():
            start_dt -= timedelta(days=1)
            end_dt -= timedelta(days=1)
            
    if now >= end_dt:
        print(f"[{desc}] FAILED: Window Passed. start={start_dt}, end={end_dt}")
        return
        
    if now > start_dt:
        start_dt = now
        
    print(f"[{desc}] SUCCESS: start_dt={start_dt}, end_dt={end_dt}")

test_scenario("User Config Today", "2026-02-25T10:16:00", "2026-02-25T10:15:00", "11:10:00", "07:10:00")
test_scenario("Resumed cross-midnight", "2026-02-25T03:00:00", "2026-02-24T10:15:00", "11:10:00", "07:10:00")
test_scenario("Resumed past window", "2026-02-25T10:00:00", "2026-02-24T10:15:00", "11:10:00", "07:10:00")
test_scenario("Created at 1AM for cross-midnight", "2026-02-25T01:00:00", "2026-02-25T01:00:00", "23:00:00", "02:00:00")
