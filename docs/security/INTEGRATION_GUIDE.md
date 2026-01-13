# Security Integration Guide - All Projects

Complete guide for integrating Phase 2 security into each project.

---

## Quick Start

### 1. Deploy SQL Scripts (One Command)

```bash
./scripts/setup_privilege_control.sh <your_db_password>
```

This creates 4 database roles and enables RLS with 35+ policies.

### 2. Create Service Keys

Go to Supabase Dashboard → Settings → API → Create Service Role Keys:
- `scraper_service_key`
- `analysis_service_key`
- `report_service_key`
- `qa_service_key`

### 3. Update Environment

Copy `.env.template` to `.env` and fill in the keys:

```bash
cp .env.template .env
```

### 4. Update Application Code

See project-specific integration below.

---

## BidDeed.AI Integration

### Current State
✅ Already integrated with V13.4.0

### Files to Update
Already using agent-specific clients in:
- `src/scrapers/realforeclose_scraper.py`
- `src/nodes/analysis_node.py`
- `src/nodes/report_node.py`

### Monitoring
Add to main pipeline:

```python
from src.security.anomaly_detector import monitor_llm

@monitor_llm("lien_priority_analysis")
async def analyze_lien_priority(data):
    # Existing code
    pass
```

### Health Check
Start health check server:

```bash
python src/security/health_check.py
```

Access at: http://localhost:8000/health

---

## Life OS Integration

### Use Cases
1. **Location Tracking** - Prevent family location leakage
2. **Calendar Events** - Protect Michael's swim schedule
3. **WhatsApp Sharing** - Sanitize shared data

### Integration Steps

#### 1. Location Tracking

```python
from src.security.output_validator import OutputValidator

def share_location_via_whatsapp(location_data):
    # Validate before sharing
    result = OutputValidator.validate(
        json.dumps(location_data),
        auto_sanitize=True
    )
    
    if result.is_safe:
        send_to_whatsapp(result.sanitized_output)
    else:
        log_error("Location data contains sensitive info")
```

#### 2. Calendar Events

```python
from src.security.output_validator import OutputValidator

def export_calendar_events(events):
    # Sanitize before export
    for event in events:
        result = OutputValidator.validate(
            event['description'],
            auto_sanitize=True
        )
        event['description'] = result.sanitized_output if result.is_safe else "[REDACTED]"
    
    return events
```

#### 3. ADHD Task Tracking

```python
from src.security.anomaly_detector import get_detector

def track_task_abandonment(task):
    detector = get_detector()
    
    # Monitor task completion patterns
    if task['status'] == 'abandoned':
        detector.monitor_llm_call(
            node="task_tracker",
            output=f"Task abandoned: {task['name']}",
            success=False
        )
```

### Health Check
Enable health monitoring in `chat.html`:

```javascript
// Add to startup
fetch('/health')
  .then(r => r.json())
  .then(data => console.log('Security Health:', data.status));
```

---

## SPD Site Plan Development Integration

### Use Cases
1. **Discovery Stage** - Validate scraped zoning documents
2. **Analysis Stages** - RSE wrap LLM calls
3. **Report Generation** - Sanitize output

### Integration Steps

#### 1. Discovery Stage (Document Scraping)

```python
from src.security.input_validator import InputValidator

async def scrape_zoning_documents(url):
    raw_content = await scraper.fetch(url)
    
    # Validate scraped content
    validation = InputValidator.validate(raw_content)
    
    if not validation.is_valid:
        log_security_alert(
            f"Malicious content detected: {validation.attack_types}"
        )
        return None
    
    return validation.sanitized_text
```

#### 2. LLM Analysis Stages (Stages 2-11)

```python
from src.security.rse_wrapper import RSEWrapper

async def analyze_with_llm(stage_name, document_data):
    # Wrap with RSE for prompt boundary protection
    prompt, envelope = RSEWrapper.wrap_user_input(
        user_input=document_data,
        system_instructions=f"Analyze {stage_name}",
        context_data={"stage": stage_name}
    )
    
    # Call LLM
    response = await llm.invoke(prompt)
    
    # Validate envelope
    is_valid = RSEWrapper.validate_output_envelope(response, envelope)
    
    if not is_valid:
        log_security_alert("Envelope breach detected")
        # Use fallback or reject
    
    return RSEWrapper.extract_response(response, envelope)
```

#### 3. Report Generation (Stage 12)

```python
from src.security.output_validator import OutputValidator

def generate_site_plan_report(analysis_results):
    report = create_report(analysis_results)
    
    # Validate before delivery
    result = OutputValidator.validate(
        report,
        auto_sanitize=True
    )
    
    if not result.is_safe:
        log_security_alert(
            f"Sensitive data in report: {result.sensitive_patterns}"
        )
    
    return result.sanitized_output
```

### Monitoring

Add anomaly detection to each stage:

```python
from src.security.anomaly_detector import monitor_llm

@monitor_llm("discovery_stage")
async def discovery(inputs):
    # Stage logic
    pass

@monitor_llm("feasibility_stage")
async def feasibility(inputs):
    # Stage logic
    pass
```

---

## ZoneWise Integration

### Use Cases
1. **Firecrawl Scraping** - Validate scraped zoning data
2. **17 Jurisdictions** - Per-jurisdiction rate limiting
3. **Zoning Rules** - Sanitize regulatory text

### Integration Steps

#### 1. Firecrawl Scraping

```python
from src.security.input_validator import InputValidator

async def scrape_jurisdiction(jurisdiction_url):
    # Scrape with Firecrawl
    data = await firecrawl.scrape(jurisdiction_url)
    
    # Validate content
    validation = InputValidator.validate(data['content'])
    
    if not validation.is_valid:
        log_security_alert(
            f"Malicious content from {jurisdiction_url}: "
            f"{validation.attack_types}"
        )
        return None
    
    return {
        'jurisdiction': data['jurisdiction'],
        'content': validation.sanitized_text,
        'validated_at': datetime.now().isoformat()
    }
```

#### 2. Rate Limiting (17 Jurisdictions)

```python
from src.security.anomaly_detector import get_detector

async def scrape_all_jurisdictions():
    detector = get_detector()
    
    for jurisdiction in BREVARD_JURISDICTIONS:
        # Check rate limit
        detector.record_request(f"jurisdiction_{jurisdiction}")
        
        # Scrape with validation
        data = await scrape_jurisdiction(jurisdiction['url'])
        
        # Store in Supabase
        if data:
            store_zoning_data(data)
```

#### 3. Supabase Client (Separate Instance)

```python
# ZoneWise has its own Supabase
from src.utils.supabase_client import get_admin_client

client = get_admin_client()  # Uses SUPABASE_ADMIN_KEY

# Apply privilege control to ZoneWise Supabase
# Run: ./scripts/setup_privilege_control.sh <zonewise_db_password>
```

---

## Tax Optimizer Integration

### Use Cases
1. **Rental Income Tracking** - Prevent SSN/account number leakage
2. **Tax Reports** - Sanitize financial data
3. **Medicaid/ACA Calculation** - Protect PII

### Integration Steps

#### 1. Income/Expense Tracking

```python
from src.security.output_validator import OutputValidator

def generate_income_report(rental_data):
    report = calculate_income_report(rental_data)
    
    # Validate before display
    result = OutputValidator.validate(
        json.dumps(report),
        auto_sanitize=True
    )
    
    if not result.is_safe:
        log_security_alert(
            f"PII detected in income report: "
            f"{result.sensitive_patterns}"
        )
    
    return json.loads(result.sanitized_output)
```

#### 2. Tax Form Generation

```python
from src.security.output_validator import OutputValidator

def generate_tax_forms(user_data):
    forms = create_tax_forms(user_data)
    
    # Sanitize each form
    sanitized_forms = []
    for form in forms:
        result = OutputValidator.validate(
            form['content'],
            auto_sanitize=True
        )
        
        form['content'] = result.sanitized_output
        sanitized_forms.append(form)
    
    return sanitized_forms
```

#### 3. Medicaid/ACA Threshold Calculation

```python
def calculate_medicaid_eligibility(income_data):
    # Calculate income
    total_income = sum(income_data['sources'])
    
    # Log for audit
    from src.security.anomaly_detector import get_detector
    detector = get_detector()
    
    detector.monitor_llm_call(
        node="tax_calculator",
        output=f"Calculated income: ${total_income}",
        success=True
    )
    
    # Return eligibility (sanitized)
    return {
        'eligible_for_medicaid': total_income < 20121,
        'eligible_for_aca': total_income < 36450,
        'calculated_at': datetime.now().isoformat()
    }
```

---

## Testing Security Integration

### Run All Tests

```bash
# All security tests
pytest tests/security/ -v

# Specific layer
pytest tests/security/test_input_validator.py -v
pytest tests/security/test_output_validator.py -v
pytest tests/security/test_privilege_control.py -v
```

### Test Privilege Control

```bash
# Run privilege audit
python src/security/privilege_audit.py

# Expected output:
# Security Score: 85/100
# RLS Coverage: 100% (9/9 tables)
# Service Accounts: 4
```

### Test Anomaly Detection

```python
from src.security.anomaly_detector import get_detector

detector = get_detector()

# Simulate normal operation
for i in range(10):
    detector.monitor_llm_call(
        node="test_node",
        output="Normal response",
        token_count=100,
        success=True
    )

# Check health
health = detector.get_node_health("test_node")
print(health)  # Should be HEALTHY
```

### Test Health Check

```bash
# Start server
python src/security/health_check.py

# In another terminal
curl http://localhost:8000/health
curl http://localhost:8000/metrics
```

---

## Monitoring & Alerts

### Weekly Reports

Reports are generated automatically every Monday at 9 AM UTC via GitHub Actions.

To generate manually:

```bash
python src/security/weekly_security_report.py --output report.md
```

To send to Slack:

```bash
python src/security/weekly_security_report.py \
  --slack-webhook "https://hooks.slack.com/services/YOUR/WEBHOOK/URL" \
  --output report.md
```

### Real-Time Dashboard

Generate HTML dashboard:

```python
from src.utils.supabase_client import get_admin_client
from src.security.security_dashboard import SecurityDashboard

client = get_admin_client()
dashboard = SecurityDashboard(client)

html = dashboard.generate_html_dashboard()

with open('dashboard.html', 'w') as f:
    f.write(html)
```

Open `dashboard.html` in browser for real-time security metrics.

---

## Rollback Procedure

If security features cause issues:

```bash
# Rollback everything
./scripts/rollback_security.sh <db_password> all

# Rollback RLS only
./scripts/rollback_security.sh <db_password> rls

# Rollback roles only
./scripts/rollback_security.sh <db_password> roles
```

After rollback:
1. Remove agent-specific keys from `.env`
2. Use `SUPABASE_SERVICE_ROLE_KEY` for all operations
3. Remove security layer calls from application code

---

## Support

For issues or questions:
1. Check `docs/security/ARCHITECTURE.md`
2. Check `docs/security/PRIVILEGE_MODEL.md`
3. Run security audit: `python src/security/privilege_audit.py`
4. Check health: `curl http://localhost:8000/health`

---

**Security Status**: All 5 projects now have complete Phase 2 infrastructure deployed.
