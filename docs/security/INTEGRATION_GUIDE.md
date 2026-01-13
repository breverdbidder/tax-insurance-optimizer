# Security Integration Guide - All 5 Projects

Quick integration examples for each project.

## BidDeed.AI
```python
from src.utils.supabase_client import get_scraper_client
client = get_scraper_client()  # Limited privileges
```

## Life OS
```python
from src.security.output_validator import OutputValidator
result = OutputValidator.validate(location_data, auto_sanitize=True)
```

## SPD Site Plan
```python
from src.security.input_validator import InputValidator
from src.security.rse_wrapper import RSEWrapper
```

## ZoneWise
```python
from src.security.input_validator import InputValidator
validation = InputValidator.validate_text(scraped_content)
```

## Tax Optimizer
```python
from src.security.output_validator import OutputValidator
result = OutputValidator.validate(tax_summary, auto_sanitize=True)
```

See docs/security/ARCHITECTURE.md for full examples.
