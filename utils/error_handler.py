"""
Error handling utilities for robust operation
"""

import time
import logging
import functools
from typing import Any, Callable, Optional, Dict, List
from dataclasses import dataclass

from rich.console import Console


@dataclass
class RetryConfig:
    """Configuration for retry logic"""
    max_attempts: int = 3
    base_delay: float = 1.0
    exponential_backoff: bool = True
    retry_exceptions: tuple = (Exception,)


class RateLimiter:
    """Simple rate limiter to prevent API abuse"""
    
    def __init__(self, max_requests_per_second: float = 5.0):
        self.max_requests_per_second = max_requests_per_second
        self.last_request_time = 0
        self.request_times = []
    
    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        current_time = time.time()
        
        # Clean old request times (older than 1 second)
        self.request_times = [t for t in self.request_times if current_time - t < 1.0]
        
        # Check if we need to wait
        if len(self.request_times) >= self.max_requests_per_second:
            sleep_time = 1.0 - (current_time - self.request_times[0])
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        # Record this request
        self.request_times.append(current_time)


class SecurityScannerError(Exception):
    """Base exception for scanner errors"""
    pass


class ContractNotFoundError(SecurityScannerError):
    """Contract address not found or invalid"""
    pass


class RPCConnectionError(SecurityScannerError):
    """RPC connection failed"""
    pass


class AnalysisError(SecurityScannerError):
    """Error during security analysis"""
    pass


class RateLimitError(SecurityScannerError):
    """Rate limit exceeded"""
    pass


def with_retry(config: RetryConfig = None):
    """Decorator to add retry logic to functions"""
    if config is None:
        config = RetryConfig()
    
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            last_exception = None
            
            for attempt in range(config.max_attempts):
                try:
                    return func(*args, **kwargs)
                
                except config.retry_exceptions as e:
                    last_exception = e
                    
                    if attempt < config.max_attempts - 1:  # Not the last attempt
                        if config.exponential_backoff:
                            delay = config.base_delay * (2 ** attempt)
                        else:
                            delay = config.base_delay
                        
                        logging.warning(f"Attempt {attempt + 1} failed for {func.__name__}: {str(e)}. Retrying in {delay}s...")
                        time.sleep(delay)
                    else:
                        logging.error(f"All {config.max_attempts} attempts failed for {func.__name__}")
            
            # If we get here, all attempts failed
            raise last_exception
        
        return wrapper
    return decorator


def with_rate_limit(rate_limiter: RateLimiter):
    """Decorator to add rate limiting to functions"""
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            rate_limiter.wait_if_needed()
            return func(*args, **kwargs)
        return wrapper
    return decorator


def safe_execute(func: Callable, default_value: Any = None, 
                error_message: str = "Operation failed") -> Any:
    """Safely execute a function with error handling"""
    try:
        return func()
    except Exception as e:
        logging.warning(f"{error_message}: {str(e)}")
        return default_value


def validate_bsc_address(address: str) -> bool:
    """Validate BSC address format"""
    if not isinstance(address, str):
        return False
    
    # Remove '0x' prefix if present
    if address.startswith('0x'):
        address = address[2:]
    
    # Check length (should be 40 hex characters)
    if len(address) != 40:
        return False
    
    # Check if all characters are valid hex
    try:
        int(address, 16)
        return True
    except ValueError:
        return False


def format_error_response(error: Exception, context: str = "") -> Dict[str, Any]:
    """Format error into standardized response"""
    error_type = type(error).__name__
    error_message = str(error)
    
    return {
        "error": True,
        "error_type": error_type,
        "error_message": error_message,
        "context": context,
        "timestamp": time.time()
    }


class ErrorAggregator:
    """Collect and categorize errors during analysis"""
    
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.console = Console()
    
    def add_error(self, error: Exception, context: str = ""):
        """Add an error to the collection"""
        self.errors.append({
            "error": error,
            "context": context,
            "timestamp": time.time(),
            "type": type(error).__name__
        })
    
    def add_warning(self, message: str, context: str = ""):
        """Add a warning to the collection"""
        self.warnings.append({
            "message": message,
            "context": context,
            "timestamp": time.time()
        })
    
    def has_errors(self) -> bool:
        """Check if any errors were collected"""
        return len(self.errors) > 0
    
    def has_warnings(self) -> bool:
        """Check if any warnings were collected"""
        return len(self.warnings) > 0
    
    def get_summary(self) -> Dict[str, Any]:
        """Get summary of collected errors and warnings"""
        return {
            "total_errors": len(self.errors),
            "total_warnings": len(self.warnings),
            "error_types": list(set(e["type"] for e in self.errors)),
            "has_critical_errors": any("Critical" in e["type"] for e in self.errors)
        }
    
    def display_summary(self):
        """Display error summary using rich console"""
        if self.has_errors():
            self.console.print(f"\n⚠️ [red]Errors encountered: {len(self.errors)}[/red]")
            for error in self.errors[-3:]:  # Show last 3 errors
                self.console.print(f"   • {error['type']}: {error['context']}")
        
        if self.has_warnings():
            self.console.print(f"\n⚠️ [yellow]Warnings: {len(self.warnings)}[/yellow]")
            for warning in self.warnings[-3:]:  # Show last 3 warnings
                self.console.print(f"   • {warning['message']}")


def setup_logging(level: str = "INFO", log_file: Optional[str] = None):
    """Setup logging configuration"""
    logging_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Setup handlers
    handlers = [logging.StreamHandler()]
    
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    
    # Configure logging
    logging.basicConfig(
        level=logging_level,
        handlers=handlers,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def handle_rpc_errors(func: Callable) -> Callable:
    """Decorator specifically for RPC error handling"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        
        except ConnectionError as e:
            raise RPCConnectionError(f"Failed to connect to BSC RPC: {str(e)}")
        
        except TimeoutError as e:
            raise RPCConnectionError(f"RPC request timed out: {str(e)}")
        
        except ValueError as e:
            if "invalid address" in str(e).lower():
                raise ContractNotFoundError(f"Invalid contract address: {str(e)}")
            else:
                raise AnalysisError(f"RPC value error: {str(e)}")
        
        except Exception as e:
            raise AnalysisError(f"Unexpected RPC error: {str(e)}")
    
    return wrapper


# Global rate limiter instance
default_rate_limiter = RateLimiter(max_requests_per_second=5.0)