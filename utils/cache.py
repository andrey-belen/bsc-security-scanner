"""
Caching utilities for performance optimization
"""

import time
import json
import hashlib
from typing import Any, Dict, Optional, Callable
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CacheEntry:
    """Cache entry with metadata"""
    data: Any
    timestamp: float
    ttl: float
    key: str
    
    def is_expired(self) -> bool:
        """Check if cache entry has expired"""
        return time.time() - self.timestamp > self.ttl


class MemoryCache:
    """In-memory cache with TTL support"""
    
    def __init__(self, default_ttl: float = 300):  # 5 minutes default
        self.cache: Dict[str, CacheEntry] = {}
        self.default_ttl = default_ttl
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        if key in self.cache:
            entry = self.cache[key]
            if not entry.is_expired():
                return entry.data
            else:
                # Remove expired entry
                del self.cache[key]
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Set value in cache"""
        if ttl is None:
            ttl = self.default_ttl
        
        entry = CacheEntry(
            data=value,
            timestamp=time.time(),
            ttl=ttl,
            key=key
        )
        self.cache[key] = entry
    
    def clear(self) -> None:
        """Clear all cache entries"""
        self.cache.clear()
    
    def cleanup_expired(self) -> int:
        """Remove expired entries and return count removed"""
        expired_keys = [
            key for key, entry in self.cache.items()
            if entry.is_expired()
        ]
        
        for key in expired_keys:
            del self.cache[key]
        
        return len(expired_keys)
    
    def size(self) -> int:
        """Get current cache size"""
        return len(self.cache)


class FileCache:
    """File-based cache for persistent storage"""
    
    def __init__(self, cache_dir: str = ".cache", default_ttl: float = 3600):  # 1 hour default
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.default_ttl = default_ttl
    
    def _get_cache_path(self, key: str) -> Path:
        """Get file path for cache key"""
        # Create hash of key to avoid filesystem issues
        key_hash = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / f"{key_hash}.json"
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from file cache"""
        cache_path = self._get_cache_path(key)
        
        if cache_path.exists():
            try:
                with open(cache_path, 'r') as f:
                    cache_data = json.load(f)
                
                # Check if expired
                if time.time() - cache_data['timestamp'] <= cache_data['ttl']:
                    return cache_data['data']
                else:
                    # Remove expired file
                    cache_path.unlink(missing_ok=True)
                    
            except (json.JSONDecodeError, KeyError, OSError):
                # Remove corrupted cache file
                cache_path.unlink(missing_ok=True)
        
        return None
    
    def set(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Set value in file cache"""
        if ttl is None:
            ttl = self.default_ttl
        
        cache_path = self._get_cache_path(key)
        cache_data = {
            'data': value,
            'timestamp': time.time(),
            'ttl': ttl,
            'key': key
        }
        
        try:
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f, indent=2)
        except (OSError, TypeError):
            # Failed to cache, but don't raise error
            pass
    
    def clear(self) -> None:
        """Clear all cache files"""
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink(missing_ok=True)
    
    def cleanup_expired(self) -> int:
        """Remove expired cache files"""
        removed_count = 0
        current_time = time.time()
        
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, 'r') as f:
                    cache_data = json.load(f)
                
                if current_time - cache_data['timestamp'] > cache_data['ttl']:
                    cache_file.unlink()
                    removed_count += 1
                    
            except (json.JSONDecodeError, KeyError, OSError):
                # Remove corrupted files
                cache_file.unlink(missing_ok=True)
                removed_count += 1
        
        return removed_count


def cache_key_for_address(address: str, analysis_type: str = "full") -> str:
    """Generate cache key for contract address analysis"""
    return f"scan:{address.lower()}:{analysis_type}"


def cached(cache_instance: MemoryCache, ttl: Optional[float] = None):
    """Decorator to add caching to functions"""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs) -> Any:
            # Generate cache key from function name and arguments
            key = f"{func.__name__}:{str(args)}:{str(sorted(kwargs.items()))}"
            
            # Try to get from cache first
            cached_result = cache_instance.get(key)
            if cached_result is not None:
                return cached_result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache_instance.set(key, result, ttl)
            return result
        
        return wrapper
    return decorator


# Global cache instances
memory_cache = MemoryCache(default_ttl=300)  # 5 minutes
file_cache = FileCache(cache_dir=".cache", default_ttl=3600)  # 1 hour


def get_contract_cache_key(address: str) -> str:
    """Get standardized cache key for contract"""
    return f"contract:{address.lower()}"


def cache_contract_result(address: str, result: Dict[str, Any], ttl: float = 3600):
    """Cache contract analysis result"""
    key = get_contract_cache_key(address)
    file_cache.set(key, result, ttl)


def get_cached_contract_result(address: str) -> Optional[Dict[str, Any]]:
    """Get cached contract analysis result"""
    key = get_contract_cache_key(address)
    return file_cache.get(key)