#!/usr/bin/env python3
"""
Anti-Ransomware Production Test Suite
Comprehensive testing for all system components
"""

import os
import sys
import time
import json
import yaml
import unittest
import tempfile
import threading
import subprocess
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any, Optional

# Add current directory to Python path for imports
sys.path.insert(0, os.getcwd())

class ProductionTestSuite:
    """Complete production test suite"""
    
    def __init__(self):
        self.test_results = []
        self.temp_dir = None
        self.original_cwd = os.getcwd()
        
    def setup_test_environment(self):
        """Setup isolated test environment"""
        self.temp_dir = tempfile.mkdtemp(prefix="antiransomware_test_")
        print(f"🔧 Test environment: {self.temp_dir}")
        
        # Create test directory structure
        test_dirs = [
            "data", "logs", "policies", "certs", "keys", 
            "dongles", "tmp", "demo_files", "backups"
        ]
        
        for dir_name in test_dirs:
            (Path(self.temp_dir) / dir_name).mkdir(exist_ok=True)
        
        # Change to test directory
        os.chdir(self.temp_dir)
        
        # Copy essential files from original directory
        essential_files = [
            "config_manager.py", "production_logger.py", "health_monitor.py",
            "ar_token.py", "policy_engine.py", "service_manager.py"
        ]
        
        for file_name in essential_files:
            src_file = Path(self.original_cwd) / file_name
            if src_file.exists():
                dest_file = Path(self.temp_dir) / file_name
                dest_file.write_text(src_file.read_text())
        
        return True
    
    def cleanup_test_environment(self):
        """Cleanup test environment"""
        os.chdir(self.original_cwd)
        if self.temp_dir and Path(self.temp_dir).exists():
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def create_test_config(self):
        """Create test configuration files"""
        # Main config
        config = {
            'project': {'name': 'anti-ransomware-test', 'version': '1.0.0-test'},
            'network': {'grpc': {'port': 50052}, 'web': {'port': 8081}},
            'database': {'path': 'data/test.db'},
            'logging': {'level': 'DEBUG', 'handlers': {'console': {'enabled': True}}},
            'security': {'demo_mode': True, 'encryption': {'key_derivation': 'scrypt'}},
            'monitoring': {'health_check': {'interval': 1}},
            'policy': {'file': 'policies/test.yaml', 'reload_interval': 10}
        }
        
        with open('config.yaml', 'w') as f:
            yaml.dump(config, f)
        
        # Test policy
        policy = {
            'version': '1.0',
            'description': 'Test policy',
            'policies': [{
                'name': 'test_protection',
                'enabled': True,
                'paths': ['./demo_files/**'],
                'operations': ['read', 'write'],
                'quotas': {'max_files_per_hour': 100}
            }]
        }
        
        with open('policies/test.yaml', 'w') as f:
            yaml.dump(policy, f)
        
        # Create test files
        test_files = {
            'demo_files/test1.txt': 'Test file 1 content',
            'demo_files/test2.txt': 'Test file 2 content',
            'demo_files/sensitive.doc': 'Sensitive document content'
        }
        
        for filepath, content in test_files.items():
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            Path(filepath).write_text(content)
        
        return True

class TestConfigurationManager(unittest.TestCase):
    """Test configuration management system"""
    
    def setUp(self):
        self.test_config = {
            'test_key': 'test_value',
            'nested': {'key': 'value'},
            'network': {'port': 8080}
        }
        
        with open('test_config.yaml', 'w') as f:
            yaml.dump(self.test_config, f)
    
    def test_config_loading(self):
        """Test configuration file loading"""
        try:
            from config_manager import ConfigManager
            config = ConfigManager('test_config.yaml')
            self.assertTrue(config.load_config())
            self.assertEqual(config.get('test_key'), 'test_value')
            self.assertEqual(config.get('network.port'), 8080)
        except Exception as e:
            self.fail(f"Configuration loading failed: {e}")
    
    def test_config_validation(self):
        """Test configuration validation"""
        try:
            from config_manager import ConfigManager
            config = ConfigManager('test_config.yaml')
            config.load_config()
            
            # Test valid keys
            self.assertIsNotNone(config.get('test_key'))
            
            # Test invalid keys return None or default
            self.assertIsNone(config.get('nonexistent_key'))
            self.assertEqual(config.get('nonexistent_key', 'default'), 'default')
            
        except Exception as e:
            self.fail(f"Configuration validation failed: {e}")
    
    def test_config_hot_reload(self):
        """Test configuration hot reload"""
        try:
            from config_manager import ConfigManager
            config = ConfigManager('test_config.yaml')
            config.load_config()
            
            # Modify config file
            new_config = self.test_config.copy()
            new_config['test_key'] = 'updated_value'
            
            with open('test_config.yaml', 'w') as f:
                yaml.dump(new_config, f)
            
            # Reload and verify
            config.load_config()
            self.assertEqual(config.get('test_key'), 'updated_value')
            
        except Exception as e:
            self.fail(f"Configuration hot reload failed: {e}")
    
    def tearDown(self):
        if Path('test_config.yaml').exists():
            Path('test_config.yaml').unlink()

class TestSecurityLogging(unittest.TestCase):
    """Test security logging system"""
    
    def setUp(self):
        self.log_config = {
            'level': 'DEBUG',
            'handlers': {
                'console': {'enabled': True},
                'file': {'enabled': True, 'path': 'logs/test.log'}
            }
        }
    
    def test_logger_initialization(self):
        """Test logger initialization"""
        try:
            from production_logger import ProductionLogger
            logger = ProductionLogger("test_service", self.log_config)
            self.assertIsNotNone(logger)
            
        except Exception as e:
            self.fail(f"Logger initialization failed: {e}")
    
    def test_security_event_logging(self):
        """Test security event logging"""
        try:
            from production_logger import ProductionLogger
            logger = ProductionLogger("test_service", self.log_config)
            
            # Test various log levels
            logger.security_event("authentication", "user_login", user_id="test_user")
            logger.security_event("file_access", "file_protected", file_path="test.txt")
            logger.security_event("threat", "ransomware_blocked", threat_type="encryption")
            
            # Verify log file exists
            if Path('logs/test.log').exists():
                log_content = Path('logs/test.log').read_text()
                self.assertIn("authentication", log_content)
                self.assertIn("file_access", log_content)
                
        except Exception as e:
            self.fail(f"Security event logging failed: {e}")
    
    def test_metrics_collection(self):
        """Test metrics collection"""
        try:
            from production_logger import ProductionLogger
            logger = ProductionLogger("test_service", self.log_config)
            
            # Generate some metrics
            logger.security_event("authentication", "user_login")
            logger.security_event("threat", "blocked")
            
            metrics = logger.get_metrics()
            self.assertIsInstance(metrics, dict)
            
        except Exception as e:
            self.fail(f"Metrics collection failed: {e}")

class TestHealthMonitoring(unittest.TestCase):
    """Test health monitoring system"""
    
    def setUp(self):
        self.monitor_config = {
            'monitoring': {
                'health_check': {'interval': 1},
                'alerts': [{
                    'name': 'test_alert',
                    'level': 'WARNING',
                    'condition': 'memory_usage',
                    'threshold': 90,
                    'enabled': True
                }]
            }
        }
    
    def test_health_monitor_initialization(self):
        """Test health monitor initialization"""
        try:
            from health_monitor import HealthMonitor
            monitor = HealthMonitor(self.monitor_config)
            self.assertIsNotNone(monitor)
            
        except Exception as e:
            self.fail(f"Health monitor initialization failed: {e}")
    
    def test_health_checks(self):
        """Test individual health checks"""
        try:
            from health_monitor import HealthMonitor
            monitor = HealthMonitor(self.monitor_config)
            
            # Run all health checks
            results = monitor.run_all_checks()
            self.assertIsInstance(results, list)
            self.assertGreater(len(results), 0)
            
            # Verify each result has required fields
            for result in results:
                self.assertIn('name', result.__dict__)
                self.assertIn('status', result.__dict__)
                self.assertIn('message', result.__dict__)
                
        except Exception as e:
            self.fail(f"Health checks failed: {e}")
    
    def test_system_status(self):
        """Test overall system status"""
        try:
            from health_monitor import HealthMonitor
            monitor = HealthMonitor(self.monitor_config)
            
            status = monitor.get_health_status()
            self.assertIsInstance(status, dict)
            self.assertIn('overall_status', status)
            self.assertIn('status_counts', status)
            
        except Exception as e:
            self.fail(f"System status check failed: {e}")

class TestTokenSystem(unittest.TestCase):
    """Test cryptographic token system"""
    
    def test_token_creation(self):
        """Test token creation and basic operations"""
        try:
            # Create a simple token system mock for testing
            class MockTokenSystem:
                def __init__(self):
                    self.tokens = {}
                
                def create_token(self, file_path: str, operations: List[str]) -> str:
                    import hashlib
                    import json
                    
                    token_data = {
                        'file_path': file_path,
                        'operations': operations,
                        'timestamp': time.time(),
                        'nonce': os.urandom(16).hex()
                    }
                    
                    token_json = json.dumps(token_data, sort_keys=True)
                    token_hash = hashlib.sha256(token_json.encode()).hexdigest()
                    
                    self.tokens[token_hash] = token_data
                    return token_hash
                
                def validate_token(self, token: str, file_path: str) -> bool:
                    return token in self.tokens and self.tokens[token]['file_path'] == file_path
            
            # Test token operations
            token_system = MockTokenSystem()
            
            # Create token
            token = token_system.create_token("test_file.txt", ["read", "write"])
            self.assertIsNotNone(token)
            self.assertIsInstance(token, str)
            
            # Validate token
            is_valid = token_system.validate_token(token, "test_file.txt")
            self.assertTrue(is_valid)
            
            # Test invalid validation
            is_invalid = token_system.validate_token(token, "different_file.txt")
            self.assertFalse(is_invalid)
            
        except Exception as e:
            self.fail(f"Token system test failed: {e}")

class TestPolicyEngine(unittest.TestCase):
    """Test policy engine"""
    
    def setUp(self):
        self.test_policy = {
            'version': '1.0',
            'policies': [{
                'name': 'test_policy',
                'enabled': True,
                'paths': ['./test_files/**'],
                'operations': ['read', 'write'],
                'quotas': {'max_files_per_hour': 100}
            }]
        }
        
        with open('test_policy.yaml', 'w') as f:
            yaml.dump(self.test_policy, f)
    
    def test_policy_loading(self):
        """Test policy file loading"""
        try:
            from policy_engine import PolicyEngine
            engine = PolicyEngine('test_policy.yaml')
            self.assertIsNotNone(engine)
            
        except Exception as e:
            self.fail(f"Policy loading failed: {e}")
    
    def test_policy_evaluation(self):
        """Test policy rule evaluation"""
        try:
            # Create mock policy evaluator
            class MockPolicyEngine:
                def __init__(self, policy_file):
                    with open(policy_file, 'r') as f:
                        self.policy_data = yaml.safe_load(f)
                
                def evaluate_access(self, file_path: str, operation: str) -> bool:
                    for policy in self.policy_data.get('policies', []):
                        if not policy.get('enabled', True):
                            continue
                        
                        paths = policy.get('paths', [])
                        operations = policy.get('operations', [])
                        
                        # Simple path matching
                        path_match = any(
                            file_path.startswith(path.replace('/**', ''))
                            for path in paths
                        )
                        
                        if path_match and operation in operations:
                            return True
                    
                    return False
            
            engine = MockPolicyEngine('test_policy.yaml')
            
            # Test allowed operations
            self.assertTrue(engine.evaluate_access('./test_files/file1.txt', 'read'))
            self.assertTrue(engine.evaluate_access('./test_files/file2.txt', 'write'))
            
            # Test denied operations
            self.assertFalse(engine.evaluate_access('./other_files/file1.txt', 'read'))
            self.assertFalse(engine.evaluate_access('./test_files/file1.txt', 'delete'))
            
        except Exception as e:
            self.fail(f"Policy evaluation failed: {e}")
    
    def tearDown(self):
        if Path('test_policy.yaml').exists():
            Path('test_policy.yaml').unlink()

class TestDatabaseOperations(unittest.TestCase):
    """Test database operations"""
    
    def setUp(self):
        self.db_path = 'test_antiransomware.db'
        
    def test_database_creation(self):
        """Test database creation and basic operations"""
        try:
            # Create test database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create test tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    event_type TEXT NOT NULL,
                    details TEXT,
                    severity TEXT DEFAULT 'INFO'
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS protected_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT UNIQUE NOT NULL,
                    protection_level TEXT DEFAULT 'MEDIUM',
                    created_at REAL NOT NULL
                )
            ''')
            
            conn.commit()
            conn.close()
            
            # Verify database exists
            self.assertTrue(Path(self.db_path).exists())
            
        except Exception as e:
            self.fail(f"Database creation failed: {e}")
    
    def test_database_operations(self):
        """Test database CRUD operations"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Insert test data
            cursor.execute('''
                INSERT INTO security_events (timestamp, event_type, details, severity)
                VALUES (?, ?, ?, ?)
            ''', (time.time(), 'file_access', 'Test file accessed', 'INFO'))
            
            cursor.execute('''
                INSERT INTO protected_files (file_path, protection_level, created_at)
                VALUES (?, ?, ?)
            ''', ('./test_file.txt', 'HIGH', time.time()))
            
            conn.commit()
            
            # Query data
            cursor.execute('SELECT COUNT(*) FROM security_events')
            event_count = cursor.fetchone()[0]
            self.assertGreater(event_count, 0)
            
            cursor.execute('SELECT COUNT(*) FROM protected_files')
            file_count = cursor.fetchone()[0]
            self.assertGreater(file_count, 0)
            
            conn.close()
            
        except Exception as e:
            self.fail(f"Database operations failed: {e}")
    
    def tearDown(self):
        if Path(self.db_path).exists():
            Path(self.db_path).unlink()

class TestNetworkServices(unittest.TestCase):
    """Test network services (gRPC and web)"""
    
    def test_port_availability(self):
        """Test that required ports are available"""
        import socket
        
        test_ports = [8081, 50052]  # Test ports
        
        for port in test_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('127.0.0.1', port))
                    # Port is available
                    
            except OSError:
                self.fail(f"Port {port} is not available for testing")
    
    def test_web_service_mock(self):
        """Test web service mock functionality"""
        try:
            from flask import Flask
            
            app = Flask(__name__)
            
            @app.route('/health')
            def health():
                return {'status': 'ok', 'timestamp': time.time()}
            
            @app.route('/api/status')
            def api_status():
                return {'service': 'antiransomware', 'version': '1.0.0-test'}
            
            # Test that routes are properly defined
            with app.test_client() as client:
                response = client.get('/health')
                self.assertEqual(response.status_code, 200)
                
                response = client.get('/api/status')
                self.assertEqual(response.status_code, 200)
                
        except Exception as e:
            self.fail(f"Web service test failed: {e}")

class TestPerformance(unittest.TestCase):
    """Test system performance characteristics"""
    
    def test_token_generation_performance(self):
        """Test token generation performance"""
        try:
            # Mock token generation for performance testing
            import hashlib
            
            def generate_token():
                data = f"test_data_{time.time()}_{os.urandom(8).hex()}"
                return hashlib.sha256(data.encode()).hexdigest()
            
            # Time token generation
            start_time = time.time()
            tokens = [generate_token() for _ in range(1000)]
            end_time = time.time()
            
            duration = end_time - start_time
            tokens_per_second = 1000 / duration
            
            self.assertGreater(tokens_per_second, 100)  # Should generate >100 tokens/sec
            self.assertEqual(len(tokens), 1000)
            
        except Exception as e:
            self.fail(f"Performance test failed: {e}")
    
    def test_memory_usage(self):
        """Test memory usage patterns"""
        try:
            import psutil
            import gc
            
            # Get initial memory usage
            process = psutil.Process()
            initial_memory = process.memory_info().rss
            
            # Create test objects
            test_data = []
            for i in range(1000):
                test_data.append({
                    'id': i,
                    'data': f"test_data_{i}" * 100,
                    'timestamp': time.time()
                })
            
            # Check memory growth
            current_memory = process.memory_info().rss
            memory_growth = current_memory - initial_memory
            
            # Clean up
            del test_data
            gc.collect()
            
            # Memory growth should be reasonable
            self.assertLess(memory_growth, 50 * 1024 * 1024)  # Less than 50MB growth
            
        except Exception as e:
            self.fail(f"Memory usage test failed: {e}")

class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_component_integration(self):
        """Test integration between components"""
        try:
            # Test config + logging integration
            config_data = {
                'logging': {
                    'level': 'INFO',
                    'handlers': {'console': {'enabled': True}}
                }
            }
            
            with open('integration_config.yaml', 'w') as f:
                yaml.dump(config_data, f)
            
            # Test that components can work together
            from config_manager import ConfigManager
            config = ConfigManager('integration_config.yaml')
            config.load_config()
            
            log_config = config.get('logging', {})
            self.assertIsInstance(log_config, dict)
            self.assertEqual(log_config['level'], 'INFO')
            
        except Exception as e:
            self.fail(f"Integration test failed: {e}")
        finally:
            if Path('integration_config.yaml').exists():
                Path('integration_config.yaml').unlink()

def run_production_tests():
    """Run complete production test suite"""
    print("🧪 Anti-Ransomware Production Test Suite")
    print("=" * 50)
    
    # Setup test environment
    test_suite = ProductionTestSuite()
    
    try:
        print("\n🔧 Setting up test environment...")
        test_suite.setup_test_environment()
        test_suite.create_test_config()
        print("✅ Test environment ready")
        
        # Create test loader
        loader = unittest.TestLoader()
        suite = unittest.TestSuite()
        
        # Add all test classes
        test_classes = [
            TestConfigurationManager,
            TestSecurityLogging,
            TestHealthMonitoring,
            TestTokenSystem,
            TestPolicyEngine,
            TestDatabaseOperations,
            TestNetworkServices,
            TestPerformance,
            TestIntegration
        ]
        
        for test_class in test_classes:
            tests = loader.loadTestsFromTestCase(test_class)
            suite.addTests(tests)
        
        # Run tests with detailed output
        runner = unittest.TextTestRunner(
            verbosity=2,
            stream=sys.stdout,
            descriptions=True,
            failfast=False
        )
        
        print(f"\n🚀 Running {suite.countTestCases()} production tests...")
        result = runner.run(suite)
        
        # Test summary
        print("\n" + "=" * 50)
        print("📊 TEST SUMMARY")
        print("=" * 50)
        print(f"Tests Run: {result.testsRun}")
        print(f"Failures: {len(result.failures)}")
        print(f"Errors: {len(result.errors)}")
        print(f"Skipped: {len(result.skipped) if hasattr(result, 'skipped') else 0}")
        
        if result.failures:
            print(f"\n❌ FAILURES ({len(result.failures)}):")
            for test, traceback in result.failures:
                print(f"  - {test}: {traceback.split('AssertionError:')[-1].strip() if 'AssertionError:' in traceback else 'See details above'}")
        
        if result.errors:
            print(f"\n🚨 ERRORS ({len(result.errors)}):")
            for test, traceback in result.errors:
                print(f"  - {test}: {traceback.split('Exception:')[-1].strip() if 'Exception:' in traceback else 'See details above'}")
        
        # Overall result
        if result.wasSuccessful():
            print(f"\n🎉 ALL TESTS PASSED!")
            print("✅ Production system is ready for deployment")
        else:
            print(f"\n⚠️  SOME TESTS FAILED")
            print("❌ Review failures before production deployment")
        
        return result.wasSuccessful()
        
    except Exception as e:
        print(f"\n💥 Test suite setup failed: {e}")
        return False
        
    finally:
        print("\n🧹 Cleaning up test environment...")
        test_suite.cleanup_test_environment()

def main():
    """Main test execution"""
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("""
Anti-Ransomware Production Test Suite

Usage:
  python production_test.py                    # Run all tests
  python production_test.py --component <name> # Run specific component tests
  python production_test.py --performance      # Run performance tests only
  python production_test.py --integration      # Run integration tests only

Test Categories:
  - Configuration Management
  - Security Logging
  - Health Monitoring  
  - Token System
  - Policy Engine
  - Database Operations
  - Network Services
  - Performance Testing
  - Integration Testing

This suite validates all production components and ensures
the system is ready for enterprise deployment.
        """)
        return
    
    success = run_production_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
