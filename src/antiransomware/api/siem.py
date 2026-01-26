#!/usr/bin/env python3
"""
SIEM Integration CLI
Configure and test Elasticsearch, Syslog, and Webhook integrations.
"""

import os
import sys
import json
import logging
import argparse
import time
from pathlib import Path
from typing import Dict, Any, Optional, List

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('siem_integration.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

class SIEMConfig:
    def __init__(self, config_path: str = 'admin_config.json'):
        self.config_path = Path(config_path)
        self.config = self._load_config()

    def _load_config(self) -> Dict[str, Any]:
        if not self.config_path.exists():
            return { 'elasticsearch': {}, 'syslog': {}, 'webhook': {} }
        try:
            with open(self.config_path, 'r') as f:
                data = json.load(f)
            return data.get('siem', { 'elasticsearch': {}, 'syslog': {}, 'webhook': {} })
        except Exception as e:
            logger.error(f'Failed to load config: {e}')
            return { 'elasticsearch': {}, 'syslog': {}, 'webhook': {} }

    def save(self):
        try:
            full = {}
            if self.config_path.exists():
                with open(self.config_path, 'r') as f:
                    full = json.load(f)
            full['siem'] = self.config
            with open(self.config_path, 'w') as f:
                json.dump(full, f, indent=2)
            logger.info('SIEM config saved')
        except Exception as e:
            logger.error(f'Failed to save config: {e}')

class SIEMClient:
    def __init__(self, cfg: SIEMConfig):
        self.cfg = cfg
        self._es = None
        self._syslog_available = False
        self._init_clients()

    def _init_clients(self):
        # Elasticsearch client
        es_cfg = self.cfg.config.get('elasticsearch', {})
        if es_cfg.get('enabled') and es_cfg.get('url'):
            try:
                from elasticsearch import Elasticsearch  # type: ignore
                auth = None
                if es_cfg.get('username') and es_cfg.get('password'):
                    auth = (es_cfg['username'], es_cfg['password'])
                self._es = Elasticsearch([es_cfg['url']], http_auth=auth)
            except Exception as e:
                logger.warning(f'Elasticsearch not available: {e}')

        # Syslog availability
        try:
            import syslog  # type: ignore
            self._syslog_available = True
        except Exception:
            self._syslog_available = False

    def send_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        results = { 'elasticsearch': False, 'syslog': False, 'webhook': False }

        # Elasticsearch
        if self._es is not None:
            try:
                index = f"anti-ransomware-{time.strftime('%Y-%m')}"
                self._es.index(index=index, body=event)
                results['elasticsearch'] = True
            except Exception as e:
                logger.error(f'Elasticsearch send failed: {e}')

        # Syslog
        syslog_cfg = self.cfg.config.get('syslog', {})
        if syslog_cfg.get('enabled') and self._syslog_available:
            try:
                import syslog  # type: ignore
                syslog.openlog('anti-ransomware', syslog.LOG_PID, syslog.LOG_LOCAL0)
                msg = f"{event.get('event_type','event')} - {event.get('result','unknown')}"
                syslog.syslog(syslog.LOG_INFO, msg)
                results['syslog'] = True
            except Exception as e:
                logger.error(f'Syslog send failed: {e}')

        # Webhook
        wh_cfg = self.cfg.config.get('webhook', {})
        if wh_cfg.get('enabled') and wh_cfg.get('url'):
            try:
                import requests  # type: ignore
                headers = wh_cfg.get('headers', {})
                r = requests.post(wh_cfg['url'], json=event, headers=headers, timeout=10)
                results['webhook'] = r.status_code < 300
            except Exception as e:
                logger.error(f'Webhook send failed: {e}')

        return results

    def test_connections(self) -> Dict[str, Any]:
        results = {}
        # ES
        try:
            results['elasticsearch'] = bool(self._es and self._es.ping())
        except Exception:
            results['elasticsearch'] = False
        # Syslog
        results['syslog'] = self._syslog_available and self.cfg.config.get('syslog',{}).get('enabled', False)
        # Webhook
        wh = self.cfg.config.get('webhook', {})
        results['webhook'] = bool(wh.get('enabled') and wh.get('url'))
        return results


def main():
    parser = argparse.ArgumentParser(description='SIEM Integration CLI')
    sub = parser.add_subparsers(dest='command')

    # Configure
    cfg_cmd = sub.add_parser('configure', help='Configure SIEM targets')
    cfg_cmd.add_argument('--elasticsearch-url')
    cfg_cmd.add_argument('--elasticsearch-username')
    cfg_cmd.add_argument('--elasticsearch-password')
    cfg_cmd.add_argument('--enable-elasticsearch', action='store_true')
    cfg_cmd.add_argument('--enable-syslog', action='store_true')
    cfg_cmd.add_argument('--webhook-url')
    cfg_cmd.add_argument('--enable-webhook', action='store_true')

    # Test
    test_cmd = sub.add_parser('test', help='Test configured integrations')

    # Send event
    send_cmd = sub.add_parser('send', help='Send a test event')
    send_cmd.add_argument('--type', default='TEST_EVENT')
    send_cmd.add_argument('--result', default='ok')
    send_cmd.add_argument('--details')

    args = parser.parse_args()
    cfg = SIEMConfig()

    if args.command == 'configure':
        es = cfg.config.setdefault('elasticsearch', {})
        if args.elasticsearch_url:
            es['url'] = args.elasticsearch_url
        if args.elasticsearch_username:
            es['username'] = args.elasticsearch_username
        if args.elasticsearch_password:
            es['password'] = args.elasticsearch_password
        if args.enable_elasticsearch:
            es['enabled'] = True

        sysl = cfg.config.setdefault('syslog', {})
        if args.enable_syslog:
            sysl['enabled'] = True

        wh = cfg.config.setdefault('webhook', {})
        if args.webhook_url:
            wh['url'] = args.webhook_url
        if args.enable_webhook:
            wh['enabled'] = True

        cfg.save()
        print('SIEM configuration updated')
        return 0

    client = SIEMClient(cfg)

    if args.command == 'test':
        results = client.test_connections()
        print(json.dumps(results, indent=2))
        return 0

    if args.command == 'send':
        event = {
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'event_type': args.type,
            'result': args.result,
            'details': args.details or ''
        }
        results = client.send_event(event)
        print(json.dumps(results, indent=2))
        return 0

    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())
