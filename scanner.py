import os
import subprocess
import logging
import json
import psutil
import tempfile
import shutil
import asyncio
import aiohttp
import git
import ssl
import traceback
import fnmatch
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from sqlalchemy.orm import Session
from collections import defaultdict
import re
from models import AnalysisResult
import time
from typing import Dict, Any

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

@dataclass
class ScanConfig:
    """Configuration for large repository scanning"""
    max_file_size_mb: int = 25
    max_total_size_mb: int = 300
    max_memory_mb: int = 1500
    chunk_size_mb: int = 30
    max_files_per_chunk: int = 50
    
    timeout_seconds: int = 540
    chunk_timeout: int = 120
    file_timeout_seconds: int = 20
    max_retries: int = 2
    concurrent_processes: int = 1

    exclude_patterns: List[str] = field(default_factory=lambda: [
        '.git', '.svn', 'node_modules', 'vendor',
        'bower_components', 'packages', 'dist',
        'build', 'out', 'venv', '.env', '__pycache__',
        '*.min.*', '*.bundle.*', '*.map', 
        '*.{pdf,jpg,jpeg,png,gif,zip,tar,gz,rar,mp4,mov}',
        'package-lock.json', 'yarn.lock',
        'coverage', 'test*', 'docs'
    ])

    # New: Define available scan configurations
    scan_configs: List[Dict] = field(default_factory=lambda: [
        {"name": "security_audit", "config": "p/security-audit"},
        {"name": "default", "config": "p/default"}
        
])
    

class SecurityScanner:
    def __init__(self, config: ScanConfig = ScanConfig(), db_session: Optional[Session] = None, analysis_id: Optional[int] = None):
        self.config = config
        self.db_session = db_session
        self.analysis_id = analysis_id
        self.temp_dir = None
        self.repo_dir = None
        self._session = None
        self.scan_stats = {
            'start_time': None,
            'end_time': None,
            'total_files': 0,
            'files_processed': 0,
            'files_skipped': 0,
            'files_too_large': 0,
            'total_size_mb': 0,
            'memory_usage_mb': 0,
            'findings_count': 0
        }
    

    async def _run_semgrep_scan(self, target_dir: Path, scan_config: Dict) -> Dict:
        """Execute memory-conscious semgrep scan with specific configuration"""
        try:
            semgrepignore_path = target_dir / '.semgrepignore'
            with open(semgrepignore_path, 'w') as f:
                for pattern in self.config.exclude_patterns:
                    f.write(f"{pattern}\n")

            cmd = [
                "semgrep",
                "scan",
                "--config", scan_config["config"],
                "--json",
                "--verbose",
                "--metrics=on",
                "--no-git-ignore",
                "--optimizations=all",
                str(target_dir)
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(target_dir)
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.config.timeout_seconds
                )
            except asyncio.TimeoutError:
                process.kill()
                logger.error(f"Scan timed out after {self.config.timeout_seconds}s")
                return self._create_empty_result(error="Scan timed out")

            self.scan_stats['memory_usage_mb'] = psutil.Process().memory_info().rss / (1024 * 1024)
            
            stderr_output = stderr.decode() if stderr else ""
            if stderr_output:
                logger.warning(f"Semgrep stderr ({scan_config['name']}): {stderr_output}")
                match = re.search(r"Ran \d+ rules on (\d+) files:", stderr_output)
                if match:
                    self.scan_stats['files_scanned'] = int(match.group(1))

            output = stdout.decode() if stdout else ""
            if not output.strip():
                return self._create_empty_result()

            try:
                results = json.loads(output)
                processed_results = self._process_scan_results(results)
                processed_results['scan_source'] = scan_config['name']
                return processed_results
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Semgrep JSON output: {str(e)}")
                return self._create_empty_result(error="Invalid Semgrep output format")

        except Exception as e:
            logger.error(f"Error in semgrep scan: {str(e)}")
            return self._create_empty_result(error=str(e))
        finally:
            if semgrepignore_path.exists():
                semgrepignore_path.unlink()

    async def run_multiple_semgrep_scans(self, target_dir: Path) -> Dict:
        """Run multiple semgrep scans with different configurations"""
        try:
            # Run scans concurrently
            scan_tasks = [
                self._run_semgrep_scan(target_dir, config)
                for config in self.config.scan_configs
            ]
            scan_results = await asyncio.gather(*scan_tasks)

            # Merge results
            merged_findings = []
            total_files_scanned = 0
            total_files_skipped = 0
            severity_counts = defaultdict(int)
            category_counts = defaultdict(int)
            seen_findings = set()

            for result in scan_results:
                findings = result.get('findings', [])
                stats = result.get('stats', {})
                scan_source = result.get('scan_source', 'unknown')

                # Update counters
                total_files_scanned = max(
                    total_files_scanned,
                    stats.get('scan_stats', {}).get('files_scanned', 0)
                )
                total_files_skipped += stats.get('scan_stats', {}).get('skipped_files', 0)

                # Process findings
                for finding in findings:
                    # Create unique identifier for deduplication
                    finding_id = (
                        finding.get('file', ''),
                        finding.get('line_start', 0),
                        finding.get('line_end', 0),
                        finding.get('code_snippet', '')
                    )

                    if finding_id not in seen_findings:
                        seen_findings.add(finding_id)
                        finding['scan_source'] = scan_source
                        merged_findings.append(finding)
                        severity_counts[finding.get('severity', 'UNKNOWN')] += 1
                        category_counts[finding.get('category', 'unknown')] += 1

            return {
                'findings': merged_findings,
                'stats': {
                    'total_findings': len(merged_findings),
                    'severity_counts': dict(severity_counts),
                    'category_counts': dict(category_counts),
                    'scan_stats': {
                        'files_scanned': total_files_scanned,
                        'skipped_files': total_files_skipped,
                        'files_with_findings': len(set(f.get('file', '') for f in merged_findings))
                    },
                    'memory_usage_mb': self.scan_stats.get('memory_usage_mb', 0)
                }
            }

        except Exception as e:
            logger.error(f"Error running multiple scans: {str(e)}")
            return self._create_empty_result(error=str(e))

    def _process_scan_results(self, results: Dict) -> Dict:
        """Process scan results with accurate file counting from semgrep output"""
        findings = results.get('results', [])
        stats = results.get('stats', {})
        paths = results.get('paths', {})
        parse_metrics = results.get('parse_metrics', {})
        
        processed_findings = []
        severity_counts = defaultdict(int)
        category_counts = defaultdict(int)
        files_with_findings = set()
        
        for finding in findings:
            file_path = finding.get('path', '')
            if file_path:
                files_with_findings.add(file_path)

            severity = finding.get('extra', {}).get('severity', 'INFO').upper()
            category = finding.get('extra', {}).get('metadata', {}).get('category', 'security')
            
            severity_counts[severity] += 1
            category_counts[category] += 1
            
            processed_findings.append({
                'id': finding.get('check_id'),
                'file': file_path,
                'line_start': finding.get('start', {}).get('line'),
                'line_end': finding.get('end', {}).get('line'),
                'code_snippet': finding.get('extra', {}).get('lines', ''),
                'message': finding.get('extra', {}).get('message', ''),
                'severity': severity,
                'category': category,
                'cwe': finding.get('extra', {}).get('metadata', {}).get('cwe', []),
                'owasp': finding.get('extra', {}).get('metadata', {}).get('owasp', []),
                'fix_recommendations': finding.get('extra', {}).get('metadata', {}).get('fix', ''),
                'references': finding.get('extra', {}).get('metadata', {}).get('references', [])
            })

        scan_stats = {
            'total_files': stats.get('total', {}).get('files', 0),
            'files_scanned': len(paths.get('scanned', [])),
            'files_with_findings': len(files_with_findings),
            'skipped_files': len(paths.get('skipped', [])),
            'partially_scanned': parse_metrics.get('partially_parsed_files', 0)
        }

        return {
            'findings': processed_findings,
            'stats': {
                'total_findings': len(processed_findings),
                'severity_counts': dict(severity_counts),
                'category_counts': dict(category_counts),
                'scan_stats': scan_stats,
                'memory_usage_mb': self.scan_stats.get('memory_usage_mb', 0)
            }
        }

    def _create_empty_result(self, error: Optional[str] = None) -> Dict:
        """Create empty result structure with optional error information"""
        return {
            'findings': [],
            'stats': {
                'total_findings': 0,
                'severity_counts': {
                    'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0
                },
                'category_counts': {},
                'scan_stats': self.scan_stats,
                'memory_usage_mb': self.scan_stats['memory_usage_mb']
            },
            'errors': [error] if error else []
        }

    async def scan_repository(self, repo_url: str, installation_token: str, user_id: str, multi_scan: bool = True) -> Dict:
        """Main method to scan a repository with comprehensive error handling"""
        try:
            repo_dir = await self._clone_repository(repo_url, installation_token)
            
            # Choose between single or multiple scans
            if multi_scan:
                scan_results = await self.run_multiple_semgrep_scans(repo_dir)
            else:
                scan_results = await self._run_semgrep_scan(repo_dir, self.config.scan_configs[0])
            
            repo_name = repo_url.split('github.com/')[-1].rstrip('.git')
            
            results_data = {
                'findings': scan_results.get('findings', []),
                'stats': scan_results.get('stats', {}),
                'metadata': {
                    'scan_duration_seconds': (
                        datetime.now() - self.scan_stats['start_time']
                    ).total_seconds() if self.scan_stats['start_time'] else 0,
                    'memory_usage_mb': scan_results.get('stats', {}).get('memory_usage_mb', 0)
                },
                'summary': {
                    'total_findings': len(scan_results.get('findings', [])),
                    'severity_counts': scan_results.get('stats', {}).get('severity_counts', {}),
                    'category_counts': scan_results.get('stats', {}).get('category_counts', {}),
                    'files_scanned': scan_results.get('stats', {}).get('scan_stats', {}).get('files_scanned', 0),
                    'files_with_findings': scan_results.get('stats', {}).get('scan_stats', {}).get('files_with_findings', 0),
                    'skipped_files': scan_results.get('stats', {}).get('scan_stats', {}).get('skipped_files', 0),
                    'partially_scanned': scan_results.get('stats', {}).get('scan_stats', {}).get('partially_scanned', 0)
                }
            }

            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(AnalysisResult).get(self.analysis_id)
                    if analysis:
                        analysis.results = results_data
                        analysis.status = 'completed'
                        self.db_session.commit()
                        logger.info(f"Updated analysis results in database with ID: {analysis.id}")
                except Exception as e:
                    self.db_session.rollback()
                    logger.error(f"Failed to update analysis results: {str(e)}")

            return {
                'success': True,
                'data': {
                    'repository': repo_url,
                    'user_id': user_id,
                    'timestamp': datetime.now().isoformat(),
                    'findings': scan_results.get('findings', []),
                    'summary': results_data['summary'],
                    'metadata': results_data['metadata']
                }
            }

        except Exception as e:
            logger.error(f"Scan repository error: {str(e)}")
            if self.db_session and self.analysis_id:
                try:
                    analysis = self.db_session.query(AnalysisResult).getanalysis = self.db_session.query(AnalysisResult).get(self.analysis_id)
                    if analysis:
                        analysis.status = 'error'
                        analysis.error = str(e)
                        self.db_session.commit()
                except Exception as db_e:
                    logger.error(f"Failed to store error record: {str(db_e)}")
                    self.db_session.rollback()
            
            return {
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'SCAN_ERROR',
                    'type': type(e).__name__,
                    'timestamp': datetime.now().isoformat()
                }
            }

    async def _clone_repository(self, repo_url: str, token: str) -> Path:
        """Clone repository with size validation and optimizations"""
        try:
            size_info = await self._check_repository_size(repo_url, token)
            if not size_info['is_compatible']:
                raise ValueError(
                    f"Repository size ({size_info['size_mb']:.2f}MB) exceeds "
                    f"limit of {self.config.max_total_size_mb}MB"
                )

            self.repo_dir = self.temp_dir / f"repo_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            auth_url = repo_url.replace('https://', f'https://x-access-token:{token}@')
            
            logger.info(f"Cloning repository to {self.repo_dir}")
            
            git_options = [
                '--depth=1',
                '--single-branch',
                '--no-tags',
                f'--branch={size_info["default_branch"]}'
            ]
            
            repo = git.Repo.clone_from(
                auth_url,
                self.repo_dir,
                multi_options=git_options
            )

            logger.info(f"Successfully cloned repository: {size_info['size_mb']:.2f}MB")
            return self.repo_dir

        except Exception as e:
            if self.repo_dir and self.repo_dir.exists():
                shutil.rmtree(self.repo_dir)
            raise RuntimeError(f"Repository clone failed: {str(e)}") from e

    async def _check_repository_size(self, repo_url: str, token: str) -> Dict:
        """Pre-check repository size using GitHub API"""
        if not self._session:
            logger.error("HTTP session not initialized")
            raise RuntimeError("Scanner session not initialized")
            
        try:
            if not token:
                raise ValueError("GitHub token is empty or invalid")
                
            logger.info(f"Checking size for repository: {repo_url}")
            
            try:
                if 'github.com/' not in repo_url:
                    raise ValueError(f"Invalid GitHub URL format: {repo_url}")
                    
                path_part = repo_url.split('github.com/')[-1].replace('.git', '')
                if '/' not in path_part:
                    raise ValueError(f"Invalid repository path format: {path_part}")
                    
                owner, repo = path_part.split('/')
                logger.info(f"Parsed owner: {owner}, repo: {repo}")
                
            except Exception as e:
                logger.error(f"Failed to parse repository URL: {str(e)}")
                raise ValueError(f"Invalid repository URL format: {str(e)}")
            
            api_url = f"https://api.github.com/repos/{owner}/{repo}"
            headers = {
                'Authorization': f'Bearer {token}',
                'Accept': 'application/vnd.github.v3+json',
                'User-Agent': 'SecurityScanner'
            }
            
            async with self._session.get(api_url, headers=headers) as response:
                response_text = await response.text()
                logger.info(f"GitHub API Status: {response.status}")
                
                if response.status != 200:
                    raise ValueError(f"GitHub API error: {response_text}")
                
                data = json.loads(response_text)
                size_kb = data.get('size', 0)
                size_mb = size_kb / 1024
                
                logger.info(f"Repository size: {size_mb:.2f}MB")
                logger.info(f"Language: {data.get('language', 'unknown')}")
                logger.info(f"Default branch: {data.get('default_branch', 'main')}")
                
                return {
                    'size_mb': size_mb,
                    'is_compatible': size_mb <= self.config.max_total_size_mb,
                    'language': data.get('language'),
                    'default_branch': data.get('default_branch', 'main')
                }
                
        except Exception as e:
            logger.error(f"Error checking repository size: {str(e)}")
            raise

    async def __aenter__(self):
        await self._setup()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._cleanup()

    async def _setup(self):
        """Initialize scanner resources"""
        try:
            self.temp_dir = Path(tempfile.mkdtemp(prefix='scanner_'))
            logger.info(f"Created temporary directory: {self.temp_dir}")
            
            ssl_context = ssl.create_default_context()
            conn = aiohttp.TCPConnector(ssl=ssl_context)
            timeout = aiohttp.ClientTimeout(total=30)
            
            self._session = aiohttp.ClientSession(
                connector=conn,
                timeout=timeout,
                raise_for_status=True
            )
            
            self.scan_stats['start_time'] = datetime.now()
            logger.info("Scanner setup completed successfully")
            
        except Exception as e:
            logger.error(f"Error in scanner setup: {str(e)}")
            logger.error(f"Exception traceback: {traceback.format_exc()}")
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
            raise

    async def _cleanup(self):
        """Cleanup scanner resources"""
        try:
            if self._session and not self._session.closed:
                await self._session.close()
                logger.info("Closed aiohttp session")
                
            if self.temp_dir and self.temp_dir.exists():
                shutil.rmtree(self.temp_dir)
                logger.info(f"Cleaned up temporary directory: {self.temp_dir}")
                
            self.scan_stats['end_time'] = datetime.now()
            
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")

def deduplicate_findings(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """Remove duplicate findings from scan results based on multiple criteria."""
    if not scan_results.get('success') or 'data' not in scan_results:
        return scan_results

    original_summary = scan_results['data'].get('summary', {})
    findings = scan_results['data'].get('findings', [])
    
    if not findings:
        return scan_results
    
    # Track seen findings
    seen_findings = set()
    deduplicated_findings = []
    
    for finding in findings:
        finding_signature = (
            finding.get('file', ''),
            finding.get('line_start', 0),
            finding.get('line_end', 0),
            finding.get('category', ''),
            finding.get('severity', ''),
            finding.get('code_snippet', '')
        )
        
        if finding_signature not in seen_findings:
            seen_findings.add(finding_signature)
            deduplicated_findings.append(finding)
    
    # Update the results with deduplicated findings
    scan_results['data']['findings'] = deduplicated_findings
    scan_results['data']['summary']['total_findings'] = len(deduplicated_findings)
    
    return scan_results

# Helper function for the web routes
async def scan_repository_handler(
    repo_url: str,
    installation_token: str,
    user_id: str,
    multi_scan: bool = True,
    db_session: Optional[Session] = None
) -> Dict:
    """Handler function for web routes with input validation"""
    logger.info(f"Starting scan request for repository: {repo_url}")
    
    if not all([repo_url, installation_token, user_id]):
        return {
            'success': False,
            'error': {
                'message': 'Missing required parameters',
                'code': 'INVALID_PARAMETERS'
            }
        }

    if not repo_url.startswith(('https://github.com/', 'git@github.com:')):
        return {
            'success': False,
            'error': {
                'message': 'Invalid repository URL format',
                'code': 'INVALID_REPOSITORY_URL',
                'details': 'Only GitHub repositories are supported'
            }
        }

    try:
        config = ScanConfig()
        async with SecurityScanner(config, db_session) as scanner:
            try:
                size_info = await scanner._check_repository_size(repo_url, installation_token)
                if not size_info['is_compatible']:
                    return {
                        'success': False,
                        'error': {
                            'message': 'Repository too large for analysis',
                            'code': 'REPOSITORY_TOO_LARGE',
                            'details': {
                                'size_mb': size_info['size_mb'],
                                'limit_mb': config.max_total_size_mb,
                                'recommendation': 'Consider analyzing specific directories or branches'
                            }
                        }
                    }
                
                results = await scanner.scan_repository(
                    repo_url,
                    installation_token,
                    user_id,
                    multi_scan=multi_scan
                )
                
                if results.get('success'):
                    results['data']['repository_info'] = {
                        'size_mb': size_info['size_mb'],
                        'primary_language': size_info['language'],
                        'default_branch': size_info['default_branch']
                    }
                
                return results

            except Exception as e:
                return {
                    'success': False,
                    'error': {
                        'message': str(e),
                        'code': 'SCAN_ERROR',
                        'type': type(e).__name__,
                        'timestamp': datetime.now().isoformat()
                    }
                }

    except Exception as e:
        logger.error(f"Handler error: {str(e)}")
        return {
            'success': False,
            'error': {
                'message': 'Unexpected error in scan handler',
                'code': 'INTERNAL_ERROR',
                'details': str(e),
                'type': type(e).__name__,
                'timestamp': datetime.now().isoformat()
            }
        }
                