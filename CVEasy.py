#!/usr/bin/env python3
"""
CVEasy - A tool for parsing and analyzing Nessus vulnerability scan files

This script parses Nessus XML files, generates summary reports, creates detailed finding files,
and researches exploits through multiple sources like go-exploitdb and the Trickest CVE repository.
"""

import os
import sys
import xml.etree.ElementTree as ET
import argparse
import subprocess
import json
import glob
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import logging
import re
import socket
import requests
from time import sleep

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
logger = logging.getLogger(__name__)

class Finding:
    """Class to represent a vulnerability finding from a Nessus scan"""
    
    def __init__(self, plugin_id, plugin_name, severity, description):
        self.plugin_id = plugin_id
        self.plugin_name = plugin_name
        self.severity = severity
        self.description = description
        self.cves = set()
        self.affected_ips = {}  # IP -> plugin_output
        self.exploit_available_nessus = False
        self.exploit_research = {}  # Store research data by CVE
        
    def add_affected_ip(self, ip, plugin_output):
        """Add an affected IP address and its plugin output"""
        self.affected_ips[ip] = plugin_output
        
    def add_cve(self, cve):
        """Add a CVE to the finding"""
        if cve and cve != 'N/A':
            self.cves.add(cve)
            
    def get_exploit_status(self):
        """Determine the exploit availability status"""
        if self.exploit_research:
            return "Y - Research"
        elif self.exploit_available_nessus:
            return "Y - Nessus"
        return "N"
        
    def get_normalized_name(self):
        """Return a normalized name for file naming"""
        # Replace special characters with dashes and remove redundant dashes
        name = re.sub(r'[^\w\s-]', '-', self.plugin_name)
        name = re.sub(r'[-\s]+', '-', name).strip('-')
        return f"{self.plugin_id}-{name}"
        
    def get_severity_num(self):
        """Get numerical severity for sorting"""
        severity_map = {
            'Critical': 4,
            'High': 3,
            'Medium': 2, 
            'Low': 1,
            'Info': 0
        }
        return severity_map.get(self.severity, -1)
        
    def __lt__(self, other):
        """Custom less than for sorting findings"""
        # First compare by exploit status (Y-Research > Y-Nessus > N)
        exploit_status_self = 2 if self.exploit_research else (1 if self.exploit_available_nessus else 0)
        exploit_status_other = 2 if other.exploit_research else (1 if other.exploit_available_nessus else 0)
        
        if exploit_status_self != exploit_status_other:
            return exploit_status_self > exploit_status_other
        
        # If GitHub research is available, compare by POC count next
        if hasattr(self, 'poc_count') and hasattr(other, 'poc_count'):
            if self.poc_count != other.poc_count:
                return self.poc_count > other.poc_count
            
            # If star counts are available, compare those next
            if hasattr(self, 'star_count') and hasattr(other, 'star_count'):
                if self.star_count != other.star_count:
                    return self.star_count > other.star_count
        
        # Finally by severity
        severity_self = self.get_severity_num()
        severity_other = other.get_severity_num()
        
        if severity_self != severity_other:
            return severity_self > severity_other
        
        # As a last resort, sort by plugin ID for consistency
        return self.plugin_id < other.plugin_id

class NessusParser:
    """Parser for Nessus XML files"""
    
    def __init__(self, options):
        self.options = options
        self.findings = {}  # plugin_id -> Finding
        self.cve_research_cache = {}  # Cache for CVE research results
    
    def _is_ip_address(self, address):
        """Check if a string is an IP address using socket validation."""
        try:
            # Try to parse as IPv4
            socket.inet_pton(socket.AF_INET, address)
            return True
        except socket.error:
            # Not IPv4, try IPv6
            try:
                socket.inet_pton(socket.AF_INET6, address)
                return True
            except socket.error:
                # Not IPv6 either
                return False
        except Exception:
            # Handle any other errors
            return False
        
    def parse_files(self):
        """Parse all specified Nessus files"""
        file_paths = []
        
        # Handle glob patterns in input paths
        for path in self.options.input_files:
            # Handle directories by looking for .nessus files
            if os.path.isdir(path):
                dir_nessus_files = glob.glob(os.path.join(path, "*.nessus"))
                if dir_nessus_files:
                    file_paths.extend(dir_nessus_files)
                    logger.info(f"Found {len(dir_nessus_files)} .nessus files in directory: {path}")
                else:
                    logger.warning(f"No .nessus files found in directory: {path}")
                continue
                
            # Handle glob patterns
            if '*' in path:
                matched_files = glob.glob(path)
                file_paths.extend(matched_files)
                if not matched_files:
                    logger.warning(f"No files found matching pattern: {path}")
            else:
                file_paths.append(path)
                
        if not file_paths:
            logger.error("No files found matching the specified patterns")
            sys.exit(1)
            
        for file_path in file_paths:
            logger.info(f"Parsing file: {file_path}")
            self._parse_single_file(file_path)
            
    def _parse_single_file(self, file_path):
        """Parse a single Nessus file"""
        tree = ET.parse(file_path)
        root = tree.getroot()
        
        for report_host in root.findall('Report/ReportHost'):
            ip_address = report_host.get('name')
            
            for report_item in report_host.findall('ReportItem'):
                plugin_id = report_item.get('pluginID', 'Unknown')
                plugin_name = report_item.get('pluginName', 'Unknown')
                severity = report_item.get('severity', '0')
                
                # Map numeric severity to text
                severity_map = {'0': 'Info', '1': 'Low', '2': 'Medium', '3': 'High', '4': 'Critical'}
                severity_text = severity_map.get(severity, severity)
                
                # Get description
                description_elem = report_item.find('description')
                description = description_elem.text if description_elem is not None else 'No description available'
                
                # Check if exploit is available according to Nessus
                exploit_elem = report_item.find('exploit_available')
                exploit_available = (exploit_elem is not None and exploit_elem.text == 'true')
                
                # Get plugin output if available
                plugin_output_elem = report_item.find('plugin_output')
                plugin_output = plugin_output_elem.text if plugin_output_elem is not None else None
                
                # Create or update finding
                if plugin_id not in self.findings:
                    self.findings[plugin_id] = Finding(plugin_id, plugin_name, severity_text, description)
                    self.findings[plugin_id].exploit_available_nessus = exploit_available
                
                # Add affected IP
                self.findings[plugin_id].add_affected_ip(ip_address, plugin_output)
                
                # Process CVEs
                for cve_elem in report_item.findall('cve'):
                    if cve_elem.text:
                        self.findings[plugin_id].add_cve(cve_elem.text)
    
    def research_exploits(self):
        """Research exploits for all CVEs"""
        if not self.options.research:
            return
            
        # Initialize the star cache regardless of GitHub token status
        self.github_star_cache = {}
        self.github_token_valid = False
            
        # Load GitHub token from file if specified
        if self.options.github_token_file and not self.options.github_token:
            try:
                with open(self.options.github_token_file, 'r') as f:
                    # Read the first line and strip whitespace
                    self.options.github_token = f.readline().strip()
                    logger.info(f"GitHub token loaded from file: {self.options.github_token_file}")
            except Exception as e:
                logger.error(f"Error reading GitHub token from file: {e}")
        
        # Validate GitHub token if provided
        if self.options.github_token:
            self.github_token_valid = self._validate_github_token(self.options.github_token)
            if not self.github_token_valid:
                logger.warning("GitHub star counts will not be collected. Proceeding without this information.")
        else:
            logger.info("No GitHub token provided. Star counts will not be collected.")
        
        # Loop through findings and grab CVEs...
        all_cves = set()
        for finding in self.findings.values():
            all_cves.update(finding.cves)
            
        # Process CVEs based on research options
        if all_cves:
            logger.info(f"Researching {len(all_cves)} unique CVEs...")
            
            # Research using go-exploitdb
            if 'exploitdb' in self.options.research_sources:
                self._research_with_exploitdb(all_cves)
                
            # Research using trickest/cve repository
            if 'trickest' in self.options.research_sources:
                self._research_with_trickest(all_cves)
                
            # Associate research results with findings
            self._associate_research_results()

            # Only fetch GitHub star counts if we have a valid token
        if self.github_token_valid:
            self._fetch_all_github_star_counts()
    
    def _research_with_exploitdb(self, cves):
        """Research CVEs using go-exploitdb"""
        logger.info("Researching with go-exploitdb...")
        
        for cve in cves:
            if cve in self.cve_research_cache:
                continue
                
            try:
                result = subprocess.run(
                    ['go-exploitdb', 'search', '--type', 'CVE', '--dbpath', self.options.exploitdb_path, '--param', cve],
                    capture_output=True, text=True, check=False
                )
                
                if "No Record Found" not in result.stdout:
                    # Process the output to remove redundant information
                    processed_output = self._process_exploitdb_output(result.stdout, cve)
                    if processed_output:
                        self.cve_research_cache[cve] = processed_output
            except Exception as e:
                logger.error(f"Error researching {cve} with go-exploitdb: {e}")
    
    def _process_exploitdb_output(self, output, cve):
        """Process and clean go-exploitdb output"""
        if not output or "No Record Found" in output:
            return None
            
        # Instead of categorizing by source type, track all exploits by URL
        exploits_by_url = {}
        
        lines = output.strip().split('\n')
        current_exploit = None
        
        for line in lines:
            line = line.strip()
            
            # Skip unnecessary lines
            if not line or line == "Results: " or line.startswith("-------"):
                continue
                
            # New exploit reference section
            if line.startswith("[*]CVE-ExploitID Reference:"):
                current_exploit = {'source_types': []}
                continue
                
            # Skip detail info header
            if line.startswith("[*]Exploit Detail Info:"):
                # When we hit a detail info header, we've finished processing one exploit entry
                if current_exploit and 'url' in current_exploit and 'type' in current_exploit:
                    url = current_exploit['url']
                    source_type = current_exploit['type']
                    
                    if url not in exploits_by_url:
                        exploits_by_url[url] = current_exploit
                        exploits_by_url[url]['source_types'] = [source_type]
                    else:
                        # If we've seen this URL before, merge the information
                        if source_type not in exploits_by_url[url]['source_types']:
                            exploits_by_url[url]['source_types'].append(source_type)
                        
                        # Keep the most informative description
                        if ('description' in current_exploit and 
                            (('description' not in exploits_by_url[url]) or 
                             (len(current_exploit['description']) > len(exploits_by_url[url]['description'])))):
                            exploits_by_url[url]['description'] = current_exploit['description']
                
                current_exploit = None
                continue
                
            # Extract exploit details
            if ': ' in line and current_exploit is not None:
                key, value = line.split(': ', 1)
                key = key.strip()
                value = value.strip()
                
                if key == "Exploit Type":
                    current_exploit['type'] = value
                elif key == "URL":
                    current_exploit['url'] = value
                elif key == "Description":
                    current_exploit['description'] = value
        
        # Process the last exploit if it exists
        if current_exploit and 'url' in current_exploit and 'type' in current_exploit:
            url = current_exploit['url']
            source_type = current_exploit['type']
            
            if url not in exploits_by_url:
                exploits_by_url[url] = current_exploit
                exploits_by_url[url]['source_types'] = [source_type]
            else:
                if source_type not in exploits_by_url[url]['source_types']:
                    exploits_by_url[url]['source_types'].append(source_type)
                
                if ('description' in current_exploit and 
                    (('description' not in exploits_by_url[url]) or 
                     (len(current_exploit['description']) > len(exploits_by_url[url]['description'])))):
                    exploits_by_url[url]['description'] = current_exploit['description']
        
        # Now categorize the exploits based on their source_types for backwards compatibility
        github_exploits = []
        inthewild_exploits = []
        other_exploits = []
        
        for url, exploit in exploits_by_url.items():
            # Make a copy with the proper source types
            exploit_copy = exploit.copy()
            
            # Use the list of sources instead of just a single type
            if 'source_types' in exploit_copy:
                exploit_copy['sources'] = exploit_copy['source_types']
                del exploit_copy['source_types']
                
            if 'type' in exploit_copy:
                del exploit_copy['type']  # Remove the individual type as we now have a list
            
            # Add to the appropriate categories based on source types
            if any('GitHub' in source for source in exploit_copy.get('sources', [])):
                github_exploits.append(exploit_copy)
            
            if any('InTheWild' in source for source in exploit_copy.get('sources', [])):
                # Only add if not already in github_exploits with the same URL
                if not any(e['url'] == url for e in github_exploits):
                    inthewild_exploits.append(exploit_copy)
            
            if not any(('GitHub' in source or 'InTheWild' in source) for source in exploit_copy.get('sources', [])):
                other_exploits.append(exploit_copy)
        
        # Format the processed output
        processed_output = {}
        
        if github_exploits:
            processed_output['github'] = github_exploits
            
        if inthewild_exploits:
            processed_output['inthewild'] = inthewild_exploits
            
        if other_exploits:
            processed_output['other'] = other_exploits
            
        return processed_output if processed_output else None
    
    def _research_with_trickest(self, cves):
        """Research CVEs using the trickest/cve repository"""
        if not self.options.trickest_path:
            logger.warning("Trickest CVE repository path not specified, skipping trickest research")
            return
            
        logger.info("Researching with trickest/cve repository...")
        
        for cve in cves:
            # Skip if already in cache
            if cve in self.cve_research_cache and 'trickest' in self.cve_research_cache[cve]:
                continue
                
            # Initialize empty trickest data for this CVE if not already present
            if cve not in self.cve_research_cache:
                self.cve_research_cache[cve] = {}
                
            # Extract the year from the CVE (format: CVE-YYYY-NNNN)
            try:
                year = cve.split('-')[1]
                # Look for the CVE markdown file in the correct year directory
                cve_md_path = os.path.join(self.options.trickest_path, year, f"{cve}.md")
                
                if os.path.isfile(cve_md_path):
                    logger.debug(f"Found Trickest information for {cve}")
                    
                    try:
                        with open(cve_md_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                            # Extract sections from the markdown content
                            sections = self._extract_md_sections(content, cve)
                            
                            if sections:
                                self.cve_research_cache[cve]['trickest'] = sections
                    except Exception as e:
                        logger.error(f"Error reading Trickest file for {cve}: {e}")
            except Exception as e:
                logger.error(f"Error processing Trickest data for {cve}: {e}")
                
    def _extract_md_sections(self, content, cve):
        """Extract relevant sections from a Trickest markdown file"""
        sections = []
        
        # Look for these headings in the markdown file
        sections_to_extract = {
            "description": ["## Description", "### Description"],
            "reference": ["## Reference", "### Reference", "#### Reference"],
            "github": ["## Github", "### Github", "#### Github"],
            "poc": ["## POC", "### POC"]
        }
        
        # Extract each type of section
        extracted_data = {}
        
        # Split the content by headings
        lines = content.split('\n')
        current_section = None
        section_content = []
        
        for line in lines:
            line_lower = line.strip()
            
            # Check if this line is a heading we're interested in
            new_section = None
            for section_type, possible_headings in sections_to_extract.items():
                if any(line.startswith(heading) for heading in possible_headings):
                    new_section = section_type
                    break
            
            # If we found a new section, save the previous one and start the new one
            if new_section:
                if current_section and section_content:
                    extracted_data[current_section] = '\n'.join(section_content).strip()
                current_section = new_section
                section_content = []
            # Otherwise add the line to the current section
            elif current_section:
                section_content.append(line)
        
        # Don't forget the last section
        if current_section and section_content:
            extracted_data[current_section] = '\n'.join(section_content).strip()
        
        # Create structured sections for the output
        if "description" in extracted_data and extracted_data["description"]:
            sections.append({
                "type": "description",
                "content": f"### Description\n\n{extracted_data['description']}"
            })
        
        # Combine reference and github information
        references = []
        
        if "reference" in extracted_data and extracted_data["reference"]:
            references.append({
                "type": "references",
                "content": f"### References\n\n{extracted_data['reference']}"
            })
        
        if "github" in extracted_data and extracted_data["github"]:
            references.append({
                "type": "github",
                "content": f"### GitHub\n\n{extracted_data['github']}"
            })
        
        if "poc" in extracted_data and extracted_data["poc"]:
            references.append({
                "type": "poc",
                "content": f"### Proof of Concept\n\n{extracted_data['poc']}"
            })
        
        if references:
            sections.append({
                "type": "references",
                "references": references
            })
        
        # Add link to MITRE with the CVE number displayed
        sections.append({
            "type": "mitre",
            "content": f"View on MITRE: {cve}",
            "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"
        })
        
        return sections
    
    def _associate_research_results(self):
        """Associate research results with findings"""
        for finding in self.findings.values():
            for cve in finding.cves:
                if cve in self.cve_research_cache and self.cve_research_cache[cve]:
                    finding.exploit_research[cve] = self.cve_research_cache[cve]
    
    def _fetch_all_github_star_counts(self):
        """Fetch star counts for all GitHub repositories at once."""
        # Initialize cache if not exists
        if not hasattr(self, 'github_token_valid') or not self.github_token_valid:
            logger.warning("Skipping GitHub star count collection - no valid token available")
            return
            
        # Collect all unique GitHub URLs from all findings
        all_github_urls = set()
        
        for finding in self.findings.values():
            if finding.exploit_research:
                for cve, research in finding.exploit_research.items():
                    # Collect from Go-ExploitDB
                    for source_type in ['github', 'inthewild', 'other']:
                        if source_type in research:
                            for exploit in research[source_type]:
                                if 'url' in exploit and 'github.com' in exploit['url']:
                                    all_github_urls.add(exploit['url'])
                    
                    # Collect from Trickest
                    if 'trickest' in research:
                        for item in research['trickest']:
                            if item['type'] == 'references' and 'references' in item:
                                for ref in item['references']:
                                    if ref['type'] == 'github':
                                        # Extract URLs using regex
                                        urls = re.findall(r'https?://github\.com/[^\s\)]+', ref['content'])
                                        for url in urls:
                                            all_github_urls.add(url)
        
        # Fetch star counts for all URLs
        if all_github_urls:
            total_urls = len(all_github_urls)
            logger.info(f"Collecting GitHub star counts for {total_urls} repositories...")
            
            for i, url in enumerate(all_github_urls, 1):
                if total_urls > 10:
                    if i % (round(total_urls,-1)/10) == 0:  # Log progress every 10% repositories
                        logger.info(f"Fetched star counts for {i}/{total_urls} repositories...")
                
                self._get_github_star_count(url)
            
            logger.info(f"Completed fetching star counts for {total_urls} repositories")
    
    def _get_github_star_count(self, repo_url):
        """Fetch star count for a GitHub repository."""
        if not self.options.github_token or not repo_url or 'github.com' not in repo_url:
            return 0
            
        # Parse owner and repo from URL
        parts = repo_url.replace('https://github.com/', '').split('/')
        if len(parts) < 2:
            return 0
            
        owner, repo = parts[0], parts[1]
        # Remove any trailing information from repo name
        repo = repo.split('#')[0].split('?')[0]
        
        # Check cache first
        cache_key = f"{owner}/{repo}"
        if hasattr(self, 'github_star_cache') and cache_key in self.github_star_cache:
            return self.github_star_cache[cache_key]
        
        # Initialize cache if not exists
        if not hasattr(self, 'github_star_cache'):
            self.github_star_cache = {}
        
        try:
            headers = {'Authorization': f'token {self.options.github_token}'} if self.options.github_token else {}
            url = f"https://api.github.com/repos/{owner}/{repo}"
            
            response = requests.get(url, headers=headers)
            
            # Handle rate limiting
            if response.status_code == 403 and 'X-RateLimit-Remaining' in response.headers:
                if int(response.headers['X-RateLimit-Remaining']) == 0:
                    logger.warning(f"GitHub API rate limit reached. Waiting 60 seconds...")
                    sleep(60)  # Wait and try again
                    return self._get_github_star_count(repo_url)
            
            if response.status_code == 200:
                data = response.json()
                star_count = data.get('stargazers_count', 0)
                
                # Cache the result
                self.github_star_cache[cache_key] = star_count
                return star_count
            else:
                logger.debug(f"Error fetching GitHub stars for {owner}/{repo}: {response.status_code}")
                return 0
        except Exception as e:
            logger.debug(f"Error fetching GitHub stars: {e}")
            return 0

    def _sort_findings_with_criteria(self, findings, criteria_str):
        """Sort findings according to specified criteria."""
        if criteria_str.lower() == 'default':
            # Use the built-in __lt__ method for default sorting
            return sorted(findings)
        
        valid_criteria = {
            'exploit_status': lambda f: 2 if f.exploit_research else (1 if f.exploit_available_nessus else 0),
            'poc_count': lambda f: getattr(f, 'poc_count', 0),
            'star_count': lambda f: getattr(f, 'star_count', 0),
            'severity': lambda f: f.get_severity_num(),
            'plugin_id': lambda f: int(f.plugin_id) if f.plugin_id.isdigit() else f.plugin_id
        }
        
        # Parse the criteria string
        criteria = []
        for crit in criteria_str.split(','):
            crit = crit.strip()
            reverse = False
            if ':' in crit:
                crit, direction = crit.split(':', 1)
                reverse = (direction.lower() in ['desc', 'descending', 'down', 'd'])
            
            # Validate the criterion
            if crit not in valid_criteria:
                logger.warning(f"Invalid sorting criterion: {crit}. "
                            f"Valid options are: {', '.join(valid_criteria.keys())}. "
                            f"Ignoring this criterion.")
                continue
            
            # Check if the criterion is applicable
            if crit in ['poc_count', 'star_count'] and not self.options.research:
                logger.warning(f"Sorting by {crit} requires --research option. Ignoring this criterion.")
                continue
            
            if crit == 'star_count' and not self.options.github_token:
                logger.warning(f"Sorting by star_count requires --github-token. Ignoring this criterion.")
                continue
            
            criteria.append((crit, valid_criteria[crit], reverse))
        
        if not criteria:
            logger.warning("No valid sorting criteria provided. Using default sorting.")
            return sorted(findings)
        
        # Sort with multiple criteria
        result = list(findings)
        # Sort by each criterion in reverse order (least important first)
        for crit_name, key_func, reverse in reversed(criteria):
            logger.debug(f"Sorting by criterion: {crit_name} (reverse={reverse})")
            result.sort(key=key_func, reverse=reverse)
        
        return result

    def generate_summary(self):
        """Generate summary file in markdown format"""
        if not self.findings:
            logger.warning("No findings to summarize")
            return
            
        # Calculate POC count and star count for each finding BEFORE sorting
        if self.options.research:
            for plugin_id, finding in self.findings.items():
                poc_count = 0
                total_stars = 0
                
                if finding.exploit_research:
                    # Collect all GitHub URLs
                    github_urls = set()
                    
                    for cve, research in finding.exploit_research.items():
                        # Collect from Go-ExploitDB
                        for source_type in ['github', 'inthewild', 'other']:
                            if source_type in research:
                                for exploit in research[source_type]:
                                    if 'url' in exploit and 'github.com' in exploit['url']:
                                        github_urls.add(exploit['url'])
                        
                        # Collect from Trickest
                        if 'trickest' in research:
                            for item in research['trickest']:
                                if item['type'] == 'references' and 'references' in item:
                                    for ref in item['references']:
                                        if ref['type'] == 'github':
                                            # Extract URLs using regex
                                            urls = re.findall(r'https?://github\.com/[^\s\)]+', ref['content'])
                                            for url in urls:
                                                github_urls.add(url)
                    
                    # Count POCs and get star counts from cache
                    poc_count = len(github_urls)
                    for url in github_urls:
                        # Extract owner/repo from URL for cache lookup
                        parts = url.replace('https://github.com/', '').split('/')
                        if len(parts) >= 2:
                            owner, repo = parts[0], parts[1]
                            repo = repo.split('#')[0].split('?')[0]
                            cache_key = f"{owner}/{repo}"
                            total_stars += self.github_star_cache.get(cache_key, 0)
                
                # Directly set attributes on the finding object
                finding.poc_count = poc_count
                finding.star_count = total_stars
        
        # AFTER setting the attributes, sort the findings
        sorted_findings = self._sort_findings_with_criteria(
            self.findings.values(), 
            self.options.sort_summary
        )
            
    # [rest of function continues as before]
        
        # Create output directory if specified
        output_dir = self.options.output_dir
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # Summary filename
        prefix = self.options.prefix + "-" if self.options.prefix else ""
        summary_file = os.path.join(output_dir, f"{prefix}findings-summary.md")
        
        # Calculate POC count and star count for each finding if research is enabled
        finding_stats = {}
        if self.options.research:
            for plugin_id, finding in self.findings.items():
                poc_count = 0
                total_stars = 0
                
                if finding.exploit_research:
                    # Collect all GitHub URLs
                    github_urls = set()
                    
                    for cve, research in finding.exploit_research.items():
                        # Collect from Go-ExploitDB
                        for source_type in ['github', 'inthewild', 'other']:
                            if source_type in research:
                                for exploit in research[source_type]:
                                    if 'url' in exploit and 'github.com' in exploit['url']:
                                        github_urls.add(exploit['url'])
                        
                        # Collect from Trickest
                        if 'trickest' in research:
                            for item in research['trickest']:
                                if item['type'] == 'references' and 'references' in item:
                                    for ref in item['references']:
                                        if ref['type'] == 'github':
                                            # Extract URLs using regex
                                            urls = re.findall(r'https?://github\.com/[^\s\)]+', ref['content'])
                                            for url in urls:
                                                github_urls.add(url)
                    
                    # Count POCs and get star counts from cache
                    poc_count = len(github_urls)
                    # Transform GitHub URLs to owner/repo cache keys for lookup
                    cache_keys = []
                    for url in github_urls:
                        parts = url.replace('https://github.com/', '').split('/')
                        if len(parts) >= 2:
                            owner, repo = parts[0], parts[1]
                            repo = repo.split('#')[0].split('?')[0]
                            cache_keys.append(f"{owner}/{repo}")
                            
                    # Sum the star counts from cache
                    total_stars = sum(self.github_star_cache.get(key, 0) for key in cache_keys)
                                    
                finding_stats[plugin_id] = {
                    'poc_count': poc_count,
                    'total_stars': total_stars
                }
        
        # Create summary table
        with open(summary_file, 'w', encoding='utf-8') as f:
            f.write("# Nessus Scan Summary\n\n")
            f.write(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
            
            # Table header - conditionally include POC and Star count columns
            if self.options.research:
                f.write("| Plugin ID | Severity | Plugin Name | Affected IP Count | Exploit Available | POC Count | Star Count | Tester Notes |\n")
                f.write("|-----------|----------|-------------|------------------|------------------|-----------|------------|------------|\n")
            else:
                f.write("| Plugin ID | Severity | Plugin Name | Affected IP Count | Exploit Available | Tester Notes |\n")
                f.write("|-----------|----------|-------------|------------------|------------------|------------|\n")
            
            # Table rows
            for finding in sorted_findings:
                # Create Obsidian-compatible link if creating finding files
                if self.options.create_findings:
                    findings_subdir = self.options.findings_subdir
                    filename = f"{finding.get_normalized_name()}.md"
                    # Use explicit markdown link format instead of Obsidian wiki-links to avoid pipe issues
                    plugin_id_link = f"[{finding.plugin_id}]({findings_subdir}/{filename})"
                    # Create a link to the Affected IPs section of the finding file
                    affected_ips_link = f"[[{findings_subdir}/{filename}#Affected IPs\\|{len(finding.affected_ips)}]]"
                else:
                    plugin_id_link = finding.plugin_id
                    affected_ips_link = str(len(finding.affected_ips))
                
                # Conditionally include POC and Star count columns
                if self.options.research:
                    stats = finding_stats.get(finding.plugin_id, {'poc_count': 0, 'total_stars': 0})
                    poc_count = stats['poc_count']
                    star_count = stats['total_stars']
                    f.write(f"| {plugin_id_link} | {finding.severity} | {finding.plugin_name} | {affected_ips_link} | {finding.get_exploit_status()} | {poc_count} | {star_count} | |\n")
                else:
                    f.write(f"| {plugin_id_link} | {finding.severity} | {finding.plugin_name} | {affected_ips_link} | {finding.get_exploit_status()} | |\n")
            
            # Add summary statistics
            f.write("\n## Summary Statistics\n\n")
            
            # Count unique hosts/IPs
            unique_addresses = set()
            for finding in sorted_findings:
                unique_addresses.update(finding.affected_ips.keys())
            
            # Split into IPs and hostnames
            ips = []
            hostnames = []
            for address in unique_addresses:
                if self._is_ip_address(address):
                    ips.append(address)
                else:
                    hostnames.append(address)
            
            f.write(f"* Total unique targets: {len(unique_addresses)}\n")
            f.write(f"  * IP addresses: {len(ips)}\n")
            f.write(f"  * Hostnames: {len(hostnames)}\n")
            f.write(f"* Total unique findings: {len(sorted_findings)}\n")
            
            # Count by severity
            severity_counts = defaultdict(int)
            for finding in sorted_findings:
                severity_counts[finding.severity] += 1
            
            f.write("* Findings by severity:\n")
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                if severity_counts[severity] > 0:
                    f.write(f"  * {severity}: {severity_counts[severity]}\n")
                    
            # Count by exploit status
            exploit_research_count = sum(1 for f in sorted_findings if f.exploit_research)
            exploit_nessus_count = sum(1 for f in sorted_findings if not f.exploit_research and f.exploit_available_nessus)
            
            f.write("* Findings with exploits:\n")
            f.write(f"  * Confirmed by research: {exploit_research_count}\n")
            f.write(f"  * Reported by Nessus only: {exploit_nessus_count}\n")
            
            # Add GitHub repository statistics if research was enabled
            if self.options.research:
                total_repos = sum(stats['poc_count'] for stats in finding_stats.values())
                total_stars = sum(stats['total_stars'] for stats in finding_stats.values())
                f.write("* GitHub repository statistics:\n")
                f.write(f"  * Total repositories: {total_repos}\n")
                f.write(f"  * Total stars: {total_stars}\n")
            
            logger.info(f"Summary file created: {summary_file}")
            return summary_file
    
    def generate_finding_files(self):
        """Generate individual finding files"""
        if not self.options.create_findings:
            return
            
        # Create findings directory
        output_dir = self.options.output_dir
        findings_dir = os.path.join(output_dir, self.options.findings_subdir)
        os.makedirs(findings_dir, exist_ok=True)
        
        logger.info(f"Generating finding files in {findings_dir}")
        
        # Generate files for each finding
        for finding in self.findings.values():
            filename = os.path.join(findings_dir, f"{finding.get_normalized_name()}.md")
            
            with open(filename, 'w', encoding='utf-8') as f:
                # Overview section
                f.write(f"# Overview\n\n")
                
                # Severity as H2
                f.write(f"## Severity: {finding.severity}\n\n")
                
                f.write(f"## Finding Description\n\n")
                f.write(f"{finding.description}\n\n")
                
                # CVEs section as comma-separated list
                if finding.cves:
                    f.write(f"## CVEs\n\n")
                    f.write(f"{', '.join(sorted(finding.cves))}\n\n")
                
                # Affected IPs section
                f.write(f"## Affected IPs\n\n")
                for ip in sorted(finding.affected_ips.keys()):
                    f.write(f"* {ip}\n")
                f.write("\n")
                
                # Plugin output section
                if any(output for output in finding.affected_ips.values()):
                    f.write(f"# Finding Output\n\n")
                    for ip, output in sorted(finding.affected_ips.items()):
                        if output:
                            f.write(f"## {ip}\n\n")
                            f.write("```\n")
                            f.write(f"{output}\n")
                            f.write("```\n\n")
                
                # Research section
                if finding.exploit_research:
                    f.write(f"# Research\n\n")
                    
                    # Collect all URLs across all sources
                    all_exploits = []
                    trickest_github_urls = {}
                    
                    # Collect Go-ExploitDB data
                    for cve, research in finding.exploit_research.items():
                        # Collect GitHub links from trickest data
                        if 'trickest' in research:
                            for item in research['trickest']:
                                if item['type'] == 'references' and 'references' in item:
                                    for ref in item['references']:
                                        if ref['type'] == 'github':
                                            # Extract URLs using regex
                                            import re
                                            urls = re.findall(r'https?://github\.com/[^\s\)]+', ref['content'])
                                            for url in urls:
                                                if url not in trickest_github_urls:
                                                    trickest_github_urls[url] = [cve]
                                                else:
                                                    trickest_github_urls[url].append(cve)
                        
                        # Collect Go-ExploitDB data
                        for source_type in ['github', 'inthewild', 'other']:
                            if source_type in research:
                                for exploit in research[source_type]:
                                    if 'url' in exploit and 'github.com' in exploit['url']:
                                        # Create a rich exploit entry
                                        exploit_entry = {
                                            'url': exploit['url'],
                                            'sources': exploit.get('sources', [exploit.get('type', 'Unknown')]),
                                            'cves': [cve],
                                            'description': exploit.get('description', ''),
                                            'source': 'Go-ExploitDB'
                                        }
                                        
                                        # Check if already added
                                        existing = next((e for e in all_exploits if e['url'] == exploit['url']), None)
                                        if existing:
                                            # Merge information
                                            if cve not in existing['cves']:
                                                existing['cves'].append(cve)
                                            # Merge sources if not already there
                                            for src in exploit_entry['sources']:
                                                if src not in existing['sources']:
                                                    existing['sources'].append(src)
                                        else:
                                            all_exploits.append(exploit_entry)
                    
                    # Add GitHub URLs from Trickest if not already present
                    for url, cves in trickest_github_urls.items():
                        existing = next((e for e in all_exploits if e['url'] == url), None)
                        if existing:
                            # Just add 'Trickest' as a source if not already there
                            if 'Trickest' not in existing['sources']:
                                existing['sources'].append('Trickest')
                            # Add any CVEs not already present
                            for cve in cves:
                                if cve not in existing['cves']:
                                    existing['cves'].append(cve)
                        else:
                            # Create a new entry
                            all_exploits.append({
                                'url': url,
                                'sources': ['Trickest'],
                                'cves': cves,
                                'description': '',
                                'source': 'Trickest'
                            })
                    
                    # Add star counts from cache to each exploit
                    for exploit in all_exploits:
                        if 'github.com' in exploit['url']:
                            # Extract owner/repo from URL
                            parts = exploit['url'].replace('https://github.com/', '').split('/')
                            if len(parts) >= 2:
                                owner, repo = parts[0], parts[1]
                                repo = repo.split('#')[0].split('?')[0]
                                cache_key = f"{owner}/{repo}"
                                exploit['stars'] = self.github_star_cache.get(cache_key, 0)
                            else:
                                exploit['stars'] = 0
                        else:
                            exploit['stars'] = 0
                    
                    # Sort exploits by star count (descending), then by number of sources (descending), then by URL
                    all_exploits.sort(key=lambda x: (-x['stars'], -len(x['sources']), x['url']))
                    
                    # Generate Research Summary Table
                    if all_exploits:
                        f.write("## Research Summary\n\n")
                        f.write("| URL | Star Count | Sources | Related CVEs |\n")
                        f.write("|-----|------------|---------|-------------|\n")
                        
                        for exploit in all_exploits:
                            # Format the URL as a nice GitHub link
                            repo_path = exploit['url'].replace('https://github.com/', '')
                            parts = repo_path.split('/')
                            if len(parts) >= 2:
                                display_url = f"[{parts[0]} - {parts[1]}]({exploit['url']})"
                            else:
                                display_url = f"[{exploit['url']}]({exploit['url']})"
                            
                            stars = exploit.get('stars', 0)
                            sources = ", ".join(exploit['sources'])
                            related_cves = ", ".join(sorted(exploit['cves']))
                            
                            f.write(f"| {display_url} | {stars} | {sources} | {related_cves} |\n")
                        
                        f.write("\n")
                    
                    # Create exploit details file and link to it (unless disabled)
                    has_trickest_results = False
                    for research in finding.exploit_research.values():
                        if 'trickest' in research:
                            has_trickest_results = True
                            break
                            
                    if (all_exploits or has_trickest_results) and not self.options.no_exploit_details:
                        # Create exploits detail directory if it doesn't exist
                        exploits_dir = os.path.join(findings_dir, "exploit-details")
                        os.makedirs(exploits_dir, exist_ok=True)
                        
                        # Create the exploit details file
                        exploit_details_filename = f"{finding.get_normalized_name()}-exploit-details.md"
                        exploit_details_path = os.path.join(exploits_dir, exploit_details_filename)
                        
                        f.write(f"[View detailed exploit information](exploit-details/{exploit_details_filename})\n\n")
                        
                        # Write the exploit details file
                        self._write_exploit_details_file(
                            exploit_details_path, 
                            finding, 
                            all_exploits
                        )
                
                # Tester notes section
                f.write(f"# Tester Notes\n\n")
                f.write("*Add your notes here*\n")
    
    def _write_exploit_details_file(self, filepath, finding, all_exploits):
        """Write a detailed exploit information file"""
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"# Exploit Details for {finding.plugin_name}\n\n")
            
            # Go-ExploitDB section
            has_exploitdb_results = False
            for exploit in all_exploits:
                if exploit['source'] == 'Go-ExploitDB':
                    has_exploitdb_results = True
                    break
            
            if has_exploitdb_results:
                f.write("## Go-ExploitDB\n\n")
                
                for exploit in all_exploits:
                    if exploit['source'] == 'Go-ExploitDB':
                        f.write(f"### {exploit['url']}\n\n")
                        
                        if 'description' in exploit and exploit['description']:
                            f.write(f"**Description**: {exploit['description']}\n\n")
                        
                        if 'sources' in exploit and exploit['sources']:
                            f.write(f"**Sources**: {', '.join(exploit['sources'])}\n\n")
                        else:
                            f.write(f"**Source**: {exploit.get('type', 'Unknown')}\n\n")
                        
                        f.write(f"**Related CVEs**: {', '.join(sorted(exploit['cves']))}\n\n")
            
            # Trickest section
            has_trickest_results = False
            for research in finding.exploit_research.values():
                if 'trickest' in research:
                    has_trickest_results = True
                    break
            
            if has_trickest_results:
                f.write("## Trickest Repository\n\n")
                
                # Collect and organize all trickest data by type
                descriptions = {}
                references = {}
                poc_content = {}
                mitre_links = {}
                
                # Collect data by CVE and type
                for cve, research in finding.exploit_research.items():
                    if 'trickest' in research:
                        for item in research['trickest']:
                            if item['type'] == 'description':
                                descriptions[cve] = item['content']
                            elif item['type'] == 'references' and 'references' in item:
                                for ref in item['references']:
                                    if ref['type'] == 'references':
                                        references[cve] = ref['content']
                                    elif ref['type'] == 'poc':
                                        poc_content[cve] = ref['content']
                            elif item['type'] == 'mitre':
                                if isinstance(item, dict):  # Ensure it's a dictionary
                                    mitre_links[cve] = item
                                else:
                                    mitre_links[cve] = {'content': f"View on MITRE: {cve}", 
                                                      'url': f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"}
                
                # Description section with subsections for each CVE
                if descriptions:
                    f.write("### Description\n\n")
                    for cve, content in descriptions.items():
                        if "### Description" in content:
                            content = content.replace("### Description", f"#### {cve}")
                        else:
                            f.write(f"#### {cve}\n\n")
                        f.write(f"{content}\n\n")
                        
                        # Add references directly under the description for each CVE
                        if cve in references:
                            ref_content = references[cve]
                            if "### References" in ref_content:
                                ref_content = ref_content.replace("### References", "##### References")
                            else:
                                f.write(f"##### References\n\n")
                            f.write(f"{ref_content}\n\n")
                
                # POC section with subsections for each CVE
                if poc_content:
                    f.write("### Proof of Concept\n\n")
                    for cve, content in poc_content.items():
                        if "### Proof of Concept" in content:
                            content = content.replace("### Proof of Concept", f"#### {cve}")
                        else:
                            f.write(f"#### {cve}\n\n")
                        f.write(f"{content}\n\n")
                
                # MITRE links section
                if mitre_links:
                    f.write("### MITRE CVE Links\n\n")
                    for cve, link_info in mitre_links.items():
                        # Handle both cases where link_info is a dictionary or a string
                        if isinstance(link_info, dict) and 'content' in link_info:
                            link_text = link_info['content']
                            link_url = link_info.get('url', f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}")
                        else:
                            # If it's a string or doesn't have 'content', use default format
                            link_text = f"View on MITRE: {cve}"
                            link_url = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"
                        
                        f.write(f"* [{link_text}]({link_url})\n")
                    f.write("\n")
                    
    def generate_csv(self):
        """Generate CSV output if requested"""
        if not self.options.csv_output:
            return
            
        # Create output directory if specified
        output_dir = self.options.output_dir
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
        
        # Generate summary CSV
        self._generate_summary_csv()
        
        # Generate detailed findings CSV if research is enabled
        if self.options.research:
            self._generate_detailed_csv()
            
    def _generate_summary_csv(self):
        """Generate a summary CSV with basic finding information"""
        import csv
        
        # CSV filename
        prefix = self.options.prefix + "-" if self.options.prefix else ""
        csv_file = os.path.join(self.options.output_dir, f"{prefix}findings-summary.csv")
        
        # Sort findings
        sorted_findings = sorted(self.findings.values())
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['Plugin ID', 'Severity', 'Plugin Name', 'Affected IPs', 'CVEs', 'Exploit Available'])
            
            # Write data
            for finding in sorted_findings:
                writer.writerow([
                    finding.plugin_id,
                    finding.severity,
                    finding.plugin_name,
                    ', '.join(sorted(finding.affected_ips.keys())),
                    ', '.join(sorted(finding.cves)) if finding.cves else 'N/A',
                    finding.get_exploit_status()
                ])
                
        logger.info(f"Summary CSV file created: {csv_file}")
        return csv_file
        
    def _generate_detailed_csv(self):
        """Generate a detailed CSV with extensive finding information including research data"""
        import csv
        
        # CSV filename
        prefix = self.options.prefix + "-" if self.options.prefix else ""
        csv_file = os.path.join(self.options.output_dir, f"{prefix}finding-details.csv")
        
        # Sort findings
        sorted_findings = sorted(self.findings.values())
        
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['Plugin ID', 'Finding Name', 'Finding Description', 'CVEs', 'Affected IPs', 'Research'])
            
            # Write data
            for finding in sorted_findings:
                # Collect all research links with their sources
                research_links = []
                
                # Process Go-ExploitDB and Trickest research
                if finding.exploit_research:
                    # Collect all URLs across all sources
                    all_exploits = []
                    trickest_github_urls = {}
                    
                    # Collect data from findings
                    for cve, research in finding.exploit_research.items():
                        # Collect GitHub links from trickest data
                        if 'trickest' in research:
                            for item in research['trickest']:
                                if item['type'] == 'references' and 'references' in item:
                                    for ref in item['references']:
                                        if ref['type'] == 'github':
                                            # Extract URLs using regex
                                            import re
                                            urls = re.findall(r'https?://github\.com/[^\s\)]+', ref['content'])
                                            for url in urls:
                                                if url not in trickest_github_urls:
                                                    trickest_github_urls[url] = [cve]
                                                else:
                                                    trickest_github_urls[url].append(cve)
                        
                        # Collect Go-ExploitDB data
                        for source_type in ['github', 'inthewild', 'other']:
                            if source_type in research:
                                for exploit in research[source_type]:
                                    if 'url' in exploit:
                                        # Add to exploits list
                                        all_exploits.append({
                                            'url': exploit['url'],
                                            'sources': exploit.get('sources', [exploit.get('type', 'Unknown')]),
                                            'source': 'Go-ExploitDB'
                                        })
                    
                    # Add Trickest URLs
                    for url, cves in trickest_github_urls.items():
                        # Check if URL is already in exploits
                        existing = next((e for e in all_exploits if e['url'] == url), None)
                        if existing:
                            # Add Trickest as a source if not already there
                            if 'Trickest' not in existing['sources']:
                                existing['sources'].append('Trickest')
                        else:
                            # Add as a new entry
                            all_exploits.append({
                                'url': url,
                                'sources': ['Trickest'],
                                'source': 'Trickest'
                            })
                    
                    # Format research links
                    for exploit in all_exploits:
                        sources = ", ".join(exploit['sources'])
                        research_links.append(f"{exploit['url']} - {sources}")
                
                # Join research links with newlines for CSV cell
                research_text = "\n".join(research_links)
                
                writer.writerow([
                    finding.plugin_id,
                    finding.plugin_name,
                    finding.description,
                    ', '.join(sorted(finding.cves)) if finding.cves else 'N/A',
                    ', '.join(sorted(finding.affected_ips.keys())),
                    research_text
                ])
                
        logger.info(f"Detailed findings CSV file created: {csv_file}")
        return csv_file
    def _validate_github_token(self, token):
        """Test the GitHub token to verify it works"""
        if not token:
            return False
            
        try:
            # Make a simple API request to verify the token works
            headers = {'Authorization': f'token {token}'}
            response = requests.get("https://api.github.com/rate_limit", headers=headers)
            
            if response.status_code == 200:
                # Token is valid - display rate limit info
                rate_data = response.json()
                core_remaining = rate_data.get('resources', {}).get('core', {}).get('remaining', 0)
                core_limit = rate_data.get('resources', {}).get('core', {}).get('limit', 0)
                logger.info(f"GitHub API token is valid. Rate limit: {core_remaining}/{core_limit} requests remaining")
                return True
            elif response.status_code == 401:
                logger.error("GitHub API token is invalid or has been revoked")
                return False
            else:
                logger.error(f"GitHub API request failed with status code: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"Error validating GitHub token: {e}")
            return False

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Parse Nessus files and generate reports')
    
    # Input files
    parser.add_argument('input_files', nargs='+',
                        help='Path(s) to Nessus files. Can use wildcards (e.g., *.nessus)')
    
    # Output options
    parser.add_argument('-o', '--output-dir', default='',
                        help='Output directory for reports (default: current directory)')
    parser.add_argument('-p', '--prefix', default='',
                        help='Prefix for output files (e.g., client-name)')
    parser.add_argument('-ss', '--sort-summary', default='default',
                   help='Criteria to sort the summary by. '
                        'Format: "criterion1[:direction],criterion2[:direction],...". '
                        'Valid criteria: exploit_status, poc_count, star_count, severity, plugin_id. '
                        'Directions: asc/ascending (default) or desc/descending. '
                        'Alternate formats: ~criterion or ^criterion for descending. '
                        'Example: "exploit_status,poc_count:desc,severity". '
                        'Default: exploit_status:desc,poc_count:desc,star_count:desc,severity')
    
    # Finding file options
    parser.add_argument('-f', '--create-findings', action='store_true',
                        help='Create individual finding files')
    parser.add_argument('--findings-subdir', default='findings',
                        help='Subdirectory for finding files (default: findings)')
    parser.add_argument('--no-exploit-details', action='store_true',
                        help='Disable generation of exploit details files')
    
    # CSV output
    parser.add_argument('--csv', dest='csv_output', action='store_true',
                        help='Generate CSV output instead of markdown')
    
    # Research options
    parser.add_argument('-r', '--research', action='store_true',
                        help='Research CVEs using available sources')
    parser.add_argument('--research-sources', default='exploitdb,trickest',
                        help='Comma-separated list of research sources (default: exploitdb,trickest)')
    parser.add_argument('--exploitdb-path', default='/opt/go-exploitdb/go-exploitdb.sqlite3',
                        help='Path to go-exploitdb database')
    parser.add_argument('--trickest-path', default='',
                        help='Path to trickest/cve repository clone')
    parser.add_argument('--github-token', default='',
                   help='GitHub API token for fetching repository data')
    parser.add_argument('--github-token-file', 
                    help='Path to file containing GitHub API token (more secure than --github-token)')
    
    # Verbose output
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Process research sources
    args.research_sources = args.research_sources.split(',')
    
    # Set logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    return args

def main():
    """Main function"""
    args = parse_args()
    
    try:
        # Create parser and parse files
        parser = NessusParser(args)
        parser.parse_files()
        
        # Research exploits if enabled
        if args.research:
            parser.research_exploits()
        
        # Generate output
        if args.csv_output:
            parser.generate_csv()
        else:
            parser.generate_summary()
            if args.create_findings:
                parser.generate_finding_files()
                
        logger.info("Processing completed successfully")
        
    except Exception as e:
        logger.error(f"Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()