"""
leaktorch/reporters.py
Output formatting and reporting for scan results
"""

import json
from datetime import datetime
from typing import List, Dict
from abc import ABC, abstractmethod
from .utils import mask_secret, truncate_string

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    class Fore:
        RED = YELLOW = GREEN = CYAN = WHITE = ''
    class Style:
        BRIGHT = RESET_ALL = ''

from .finding import Finding


class Reporter(ABC):
    """Base class for all reporters"""
    
    @abstractmethod
    def report(self, findings: List[Finding], statistics: Dict) -> str:
        """Generate report from findings"""
        pass


class ConsoleReporter(Reporter):
    """Console/terminal output with colors"""
    
    SEVERITY_COLORS = {
        'CRITICAL': Fore.RED + Style.BRIGHT,
        'HIGH': Fore.RED,
        'MEDIUM': Fore.YELLOW,
        'LOW': Fore.CYAN
    }
    
    def __init__(
        self,
        show_banner: bool = True,
        verbose: bool = False,
        mask_secrets: bool = True,
        quiet: bool = False
    ):
        """
        Console reporter.
        
        Args:
            show_banner: Ob das ASCII-Banner angezeigt werden soll.
            verbose: Zukünftig für detailliertere Ausgaben nutzbar.
            mask_secrets: Ob gefundene Secrets maskiert werden sollen.
            quiet: Wenn True, schreibt der Reporter NICHTS auf stdout.
        """
        self.show_banner = show_banner
        self.verbose = verbose
        self.mask_secrets = mask_secrets
        self.quiet = quiet
    
    def print_banner(self):
        """Print ASCII banner"""
        banner = f"""
{Fore.YELLOW}╔════════════════════════════════════════════════════════╗
║                    LEAKTORCH 🔦                       ║
║          Git Repository Secret Scanner                ║
╚════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def print_finding(self, finding: Finding):
        """Print a single finding"""
        color = self.SEVERITY_COLORS.get(finding.severity, Fore.WHITE)
        
        markers = []

        if finding.commit_hash:
            markers.append(f"{Fore.YELLOW}[IN GIT HISTORY ⚠️ ]{Style.RESET_ALL}")

        if not finding.commit_hash:
            if finding.is_in_gitignore:
                markers.append(f"{Fore.GREEN}[IN .gitignore ✓]{Style.RESET_ALL}")
            else:
                markers.append(f"{Fore.RED}[NOT in .gitignore ⚠️ ]{Style.RESET_ALL}")

        marker_text = " ".join(markers)
        print(f"\n{color}[{finding.severity}] {finding.secret_type}{Style.RESET_ALL} {marker_text}")
        print(f"  File: {finding.file_path}:{finding.line_number}")
        
        if finding.commit_hash:
            print(f"  Commit: {finding.commit_hash[:8]}")
        
        if self.mask_secrets:
            masked = mask_secret(finding.matched_string, visible_chars=3)
            print(f"  Match: {masked}")
        else:
            print(f"  Match: {finding.matched_string}")
        
        line_display = truncate_string(finding.line_content.strip(), max_length=100)
        print(f"  Line: {line_display}")
        print(f"  Entropy: {finding.entropy:.2f}")
    
    def print_summary(self, statistics: Dict):
        """Print scan summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
        
        print(f"Files scanned: {statistics['files_scanned']}")
        if statistics['commits_scanned'] > 0:
            print(f"Commits scanned: {statistics['commits_scanned']}")
        
        has_gitignore = statistics.get('has_gitignore', False)
        if has_gitignore:
            print(f"{Fore.GREEN}✓ .gitignore found{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}⚠️  No .gitignore found{Style.RESET_ALL}")
        
        print(f"Total findings: {statistics['total_findings']}")
        
        not_in_gitignore = statistics.get('findings_not_in_gitignore', 0)
        in_gitignore = statistics.get('findings_in_gitignore', 0)
        whitelisted = statistics.get('whitelisted_findings', 0)
        false_positives = statistics.get('false_positives_filtered', 0)
        
        if has_gitignore and (in_gitignore > 0 or not_in_gitignore > 0):
            print(f"  ├─ {Fore.RED}NOT in .gitignore: {not_in_gitignore}{Style.RESET_ALL} ⚠️")
            print(f"  └─ {Fore.GREEN}IN .gitignore: {in_gitignore}{Style.RESET_ALL} ✓")
        
        if whitelisted > 0:
            print(f"Whitelisted: {whitelisted}")
        
        if false_positives > 0:
            print(f"False positives filtered: {false_positives}")
        
        print()
        
        if statistics['total_findings'] > 0:
            print("Findings by severity:")
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
            
            for severity in severity_order:
                count = statistics['severity_breakdown'].get(severity, 0)
                if count > 0:
                    color = self.SEVERITY_COLORS[severity]
                    print(f"  {color}{severity}: {count}{Style.RESET_ALL}")
            
            print()
            
            if not_in_gitignore > 0:
                print(Fore.RED + Style.BRIGHT +
                      f"⚠️  CRITICAL: {not_in_gitignore} secret(s) NOT in .gitignore!" +
                      Style.RESET_ALL)
                print(Fore.RED +
                      "   These secrets could be committed to git!" +
                      Style.RESET_ALL)
            
            if in_gitignore > 0 and not_in_gitignore == 0:
                print(Fore.YELLOW +
                      f"ℹ️  All {in_gitignore} secret(s) are in .gitignore (protected)" +
                      Style.RESET_ALL)
        else:
            print(Fore.GREEN + "✓ No secrets detected!" + Style.RESET_ALL)
    
    def report(self, findings: List[Finding], statistics: Dict) -> str:
        """Generate console report"""
        # Quiet-Modus: überhaupt nichts auf stdout schreiben
        if self.quiet:
            return ""
        
        if self.show_banner:
            self.print_banner()
        
        if findings:
            print(f"\n{Fore.YELLOW}DETAILED FINDINGS:{Style.RESET_ALL}")
            
            not_gitignored = [f for f in findings if not f.is_in_gitignore]
            gitignored = [f for f in findings if f.is_in_gitignore]
            
            if not_gitignored:
                print(f"\n{Fore.RED}⚠️  SECRETS NOT IN .gitignore (CRITICAL):{Style.RESET_ALL}")
                for finding in not_gitignored:
                    self.print_finding(finding)
            
            if gitignored:
                print(f"\n{Fore.GREEN}✓ Secrets in .gitignore (Protected):{Style.RESET_ALL}")
                for finding in gitignored:
                    self.print_finding(finding)
        
        self.print_summary(statistics)
        
        return ""


class JSONReporter(Reporter):
    """JSON output format"""
    
    def __init__(self, pretty: bool = True, mask_secrets: bool = True):
        self.pretty = pretty
        self.mask_secrets = mask_secrets
    
    def report(self, findings: List[Finding], statistics: Dict) -> str:
        """Generate JSON report"""
        findings_data = []
        for f in findings:
            data = f.to_dict()
            if self.mask_secrets:
                data['matched'] = mask_secret(f.matched_string, visible_chars=3)
            findings_data.append(data)
        
        report = {
            'scan_date': datetime.now().isoformat(),
            'statistics': statistics,
            'findings': findings_data
        }
        
        if self.pretty:
            return json.dumps(report, indent=2)
        else:
            return json.dumps(report)
    
    def save(self, findings: List[Finding], statistics: Dict, output_path: str):
        """Save JSON report to file"""
        report_json = self.report(findings, statistics)
        
        with open(output_path, 'w') as f:
            f.write(report_json)


class MarkdownReporter(Reporter):
    """Markdown output format"""
    
    def __init__(self, mask_secrets: bool = True):
        self.mask_secrets = mask_secrets
    
    def report(self, findings: List[Finding], statistics: Dict) -> str:
        """Generate Markdown report"""
        lines = []
        
        lines.append("# LeakTorch Scan Report")
        lines.append(f"\n**Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        
        lines.append("## Statistics\n")
        lines.append(f"- Files scanned: {statistics['files_scanned']}")
        lines.append(f"- Commits scanned: {statistics['commits_scanned']}")
        lines.append(f"- Total findings: {statistics['total_findings']}")
        
        whitelisted = statistics.get('whitelisted_findings', 0)
        false_positives = statistics.get('false_positives_filtered', 0)
        
        if whitelisted > 0:
            lines.append(f"- Whitelisted: {whitelisted}")
        if false_positives > 0:
            lines.append(f"- False positives filtered: {false_positives}")
        
        lines.append("")
        
        if statistics['total_findings'] > 0:
            lines.append("### Findings by Severity\n")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                count = statistics['severity_breakdown'].get(severity, 0)
                if count > 0:
                    lines.append(f"- **{severity}**: {count}")
            lines.append("")
        
        if findings:
            lines.append("## Findings\n")
            
            by_severity = {}
            for finding in findings:
                if finding.severity not in by_severity:
                    by_severity[finding.severity] = []
                by_severity[finding.severity].append(finding)
            
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if severity in by_severity:
                    lines.append(f"### {severity} Severity\n")
                    
                    for finding in by_severity[severity]:
                        lines.append(f"#### {finding.secret_type}")
                        lines.append(f"- **File:** `{finding.file_path}:{finding.line_number}`")
                        if finding.commit_hash:
                            lines.append(f"- **Commit:** `{finding.commit_hash[:8]}`")
                        lines.append(f"- **Entropy:** {finding.entropy:.2f}")
                        
                        if self.mask_secrets:
                            masked = mask_secret(finding.matched_string, visible_chars=3)
                            lines.append(f"- **Match:** `{masked}`")
                        else:
                            lines.append(f"- **Match:** `{finding.matched_string}`")
                        
                        content = finding.line_content.strip()[:100]
                        lines.append(f"- **Line:** `{content}`\n")
        else:
            lines.append("## Results\n")
            lines.append("✓ No secrets detected!\n")
        
        return "\n".join(lines)


class CSVReporter(Reporter):
    """CSV output format"""
    
    def __init__(self, mask_secrets: bool = True):
        self.mask_secrets = mask_secrets
    
    def report(self, findings: List[Finding], statistics: Dict) -> str:
        """Generate CSV report"""
        lines = []
        
        lines.append("Severity,Type,File,Line,Commit,Entropy,Match,Content")
        
        for finding in findings:
            commit = finding.commit_hash[:8] if finding.commit_hash else ""
            content = finding.line_content.strip().replace('"', '""')[:100]
            
            if self.mask_secrets:
                match = mask_secret(finding.matched_string, visible_chars=3)
            else:
                match = finding.matched_string
            
            match = match.replace('"', '""')
            
            line = (
                f'"{finding.severity}","{finding.secret_type}",'
                f'"{finding.file_path}",{finding.line_number},"{commit}",'
                f'{finding.entropy:.2f},"{match}","{content}"'
            )
            lines.append(line)
        
        return "\n".join(lines)


class SummaryReporter(Reporter):
    """Brief summary output"""
    
    def report(self, findings: List[Finding], statistics: Dict) -> str:
        """Generate summary report"""
        lines = []
        
        lines.append("LeakTorch Scan Summary")
        lines.append("=" * 40)
        lines.append(f"Files: {statistics['files_scanned']}")
        lines.append(f"Commits: {statistics['commits_scanned']}")
        lines.append(f"Findings: {statistics['total_findings']}")
        
        whitelisted = statistics.get('whitelisted_findings', 0)
        false_positives = statistics.get('false_positives_filtered', 0)
        
        if whitelisted > 0:
            lines.append(f"Whitelisted: {whitelisted}")
        if false_positives > 0:
            lines.append(f"False positives filtered: {false_positives}")
        
        if statistics['total_findings'] > 0:
            lines.append("\nSeverity Breakdown:")
            for severity, count in statistics['severity_breakdown'].items():
                lines.append(f"  {severity}: {count}")
        
        return "\n".join(lines)


class ReporterFactory:
    """Factory for creating reporters"""
    
    _reporters = {
        'console': ConsoleReporter,
        'json': JSONReporter,
        'markdown': MarkdownReporter,
        'csv': CSVReporter,
        'summary': SummaryReporter
    }
    
    @classmethod
    def create(cls, reporter_type: str, **kwargs) -> Reporter:
        """
        Create a reporter instance
        
        Args:
            reporter_type: Type of reporter ('console', 'json', 'markdown', 'csv', 'summary')
            **kwargs: Additional arguments for the reporter
                      z.B. quiet=True, mask_secrets=False, pretty=False
        
        Returns:
            Reporter instance
        """
        reporter_class = cls._reporters.get(reporter_type.lower())
        
        if not reporter_class:
            raise ValueError(f"Unknown reporter type: {reporter_type}")
        
        return reporter_class(**kwargs)
    
    @classmethod
    def available_reporters(cls) -> List[str]:
        """Get list of available reporter types"""
        return list(cls._reporters.keys())
