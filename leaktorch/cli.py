import sys
import argparse
from pathlib import Path

from leaktorch import (
    SecretScanner,
    PatternRegistry,
    GitHandler,
    ReporterFactory,
    __version__
)


def create_parser() -> argparse.ArgumentParser:
    """Create and configure argument parser"""
    
    parser = argparse.ArgumentParser(
        prog='leaktorch',
        description='LeakTorch - Git Repository Secret Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan local repository
  leaktorch /path/to/repo
  
  # Scan remote repository
  leaktorch https://github.com/user/repo
  
  # Skip git history (faster scan)
  leaktorch /path/to/repo --no-history
  
  # Export to JSON
  leaktorch https://github.com/user/repo -o report.json
  
  # Export to Markdown
  leaktorch /path/to/repo -o report.md --format markdown
  
  # Verbose output with custom entropy threshold
  leaktorch /path/to/repo -v --entropy 5.0
  
  # Use whitelist file
  leaktorch /path/to/repo --whitelist .leaktorch-ignore
  
  # Include secrets in .gitignore files
  leaktorch /path/to/repo --include-gitignored
  
  # Show secrets unmasked (CAUTION!)
  leaktorch /path/to/repo --show-secrets
  
  # List all available patterns
  leaktorch --list-patterns

For more information: https://github.com/leaktorch/leaktorch
        """
    )
    
    parser.add_argument(
        'target',
        nargs='?',
        help='Local repository path or remote repository URL'
    )
    
    scan_group = parser.add_argument_group('Scanning Options')
    scan_group.add_argument(
        '--no-history',
        action='store_true',
        help='Skip git history scan (only scan current files)'
    )
    scan_group.add_argument(
        '--entropy',
        type=float,
        default=4.5,
        metavar='THRESHOLD',
        help='Entropy threshold for generic patterns (default: 4.5)'
    )
    scan_group.add_argument(
        '--include-gitignored',
        action='store_true',
        help='Include secrets found in .gitignore files'
    )
    scan_group.add_argument(
        '--max-file-size',
        type=int,
        default=1048576,
        metavar='BYTES',
        help='Maximum file size to scan in bytes (default: 1MB)'
    )
    scan_group.add_argument(
        '--whitelist',
        metavar='FILE',
        help='Path to whitelist file (default: .leaktorch-ignore)'
    )
    
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Export findings to file'
    )
    output_group.add_argument(
        '--format',
        choices=['json', 'markdown', 'csv', 'summary'],
        default='json',
        help='Output format for file export (default: json)'
    )
    output_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    output_group.add_argument(
        '--no-banner',
        action='store_true',
        help='Hide the banner'
    )
    output_group.add_argument(
        '--quiet',
        action='store_true',
        help='Minimal output (only show summary)'
    )
    output_group.add_argument(
        '--show-secrets',
        action='store_true',
        help='Show full secrets (not masked) - USE WITH CAUTION'
    )
    
    pattern_group = parser.add_argument_group('Pattern Management')
    pattern_group.add_argument(
        '--list-patterns',
        action='store_true',
        help='List all available detection patterns'
    )
    pattern_group.add_argument(
        '--severity',
        choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
        help='Only show findings of this severity level'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'LeakTorch {__version__}'
    )
    
    return parser


def list_patterns(pattern_registry: PatternRegistry):
    """List all available patterns"""
    print("\nAvailable Detection Patterns:")
    print("=" * 70)
    
    patterns = pattern_registry.get_all_patterns()
    
    by_severity = {}
    for name, config in patterns.items():
        if config.severity not in by_severity:
            by_severity[config.severity] = []
        by_severity[config.severity].append((name, config))
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if severity in by_severity:
            print(f"\n{severity} Severity:")
            print("-" * 70)
            
            for name, config in sorted(by_severity[severity]):
                desc = config.description if config.description else "No description"
                print(f"  • {name}")
                print(f"    {desc}")
    
    print(f"\nTotal patterns: {len(patterns)}")
    print()


def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    pattern_registry = PatternRegistry()
    
    if args.list_patterns:
        list_patterns(pattern_registry)
        sys.exit(0)
    
    if not args.target:
        parser.print_help()
        sys.exit(1)
    
    is_remote = GitHandler.is_remote_url(args.target)
    
    if not is_remote and not Path(args.target).exists():
        print(f"Error: Path does not exist: {args.target}")
        sys.exit(1)
    
    whitelist_file = args.whitelist or '.leaktorch-ignore'
    
    scanner = SecretScanner(
        pattern_registry=pattern_registry,
        entropy_threshold=args.entropy,
        scan_history=not args.no_history,
        verbose=args.verbose,
        ignore_gitignored=not args.include_gitignored,
        max_file_size=args.max_file_size,
        whitelist_file=whitelist_file if Path(whitelist_file).exists() else None
    )
    
    console_reporter = ReporterFactory.create(
        'console',
        show_banner=not args.no_banner,
        verbose=args.verbose,
        mask_secrets=not args.show_secrets
    )
    
    if not args.quiet and not args.no_banner:
        console_reporter.print_banner()
    
    try:
        if args.verbose:
            target_type = "remote repository" if is_remote else "local repository"
            print(f"Scanning {target_type}: {args.target}")
        
        findings = scanner.scan_repository(args.target, is_remote=is_remote)
        statistics = scanner.get_statistics()
        
        if args.severity:
            findings = scanner.get_findings_by_severity(args.severity)
            statistics['total_findings'] = len(findings)
        
        if args.quiet:
            console_reporter.print_summary(statistics)
        else:
            console_reporter.report(findings, statistics)
        
        if args.output:
            reporter = ReporterFactory.create(
                args.format,
                pretty=True,
                mask_secrets=not args.show_secrets
            )
            
            if args.format == 'json':
                reporter.save(findings, statistics, args.output)
            else:
                report_content = reporter.report(findings, statistics)
                with open(args.output, 'w') as f:
                    f.write(report_content)
            
            print(f"\n✓ Report exported to: {args.output}")
        
        exit_code = 1 if findings else 0
        
        if exit_code == 1 and not args.quiet:
            print("\n⚠ Exiting with code 1 (secrets detected)")
        
        sys.exit(exit_code)
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\nError: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
