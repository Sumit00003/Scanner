import argparse
from scanner import Scanner
from reporter import Reporter


def main():
    p = argparse.ArgumentParser(description="LibFinder - JS recon")
    p.add_argument("-u", "--url", required=True)
    p.add_argument("--json",     help="write JSON report")
    p.add_argument("--csv",      help="write CSV report")
    p.add_argument("--md",       help="write Markdown report")
    p.add_argument("--no-validate-secrets", action="store_true")
    args = p.parse_args()

    scanner = Scanner(validate_secrets=not args.no_validate_secrets)
    report = scanner.scan(args.url)

    rep = Reporter()
    rep.console_report(report)

    if args.json: rep.export_json(report, args.json)
    if args.csv:  rep.export_csv(report, args.csv)
    if args.md:   rep.export_markdown(report, args.md)


if __name__ == "__main__":
    main()
