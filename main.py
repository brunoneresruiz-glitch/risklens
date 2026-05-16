import argparse
import sys

from rich.console import Console
from rich.table import Table
from rich import box

from risklens.analyzer import analyze_url
from risklens.scorer import evaluate
from risklens.logger import log_result


console = Console()

SEVERITY_COLOURS = {
    "high":   "red",
    "medium": "yellow",
    "low":    "cyan",
}

VERDICT_COLOURS = {
    "HIGH RISK":   "bold red",
    "MEDIUM RISK": "bold yellow",
    "LOW RISK":    "bold cyan",
    "CLEAN":       "bold green",
}


def run(url: str) -> None:
    findings   = analyze_url(url)
    evaluation = evaluate(findings)
    log_result(findings, evaluation)

    _print_result(findings, evaluation)


def _print_result(findings: dict, evaluation: dict) -> None:
    verdict = evaluation["verdict"]
    signals = evaluation["signals"]

    console.print()

    info = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    info.add_column(style="dim", width=10)
    info.add_column()
    info.add_row("URL",    findings["url"])
    info.add_row("Domain", findings["domain"])
    info.add_row("HTTPS",  "Yes" if findings["is_https"] else "[red]No[/red]")
    console.print(info)

    colour = VERDICT_COLOURS.get(verdict, "white")
    console.print(f"  VERDICT  ─── [{colour}]{verdict}[/{colour}]\n")

    if not signals:
        console.print("  [green]No suspicious signals detected.[/green]\n")
        return

    console.print("  Signals detected:")
    for signal in signals:
        sev    = signal["severity"]
        colour = SEVERITY_COLOURS.get(sev, "white")
        label  = f"[{colour}][{sev.upper()}][/{colour}]"
        console.print(f"   {label:<30} {signal['description']}")

    console.print()
    console.print("  [dim]Log saved → logs/results.json[/dim]\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="phishguard",
        description="URL phishing analyser — flags suspicious signals and logs results.",
    )
    parser.add_argument("url", help="The URL to analyse")
    args = parser.parse_args()

    run(args.url)