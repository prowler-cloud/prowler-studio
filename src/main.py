"""Main script to ingest Prowler findings and process them."""

from src.parser import load_findings
from src.agent import SecurityRemediationAgent


def main():
    """Load findings and process them with the remediation agent."""
    # Load all findings from the JSON file
    findings = load_findings("prowler_iam_findings.json")
    print(f"Loaded {len(findings)} findings\n")

    # Initialize the agent
    agent = SecurityRemediationAgent()

    # For now, just process the first finding
    finding = findings[0]

    print(f"\n{'='*80}")
    print(f"PROCESSING FINDING 1/{len(findings)}")
    print(f"{'='*80}")
    print(f"ID: {finding.finding_id}")
    print(f"Check: {finding.check_id}")
    print(f"Severity: {finding.severity}")
    print(f"Problem: {finding.problem}")
    print(f"{'='*80}\n")

    # Let the agent handle the remediation
    try:
        result = agent.remediate_finding(finding)

        print(f"\n{'='*80}")
        print("AGENT RESULT")
        print(f"{'='*80}")
        print(result)
        print(f"{'='*80}\n")
    except Exception as e:
        print(f"\n{'='*80}")
        print("ERROR")
        print(f"{'='*80}")
        print(f"Failed to process finding: {e}")
        print(f"{'='*80}\n")


if __name__ == "__main__":
    main()
