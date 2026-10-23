import os
import sys
os.environ["PHISHGUARD_WHOIS"] = "1" if "--whois" in sys.argv else "0"

import argparse
import csv
import random

from scorer import analyze_url, TRUSTED_DOMAINS


def load_phishing(path, n):
    with open(path, encoding="utf-8", errors="ignore") as f:
        urls = [line.strip() for line in f if line.strip().startswith(("http://", "https://"))]
    random.shuffle(urls)
    return urls[:n]


def load_legit(path, n):
    domains = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if len(row) < 2 or not row[0].isdigit():
                continue
            rank, domain = int(row[0]), row[1].strip().lower()
            # Skip the very top (our trusted list covers those) to make the test fair
            if 200 <= rank <= 20000 and domain not in TRUSTED_DOMAINS:
                domains.append("https://" + domain)
    random.shuffle(domains)
    return domains[:n]


def run(urls):
    return [analyze_url(u) for u in urls]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--phish", default="phishing.txt")
    ap.add_argument("--legit", default="tranco.csv")
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--whois", action="store_true")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    random.seed(args.seed)  # same sample every run, so results are comparable
    phish = run(load_phishing(args.phish, args.n))
    legit = run(load_legit(args.legit, args.n))

    # "Flagged" means yellow or red. "Strict" means red only.
    tp = sum(r["verdict"] != "green" for r in phish)
    fn = len(phish) - tp
    fp = sum(r["verdict"] != "green" for r in legit)
    tn = len(legit) - fp
    tp_red = sum(r["verdict"] == "red" for r in phish)
    fp_red = sum(r["verdict"] == "red" for r in legit)

    total = len(phish) + len(legit)
    print(f"\n=== PhishGuard results (domain-age check {'ON' if args.whois else 'off for speed'}) ===")
    print(f"Phishing URLs tested : {len(phish)}")
    print(f"Legitimate tested    : {len(legit)}\n")
    print(f"Detection rate (yellow or red) : {tp / max(len(phish), 1):.1%}")
    print(f"Detection rate (red only)      : {tp_red / max(len(phish), 1):.1%}")
    print(f"False positive rate (yellow+)  : {fp / max(len(legit), 1):.1%}")
    print(f"False positive rate (red only) : {fp_red / max(len(legit), 1):.1%}")
    print(f"Overall accuracy               : {(tp + tn) / max(total, 1):.1%}\n")
    print("               Predicted flagged | Predicted safe")
    print(f"Actual phish   {tp:>16} | {fn:>14}")
    print(f"Actual legit   {fp:>16} | {tn:>14}")

    print("\n--- Sample MISSED phishing URLs (look at these to improve rules) ---")
    for r in [r for r in phish if r["verdict"] == "green"][:10]:
        print(f"  {r['score']:>3}  {r['url'][:90]}")

    print("\n--- Sample FALSE POSITIVES (legit sites flagged) ---")
    for r in [r for r in legit if r["verdict"] != "green"][:10]:
        print(f"  {r['score']:>3}  {r['url'][:60]}  ->  {r['reasons'][0][:60]}")


if __name__ == "__main__":
    main()