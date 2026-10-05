# PcapAnalyzer
PcapAnalyzer reads packet captures (`.pcap` / `.pcapng`) and turns them into a report that explains what happened on the network: who talked to whom, what they requested, and whether anything looks like an attack. Drop your captures in a folder, run three scripts, and read one Markdown report.

## Quick start
```
git checkout dev
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# put your .pcap files in pcap_file/, then:
python pcap_scanner.py              # 1. every IP packet      -> Examples_Outputs/pcap_analyzed.txt
python breakdown_packets_scanner.py # 2. HTTP request detail  -> Examples_Outputs/pcap_http_analyzed.txt
python pcap_formatted.py --no-ai    # 3. final report         -> Better_Outputs/<capture>_report.md
```
You never have to name a capture file; each script processes whatever is in the folder. Step 3 works with no API key at all. See [Step 4](#step-4-get-api-access-and-credits) to add the optional Gemini narrative.

## What you get
The final report (`Better_Outputs/<capture>_report.md`) is written for someone who does not read packet dumps. For the bundled sample capture, `pcap_file/IT6300FE.pcap`, it reports two incidents:
- **SQL injection attempts:** one host sent payloads such as `uvu' or 'a'='a` to a web server's login forms.
- **Brute-force login attack:** another host sent 14 login requests in one second with the User-Agent `Mozilla/5.0 (Hydra)`, a password-guessing tool.

The report follows a standard security-assessment layout: a header table (subject, date, overall risk), executive summary, scope and methodology, summary-of-findings table, detailed findings (ID, severity, affected hosts, description, evidence, impact, recommendation), timeline, hosts involved, prioritized recommendations, limitations, and appendices with the traffic and HTTP statistics. [Details below.](#the-final-report-better_outputs)

## Repository layout
- `pcap_scanner.py` — Lists every IP packet (source, destination, protocol) in each capture.
- `breakdown_packets_scanner.py` — Extracts HTTP requests: time, method, URL, host, User-Agent, cookies (redacted), SQL injection flags.
- `pcap_formatted.py` — Combines the two reports above into the final report; optionally adds a Gemini-written narrative.
- `pcap_insights.py` — Parses the scanner reports and computes hosts, timelines and findings locally.
- `pcap_utils.py` — Shared folder discovery, report numbering and SQL injection patterns.
- `pcap_file/` — Your captures (input).
- `Examples_Outputs/` — Scanner reports.
- `Better_Outputs/` — Final reports.

## Two branches, two AI providers
This repo has two long-lived branches that each hold a complete, independent implementation of the AI step.

### Main branch: OpenAI
- The `main` branch uses OpenAI's API to generate explanations and solutions.
- `pcap_formatted.py` on that branch imports `openai` and reads `OPENAI_API_KEY` from your `.env` file.

### Dev branch: Gemini (this branch)
- The `dev` branch uses Google's Gemini. The AI step is optional here: the findings and tables are computed locally, and Gemini only adds a plain-language summary, timeline, extra recommendations and open questions.
- `pcap_formatted.py` on this branch uses the `google-genai` SDK and reads `GEMINI_API_KEY` from your `.env` file.

> IMPORTANT: `main` and `dev` are NOT meant to be merged together. They are two parallel implementations of the same tool, one per AI provider. Check out whichever branch matches the AI provider you want to use (`git checkout main` for OpenAI, `git checkout dev` for Gemini) and stay on it. The rest of this guide describes `dev`.

# Step-by-Step Setup Guide
Follow these steps in order the first time you set up the project on your own machine.

## Step 1: Pick your branch (OpenAI vs. Gemini)
- `main` -> uses **OpenAI**. Check it out with `git checkout main`.
- `dev` (this branch) -> uses **Gemini**. Check it out with `git checkout dev`.

Do not mix them: pick one provider, check out the matching branch, and do all your work there.

## Step 2: Clone the repository
```
git clone <repo-url>
cd PcapAnalyzer
git checkout dev   # or: git checkout main
```

## Step 3: Install dependencies
On this branch, install everything from the lockfile:
```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
That pulls in `scapy` (pcap parsing), `python-dotenv` (`.env` loading) and `google-genai` (the current Gemini SDK).

> Note: the old `google-generativeai` package is end-of-life and no longer receives updates. This branch uses `google-genai` instead. On `main` (OpenAI), install `openai` rather than either of these.

## Step 4: Get API access and credits
This step is **optional on `dev`**: without a key you still get the full local report (`--no-ai`). Do only the section for the provider matching the branch you checked out in Step 1.

### Gemini (for the `dev` branch)
1. Go to [Google AI Studio](https://aistudio.google.com/) and sign in with a Google account.
2. Click **Get API key** > **Create API key**, and either create a new Google Cloud project or attach it to an existing one.
3. Copy the generated key and store it somewhere safe.
4. **Enable the API on the key's project.** In the [Google Cloud Console](https://console.cloud.google.com/), select the project the key belongs to and enable the **Generative Language API** under **APIs & Services**. Without this, every request fails with `403 PERMISSION_DENIED / SERVICE_DISABLED`. The script prints that error, skips the AI narrative, and still writes the local report.
5. Gemini API usage is free up to a generous quota on the free tier. For higher rate limits, enable billing on the same project under **Billing**.

### OpenAI (for the `main` branch)
1. Go to https://platform.openai.com/ and sign up or log in.
2. Open the [Billing page](https://platform.openai.com/settings/organization/billing/overview) in your account settings and add a payment method, then purchase credits (OpenAI's chat completion API, including the `gpt-4` model used on the main branch, requires paid credits/a positive balance — free trial credit is no longer reliably available for new accounts).
3. Go to the [API Keys page](https://platform.openai.com/api-keys) and click **Create new secret key**.
4. Copy the generated key immediately and store it somewhere safe — OpenAI will not show it to you again.
5. Optionally set a usage limit/budget alert under Billing > Limits so you don't get an unexpectedly large bill.

## Step 5: Create your `.env` file
In the root of the repo, create a file named `.env` (it is already listed in `.gitignore`, so it will never be committed). Add only the lines that match your branch:
```
# dev branch (Gemini)
GEMINI_API_KEY=your_gemini_key_here

# optional: where the final reports go (default: ./Better_Outputs)
# output_folder_path=./Better_Outputs
# optional: where pcap_formatted.py looks for the scanner reports (default: ./Examples_Outputs)
# analyzed_folder_path=./Examples_Outputs

# optional: override the model (see "Model choice and cost" below)
# GEMINI_MODEL=gemini-3.1-flash-lite

# main branch (OpenAI)
OPENAI_API_KEY=your_openai_key_here
```

## Step 6: Folders
No code edits are required, and you never have to name a capture file. Drop your `.pcap` / `.pcapng` files into `pcap_file/` and the tools pick up whatever is there. Default folders are resolved from the repo root, so the tools work from any directory.
- `pcap_file/` — Your captures. Read by `pcap_scanner.py` and `breakdown_packets_scanner.py`.
- `Examples_Outputs/` — The scanners write their reports here, and `pcap_formatted.py` reads them from here.
- `Better_Outputs/` — `pcap_formatted.py` writes the finished reports here. Created automatically if missing.

## Step 7: Run the tools
The tools form a pipeline; run them in this order:
```
python pcap_scanner.py              # 1. every packet -> Examples_Outputs/pcap_analyzed*.txt
python breakdown_packets_scanner.py # 2. HTTP detail  -> Examples_Outputs/pcap_http_analyzed*.txt
python pcap_formatted.py            # 3. final report -> Better_Outputs/<capture>_report.md
```
Override the defaults with `--input-folder` / `--output-folder`. `pcap_scanner.py` also accepts one optional file path to analyze a single capture. Pass `--help` to any tool to see all options.

### Report file names
The scanner reports (steps 1 and 2) are never overwritten. Each capture found produces its own report, numbered in the order they are created:
```
Examples_Outputs/pcap_analyzed.txt        # first basic report
Examples_Outputs/pcap_analyzed002.txt     # next one, then 003, 004, ...
Examples_Outputs/pcap_http_analyzed.txt   # first HTTP breakdown report
Examples_Outputs/pcap_http_analyzed002.txt
```
The first line of every scanner report names the capture it came from. Because numbers keep increasing, re-running the scanners creates new reports; delete old ones from `Examples_Outputs/` when you no longer need them.

The final report in `Better_Outputs/` is named after the capture (`IT6300FE_report.md`) and is overwritten each time you re-run `pcap_formatted.py`. When several numbered scanner reports exist for one capture, it uses the newest of each kind.

## The final report (`Better_Outputs/`)
`pcap_formatted.py` does not re-read the raw capture. It reads the two analyzed files for each capture and turns them into one Markdown report:
- **Executive summary** and an **overall risk** rating, with a severity legend (High / Medium / Low / Informational).
- **Findings** with IDs (F-01, F-02, ...), each with severity, affected hosts, description, evidence, impact and a recommended fix. Current rules: attack tools in the User-Agent (Hydra, sqlmap, Nikto, ...), SQL injection indicators (URL-decoded), repeated POSTs to one endpoint, and unencrypted HTTP carrying cookies or logins.
- **Scope and methodology**, so a reader knows what was analyzed and how.
- **Timeline of events**: activity windows (who talked to whom, when, how many requests).
- **Hosts involved** with their role (web client / web server) and which ones attacked or were targeted.
- **Recommendations** in priority order, tied back to finding IDs.
- **Limitations**, so you know what the data cannot tell you.
- **Appendices** with the traffic breakdown and HTTP activity tables (protocols, busiest conversations, methods, sites, URLs, User-Agents).

Everything above except the narrative is computed locally and deterministically. Gemini only writes the executive summary, the plain-language timeline, extra recommendations and open questions, and it is told to use only the facts it is given. If it mentions an IP address that is not in your capture, its text is discarded.

**It works without AI.** With `--no-ai`, with no `GEMINI_API_KEY`, or if the API rejects the request, you still get the full report; the header says why the AI narrative is missing.
```
python pcap_formatted.py --no-ai    # free, fully offline
```

### Limits to keep in mind
- The findings are heuristics over text reports, not full packet inspection. SQL injection detection is substring matching on the URL-decoded request and can miss obfuscated payloads or flag harmless text.
- The HTTP scanner keeps only GET, PUT, POST and DELETE requests, so most server responses are absent. The report can show that an attack was attempted, but usually not whether it succeeded.
- Encrypted traffic (HTTPS) cannot be inspected; it only appears as TCP in the packet counts.
- Passwords and cookie values are redacted by the scanner.

## Model choice and cost
The AI step is built to stay cheap:
- **Endpoint traffic only.** The AI sees just HTTP requests to an endpoint (`GET`, `PUT`, `POST`, `DELETE`): methods, URLs, the hosts involved, activity windows and the rule-based findings. Packet-level data (protocol mix, non-HTTP hosts, conversations) is analyzed locally and never sent.
- **No endpoints, no AI call.** A capture with no such requests costs nothing; the report says the AI step was skipped.
- **The full capture is still inspected, without AI.** Every packet is analyzed locally and shown in the report's tables; only the narrative is AI-written.
- **One request per capture**, not per packet. It sends a compact digest of about 1,000 tokens instead of the raw packets.
- It defaults to `gemini-3.1-flash-lite`, Google's cheapest generally-available tier.
- "Thinking" is disabled, so you are never billed for reasoning tokens.
- Output is capped (`--max-output-tokens`, default 1400).

A typical capture costs a fraction of a cent. Every run prints the call count, token totals and an estimated USD cost.

To use a different model:
```
python pcap_formatted.py --model gemini-2.5-flash-lite
# or set GEMINI_MODEL in .env
```
If your project still has access to the legacy `gemini-2.5-flash-lite` ($0.10/$0.40 per 1M tokens), it is cheaper than the 3.x Flash-Lite default. Google closed that family to new projects, so it is not the default here. Check current rates at [ai.google.dev/gemini-api/docs/pricing](https://ai.google.dev/gemini-api/docs/pricing).

## Contributing:
Contributions to PcapAnalyzer are welcome! Feel free to submit bug reports, feature requests, or even pull requests to enhance the functionality of this pcap analysis toolkit.
