# The Slowest CVE Aggregator
Simply an old-fashioned CLI tool in Rust that's here to help you easily and slowly find information about specific vulnerabilities using CVE ID.
This tool pulls data from:
- The NVD CVE Database
- EPSS (Exploit Prediction Scoring System)
- KEV (Known Exploited Vulnerabilities)

## Disclaimer
This code is not optimal, it is slow, but it works.
**TODO**
- Concurrent Requests with try_join! to fetch multiple resources in parallel.
- Error Handling improvements with descriptive messages.
- Memory Optimizations by avoiding unnecessary cloning.
- Graceful Error Handling and avoiding the use of unwrap().

## How to Run

1. **Clone the repository**:
   ```bash
   git clone git@github.com:krisinfosec/slowest_cve_aggregator.git
   cd slowest_cve_aggregator
   ```

2. **Install Rust**
If you don't have Rust installed, you can install it by following the instructions at https://www.rust-lang.org/tools/install.

3. **Run the program**
Run the following command to run the script (example CVEs):
```
cargo run --release -- CVE-2021-44228 CVE-2024–21538 CVE-2020-2883
```

4. **Results**
On its first run, the program will generate two files: known_exploited_vulnerabilities.json, which contains the current KEV vulnerabilities database, and CVE-Name.json, which stores the results gathered from CVE, EPSS, and KEV data. On subsequent runs, the program will check if the KEV database file is older than one day. If it is, the program will download the latest version of the data. Additionally, the program will display the results in the console.

5. **License**
This project is licensed under the GNU GENERAL PUBLIC LICENSE. [Link here|https://raw.githubusercontent.com/krisinfosec/slowest_cve_aggregator/refs/heads/main/LICENSE]

