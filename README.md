# cvemap
Navigate the CVE jungle with ease.

# Example
```console
 ✗ ./cvemap -p papercut_mf -f age
╭────────────────┬─────────┬──────┬──────────┬────────────────┬─────────────┬──────────┬───────────┬──────╮
│ CVE-ID         │    EPSS │ CVSS │ SEVERITY │ CWE            │ PRODUCT     │ VENDOR   │ STATUS    │  AGE │
├────────────────┼─────────┼──────┼──────────┼────────────────┼─────────────┼──────────┼───────────┼──────┤
│ CVE-2014-2657  │ 0.00251 │  7.5 │ HIGH     │ NVD-CWE-noinfo │ papercut_mf │ papercut │ MODIFIED  │ 3454 │
│ CVE-2014-2658  │ 0.00346 │    5 │ MEDIUM   │ NVD-CWE-noinfo │ papercut_mf │ papercut │ MODIFIED  │ 3454 │
│ CVE-2014-2659  │  0.0016 │  6.8 │ MEDIUM   │ CWE-352        │ papercut_mf │ papercut │ MODIFIED  │ 3460 │
│ CVE-2019-12135 │ 0.03442 │  9.8 │ CRITICAL │ NVD-CWE-noinfo │ papercut_mf │ papercut │ CONFIRMED │ 1589 │
│ CVE-2019-8948  │ 0.00256 │  9.8 │ CRITICAL │ CWE-74         │ papercut_mf │ papercut │ CONFIRMED │ 1695 │
│ CVE-2023-2533  │ 0.00074 │  8.8 │ HIGH     │ CWE-352        │ papercut_mf │ papercut │ MODIFIED  │  114 │
│ CVE-2023-27350 │ 0.97127 │  9.8 │ CRITICAL │ CWE-284        │ papercut_mf │ papercut │ MODIFIED  │  175 │
│ CVE-2023-27351 │ 0.00522 │  7.5 │ HIGH     │ CWE-287        │ papercut_mf │ papercut │ CONFIRMED │  175 │
│ CVE-2023-3486  │ 0.00081 │  7.5 │ HIGH     │ CWE-434        │ papercut_mf │ papercut │ CONFIRMED │   79 │
│ CVE-2023-39143 │ 0.89139 │  9.8 │ CRITICAL │ CWE-22         │ papercut_mf │ papercut │ CONFIRMED │   69 │
╰────────────────┴─────────┴──────┴──────────┴────────────────┴─────────────┴──────────┴───────────┴──────╯
```

### JSON Output
```console
✗ go run .  -p papercut_mf -nt -kev -j
[
  {
    "cve_id": "CVE-2023-27350",
    "severity": "critical",
    "cvss_score": 9.8,
    ...
  }
]
```

## Usage
```
OPTIONS:
   -id, -cve-id string[]           cve to list for given id
   -v, -vendor string[]            cve to list for given vendor
   -p, -product string[]           cve to list for given product
   -s, -severity string[]          cve to list for given severity
   -cs, -cvss-score string[]       cve to list for given cvss score
   -c, -cpe string                 cve to list for given cpe
   -es, -epss-score string[]       cve to list for given epss score
   -ep, -epss-percentile string[]  cve to list for given epss percentile
   -age string                     cve to list published by given age in days
   -a, -assignee string[]          cve to list for given publisher assignee
   -st, -status string             cve to list for given vulnerability status in cli output
   -r, -reference string[]         cve to list for given reference
   -k, -kev                        display cve for known exploitable vulnerabilities by cisa
   -nt, -nuclei-template           display cve having nuclei templates
   -poc                            display cve having poc
   -f, -field string[]             field to display in cli output (supported: assignee, age, kev, template, poc)
   -e, -exclude string[]           field to exclude from cli output
   -l, -limit int                  limit the number of results to display (default 100)
   -j, -json                       return output in json format
```
