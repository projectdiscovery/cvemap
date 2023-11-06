<h1 align="center">CVEMap</h1>

<p align="center">
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-_red.svg"></a>
<a href="https://goreportcard.com/badge/github.com/projectdiscovery/cvemap"><img src="https://goreportcard.com/badge/github.com/projectdiscovery/cvemap"></a>
<a href="https://pkg.go.dev/github.com/projectdiscovery/cvemap/pkg/cvemap"><img src="https://img.shields.io/badge/go-reference-blue"></a>
<a href="https://github.com/projectdiscovery/cvemap/releases"><img src="https://img.shields.io/github/release/projectdiscovery/cvemap"></a>
<a href="https://twitter.com/pdiscoveryio"><img src="https://img.shields.io/twitter/follow/pdiscoveryio.svg?logo=twitter"></a>
<a href="https://discord.gg/projectdiscovery"><img src="https://img.shields.io/discord/695645237418131507.svg?logo=discord"></a>
</p>
<p align="center">
  <a href="#features">Features</a> •
  <a href="#installation">Installation</a> •
  <a href="#usage">Usage</a> •
  <a href="#examples">Example</a> •
  <a href="https://discord.gg/projectdiscovery">Join Discord</a>
</p>

Navigate the Common Vulnerabilities and Exposures (CVE) jungle with ease using CVEMAP, a command-line interface (CLI) tool designed to provide a structured and easily navigable interface to various vulnerability databases.

   
# Features

![image](static/cvemap.png)

 - **CVE Dataset (NIST)**
 - **Mapping of CVE to EPSS**
 - **Mapping of CVE to KEV**
 - **Mapping of CVE to HackerOne**
 - **Mapping of CVE to CPE**
 - **Mapping of CVE to Nuclei Template**
 - **Mapping of CVE to GitHub POCs**
 - Customizable Filters
 - STDIN Input / JSONL Output


## Installation

cvemap requires **Go 1.21** to install successfully. To install, just run the below command or download pre-compiled binary from [release page](https://github.com/projectdiscovery/cvemap/releases).

```console
go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest
```

## Usage
```console
cvemap -h
```
This will display help for the tool. Here are all the switches it supports.

```console
Usage:
  cvemap [flags]

Flags:
INPUT:
   -id string[]                    cve to list for given id

OPTIONS:
   -v, -vendor string[]            cve to list for given vendor
   -p, -product string[]           cve to list for given product
   -s, -severity string[]          cve to list for given severity
   -cs, -cvss-score string[]       cve to list for given cvss score
   -c, -cpe string                 cve to list for given cpe
   -es, -epss-score string         cve to list for given epss score
   -ep, -epss-percentile string[]  cve to list for given epss percentile
   -age string                     cve to list published by given age in days
   -a, -assignee string[]          cve to list for given publisher assignee
   -vs, -vstatus value             cve to list for given vulnerability status in cli output. supported: new, confirmed, unconfirmed, modified, rejected, unknown

UPDATE:
   -up, -update                 update cvemap to latest version
   -duc, -disable-update-check  disable automatic cvemap update check

FILTER:
   -k, -kev         display cves marked as exploitable vulnerabilities by cisa (default true)
   -t, -template    display cves that has public nuclei templates (default true)
   -poc             display cves that has public published poc (default true)
   -h1, -hackerone  display cves reported on hackerone (default true)

OUTPUT:
   -f, -field value     fields to display in cli output. supported: age, template, poc, assignee, product, vendor, vstatus, kev, cwe, epss
   -fe, -exclude value  fields to exclude from cli output. supported: age, template, poc, assignee, product, vendor, vstatus, kev, cwe, epss
   -l, -limit int       limit the number of results to display (default 50)
   -j, -json            return output in json format

DEBUG:
   -version  Version
   -silent   Silent
   -verbose  Verbose
```

## Examples

As default, cvemap list all the known exploited vulnerabilities based cves published by [cisa](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).

List top known exploited vulnerabilities:

```console
$ cvemap -limit 10


   ______   _____  ____ ___  ____  ____
  / ___/ | / / _ \/ __ \__ \/ __ \/ __ \
 / /__ | |/ /  __/ / / / / / /_/ / /_/ /
 \___/ |___/\___/_/ /_/ /_/\__,_/ .___/ 
                               /_/
                 

      projectdiscovery.io

╭────────────────┬──────┬──────────┬─────────┬────────────────────────┬──────────┬─────╮
│ ID             │ CVSS │ SEVERITY │    EPSS │ PRODUCT                │ TEMPLATE │ AGE │
├────────────────┼──────┼──────────┼─────────┼────────────────────────┼──────────┼─────┤
│ CVE-2023-5631  │  5.4 │ MEDIUM   │ 0.00986 │ webmail                │ ❌       │  18 │
│ CVE-2023-5217  │  8.8 │ HIGH     │ 0.26047 │ libvpx                 │ ❌       │  38 │
│ CVE-2023-4966  │  7.5 │ HIGH     │ 0.92267 │ netscaler_application  │ ✅       │  26 │
│ CVE-2023-4863  │  8.8 │ HIGH     │  0.4101 │ chrome                 │ ❌       │  54 │
│ CVE-2023-46748 │  8.8 │ HIGH     │ 0.00607 │                        │ ❌       │  10 │
│ CVE-2023-46747 │  9.8 │ CRITICAL │ 0.95304 │                        │ ✅       │  10 │
│ CVE-2023-46604 │   10 │ CRITICAL │ 0.01596 │                        │ ✅       │   9 │
│ CVE-2023-44487 │  7.5 │ HIGH     │ 0.52748 │ http                   │ ❌       │  26 │
│ CVE-2023-42824 │  7.8 │ HIGH     │ 0.00062 │ ipados                 │ ❌       │  32 │
│ CVE-2023-42793 │  9.8 │ CRITICAL │ 0.97264 │ teamcity               │ ✅       │  47 │
╰────────────────┴──────┴──────────┴─────────┴────────────────────────┴──────────┴─────╯
```

List top cves being reported on hackerone platform using `-h1` or `-hackerone` option.

```console
$ cvemap -h1

   ______   _____  ____ ___  ____  ____
  / ___/ | / / _ \/ __ \__ \/ __ \/ __ \
 / /__ | |/ /  __/ / / / / / /_/ / /_/ /
 \___/ |___/\___/_/ /_/ /_/\__,_/ .___/ 
                               /_/
      projectdiscovery.io

╭────────────────┬──────┬──────────┬──────┬─────────┬───────────────────────┬──────────┬──────╮
│ CVE            │ CVSS │ SEVERITY │ RANK │ REPORTS │ PRODUCT               │ TEMPLATE │  AGE │
├────────────────┼──────┼──────────┼──────┼─────────┼───────────────────────┼──────────┼──────┤
│ CVE-2020-35946 │  5.4 │ MEDIUM   │    1 │     304 │ all_in_one_seo_pack   │ ❌       │ 1038 │
│ CVE-2023-4966  │  7.5 │ HIGH     │    2 │      54 │ netscaler_application │ ✅       │   26 │
│ CVE-2023-22518 │  9.1 │ CRITICAL │    3 │      27 │                       │ ✅       │    5 │
│ CVE-2017-15277 │  6.5 │ MEDIUM   │    4 │    1139 │ graphicsmagick        │ ❌       │ 2215 │
│ CVE-2023-35813 │  9.8 │ CRITICAL │    5 │      54 │ experience_commerce   │ ✅       │  141 │
│ CVE-2022-38463 │  6.1 │ MEDIUM   │    6 │     342 │ servicenow            │ ✅       │  439 │
│ CVE-2020-11022 │  6.1 │ MEDIUM   │    7 │     209 │ jquery                │ ❌       │ 1285 │
│ CVE-2020-11023 │  6.1 │ MEDIUM   │    8 │     208 │ jquery                │ ❌       │ 1285 │
│ CVE-2023-38205 │  7.5 │ HIGH     │    9 │     162 │ coldfusion            │ ✅       │   52 │
│ CVE-2019-11358 │  6.1 │ MEDIUM   │   10 │     214 │ jquery                │ ❌       │ 1660 │
╰────────────────┴──────┴──────────┴──────┴─────────┴───────────────────────┴──────────┴──────╯
```

cvemap provide multiple ways to query cve data i.e by `product`, `vendor`, `severity`, `cpe`, `assignee`, `cvss-score`, `epss-score`, `age` etc, for example:

List all the cves published for Jira product:

```console
cvemap -product confluence -l 5 -silent
╭───────────────┬──────┬──────────┬─────────┬────────────┬──────────╮
│ ID            │ CVSS │ SEVERITY │    EPSS │ PRODUCT    │ TEMPLATE │
├───────────────┼──────┼──────────┼─────────┼────────────┼──────────┤
│ CVE-2020-4027 │  4.7 │ MEDIUM   │ 0.00105 │ confluence │ ❌       │
│ CVE-2019-3398 │  8.8 │ HIGH     │ 0.97342 │ confluence │ ✅       │
│ CVE-2019-3396 │  9.8 │ CRITICAL │ 0.97504 │ confluence │ ✅       │
│ CVE-2019-3395 │  9.8 │ CRITICAL │ 0.07038 │ confluence │ ❌       │
│ CVE-2019-3394 │  8.8 │ HIGH     │  0.1885 │ confluence │ ❌       │
╰───────────────┴──────┴──────────┴─────────┴────────────┴──────────╯
```

As default, cvemap display default / limit fields which can be custizmed and controoled using `-field`/ `-f` option, for example:

```console
$ cvemap -silent -severity critical -field assignee,vstatus,poc -l 5
╭───────────────┬──────┬──────────┬─────────┬──────────────────┬──────────┬────────────────────────┬─────────────┬───────╮
│ ID            │ CVSS │ SEVERITY │    EPSS │ PRODUCT          │ TEMPLATE │ ASSIGNEE               │ VSTATUS     │ POC   │
├───────────────┼──────┼──────────┼─────────┼──────────────────┼──────────┼────────────────────────┼─────────────┼───────┤
│ CVE-2023-5843 │    9 │ CRITICAL │ 0.00053 │                  │ ❌       │ security@wordfence.com │ UNCONFIRMED │ FALSE │
│ CVE-2023-5832 │  9.1 │ CRITICAL │ 0.00043 │                  │ ❌       │ security@huntr.dev     │ UNCONFIRMED │ FALSE │
│ CVE-2023-5824 │  9.6 │ CRITICAL │ 0.00045 │                  │ ❌       │ secalert@redhat.com    │ UNCONFIRMED │ FALSE │
│ CVE-2023-5820 │  9.6 │ CRITICAL │ 0.00047 │                  │ ❌       │ security@wordfence.com │ UNCONFIRMED │ FALSE │
│ CVE-2023-5807 │  9.8 │ CRITICAL │ 0.00076 │ education_portal │ ❌       │ cve@usom.gov.tr        │ CONFIRMED   │ FALSE │
╰───────────────┴──────┴──────────┴─────────┴──────────────────┴──────────┴────────────────────────┴─────────────┴───────╯
```

To list cves with matching threshold like, CVSS score or EPSS Score / Percentile, below options can be used:

```console
$ cvemap -silent -cs '> 7' -es '> 0.00053' -l 5
╭───────────────┬──────┬──────────┬─────────┬───────────────────────────────────────┬──────────╮
│ ID            │ CVSS │ SEVERITY │    EPSS │ PRODUCT                               │ TEMPLATE │
├───────────────┼──────┼──────────┼─────────┼───────────────────────────────────────┼──────────┤
│ CVE-2023-5860 │  7.2 │ HIGH     │ 0.00132 │                                       │ ❌       │
│ CVE-2023-5843 │    9 │ CRITICAL │ 0.00053 │                                       │ ❌       │
│ CVE-2023-5807 │  9.8 │ CRITICAL │ 0.00076 │ education_portal                      │ ❌       │
│ CVE-2023-5804 │  9.8 │ CRITICAL │ 0.00063 │ nipah_virus_testing_management_system │ ❌       │
│ CVE-2023-5802 │  8.8 │ HIGH     │ 0.00058 │ wp_knowledgebase                      │ ❌       │
╰───────────────┴──────┴──────────┴─────────┴───────────────────────────────────────┴──────────╯
```

To filter cves to match with specifc conditions like, cves has public poc or template and in the list of kev, belows options can beused:

```console
$ cvemap -silent -template=false -poc=true -kev=true -l 5 -f poc,kev
╭────────────────┬──────┬──────────┬─────────┬─────────┬──────────┬──────┬──────╮
│ ID             │ CVSS │ SEVERITY │    EPSS │ PRODUCT │ TEMPLATE │ POC  │ KEV  │
├────────────────┼──────┼──────────┼─────────┼─────────┼──────────┼──────┼──────┤
│ CVE-2023-5631  │  5.4 │ MEDIUM   │ 0.00986 │ webmail │ ❌       │ TRUE │ TRUE │
│ CVE-2023-5217  │  8.8 │ HIGH     │ 0.26047 │ libvpx  │ ❌       │ TRUE │ TRUE │
│ CVE-2023-4863  │  8.8 │ HIGH     │  0.4101 │ chrome  │ ❌       │ TRUE │ TRUE │
│ CVE-2023-44487 │  7.5 │ HIGH     │ 0.52748 │ http    │ ❌       │ TRUE │ TRUE │
│ CVE-2023-41993 │  9.8 │ CRITICAL │ 0.00617 │ safari  │ ❌       │ TRUE │ TRUE │
╰────────────────┴──────┴──────────┴─────────┴─────────┴──────────┴──────┴──────╯
```

### JSON Output

```bash
cvemap -product papercut_mf -t -kev -j
```

```json
[
  {
    "cve_id": "CVE-2023-27350",
    "cve_description": "This vulnerability allows remote attackers to bypass authentication on affected installations of PaperCut NG 22.0.5 (Build 63914). Authentication is not required to exploit this vulnerability. The specific flaw exists within the SetupCompleted class. The issue results from improper access control. An attacker can leverage this vulnerability to bypass authentication and execute arbitrary code in the context of SYSTEM. Was ZDI-CAN-18987.",
    "severity": "critical",
    "cvss_score": 9.8,
    "cvss_metrics": {
      "cvss30": {
        "score": 9.8,
        "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical"
      },
      "cvss31": {
        "score": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "severity": "critical"
      }
    },
    "weaknesses": [
      {
        "cwe_id": "NVD-CWE-Other"
      },
      {
        "cwe_id": "CWE-284",
        "cwe_name": "Improper Access Control"
      }
    ],
    "epss": {
      "epss_score": 0.97156,
      "epss_percentile": 0.99735
    },
    "cpe": {
      "cpe": "cpe:2.3:a:papercut:papercut_mf:*:*:*:*:*:*:*:*",
      "vendor": "papercut",
      "product": "papercut_mf"
    },
    "reference": [
      "http://packetstormsecurity.com/files/171982/PaperCut-MF-NG-Authentication-Bypass-Remote-Code-Execution.html",
      "http://packetstormsecurity.com/files/172512/PaperCut-NG-MG-22.0.4-Remote-Code-Execution.html",
      "http://packetstormsecurity.com/files/172780/PaperCut-PaperCutNG-Authentication-Bypass.html",
      "https://news.sophos.com/en-us/2023/04/27/increased-exploitation-of-papercut-drawing-blood-around-the-internet/",
      "https://www.papercut.com/kb/Main/PO-1216-and-PO-1219",
      "https://www.zerodayinitiative.com/advisories/ZDI-23-233/"
    ],
    "poc": [
      {
        "url": "https://github.com/Jenderal92/CVE-2023-27350",
        "source": "github-lhc",
        "added_at": "2023-07-02"
      },
      {
        "url": "https://github.com/0ximan1337/CVE-2023-27350-POC",
        "source": "github-lhc",
        "added_at": "2023-07-02"
      }
    ],
    "vendor_advisory": "https://www.papercut.com/kb/Main/PO-1216-and-PO-1219",
    "is_template": true,
    "nuclei_templates": {
      "template_url": "https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2023/CVE-2023-27350.yaml"
    },
    "is_exploited": true,
    "kev": {
      "added_date": "2023-04-21",
      "due_date": "2023-05-12"
    },
    "assignee": "zdi-disclosures@trendmicro.com",
    "published_at": "2023-04-20T16:15:07.653",
    "updated_at": "2023-06-07T18:15:09.540",
    "activity": {
      "rank": 0,
      "count": 0
    },
    "hackerone": {
      "rank": 6066,
      "count": 0
    },
    "age_in_days": 199,
    "vuln_status": "modified",
    "is_poc": true,
    "is_remote": true,
    "vulnerable_cpe": [
      "cpe:2.3:a:papercut:papercut_mf:*:*:*:*:*:*:*:*",
      "cpe:2.3:a:papercut:papercut_ng:*:*:*:*:*:*:*:*"
    ],
    "shodan": {
      "count": 4074,
      "query": [
        "http.html:\"PaperCut\"",
        "cpe:\"cpe:2.3:a:papercut:papercut_mf\""
      ]
    }
  }
]
```

## Notes

- CVE dataset gets updated daily.
- Data accuracy is based on source information.

## Acknowledgements

- **[National Vulnerability Database (NVD)](https://nvd.nist.gov/developers)**: Comprehensive CVE vulnerability data.
- **[Known Exploited Vulnerabilities Catalog (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)**: Exploited vulnerabilities catalog.
- **[Exploit Prediction Scoring System (EPSS)](https://www.first.org/epss/data_stats)**: Exploit prediction scores.
- **[HackerOne](https://hackerone.com/hacktivity/cve_discovery)**: CVE discoveries disclosure.
- **[Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)**: Vulnerability validation templates.
- **[Live-Hack-CVE](https://github.com/Live-Hack-CVE/) / [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub/)** GitHub Repository: Vulnerability PoCs references.
--------

<div align="center">

**cvemap** is made with ❤️ by the [projectdiscovery](https://projectdiscovery.io) team and distributed under [MIT License](LICENSE).

   
<a href="https://discord.gg/projectdiscovery"><img src="https://raw.githubusercontent.com/projectdiscovery/nuclei-burp-plugin/main/static/join-discord.png" width="300" alt="Join Discord"></a>