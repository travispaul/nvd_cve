# nvd_cve
🔎 Search for CVEs against a local cached copy of NIST National Vulnerability Database (NVD).

[![Build and Run Tests](https://github.com/travispaul/nvd_cve/actions/workflows/build_and_test.yml/badge.svg)](https://github.com/travispaul/nvd_cve/actions/workflows/build_and_test.yml)

`nvd_cve` is a command-line utility and Rust module for syncing and searching the NIST National Vulnerability Database.
Its functionality attempts to be useful for vulnerability management tasks and automation efforts that utilize the CVE
data. A local cache can also be useful in event that the NIST NVD website or API is unreachable.

## Usage

### Command line usage

The `nvd_cve` command line application offers `sync` and `search` commands.

```
Search for CVEs against a local cached copy of NIST National Vulnerability Database (NVD).

USAGE:
    nvd_cve [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    help      Prints this message or the help of the given subcommand(s)
    search    Search for a CVE by ID in the local cache
    sync      Sync CVE feeds to local database
```

#### 🔃 Sync

Before you can search for CVEs you should perform a `sync` which will pull the data feeds and build a local cache in SQLite.

```
Sync CVE feeds to local database

USAGE:
    nvd_cve sync [FLAGS] [OPTIONS]

FLAGS:
    -f, --force           Ignore existing Metafiles and force update all feeds
    -h, --help            Prints help information
    -n, --no-progress     Don't show progress bar when syncing feeds
    -s, --show-default    Show default config values and exit
    -V, --version         Prints version information
    -v, --verbose         Print verbose logs (Set level with RUST_LOG)

OPTIONS:
    -d, --db <FILE>       Path to SQLite database where CVE feed data will be stored
    -l, --feeds <LIST>    Comma separated list of CVE feeds to fetch and sync, defaults to: all known feeds
    -u, --url <URL>       URL to use for fetching feeds, defaults to: https://nvd.nist.gov/feeds/json/cve/1.1
```

**Example:**

The initial database will take a few minutes to build, but subsequent runs
will be considerably faster as only modified feeds will be fetched and updated.

```
$ ./nvd_cve sync
[Feed: 2012] Fetching feed (1.97 MB)              [================------------------------]  42%
```

If the official NIST feeds are down or responding slowly you can use a [mirror](https://www.harmless.systems/mirror/nvd/index.html):

```
$ ./target/debug/nvd_cve sync -u https://www.harmless.systems/mirror/nvd/feeds/json/cve/1.1/    
[Feed: 2015] Fetching feed (2.10 MB)              [=======================-----------------]  59%
```

#### 🔎 Search

Search by a specific CVE or by some text within the description.

```
Search for a CVE by ID in the local cache

USAGE:
    nvd_cve search [FLAGS] [OPTIONS] [CVE]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information
    -v, --verbose    Print verbose logs (Set level with RUST_LOG)

OPTIONS:
    -d, --db <FILE>        Path to SQLite database where CVE feed data will be stored
    -t, --text <STRING>    Search the CVE descriptions instead.

ARGS:
    <CVE>    CVE ID to retrieve
```

**Examples:**

Search by CVE ID:
```
$ nvd_cve search CVE-2019-12780
{
  "data_type": "CVE",
  "data_format": "MITRE",
  "data_version": "4.0",
  "cve_data_meta": {
    "id": "CVE-2019-12780",
    "assigner": "cve@mitre.org"
  },
  "problem_type": {
    "problem_type_data": [
      {
        "description": [
          {
            "lang": "en",
            "value": "CWE-78"
          }
        ]
      }
    ]
  },
  "references": {
    "reference_data": [
      {
        "url": "https://www.exploit-db.com/exploits/46436",
        "name": "https://www.exploit-db.com/exploits/46436",
        "ref_source": "MISC",
        "tags": [
          "Exploit",
          "Third Party Advisory",
          "VDB Entry"
        ]
      }
    ]
  },
  "description": {
    "description_data": [
      {
        "lang": "en",
        "value": "The Belkin Wemo Enabled Crock-Pot allows command injection in the Wemo UPnP API via the SmartDevURL argument to the SetSmartDevInfo action. A simple POST request to /upnp/control/basicevent1 can allow an attacker to execute commands without authentication."
      }
    ]
  }
}
```

Search within CVE descriptions:

```
$ nvd_cve search -t Crock-Pot
CVE-2019-12780
```

### Module Usage

See the [examples](examples/) directory for how to use the crate programmatically.