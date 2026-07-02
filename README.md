# fluent-plugin-log-signature

[Fluentd](https://fluentd.org/) filter plugin for HMAC-SM3 log integrity signing.

## Overview

A Fluentd filter plugin that generates HMAC-SM3 signatures for log records. It concatenates values from configurable record fields, signs them with a secret fetched from a DES key management service, and attaches the resulting signature to each record — useful for log integrity verification and tamper detection.

### How It Works

1. Sorts the configured `keys` alphabetically
2. Concatenates their record values with the configured `delimiter`
3. Fetches a signing secret from the DES service (cached; pre-fetched at startup with 3 retries)
4. Computes HMAC-SM3 over the concatenated string
5. Attaches `signature` to the record (with optional `version_prefix`)

If the DES service is unreachable, records pass through without a signature — no data loss.

## Configuration

| Parameter | Type | Default | Required | Description |
|-----------|------|---------|----------|-------------|
| `keys` | array(string) | — | yes | Record fields to concatenate (sorted alphabetically) |
| `delimiter` | string | `&` | no | Separator between field values |
| `des_url` | string | — | yes | DES key management service endpoint (POST) |
| `secret_name` | string | `''` | no | Secret name to request from the DES service |
| `auth` | string | `''` | no | Base64-encoded `Authorization` header |
| `sign_log_print` | bool | `false` | no | Enable debug logging of values and signature |
| `version_prefix` | string | `''` | no | Signature prefix (e.g. `v1` → `v1-<hex>`) |

### Example

```
<filter example.**>
  @type log_signature
  keys timestamp,message,level
  delimiter |
  des_url http://des.internal:8080/api/getSecret
  secret_name my-secret
  auth QmFzaWMgWTJ4ekxYTnBaMjVsY2pwemRHRmphMVkxUUdNeGN5RT0=
  version_prefix v1
</filter>
```

Input:
```json
{"timestamp":"1691377710","message":"login attempt","level":"info"}
```

Output:
```json
{"timestamp":"1691377710","message":"login attempt","level":"info","signature":"v1-e3aef099fe612c04844430e7e8b959c2fe31685576ea72ae416b18f840b60a8a"}
```

## Installation

### RubyGems

```
$ gem install fluent-plugin-log-signature
```

### Bundler

Add following line to your Gemfile:

```ruby
gem "fluent-plugin-log-signature"
```

And then execute:

```
$ bundle
```

## Configuration

You can generate configuration template:

```
$ fluent-plugin-config-format filter log-signature
```

See [Configuration](#configuration) above for all available parameters and usage examples.

## Copyright

* Copyright(c) 2023- wang.zhe
* License
  * Apache License, Version 2.0
