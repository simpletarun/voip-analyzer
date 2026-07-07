# Database Schema

Storage is SQLite (WAL mode) under `data/voip_data.db`. The schema is created
and migrated automatically by `src/database/connection.py`.

## Tables

### `schema_version`
| Column | Type |
|--------|------|
| version | INTEGER (PK) |

### `sessions`
| Column | Type | Notes |
|--------|------|-------|
| id | INTEGER PK AUTOINCREMENT | |
| timestamp | TEXT NOT NULL | ISO-8601 UTC |
| duration_seconds | REAL | |
| total_packets | INTEGER | |
| total_bytes | INTEGER | |
| p2p_count | INTEGER | |
| relay_count | INTEGER | |
| unknown_count | INTEGER | |
| countries | TEXT | JSON-encoded list |
| protocol | TEXT | |
| notes | TEXT | |

Index: `idx_sessions_ts(timestamp)`.

### `peers`
| Column | Type | Notes |
|--------|------|-------|
| ip | TEXT PK | |
| isp / org / city / country | TEXT | |
| lat / lon | REAL | |
| asn | TEXT | |
| classification | TEXT | RELAY / P2P_PEER / USER / UNKNOWN |
| confidence | REAL | |
| first_seen / last_seen | TEXT | |
| packet_count / byte_count | INTEGER | |
| is_favorite | INTEGER | |
| notes | TEXT | |
| session_id | INTEGER | FK -> sessions(id) ON DELETE CASCADE |

Indexes: `idx_peers_country`, `idx_peers_isp`, `idx_peers_classification`,
`idx_peers_session`.

### `ip_cache`
| Column | Type | Notes |
|--------|------|-------|
| ip | TEXT PK | |
| data_json | TEXT | JSON of `IPInfo` |
| cached_at / expires_at | TEXT | |

Indexes: `idx_cache_expires`, `idx_cache_ip`.

### `settings`
| Column | Type |
|--------|------|
| key | TEXT PK |
| value | TEXT |

## Operations
* **Migrations** run on every connect (`_migrate`); new columns are added only
  if missing.
* **Backup**: `DatabaseConnection.backup(dest)` performs a hot copy.
* **Cache cleanup**: `CacheRepository.cleanup()` drops expired entries.
* **Retention**: `SessionRepository.delete_older_than(days)` enforces
  `data_retention_days`.
