#!/usr/bin/env python3
# Copyright (c) 2021 Axel Gembe <derago@gmail.com>
# Copyright 2018 Kevin M. Gallagher
# Copyright 2019,2020 Jeff Stein
#
# Based on https://github.com/jvstein/bitcoin-prometheus-exporter
# Published at https://github.com/EchterAgo/fulcrum-prometheus-exporter
# Licensed under BSD 3-clause (see LICENSE).

import json
import logging
import time
import os
import signal
import sys
import urllib

from datetime import datetime
from wsgiref.simple_server import make_server

from prometheus_client import make_wsgi_app, Gauge, Counter, Info

logger = logging.getLogger("fulcrum-exporter")


# Create Prometheus metrics to track Fulcrum stats.
BITCOIND_EXTANT_REQUEST_CONTEXTS = Gauge("fulcrum_bitcoind_extant_request_contexts", "Extant bitcoind request contexts")
BITCOIND_REQUEST_CONTEXT_TABLE_SIZE = Gauge(
    "fulcrum_bitcoind_request_context_table_size", "bitcoind request context table size")
BITCOIND_REQUEST_TIMEOUT_COUNT = Gauge("fulcrum_bitcoind_request_timeout_count", "bitcoind request timeout count")
BITCOIND_REQUEST_ZOMBIE_COUNT = Gauge("fulcrum_bitcoind_request_zombie_count", "bitcoind request zombie count")
BITCOIND_RPCCLIENT_COUNT = Gauge("fulcrum_bitcoind_rpcclient_count", "Number of bitcoind RPC clients in existence")


CONTROLLER_INFO = Info('fulcrum_controller', 'The chain and coin the controller runs on')
CONTROLLER_HEADER_COUNT = Gauge("fulcrum_controller_header_count", "Number of headers the controller knows about")
CONTROLLER_TX_NUM = Gauge("fulcrum_controller_tx_num", "Number of transactions the controller knows about")
CONTROLLER_UTXO_SET_COUNT = Gauge("fulcrum_controller_utxo_set_count", "Number of outputs in the UTXO set")
CONTROLLER_UTXO_SET_SIZE = Gauge("fulcrum_controller_utxo_set_size_mb", "Size of the UTXO set")
CONTROLLER_ZMQ_NOTIFICATION_COUNT = Gauge("fulcrum_controller_zmq_notification_count", "Number of ZMQ notifications received")
CONTROLLER_TASK_COUNT = Gauge("fulcrum_controller_task_count", "Number of controller tasks")


JEMALLOC_STATS_ACTIVE = Gauge("fulcrum_jemalloc_stats_active", "Jemalloc active bytes")
JEMALLOC_STATS_ALLOCATED = Gauge("fulcrum_jemalloc_stats_allocated", "Jemalloc allocated bytes")
JEMALLOC_STATS_MAPPED = Gauge("fulcrum_jemalloc_stats_mapped", "Jemalloc mapped bytes")
JEMALLOC_STATS_METADATA = Gauge("fulcrum_jemalloc_stats_metadata", "Jemalloc metadata bytes")
JEMALLOC_STATS_RESIDENT = Gauge("fulcrum_jemalloc_stats_resident", "Jemalloc resident bytes")
JEMALLOC_STATS_RETAINED = Gauge("fulcrum_jemalloc_stats_retained", "Jemalloc retained bytes")


MEMORY_USAGE_PHYSICAL_KB = Gauge("fulcrum_memory_usage_physical_kb", "Physical memory usage in kilobytes")
MEMORY_USAGE_VIRTUAL_KB = Gauge("fulcrum_memory_usage_virtual_kb", "Virtual memory usage in kilobytes")


JOB_QUEUE_EXTANT_JOBS = Gauge("fulcrum_job_queue_extant_jobs", "Number of jobs in the job queue")
JOB_QUEUE_EXTANT_JOBS_MAX_LIFETIME = Gauge("fulcrum_job_queue_extant_jobs_max_lifetime",
                                           "Maximum number of jobs in the job queue over the process's life time")
JOB_QUEUE_EXTANT_JOBS_LIMIT = Gauge("fulcrum_job_queue_extant_jobs_limit", "Limit for number of jobs in the job queue")
JOB_QUEUE_COUNT_LIFETIME = Gauge("fulcrum_job_queue_count_lifetime",
                                 "Number of jobs processed by the job queue over the process's life time")
JOB_QUEUE_OVERFLOWS_LIFETIME = Gauge("fulcrum_job_queue_overflows_lifetime",
                                     "Number of job queue overflows over the process's life time")
JOB_QUEUE_THREAD_COUNT_MAX = Gauge("fulcrum_job_queue_thread_count_max", "Maximum number of threads for the job queue")


SERVER_MANAGER_PEER_COUNT = Gauge("fulcrum_server_manager_peer_count", "Peer count", labelnames=["peertype"])
SERVER_MANAGER_SERVER_CLIENT_COUNT = Gauge("fulcrum_server_manager_server_client_count",
                                           "Client count by server type", labelnames=["servertype"])
SERVER_MANAGER_CLIENT_COUNT = Gauge("fulcrum_server_manager_client_count", "Client count")
SERVER_MANAGER_CLIENT_COUNT_MAX_LIFETIME = Gauge(
    "fulcrum_server_manager_client_count_max_lifetime", "Max client count over the process's life time")
SERVER_MANAGER_TOTAL_LIFETIME_CLIENTS = Gauge(
    "fulcrum_server_manager_total_lifetime_clients", "Total number of clients over the process's life time")
SERVER_MANAGER_TRANSACTIONS_SENT_COUNT = Gauge(
    "fulcrum_server_manager_transactions_sent_count", "Number of transactions sent using this server")
SERVER_MANAGER_TRANSACTIONS_SENT_SIZE_BYTES = Gauge(
    "fulcrum_server_manager_transactions_sent_size_bytes", "Size of the transactions sent using this server in bytes")


STORAGE_DB_SHARED_BLOCK_CACHE = Gauge("fulcrum_storage_db_shared_block_cache",
                                      "Storage shared block cache", labelnames=["type"])
STORAGE_DB_SHARED_WRITE_BUFFER_MANAGER = Gauge("fulcrum_storage_db_shared_write_buffer_manager",
                                               "Storage shared write buffer manager", labelnames=["type"])
STORAGE_DB_STATS_CUR_SIZE_ALL_MEM_TABLES_BYTES = Gauge("fulcrum_storage_db_stats_cur_size_all_mem_tables_bytes",
                                                       "Approximate size of active and unflushed immutable memtables in bytes", labelnames=["database"])
STORAGE_DB_STATS_ESTIMATE_TABLE_READERS_MEM_BYTES = Gauge("fulcrum_storage_db_stats_estimate_table_readers_mem_bytes",
                                                          "Estimated memory used for reading SST tables, excluding memory used in block cache (e.g., filter and index blocks) in bytes", labelnames=["database"])
STORAGE_CACHES_LRU_SIZE_BYTES = Gauge("fulcrum_storage_caches_lru_size_bytes",
                                      "LRU Cache size in bytes", labelnames=["cachetype"])
STORAGE_CACHES_LRU_ENTRY_COUNT = Gauge("fulcrum_storage_caches_lru_entry_count",
                                       "LRU Cache entry count", labelnames=["cachetype"])
STORAGE_CACHES_LRU_APPROX_HITS = Gauge("fulcrum_storage_caches_lru_approx_hits",
                                       "LRU Cache approximate hits", labelnames=["cachetype"])
STORAGE_CACHES_LRU_APPROX_MISSES = Gauge("fulcrum_storage_caches_lru_approx_misses",
                                         "LRU Cache approximate misses", labelnames=["cachetype"])
STORAGE_CACHES_MERKLEHEADERS = Gauge("fulcrum_storage_caches_merkleheaders", "Merkleheader cache size", labelnames=["type"])
STORAGE_MERGE_CALLS = Gauge("fulcrum_storage_merge_calls", "Merged storage calls")


SUBSMGR_ACTIVE_SUBS_COUNT = Gauge("fulcrum_subsmgr_active_subs_count", "Number of active client subscriptions")
SUBSMGR_UNIQUE_SCRIPTHASH_SUBS = Gauge("fulcrum_subsmgr_unique_subs_count",
                                       "Number of unique scripthashes subscribed (including zombies)")
SUBSMGR_PENDING_NOTIF_COUNT = Gauge("fulcrum_subsmgr_pending_notif_count", "Number of pending notifications")
SUBSMGR_SUBS_BUCKET_COUNT = Gauge("fulcrum_subsmgr_subs_bucket_count", "Number of subscription buckets")
SUBSMGR_SUBS_CACHE_HITS = Gauge("fulcrum_subsmgr_subs_cache_hits", "Number of subscription cache hits")
SUBSMGR_SUBS_CACHE_MISSES = Gauge("fulcrum_subsmgr_subs_cache_misses", "Number of subscription cache misses")
SUBSMGR_SUBS_LOAD_FACTOR = Gauge("fulcrum_subsmgr_subs_load_factor", "Subscription load factor")


EXPORTER_ERRORS = Counter("fulcrum_exporter_errors",
                          "Number of errors encountered by the exporter", labelnames=["type"])
PROCESS_TIME = Counter("fulcrum_exporter_process_time", "Time spent processing metrics from Fulcrum")


FULCRUM_STATS_URL = os.environ.get("FULCRUM_STATS_URL", "http://127.0.0.1:8080/stats")
METRICS_ADDR = os.environ.get("METRICS_ADDR", "")  # empty = any address
METRICS_PORT = int(os.environ.get("METRICS_PORT", "50039"))
RETRIES = int(os.environ.get("RETRIES", 5))
TIMEOUT = int(os.environ.get("TIMEOUT", 30))
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")


def refresh_metrics() -> None:
    with urllib.request.urlopen(FULCRUM_STATS_URL) as stats_json:
        stats = json.load(stats_json)

    daemon = stats["Bitcoin Daemon"]
    BITCOIND_EXTANT_REQUEST_CONTEXTS.set(daemon["extant request contexts"])
    BITCOIND_REQUEST_CONTEXT_TABLE_SIZE.set(daemon["request context table size"])
    BITCOIND_REQUEST_TIMEOUT_COUNT.set(daemon["request timeout count"])
    BITCOIND_REQUEST_ZOMBIE_COUNT.set(daemon["request zombie count"])
    BITCOIND_RPCCLIENT_COUNT.set(len(daemon["rpc clients"]))

    ctrl = stats["Controller"]
    CONTROLLER_INFO.info({"chain": ctrl["Chain"], "coin": ctrl["Coin"]})
    CONTROLLER_HEADER_COUNT.set(ctrl["Header count"])
    CONTROLLER_TX_NUM.set(ctrl["TxNum"])
    CONTROLLER_UTXO_SET_COUNT.set(ctrl["UTXO set"])
    CONTROLLER_UTXO_SET_SIZE.set(float(ctrl["UTXO set bytes"].split()[0]))
    CONTROLLER_ZMQ_NOTIFICATION_COUNT.set(sum(value["notifications"]
                                              for key, value in ctrl["ZMQ Notifiers (active)"].items()))
    CONTROLLER_TASK_COUNT.set(len(ctrl["tasks"]))

    if "Jemalloc" in stats:
        jas = stats["Jemalloc"]["stats"]
        JEMALLOC_STATS_ACTIVE.set(jas["active"])
        JEMALLOC_STATS_ALLOCATED.set(jas["allocated"])
        JEMALLOC_STATS_MAPPED.set(jas["mapped"])
        JEMALLOC_STATS_METADATA.set(jas["metadata"])
        JEMALLOC_STATS_RESIDENT.set(jas["resident"])
        JEMALLOC_STATS_RETAINED.set(jas["retained"])

    MEMORY_USAGE_PHYSICAL_KB.set(stats["Memory Usage"]["physical kB"])
    MEMORY_USAGE_VIRTUAL_KB.set(stats["Memory Usage"]["virtual kB"])

    jobq = stats["Misc"]["Job Queue (Thread Pool)"]
    JOB_QUEUE_EXTANT_JOBS.set(jobq["extant jobs"])
    JOB_QUEUE_EXTANT_JOBS_MAX_LIFETIME.set(jobq["extant jobs (max lifetime)"])
    JOB_QUEUE_EXTANT_JOBS_LIMIT.set(jobq["extant limit"])
    JOB_QUEUE_COUNT_LIFETIME.set(jobq["job count (lifetime)"])
    JOB_QUEUE_OVERFLOWS_LIFETIME.set(jobq["job queue overflows (lifetime)"])
    JOB_QUEUE_THREAD_COUNT_MAX.set(jobq["thread count (max)"])

    srvm = stats["Server Manager"]

    for peertype in ["bad", "failed", "peers", "queued"]:
        SERVER_MANAGER_PEER_COUNT.labels(peertype).set(len(srvm["PeerMgr"][peertype]))

    for servertype in ["AdminSrv", "SslSrv", "TcpSrv", "WsSrv", "WssSrv"]:
        servers = [value for key, value in srvm["Servers"].items() if key.startswith(servertype)]
        SERVER_MANAGER_SERVER_CLIENT_COUNT.labels(servertype).set(sum(s["numClients"] for s in servers))

    SERVER_MANAGER_CLIENT_COUNT.set(srvm["number of clients"])
    SERVER_MANAGER_CLIENT_COUNT_MAX_LIFETIME.set(srvm["number of clients (max lifetime)"])
    SERVER_MANAGER_TOTAL_LIFETIME_CLIENTS.set(srvm["number of clients (total lifetime connections)"])
    SERVER_MANAGER_TRANSACTIONS_SENT_COUNT.set(srvm["transactions sent"])
    SERVER_MANAGER_TRANSACTIONS_SENT_SIZE_BYTES.set(srvm["transactions sent (bytes)"])

    stor = stats["Storage"]
    STORAGE_DB_SHARED_BLOCK_CACHE.labels("capacity").set(stor["DB Shared Block Cache"]["capacity"])
    STORAGE_DB_SHARED_BLOCK_CACHE.labels("usage").set(stor["DB Shared Block Cache"]["usage"])
    STORAGE_DB_SHARED_WRITE_BUFFER_MANAGER.labels("buffersize").set(
        stor["DB Shared Write Buffer Manager"]["buffer size"])
    STORAGE_DB_SHARED_WRITE_BUFFER_MANAGER.labels("memoryusage").set(
        stor["DB Shared Write Buffer Manager"]["memory usage"])

    for database in ["blkinfo", "meta", "scripthash_history", "scripthash_unspent", "undo", "utxoset"]:
        STORAGE_DB_STATS_CUR_SIZE_ALL_MEM_TABLES_BYTES.labels(database).set(
            stor["DB Stats"][database]["rocksdb.cur-size-all-mem-tables"])
        STORAGE_DB_STATS_ESTIMATE_TABLE_READERS_MEM_BYTES.labels(database).set(
            stor["DB Stats"][database]["rocksdb.estimate-table-readers-mem"])

    STORAGE_CACHES_LRU_SIZE_BYTES.labels("blockheight2txhashes").set(
        stor["caches"]["LRU Cache: Block Height -> TxHashes"]["Size bytes"])
    STORAGE_CACHES_LRU_ENTRY_COUNT.labels("blockheight2txhashes").set(
        stor["caches"]["LRU Cache: Block Height -> TxHashes"]["nBlocks"])
    STORAGE_CACHES_LRU_APPROX_HITS.labels("blockheight2txhashes").set(
        stor["caches"]["LRU Cache: Block Height -> TxHashes"]["~hits"])
    STORAGE_CACHES_LRU_APPROX_MISSES.labels("blockheight2txhashes").set(
        stor["caches"]["LRU Cache: Block Height -> TxHashes"]["~misses"])

    STORAGE_CACHES_LRU_SIZE_BYTES.labels("txnum2txhash").set(stor["caches"]["LRU Cache: TxNum -> TxHash"]["Size bytes"])
    STORAGE_CACHES_LRU_ENTRY_COUNT.labels("txnum2txhash").set(stor["caches"]["LRU Cache: TxNum -> TxHash"]["nItems"])
    STORAGE_CACHES_LRU_APPROX_HITS.labels("txnum2txhash").set(stor["caches"]["LRU Cache: TxNum -> TxHash"]["~hits"])
    STORAGE_CACHES_LRU_APPROX_MISSES.labels("txnum2txhash").set(stor["caches"]["LRU Cache: TxNum -> TxHash"]["~misses"])

    STORAGE_CACHES_MERKLEHEADERS.labels("count").set(stor["caches"]["merkleHeaders_Size"])
    STORAGE_CACHES_MERKLEHEADERS.labels("bytes").set(stor["caches"]["merkleHeaders_SizeBytes"])

    STORAGE_MERGE_CALLS.set(stor["merge calls"])

    subm = stats["SubsMgr"]
    SUBSMGR_ACTIVE_SUBS_COUNT.set(subm["Num. active client subscriptions"])
    SUBSMGR_UNIQUE_SCRIPTHASH_SUBS.set(subm["Num. unique scripthashes subscribed (including zombies)"])
    SUBSMGR_PENDING_NOTIF_COUNT.set(len(subm["pendingNotifications"]))
    SUBSMGR_SUBS_BUCKET_COUNT.set(subm["subscriptions bucket count"])
    SUBSMGR_SUBS_CACHE_HITS.set(subm["subscriptions cache hits"])
    SUBSMGR_SUBS_CACHE_MISSES.set(subm["subscriptions cache misses"])
    SUBSMGR_SUBS_LOAD_FACTOR.set(subm["subscriptions load factor"])


def sigterm_handler(signal, frame) -> None:
    logger.critical("Received SIGTERM. Exiting.")
    sys.exit(0)


def exception_count(e: Exception) -> None:
    err_type = type(e)
    exception_name = err_type.__module__ + "." + err_type.__name__
    EXPORTER_ERRORS.labels(**{"type": exception_name}).inc()


def main():
    # Set up logging to look similar to bitcoin logs (UTC).
    logging.basicConfig(
        format="%(asctime)s %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%SZ"
    )
    logging.Formatter.converter = time.gmtime
    logger.setLevel(LOG_LEVEL)

    # Handle SIGTERM gracefully.
    signal.signal(signal.SIGTERM, sigterm_handler)

    app = make_wsgi_app()

    last_refresh = None

    def refresh_app(*args, **kwargs):
        nonlocal last_refresh
        process_start = datetime.now()

        if not last_refresh or (process_start - last_refresh).total_seconds() > 1: # Limit updates to every 1 seconds
            try:
                refresh_metrics()
            except Exception as e:
                logger.debug("Refresh failed", exc_info=True)
                exception_count(e)

            duration = datetime.now() - process_start
            PROCESS_TIME.inc(duration.total_seconds())
            logger.info("Refresh took %s seconds", duration)
            last_refresh = process_start

        return app(*args, **kwargs)

    httpd = make_server(METRICS_ADDR, METRICS_PORT, refresh_app)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
