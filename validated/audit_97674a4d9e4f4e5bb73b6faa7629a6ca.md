> Searching codebase... [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** storage/aptosdb/src/utils/iterators.rs (L333-373)
```rust
    fn next_impl(&mut self) -> Result<Option<(Version, IndexedTransactionSummary)>> {
        // If already iterated over `limit` transactions, return None.
        if self.count >= self.limit {
            return Ok(None);
        }

        Ok(match self.inner.next().transpose()? {
            Some(((address, version), txn_summary)) => {
                // No more transactions sent by this account.
                if address != self.address {
                    return Ok(None);
                }

                // This case ideally shouldn't occur if the iterator is initiated properly.
                if (self.direction == ScanDirection::Backward
                    && version > self.end_version.unwrap())
                    || (self.direction == ScanDirection::Forward
                        && version < self.start_version.unwrap())
                {
                    return Ok(None);
                }

                ensure!(
                    version == txn_summary.version(),
                    "DB corruption: version mismatch: version in key: {}, version in txn summary: {}",
                    version,
                    txn_summary.version(),
                );

                // No more transactions (in this view of the ledger).
                if version > self.ledger_version {
                    return Ok(None);
                }

                self.prev_version = Some(version);
                self.count += 1;
                Some((version, txn_summary))
            },
            None => None,
        })
    }
```

**File:** storage/aptosdb/src/transaction_store/mod.rs (L94-108)
```rust
        if start_version.is_some() {
            let mut iter = self
                .ledger_db
                .transaction_db_raw()
                .iter::<TransactionSummariesByAccountSchema>()?;
            iter.seek(&(address, start_version.unwrap()))?;
            Ok(AccountTransactionSummariesIter::new(
                iter,
                address,
                start_version,
                end_version,
                limit,
                ScanDirection::Forward,
                ledger_version,
            ))
```

**File:** api/src/transactions.rs (L400-450)
```rust
    /// If both start_version and end_version are not provided, the output consists of the summaries of
    /// most recent committed transaction from the account.
    ///
    /// The output always consists of transaction summaries ordered in ascending order by version.
    ///
    /// To retrieve a pending transaction, use /transactions/by_hash.
    #[oai(
        path = "/accounts/:address/transaction_summaries",
        method = "get",
        operation_id = "get_account_transaction_summaries",
        tag = "ApiTags::Transactions"
    )]
    async fn get_accounts_transaction_summaries(
        &self,
        accept_type: AcceptType,
        /// Address of account with or without a `0x` prefix
        address: Path<Address>,
        /// Transaction version to start list of transactions
        ///
        /// If not provided, defaults to showing the latest transactions
        start_version: Query<Option<U64>>,
        /// Transaction version to end list of transactions
        ///
        /// If not provided, defaults to showing the latest transactions
        end_version: Query<Option<U64>>,
        /// Max number of transactions to retrieve.
        ///
        /// If not provided, defaults to default page size
        limit: Query<Option<u16>>,
    ) -> BasicResultWith404<Vec<TransactionSummary>> {
        fail_point_poem("endpoint_get_accounts_transaction_summaries")?;
        self.context
            .check_api_output_enabled("Get account transaction summaries", &accept_type)?;
        let limit = if let Some(limit) = limit.0 {
            min(limit, self.context.max_transactions_page_size())
        } else {
            self.context.max_transactions_page_size()
        };
        let api = self.clone();
        api_spawn_blocking(move || {
            api.list_txn_summaries_by_account(
                &accept_type,
                address.0,
                start_version.0,
                end_version.0,
                limit,
            )
        })
        .await
    }

```

**File:** storage/db-tool/src/replay_on_archive.rs (L43-100)
```rust
#[derive(Parser)]
pub struct Opt {
    #[clap(
        long,
        help = "The first transaction version required to be replayed and verified"
    )]
    start_version: Version,

    #[clap(
        long,
        help = "The last transaction version required to be replayed and verified"
    )]
    end_version: Version,

    #[clap(flatten)]
    replay_concurrency_level: ReplayConcurrencyLevelOpt,

    #[clap(long = "target-db-dir", value_parser)]
    pub db_dir: PathBuf,

    #[clap(flatten)]
    pub rocksdb_opt: RocksdbOpt,

    #[clap(
        long,
        default_value = "500",
        help = "The number of transactions to be replayed in a chunk"
    )]
    pub chunk_size: usize,

    #[clap(long, default_value = "1", help = "The number of concurrent replays")]
    pub concurrent_replay: usize,

    #[clap(
        long,
        help = "The maximum time in seconds to wait for each transaction replay"
    )]
    pub timeout_secs: Option<u64>,

    #[clap(
        long,
        default_value_t = false,
        help = "Enable paranoid type checks in the Move VM"
    )]
    pub paranoid_type_checks: bool,
}

impl Opt {
    pub async fn run(self) -> Result<()> {
        let verifier = Verifier::new(&self)?;
        let all_errors = verifier.run()?;
        if !all_errors.is_empty() {
            error!("{} failed transactions", all_errors.len());
            for e in all_errors {
                error!("Failed: {}", e);
            }
            process::exit(2);
        }
```
