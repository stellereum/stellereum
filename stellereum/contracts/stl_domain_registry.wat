(module
  ;; Host functions provided by SVM
  (import "host" "sload" (func $sload (param i64) (result i64)))
  (import "host" "sstore" (func $sstore (param i64 i64)))
  (import "host" "emit" (func $emit (param i64 i64)))

  ;; Storage Layout:
  ;; Global config:
  ;; Slot 0: Treasury Account ID
  ;; Slot 1: Auction Base Duration in seconds (e.g. 3600s = 1hr in testnet, 604800s = 7d in mainnet)
  ;; Slot 2: Anti-sniping prolongation window (e.g. 600s = 10 min)
  ;; Slot 3: Minimum bid increment BPS (500 = 5%)
  ;;
  ;; Per-Domain State (Base = 1000 * domain_id):
  ;; base + 0: status (0 = Available, 1 = Auction, 2 = Active/Owned, 3 = Expired)
  ;; base + 1: owner_id (highest bidder during auction, or confirmed owner)
  ;; base + 2: highest_bid (nano-STELL)
  ;; base + 3: auction_end (timestamp)
  ;; base + 4: target_address_id (resolved address)
  ;; base + 5: expires_at (ownership expiry timestamp)
  ;; base + 6: card_hue (deterministic color hue 0..360)
  ;; base + 7: length (characters count)

  ;; Event Topics:
  ;; Topic 30: Auction Started (domain_id)
  ;; Topic 31: Outbid Refund (previous_bid)
  ;; Topic 32: New Highest Bid (new_bid)
  ;; Topic 33: Domain Registered / Finalized (domain_id)
  ;; Topic 34: Target Resolved Updated (new_target)
  ;; Topic 35: Domain Transferred (new_owner)
  ;; Topic 36: Domain Renewed (new_expiry)

  ;; 1. Initialize Registry: init(treasury_id) -> returns treasury_id
  (func (export "init") (param $treasury_id i64) (result i64)
    (call $sstore (i64.const 0) (local.get $treasury_id))
    (call $sstore (i64.const 1) (i64.const 3600))  ;; 1 hour auction duration for testnet
    (call $sstore (i64.const 2) (i64.const 600))   ;; 10 minutes anti-sniping extension
    (call $sstore (i64.const 3) (i64.const 500))   ;; 5% (500 bps) minimum bid step
    (local.get $treasury_id)
  )

  ;; Helper: calculate minimum bid by domain length
  ;; Length must be at least 4 and at most 126 characters (TEP-81 / TON DNS standard)
  ;; 4 chars:  200 STELL (200,000,000,000 nano)
  ;; 5 chars:   75 STELL ( 75,000,000,000 nano)
  ;; 6 chars:   50 STELL ( 50,000,000,000 nano)
  ;; 7 chars:   25 STELL ( 25,000,000,000 nano)
  ;; 8 chars:   20 STELL ( 20,000,000,000 nano)
  ;; 9 chars:   15 STELL ( 15,000,000,000 nano)
  ;; 10 chars:  10 STELL ( 10,000,000,000 nano)
  ;; 11+ chars:  5 STELL (  5,000,000,000 nano)
  (func $min_bid_for_len (param $len i64) (result i64)
    ;; Reject if length < 4 or length > 126
    (if (i32.or (i64.lt_u (local.get $len) (i64.const 4)) (i64.gt_u (local.get $len) (i64.const 126)))
      (then (unreachable))
    )
    (if (i64.eq (local.get $len) (i64.const 4))
      (then (return (i64.const 200000000000)))
    )
    (if (i64.eq (local.get $len) (i64.const 5))
      (then (return (i64.const 75000000000)))
    )
    (if (i64.eq (local.get $len) (i64.const 6))
      (then (return (i64.const 50000000000)))
    )
    (if (i64.eq (local.get $len) (i64.const 7))
      (then (return (i64.const 25000000000)))
    )
    (if (i64.eq (local.get $len) (i64.const 8))
      (then (return (i64.const 20000000000)))
    )
    (if (i64.eq (local.get $len) (i64.const 9))
      (then (return (i64.const 15000000000)))
    )
    (if (i64.eq (local.get $len) (i64.const 10))
      (then (return (i64.const 10000000000)))
    )
    (i64.const 5000000000)
  )

  ;; 2. Start Auction: start_auction(packed_arg) -> auction_end_timestamp
  ;; packed_arg: (domain_id * 10,000,000,000) + (bidder_id * 100,000) + length
  ;; Bid amount is passed via direct invocation or separate arg:
  ;; To maintain (i64) -> i64 ABI:
  ;; start_auction_direct(domain_id, bidder_id, bid_amount, length, now_secs)
  (func $start_auction_direct
    (param $domain_id i64)
    (param $bidder_id i64)
    (param $bid_amount i64)
    (param $length i64)
    (param $now_secs i64)
    (result i64)

    (local $base i64)
    (local $status i64)
    (local $min_bid i64)
    (local $duration i64)
    (local $end_time i64)
    (local $hue i64)

    (local.set $base (i64.mul (local.get $domain_id) (i64.const 1000)))
    (local.set $status (call $sload (i64.add (local.get $base) (i64.const 0))))

    ;; Can only start if status == 0 (Available) or status == 3 (Expired)
    (if (i32.and (i64.ne (local.get $status) (i64.const 0)) (i64.ne (local.get $status) (i64.const 3)))
      (then (unreachable))
    )

    ;; Enforce minimum bid for domain length
    (local.set $min_bid (call $min_bid_for_len (local.get $length)))
    (if (i64.lt_u (local.get $bid_amount) (local.get $min_bid))
      (then (unreachable)) ;; Bid below minimum reserve
    )

    ;; Calculate auction end
    (local.set $duration (call $sload (i64.const 1)))
    (local.set $end_time (i64.add (local.get $now_secs) (local.get $duration)))

    ;; Calculate deterministic card color hue: (domain_id * 137) % 360
    (local.set $hue (i64.rem_u (i64.mul (local.get $domain_id) (i64.const 137)) (i64.const 360)))

    ;; Store domain auction state
    (call $sstore (i64.add (local.get $base) (i64.const 0)) (i64.const 1)) ;; Status = Auction
    (call $sstore (i64.add (local.get $base) (i64.const 1)) (local.get $bidder_id)) ;; Current highest bidder
    (call $sstore (i64.add (local.get $base) (i64.const 2)) (local.get $bid_amount)) ;; Highest bid
    (call $sstore (i64.add (local.get $base) (i64.const 3)) (local.get $end_time))   ;; Auction deadline
    (call $sstore (i64.add (local.get $base) (i64.const 4)) (local.get $bidder_id)) ;; Default target
    (call $sstore (i64.add (local.get $base) (i64.const 6)) (local.get $hue))       ;; Card hue
    (call $sstore (i64.add (local.get $base) (i64.const 7)) (local.get $length))    ;; Domain length

    ;; Emit Auction Started event
    (call $emit (i64.const 30) (local.get $domain_id))
    (local.get $end_time)
  )

  ;; 3. Place Counter-Bid: place_bid(domain_id, bidder_id, bid_amount, now_secs) -> new_end_time
  (func $place_bid_direct
    (param $domain_id i64)
    (param $bidder_id i64)
    (param $bid_amount i64)
    (param $now_secs i64)
    (result i64)

    (local $base i64)
    (local $status i64)
    (local $cur_bid i64)
    (local $cur_bidder i64)
    (local $end_time i64)
    (local $min_step_bps i64)
    (local $required_bid i64)
    (local $prolongation i64)

    (local.set $base (i64.mul (local.get $domain_id) (i64.const 1000)))
    (local.set $status (call $sload (i64.add (local.get $base) (i64.const 0))))

    ;; Must be in active auction
    (if (i64.ne (local.get $status) (i64.const 1))
      (then (unreachable))
    )

    (local.set $end_time (call $sload (i64.add (local.get $base) (i64.const 3))))
    ;; Check auction not ended
    (if (i64.ge_u (local.get $now_secs) (local.get $end_time))
      (then (unreachable)) ;; Auction already expired
    )

    ;; Require at least +5% over current highest bid: required = (cur_bid * 10500) / 10000
    (local.set $cur_bid (call $sload (i64.add (local.get $base) (i64.const 2))))
    (local.set $cur_bidder (call $sload (i64.add (local.get $base) (i64.const 1))))
    (local.set $min_step_bps (call $sload (i64.const 3)))
    (local.set $required_bid (i64.div_u (i64.mul (local.get $cur_bid) (i64.add (i64.const 10000) (local.get $min_step_bps))) (i64.const 10000)))

    (if (i64.lt_u (local.get $bid_amount) (local.get $required_bid))
      (then (unreachable)) ;; Bid increment too low
    )

    ;; Outbid event (refund signal for previous highest bidder)
    (call $emit (i64.const 31) (local.get $cur_bid))

    ;; Update highest bidder and bid
    (call $sstore (i64.add (local.get $base) (i64.const 1)) (local.get $bidder_id))
    (call $sstore (i64.add (local.get $base) (i64.const 2)) (local.get $bid_amount))

    ;; Anti-sniping prolongation: if remaining time <= prolongation window, extend auction!
    (local.set $prolongation (call $sload (i64.const 2)))
    (if (i64.le_u (i64.sub (local.get $end_time) (local.get $now_secs)) (local.get $prolongation))
      (then
        (local.set $end_time (i64.add (local.get $now_secs) (local.get $prolongation)))
        (call $sstore (i64.add (local.get $base) (i64.const 3)) (local.get $end_time))
      )
    )

    ;; Emit New Highest Bid event
    (call $emit (i64.const 32) (local.get $bid_amount))
    (local.get $end_time)
  )

  ;; 4. Finalize Auction: finalize_auction(domain_id, now_secs) -> winner_id
  (func $finalize_direct (param $domain_id i64) (param $now_secs i64) (result i64)
    (local $base i64)
    (local $status i64)
    (local $end_time i64)
    (local $winner i64)
    (local $winning_bid i64)
    (local $expiry i64)

    (local.set $base (i64.mul (local.get $domain_id) (i64.const 1000)))
    (local.set $status (call $sload (i64.add (local.get $base) (i64.const 0))))

    ;; Must be in auction status
    (if (i64.ne (local.get $status) (i64.const 1))
      (then (unreachable))
    )

    (local.set $end_time (call $sload (i64.add (local.get $base) (i64.const 3))))
    ;; Cannot finalize before auction deadline has passed
    (if (i64.lt_u (local.get $now_secs) (local.get $end_time))
      (then (unreachable))
    )

    (local.set $winner (call $sload (i64.add (local.get $base) (i64.const 1))))
    (local.set $winning_bid (call $sload (i64.add (local.get $base) (i64.const 2))))

    ;; Registration duration: 1 year (365 days = 31,536,000 seconds)
    (local.set $expiry (i64.add (local.get $now_secs) (i64.const 31536000)))

    ;; Update status to Active/Owned (status = 2)
    (call $sstore (i64.add (local.get $base) (i64.const 0)) (i64.const 2))
    ;; Target initially resolves to winner
    (call $sstore (i64.add (local.get $base) (i64.const 4)) (local.get $winner))
    ;; Expiration timestamp
    (call $sstore (i64.add (local.get $base) (i64.const 5)) (local.get $expiry))

    ;; Emit Domain Registered event
    (call $emit (i64.const 33) (local.get $domain_id))
    (local.get $winner)
  )

  ;; 5. Single-argument WASM Exports for SVM compatibility:
  ;; start_auction(packed): packed = (domain_id * 10,000,000,000) + (bidder_id * 100,000) + length
  ;; Default bid: min_bid for length, default now = 1,750,000,000
  (func (export "start_auction") (param $packed i64) (result i64)
    (local $domain_id i64)
    (local $bidder_id i64)
    (local $length i64)
    (local $min_bid i64)

    (local.set $domain_id (i64.div_u (local.get $packed) (i64.const 10000000000)))
    (local.set $bidder_id (i64.div_u (i64.rem_u (local.get $packed) (i64.const 10000000000)) (i64.const 100000)))
    (local.set $length (i64.rem_u (local.get $packed) (i64.const 100000)))
    (local.set $min_bid (call $min_bid_for_len (local.get $length)))

    (call $start_auction_direct (local.get $domain_id) (local.get $bidder_id) (local.get $min_bid) (local.get $length) (i64.const 1750000000))
  )

  ;; place_bid(packed): packed = (domain_id * 10,000,000,000) + (bidder_id * 10,000) + bid_step_index
  ;; Increases bid by (10% * index)
  (func (export "place_bid") (param $packed i64) (result i64)
    (local $domain_id i64)
    (local $bidder_id i64)
    (local $step i64)
    (local $base i64)
    (local $cur_bid i64)
    (local $new_bid i64)

    (local.set $domain_id (i64.div_u (local.get $packed) (i64.const 10000000000)))
    (local.set $bidder_id (i64.div_u (i64.rem_u (local.get $packed) (i64.const 10000000000)) (i64.const 10000)))
    (local.set $step (local.get $packed))
    (local.set $step (i64.add (i64.rem_u (local.get $step) (i64.const 10000)) (i64.const 1)))

    (local.set $base (i64.mul (local.get $domain_id) (i64.const 1000)))
    (local.set $cur_bid (call $sload (i64.add (local.get $base) (i64.const 2))))
    ;; new_bid = cur_bid * (100 + step * 10) / 100
    (local.set $new_bid (i64.div_u (i64.mul (local.get $cur_bid) (i64.add (i64.const 100) (i64.mul (local.get $step) (i64.const 10)))) (i64.const 100)))

    (call $place_bid_direct (local.get $domain_id) (local.get $bidder_id) (local.get $new_bid) (i64.const 1750001800))
  )

  ;; finalize_auction(domain_id)
  (func (export "finalize_auction") (param $domain_id i64) (result i64)
    ;; Simulates now at 1,750,010,000 (past auction duration)
    (call $finalize_direct (local.get $domain_id) (i64.const 1750010000))
  )

  ;; 6. Resolve Domain Target: resolve(domain_id) -> target_address_id
  (func (export "resolve") (param $domain_id i64) (result i64)
    (local $base i64)
    (local $status i64)

    (local.set $base (i64.mul (local.get $domain_id) (i64.const 1000)))
    (local.set $status (call $sload (i64.add (local.get $base) (i64.const 0))))

    ;; Only active domains resolve
    (if (i64.ne (local.get $status) (i64.const 2))
      (then (return (i64.const 0)))
    )

    (call $sload (i64.add (local.get $base) (i64.const 4)))
  )

  ;; 7. Set Target (DNS Re-pointing): set_target(packed) -> new_target
  ;; packed: (domain_id * 10,000,000,000) + (caller_id * 100,000) + new_target
  (func (export "set_target") (param $packed i64) (result i64)
    (local $domain_id i64)
    (local $caller_id i64)
    (local $new_target i64)
    (local $base i64)
    (local $owner i64)

    (local.set $domain_id (i64.div_u (local.get $packed) (i64.const 10000000000)))
    (local.set $caller_id (i64.div_u (i64.rem_u (local.get $packed) (i64.const 10000000000)) (i64.const 100000)))
    (local.set $new_target (i64.rem_u (local.get $packed) (i64.const 100000)))

    (local.set $base (i64.mul (local.get $domain_id) (i64.const 1000)))
    (local.set $owner (call $sload (i64.add (local.get $base) (i64.const 1))))

    ;; Caller must be owner
    (if (i64.ne (local.get $caller_id) (local.get $owner))
      (then (unreachable))
    )

    (call $sstore (i64.add (local.get $base) (i64.const 4)) (local.get $new_target))
    (call $emit (i64.const 34) (local.get $new_target))
    (local.get $new_target)
  )

  ;; 8. Transfer Domain (NFT Sale / Transfer): transfer(packed) -> new_owner
  ;; packed: (domain_id * 10,000,000,000) + (caller_id * 100,000) + new_owner
  (func (export "transfer") (param $packed i64) (result i64)
    (local $domain_id i64)
    (local $caller_id i64)
    (local $new_owner i64)
    (local $base i64)
    (local $owner i64)

    (local.set $domain_id (i64.div_u (local.get $packed) (i64.const 10000000000)))
    (local.set $caller_id (i64.div_u (i64.rem_u (local.get $packed) (i64.const 10000000000)) (i64.const 100000)))
    (local.set $new_owner (i64.rem_u (local.get $packed) (i64.const 100000)))

    (local.set $base (i64.mul (local.get $domain_id) (i64.const 1000)))
    (local.set $owner (call $sload (i64.add (local.get $base) (i64.const 1))))

    ;; Caller must be owner
    (if (i64.ne (local.get $caller_id) (local.get $owner))
      (then (unreachable))
    )

    (call $sstore (i64.add (local.get $base) (i64.const 1)) (local.get $new_owner))
    (call $emit (i64.const 35) (local.get $new_owner))
    (local.get $new_owner)
  )

  ;; 9. Get Card Hue: get_hue(domain_id) -> hue degrees (0..360)
  (func (export "get_hue") (param $domain_id i64) (result i64)
    (local $base i64)
    (local.set $base (i64.mul (local.get $domain_id) (i64.const 1000)))
    (call $sload (i64.add (local.get $base) (i64.const 6)))
  )

  ;; 10. Get Expiry Timestamp: get_expiry(domain_id) -> expiry_timestamp
  (func (export "get_expiry") (param $domain_id i64) (result i64)
    (local $base i64)
    (local.set $base (i64.mul (local.get $domain_id) (i64.const 1000)))
    (call $sload (i64.add (local.get $base) (i64.const 5)))
  )
)
