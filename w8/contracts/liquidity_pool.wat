(module
  ;; Host storage and event functions provided by SVM
  (import "host" "sload" (func $sload (param i64) (result i64)))
  (import "host" "sstore" (func $sstore (param i64 i64)))
  (import "host" "emit" (func $emit (param i64 i64)))

  ;; Storage Layout:
  ;; Slot 0: Total LP Shares
  ;; Slot 1: Reserve Token A (e.g. STELL nano)
  ;; Slot 2: Reserve Token B (e.g. USDT micro)
  ;; Slot 3: Swap Fee BPS (e.g. 30 = 0.3%)
  ;; Slot 1000 + user_id: User LP Shares Balance

  ;; Event topics:
  ;; Topic 10: Deposit (shares minted)
  ;; Topic 11: Withdraw (shares burned)
  ;; Topic 12: Swap (amount out)

  ;; 1. Initialize Pool: init(fee_bps) -> returns fee_bps
  (func (export "init") (param $fee_bps i64) (result i64)
    (call $sstore (i64.const 0) (i64.const 0))  ;; Total shares = 0
    (call $sstore (i64.const 1) (i64.const 0))  ;; Reserve A = 0
    (call $sstore (i64.const 2) (i64.const 0))  ;; Reserve B = 0
    (call $sstore (i64.const 3) (local.get $fee_bps)) ;; Fee BPS
    (local.get $fee_bps)
  )

  ;; 2. Read Reserve A
  (func (export "get_reserve_a") (param $dummy i64) (result i64)
    (call $sload (i64.const 1))
  )

  ;; 3. Read Reserve B
  (func (export "get_reserve_b") (param $dummy i64) (result i64)
    (call $sload (i64.const 2))
  )

  ;; 4. Read Total Shares
  (func (export "get_total_shares") (param $dummy i64) (result i64)
    (call $sload (i64.const 0))
  )

  ;; 5. Read User Shares: shares_of(user_id) -> shares
  (func (export "shares_of") (param $user_id i64) (result i64)
    (call $sload (i64.add (i64.const 1000) (local.get $user_id)))
  )

  ;; 6. Deposit Liquidity: deposit(packed_arg) -> minted_shares
  ;; packed_arg encoding: (user_id * 10,000,000,000) + (amount_a * 100,000) + amount_b
  (func (export "deposit") (param $packed i64) (result i64)
    (local $user_id i64)
    (local $amount_a i64)
    (local $amount_b i64)
    (local $res_a i64)
    (local $res_b i64)
    (local $total_shares i64)
    (local $minted_shares i64)
    (local $user_slot i64)
    (local $user_shares i64)
    (local $share_a i64)
    (local $share_b i64)

    ;; Decode packed argument
    (local.set $user_id (i64.div_u (local.get $packed) (i64.const 10000000000)))
    (local.set $amount_a (i64.div_u (i64.rem_u (local.get $packed) (i64.const 10000000000)) (i64.const 100000)))
    (local.set $amount_b (i64.rem_u (local.get $packed) (i64.const 100000)))

    ;; Validate non-zero amounts
    (if (i32.or (i64.eqz (local.get $amount_a)) (i64.eqz (local.get $amount_b)))
      (then (unreachable))
    )

    (local.set $total_shares (call $sload (i64.const 0)))
    (local.set $res_a (call $sload (i64.const 1)))
    (local.set $res_b (call $sload (i64.const 2)))

    ;; Calculate minted shares
    (if (i64.eqz (local.get $total_shares))
      ;; Initial deposit: shares = (amount_a + amount_b) / 2
      (then
        (local.set $minted_shares (i64.div_u (i64.add (local.get $amount_a) (local.get $amount_b)) (i64.const 2)))
      )
      ;; Proportional deposit: shares = min((amount_a * total_shares) / res_a, (amount_b * total_shares) / res_b)
      (else
        (local.set $share_a (i64.div_u (i64.mul (local.get $amount_a) (local.get $total_shares)) (local.get $res_a)))
        (local.set $share_b (i64.div_u (i64.mul (local.get $amount_b) (local.get $total_shares)) (local.get $res_b)))
        ;; Take min
        (if (i64.lt_u (local.get $share_a) (local.get $share_b))
          (then (local.set $minted_shares (local.get $share_a)))
          (else (local.set $minted_shares (local.get $share_b)))
        )
      )
    )

    ;; Update storage
    (call $sstore (i64.const 0) (i64.add (local.get $total_shares) (local.get $minted_shares)))
    (call $sstore (i64.const 1) (i64.add (local.get $res_a) (local.get $amount_a)))
    (call $sstore (i64.const 2) (i64.add (local.get $res_b) (local.get $amount_b)))

    ;; Credit user shares
    (local.set $user_slot (i64.add (i64.const 1000) (local.get $user_id)))
    (local.set $user_shares (call $sload (local.get $user_slot)))
    (call $sstore (local.get $user_slot) (i64.add (local.get $user_shares) (local.get $minted_shares)))

    ;; Emit event (topic 10: deposit)
    (call $emit (i64.const 10) (local.get $minted_shares))
    (local.get $minted_shares)
  )

  ;; 7. Withdraw Liquidity: withdraw(packed_arg) -> payout_a
  ;; packed_arg encoding: (user_id * 1,000,000) + shares_to_burn
  (func (export "withdraw") (param $packed i64) (result i64)
    (local $user_id i64)
    (local $shares i64)
    (local $res_a i64)
    (local $res_b i64)
    (local $total_shares i64)
    (local $payout_a i64)
    (local $payout_b i64)
    (local $user_slot i64)
    (local $user_shares i64)

    (local.set $user_id (i64.div_u (local.get $packed) (i64.const 1000000)))
    (local.set $shares (i64.rem_u (local.get $packed) (i64.const 1000000)))

    (local.set $user_slot (i64.add (i64.const 1000) (local.get $user_id)))
    (local.set $user_shares (call $sload (local.get $user_slot)))
    (if (i64.lt_u (local.get $user_shares) (local.get $shares))
      (then (unreachable))
    )

    (local.set $total_shares (call $sload (i64.const 0)))
    (local.set $res_a (call $sload (i64.const 1)))
    (local.set $res_b (call $sload (i64.const 2)))

    ;; payout_a = (shares * res_a) / total_shares
    ;; payout_b = (shares * res_b) / total_shares
    (local.set $payout_a (i64.div_u (i64.mul (local.get $shares) (local.get $res_a)) (local.get $total_shares)))
    (local.set $payout_b (i64.div_u (i64.mul (local.get $shares) (local.get $res_b)) (local.get $total_shares)))

    ;; Deduct user shares
    (call $sstore (local.get $user_slot) (i64.sub (local.get $user_shares) (local.get $shares)))
    (call $sstore (i64.const 0) (i64.sub (local.get $total_shares) (local.get $shares)))
    (call $sstore (i64.const 1) (i64.sub (local.get $res_a) (local.get $payout_a)))
    (call $sstore (i64.const 2) (i64.sub (local.get $res_b) (local.get $payout_b)))

    (call $emit (i64.const 11) (local.get $payout_a))
    (local.get $payout_a)
  )

  ;; 8. Swap Quote: swap_quote(amount_a_in) -> amount_b_out
  ;; Uses constant product formula: dy = (y * dx * (10000 - fee)) / (x * 10000 + dx * (10000 - fee))
  (func $swap_quote (export "swap_quote") (param $dx i64) (result i64)
    (local $x i64)
    (local $y i64)
    (local $fee_bps i64)
    (local $multiplier i64)
    (local $numerator i64)
    (local $denominator i64)

    (local.set $x (call $sload (i64.const 1)))
    (local.set $y (call $sload (i64.const 2)))
    (local.set $fee_bps (call $sload (i64.const 3)))

    ;; multiplier = 10000 - fee_bps
    (local.set $multiplier (i64.sub (i64.const 10000) (local.get $fee_bps)))
    ;; numerator = y * dx * multiplier
    (local.set $numerator (i64.mul (i64.mul (local.get $y) (local.get $dx)) (local.get $multiplier)))
    ;; denominator = (x * 10000) + (dx * multiplier)
    (local.set $denominator (i64.add (i64.mul (local.get $x) (i64.const 10000)) (i64.mul (local.get $dx) (local.get $multiplier))))

    (i64.div_u (local.get $numerator) (local.get $denominator))
  )

  ;; 9. Execute Swap A -> B: swap_a_for_b(amount_a_in) -> amount_b_out
  (func (export "swap_a_for_b") (param $dx i64) (result i64)
    (local $dy i64)
    (local $x i64)
    (local $y i64)

    (local.set $dy (call $swap_quote (local.get $dx)))
    (if (i64.eqz (local.get $dy))
      (then (unreachable))
    )

    (local.set $x (call $sload (i64.const 1)))
    (local.set $y (call $sload (i64.const 2)))

    ;; Update reserves: x += dx, y -= dy
    (call $sstore (i64.const 1) (i64.add (local.get $x) (local.get $dx)))
    (call $sstore (i64.const 2) (i64.sub (local.get $y) (local.get $dy)))

    ;; Emit Swap Event
    (call $emit (i64.const 12) (local.get $dy))
    (local.get $dy)
  )
)
