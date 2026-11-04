(module
  ;; Host functions provided by SVM
  (import "host" "sload" (func $sload (param i64) (result i64)))
  (import "host" "sstore" (func $sstore (param i64 i64)))
  (import "host" "emit" (func $emit (param i64 i64)))

  ;; Storage slots layout:
  ;; Slot 0: Total Supply
  ;; Slot 1: Tax BPS (e.g. 50 = 0.5%)
  ;; Slot 2: Treasury Account (e.g. 99)
  ;; Slot 3: Admin Account (e.g. 1)
  ;; Slot 1000 + account_id: Account Balance

  ;; Event topics:
  ;; Topic 1: Transfer (amount)
  ;; Topic 2: Mint (amount)
  ;; Topic 3: Burn (amount)

  ;; 1. Initialize Token: init(initial_supply) -> returns initial_supply
  ;; Sets Total Supply, allocates initial supply to Admin (Account 1), sets default tax 50 bps
  (func (export "init") (param $initial_supply i64) (result i64)
    ;; Slot 0 = initial_supply
    (call $sstore (i64.const 0) (local.get $initial_supply))
    ;; Slot 1 = 50 (tax bps = 0.5%)
    (call $sstore (i64.const 1) (i64.const 50))
    ;; Slot 2 = 99 (treasury account)
    (call $sstore (i64.const 2) (i64.const 99))
    ;; Slot 3 = 1 (admin account)
    (call $sstore (i64.const 3) (i64.const 1))
    ;; Slot 1001 = initial_supply (admin balance)
    (call $sstore (i64.const 1001) (local.get $initial_supply))
    ;; Emit Mint event
    (call $emit (i64.const 2) (local.get $initial_supply))
    (local.get $initial_supply)
  )

  ;; 2. Read Total Supply: total_supply(dummy) -> total_supply
  (func (export "total_supply") (param $dummy i64) (result i64)
    (call $sload (i64.const 0))
  )

  ;; 3. Read Account Balance: balance_of(account_id) -> balance
  (func (export "balance_of") (param $account_id i64) (result i64)
    (call $sload (i64.add (i64.const 1000) (local.get $account_id)))
  )

  ;; 4. Set Transfer Tax in BPS: set_tax(tax_bps) -> new_tax
  (func (export "set_tax") (param $tax_bps i64) (result i64)
    (call $sstore (i64.const 1) (local.get $tax_bps))
    (local.get $tax_bps)
  )

  ;; 5. Transfer tokens: transfer(packed_arg) -> returns net_received
  ;; Argument packed format: (from_id * 1,000,000,000,000) + (to_id * 1,000,000) + amount
  ;; For simplified integer ABI: transfer_amount
  (func $transfer_direct (export "transfer_direct") (param $from_id i64) (param $to_id i64) (param $amount i64) (result i64)
    (local $from_slot i64)
    (local $to_slot i64)
    (local $from_bal i64)
    (local $to_bal i64)
    (local $tax_bps i64)
    (local $tax_amount i64)
    (local $net_amount i64)
    (local $treasury_slot i64)
    (local $treasury_bal i64)

    (local.set $from_slot (i64.add (i64.const 1000) (local.get $from_id)))
    (local.set $to_slot (i64.add (i64.const 1000) (local.get $to_id)))
    (local.set $treasury_slot (i64.add (i64.const 1000) (call $sload (i64.const 2))))

    (local.set $from_bal (call $sload (local.get $from_slot)))
    ;; Check sufficient balance
    (if (i64.lt_u (local.get $from_bal) (local.get $amount))
      (then (unreachable))
    )

    ;; Calculate tax = (amount * tax_bps) / 10000
    (local.set $tax_bps (call $sload (i64.const 1)))
    (local.set $tax_amount (i64.div_u (i64.mul (local.get $amount) (local.get $tax_bps)) (i64.const 10000)))
    (local.set $net_amount (i64.sub (local.get $amount) (local.get $tax_amount)))

    ;; Deduct from sender
    (call $sstore (local.get $from_slot) (i64.sub (local.get $from_bal) (local.get $amount)))

    ;; Credit net to recipient
    (local.set $to_bal (call $sload (local.get $to_slot)))
    (call $sstore (local.get $to_slot) (i64.add (local.get $to_bal) (local.get $net_amount)))

    ;; Credit tax to treasury
    (if (i64.gt_u (local.get $tax_amount) (i64.const 0))
      (then
        (local.set $treasury_bal (call $sload (local.get $treasury_slot)))
        (call $sstore (local.get $treasury_slot) (i64.add (local.get $treasury_bal) (local.get $tax_amount)))
      )
    )

    ;; Emit Transfer event
    (call $emit (i64.const 1) (local.get $net_amount))
    (local.get $net_amount)
  )

  ;; 6. Transfer single-arg wrapper (param i64) -> (result i64)
  ;; arg encoding: (from_id * 100,000,000) + (to_id * 100,000) + amount
  ;; Example: from 1 to 2 amount 500 => 1*100000000 + 2*100000 + 500 = 100200500
  (func (export "transfer") (param $packed i64) (result i64)
    (local $from_id i64)
    (local $to_id i64)
    (local $amount i64)

    (local.set $from_id (i64.div_u (local.get $packed) (i64.const 100000000)))
    (local.set $to_id (i64.div_u (i64.rem_u (local.get $packed) (i64.const 100000000)) (i64.const 100000)))
    (local.set $amount (i64.rem_u (local.get $packed) (i64.const 100000)))

    (call $transfer_direct (local.get $from_id) (local.get $to_id) (local.get $amount))
  )

  ;; 7. Burn tokens: burn(amount) -> new_total_supply
  ;; Burns from admin account (Account 1)
  (func (export "burn") (param $amount i64) (result i64)
    (local $admin_slot i64)
    (local $admin_bal i64)
    (local $cur_supply i64)
    (local $new_supply i64)

    (local.set $admin_slot (i64.const 1001))
    (local.set $admin_bal (call $sload (local.get $admin_slot)))
    (if (i64.lt_u (local.get $admin_bal) (local.get $amount))
      (then (unreachable))
    )

    ;; Decrement admin balance
    (call $sstore (local.get $admin_slot) (i64.sub (local.get $admin_bal) (local.get $amount)))

    ;; Decrement total supply
    (local.set $cur_supply (call $sload (i64.const 0)))
    (local.set $new_supply (i64.sub (local.get $cur_supply) (local.get $amount)))
    (call $sstore (i64.const 0) (local.get $new_supply))

    (call $emit (i64.const 3) (local.get $amount))
    (local.get $new_supply)
  )

  ;; 8. Mint new tokens: mint(amount) -> new_total_supply
  ;; Mints to admin account (Account 1) and increases total supply
  (func (export "mint") (param $amount i64) (result i64)
    (local $admin_slot i64)
    (local $admin_bal i64)
    (local $cur_supply i64)
    (local $new_supply i64)

    (local.set $admin_slot (i64.const 1001))
    (local.set $admin_bal (call $sload (local.get $admin_slot)))
    (call $sstore (local.get $admin_slot) (i64.add (local.get $admin_bal) (local.get $amount)))

    (local.set $cur_supply (call $sload (i64.const 0)))
    (local.set $new_supply (i64.add (local.get $cur_supply) (local.get $amount)))
    (call $sstore (i64.const 0) (local.get $new_supply))

    (call $emit (i64.const 2) (local.get $amount))
    (local.get $new_supply)
  )
)
