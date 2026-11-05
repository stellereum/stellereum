(module
  ;; Host functions provided by SVM
  (import "host" "sload" (func $sload (param i64) (result i64)))
  (import "host" "sstore" (func $sstore (param i64 i64)))
  (import "host" "emit" (func $emit (param i64 i64)))

  ;; Storage Layout:
  ;; Slot 0: Owner ID (master key)
  ;; Slot 1: Guardian ID (social recovery / rotation guardian)
  ;; Slot 2: Creation Fee Paid (2 STELL = 2,000,000,000 nano-STELL)
  ;; Slot 3: Total Sessions Count
  ;;
  ;; Per-Session Slots (base = 1000 * session_id):
  ;; base + 0: service_id (domain or service identifier)
  ;; base + 1: session_pubkey_id
  ;; base + 2: scope (bits: 1=transfer, 2=svm, 4=actor, 255=all)
  ;; base + 3: valid_until (timestamp)
  ;; base + 4: budget (nano-STELL limit)
  ;; base + 5: spent (nano-STELL consumed)
  ;; base + 6: revoked (0 = active, 1 = revoked)

  ;; Event Topics:
  ;; Topic 20: Account Created (owner)
  ;; Topic 21: Session Created (session_id)
  ;; Topic 22: Session Spent (amount)
  ;; Topic 23: Session Revoked (session_id)
  ;; Topic 24: Guardian Rotated (new_guardian)

  ;; 1. Initialize Account Object: init(owner_id) -> returns owner_id
  ;; Creation cost: 2 STELL (fixed consensus fee, recorded in slot 2)
  (func (export "init") (param $owner_id i64) (result i64)
    (call $sstore (i64.const 0) (local.get $owner_id))
    (call $sstore (i64.const 1) (i64.const 0)) ;; No guardian initially
    (call $sstore (i64.const 2) (i64.const 2000000000)) ;; 2 STELL creation anti-spam fee
    (call $sstore (i64.const 3) (i64.const 0)) ;; 0 sessions initially

    ;; Emit Account Created event
    (call $emit (i64.const 20) (local.get $owner_id))
    (local.get $owner_id)
  )

  ;; 2. Read Owner
  (func (export "get_owner") (param $dummy i64) (result i64)
    (call $sload (i64.const 0))
  )

  ;; 3. Read Guardian
  (func (export "get_guardian") (param $dummy i64) (result i64)
    (call $sload (i64.const 1))
  )

  ;; 4. Set/Rotate Guardian: rotate_guardian(new_guardian_id) -> returns new_guardian_id
  (func (export "rotate_guardian") (param $new_guardian i64) (result i64)
    (call $sstore (i64.const 1) (local.get $new_guardian))
    (call $emit (i64.const 24) (local.get $new_guardian))
    (local.get $new_guardian)
  )

  ;; 5. Create Session: create_session_direct(session_id, service_id, pubkey_id, scope, valid_until, budget) -> session_id
  (func $create_session_direct
    (param $session_id i64)
    (param $service_id i64)
    (param $pubkey_id i64)
    (param $scope i64)
    (param $valid_until i64)
    (param $budget i64)
    (result i64)

    (local $base i64)
    (local.set $base (i64.mul (local.get $session_id) (i64.const 1000)))

    (call $sstore (i64.add (local.get $base) (i64.const 0)) (local.get $service_id))
    (call $sstore (i64.add (local.get $base) (i64.const 1)) (local.get $pubkey_id))
    (call $sstore (i64.add (local.get $base) (i64.const 2)) (local.get $scope))
    (call $sstore (i64.add (local.get $base) (i64.const 3)) (local.get $valid_until))
    (call $sstore (i64.add (local.get $base) (i64.const 4)) (local.get $budget))
    (call $sstore (i64.add (local.get $base) (i64.const 5)) (i64.const 0)) ;; spent = 0
    (call $sstore (i64.add (local.get $base) (i64.const 6)) (i64.const 0)) ;; revoked = 0

    ;; Increment total sessions count
    (call $sstore (i64.const 3) (i64.add (call $sload (i64.const 3)) (i64.const 1)))

    ;; Emit Session Created event
    (call $emit (i64.const 21) (local.get $session_id))
    (local.get $session_id)
  )

  ;; 6. Create Session packed: create_session(packed) -> session_id
  ;; packed: (session_id * 10,000,000,000) + (service_id * 100,000) + budget
  ;; Defaults scope = 255 (all), valid_until = far future (2,000,000,000)
  (func (export "create_session") (param $packed i64) (result i64)
    (local $session_id i64)
    (local $service_id i64)
    (local $budget i64)

    (local.set $session_id (i64.div_u (local.get $packed) (i64.const 10000000000)))
    (local.set $service_id (i64.div_u (i64.rem_u (local.get $packed) (i64.const 10000000000)) (i64.const 100000)))
    (local.set $budget (i64.rem_u (local.get $packed) (i64.const 100000)))

    (call $create_session_direct
      (local.get $session_id)
      (local.get $service_id)
      (local.get $session_id) ;; pubkey_id = session_id
      (i64.const 255)         ;; SCOPE_ALL
      (i64.const 2000000000)  ;; valid_until
      (local.get $budget)
    )
  )

  ;; 7. Spend with Session: spend_with_session(packed) -> remaining_budget
  ;; packed: (session_id * 1,000,000) + amount
  (func (export "spend_with_session") (param $packed i64) (result i64)
    (local $session_id i64)
    (local $amount i64)
    (local $base i64)
    (local $revoked i64)
    (local $budget i64)
    (local $spent i64)
    (local $new_spent i64)

    (local.set $session_id (i64.div_u (local.get $packed) (i64.const 1000000)))
    (local.set $amount (i64.rem_u (local.get $packed) (i64.const 1000000)))
    (local.set $base (i64.mul (local.get $session_id) (i64.const 1000)))

    ;; Check not revoked
    (local.set $revoked (call $sload (i64.add (local.get $base) (i64.const 6))))
    (if (i64.ne (local.get $revoked) (i64.const 0))
      (then (unreachable)) ;; Revoked session rejected
    )

    ;; Check budget limit
    (local.set $budget (call $sload (i64.add (local.get $base) (i64.const 4))))
    (local.set $spent (call $sload (i64.add (local.get $base) (i64.const 5))))
    (local.set $new_spent (i64.add (local.get $spent) (local.get $amount)))

    (if (i64.gt_u (local.get $new_spent) (local.get $budget))
      (then (unreachable)) ;; Out of session budget
    )

    ;; Record spend
    (call $sstore (i64.add (local.get $base) (i64.const 5)) (local.get $new_spent))

    ;; Emit Session Spent event
    (call $emit (i64.const 22) (local.get $amount))

    ;; Return remaining budget
    (i64.sub (local.get $budget) (local.get $new_spent))
  )

  ;; 8. Revoke Session: revoke_session(session_id) -> 1
  (func (export "revoke_session") (param $session_id i64) (result i64)
    (local $base i64)
    (local.set $base (i64.mul (local.get $session_id) (i64.const 1000)))
    (call $sstore (i64.add (local.get $base) (i64.const 6)) (i64.const 1)) ;; revoked = 1
    (call $emit (i64.const 23) (local.get $session_id))
    (i64.const 1)
  )

  ;; 9. Check if Session is Active: is_session_active(session_id) -> 1 if active, 0 if revoked or exhausted
  (func (export "is_session_active") (param $session_id i64) (result i64)
    (local $base i64)
    (local $revoked i64)
    (local $budget i64)
    (local $spent i64)

    (local.set $base (i64.mul (local.get $session_id) (i64.const 1000)))
    (local.set $revoked (call $sload (i64.add (local.get $base) (i64.const 6))))
    (if (i64.ne (local.get $revoked) (i64.const 0))
      (then (return (i64.const 0)))
    )

    (local.set $budget (call $sload (i64.add (local.get $base) (i64.const 4))))
    (local.set $spent (call $sload (i64.add (local.get $base) (i64.const 5))))
    (if (i64.ge_u (local.get $spent) (local.get $budget))
      (then (return (i64.const 0)))
    )

    (i64.const 1)
  )

  ;; 10. Remaining Budget: get_session_budget(session_id) -> remaining
  (func (export "get_session_budget") (param $session_id i64) (result i64)
    (local $base i64)
    (local $budget i64)
    (local $spent i64)

    (local.set $base (i64.mul (local.get $session_id) (i64.const 1000)))
    (local.set $budget (call $sload (i64.add (local.get $base) (i64.const 4))))
    (local.set $spent (call $sload (i64.add (local.get $base) (i64.const 5))))
    (if (i64.ge_u (local.get $spent) (local.get $budget))
      (then (return (i64.const 0)))
    )
    (i64.sub (local.get $budget) (local.get $spent))
  )
)
